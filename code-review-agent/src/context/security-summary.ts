import * as fs from 'node:fs';
import * as path from 'node:path';
import type { FileContext, DependencyGraph } from '../types/analysis.js';

/**
 * Keywords that indicate security-relevant lines worth including in summaries.
 */
const SECURITY_RELEVANT_PATTERNS = [
  // Dangerous sinks
  /\b(subprocess|exec|eval|system|popen|spawn|shell_exec|os\.system|os\.popen)\b/,
  /\b(requests?\.(get|post|put|delete|patch|head)|fetch|urllib|http\.request|axios)\b/,
  /\b(query|execute|cursor\.execute|\.raw\(|\.query\(|sequelize|knex)\b/,
  /\b(fs\.(readFile|writeFile|unlink|rmdir|rename)|open\(|os\.remove|shutil)\b/,
  // Guard / policy patterns
  /\b(allowlist|allow_list|whitelist|denylist|deny_list|blocklist|blacklist)\b/,
  /\b(validate|sanitize|authorize|authenticate|check_perm|has_perm)\b/,
  /\b(guard|policy|permission|auth_check|is_allowed\w*|can_access\w*|ALLOWED_\w+)\b/,
  /\b(shell\s*=\s*(True|False)|parameterized|prepared_statement|bind_param)\b/,
  // Routing / dispatching
  /\b(app\.(get|post|put|delete|patch|use)|router\.(get|post|put|delete))\b/,
  /\b(dispatch|handle_request|route_to|forward_to)\b/,
];

/**
 * Maximum number of nearby files to summarize.
 */
const MAX_RELATED_FILES = 4;

/**
 * Maximum lines to extract per file summary.
 */
const MAX_SUMMARY_LINES = 15;

/**
 * Maximum bytes to read from any related file.
 */
const MAX_FILE_READ_BYTES = 64 * 1024;

export interface RelatedFileSummary {
  filePath: string;
  relationship: 'imports' | 'imported-by' | 'sibling';
  relevantLines: string[];
}

/**
 * Build compact security-relevant summaries of files related to the one
 * being analyzed. This gives the LLM enough context to understand:
 * - Whether a called module has guards (allowlist, validation)
 * - Whether an imported file contains a dangerous sink
 * - Whether sibling files provide auth/policy enforcement
 */
export function buildRelatedFileSummaries(
  file: FileContext,
  projectRoot: string,
  graph?: DependencyGraph,
): RelatedFileSummary[] {
  const summaries: RelatedFileSummary[] = [];
  const seen = new Set<string>();

  // Priority 1: files this file imports (may contain sinks or guards)
  for (const imp of file.imports) {
    if (summaries.length >= MAX_RELATED_FILES) break;
    const resolved = resolveLocalFile(imp, file.filePath, projectRoot);
    if (!resolved) continue;
    const relativePath = path.relative(projectRoot, resolved);
    if (seen.has(relativePath)) continue;
    seen.add(relativePath);

    const summary = summarizeFile(resolved, projectRoot, 'imports');
    if (summary) summaries.push(summary);
  }

  // Priority 2: files that import this file (may be routers/controllers)
  for (const importer of file.importedBy) {
    if (summaries.length >= MAX_RELATED_FILES) break;
    const fullPath = path.resolve(projectRoot, importer);
    const normalized = path.relative(projectRoot, fullPath);
    if (seen.has(normalized)) continue;
    seen.add(normalized);

    const summary = summarizeFile(fullPath, projectRoot, 'imported-by');
    if (summary) summaries.push(summary);
  }

  // Priority 3: security-relevant sibling files (guard, policy, tool, etc.)
  const securitySiblingKeywords = /\b(guard|policy|validator|auth|tool|command|executor|service|middleware)\b/i;
  for (const sibling of file.siblingFiles) {
    if (summaries.length >= MAX_RELATED_FILES) break;
    if (!securitySiblingKeywords.test(sibling)) continue;

    const siblingPath = path.resolve(path.dirname(path.resolve(projectRoot, file.filePath)), sibling);
    const normalized = path.relative(projectRoot, siblingPath);
    if (seen.has(normalized)) continue;
    seen.add(normalized);

    const summary = summarizeFile(siblingPath, projectRoot, 'sibling');
    if (summary) summaries.push(summary);
  }

  return summaries;
}

/**
 * Extract security-relevant lines from a file.
 */
function summarizeFile(
  filePath: string,
  projectRoot: string,
  relationship: RelatedFileSummary['relationship'],
): RelatedFileSummary | null {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > MAX_FILE_READ_BYTES) return null;
  } catch {
    return null;
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  const lines = content.split('\n');
  const relevantLines: string[] = [];

  for (let i = 0; i < lines.length && relevantLines.length < MAX_SUMMARY_LINES; i++) {
    const line = lines[i];
    if (SECURITY_RELEVANT_PATTERNS.some((p) => p.test(line))) {
      relevantLines.push(`L${i + 1}: ${line.trim()}`);
    }
  }

  // No relevant lines found — skip this file
  if (relevantLines.length === 0) return null;

  return {
    filePath: path.relative(projectRoot, filePath),
    relationship,
    relevantLines,
  };
}

/**
 * Try to resolve a local import specifier to an actual file path.
 * Handles:
 * - Relative imports: ./foo, ../bar
 * - Python bare module imports: tools.executor → tools/executor.py
 * - Python single-token imports: guard → guard.py, tools → tools/__init__.py
 */
function resolveLocalFile(
  specifier: string,
  fromFile: string,
  projectRoot: string,
): string | null {
  const fromDir = path.dirname(path.resolve(projectRoot, fromFile));

  let basePath: string;

  if (specifier.startsWith('.')) {
    // Relative import (JS/TS/Python relative)
    basePath = path.resolve(fromDir, specifier);
  } else if (/^[a-zA-Z_]\w*(\.[a-zA-Z_]\w*)*$/.test(specifier) && !specifier.includes('/')) {
    // Python bare module import:
    //   tools.executor → tools/executor
    //   guard → guard
    //   tools → tools
    const asPath = specifier.replace(/\./g, '/');
    basePath = path.resolve(fromDir, asPath);

    // Also try from project root (Python resolves from project root or cwd)
    const fromRoot = path.resolve(projectRoot, asPath);
    const rootCandidates = [
      `${fromRoot}.py`,
      path.join(fromRoot, '__init__.py'),
    ];
    for (const candidate of rootCandidates) {
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch { /* not found */ }
    }
  } else {
    // Non-local third-party import
    return null;
  }

  // Try exact path, then common extensions
  const candidates = [
    basePath,
    `${basePath}.ts`,
    `${basePath}.js`,
    `${basePath}.py`,
    `${basePath}.go`,
    path.join(basePath, 'index.ts'),
    path.join(basePath, 'index.js'),
    `${basePath}.tsx`,
    `${basePath}.jsx`,
    path.join(basePath, '__init__.py'),
  ];

  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch { /* not found, try next */ }
  }

  return null;
}

/**
 * Format related file summaries for inclusion in the LLM prompt.
 */
export function formatRelatedFileSummaries(summaries: RelatedFileSummary[]): string {
  if (summaries.length === 0) return '';

  const parts = summaries.map((s) => {
    const header = `${s.filePath} (${s.relationship}):`;
    return [header, ...s.relevantLines].join('\n  ');
  });

  return parts.join('\n\n');
}
