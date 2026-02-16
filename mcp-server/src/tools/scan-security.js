// src/tools/scan-security.js
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { dirname } from "path";
import { detectLanguage, runAnalyzer, generateFix, toSarif, isTestFile, extractImports } from '../utils.js';
import { discoverProjectContext } from './project-context.js';
import { resolveImportGraph } from './import-resolver.js';

export const scanSecuritySchema = {
  file_path: z.string().describe("Path to the file to scan"),
  output_format: z.enum(['json', 'sarif']).optional().describe("Output format: 'json' (default) or 'sarif' for GitHub/GitLab integration"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (counts only), 'compact' (default, actionable info), 'full' (complete metadata)"),
  include_context: z.boolean().optional().describe("Include 3 lines of surrounding context for each finding"),
  project_context: z.boolean().optional().describe("Include project security profile (frameworks, middleware, sanitizers)"),
  resolve_imports: z.boolean().optional().describe("Resolve local import graph from this file (requires project_context)")
};

// Verbosity formatters
function formatMinimal(file_path, language, issues) {
  const bySeverity = { error: 0, warning: 0, info: 0 };
  issues.forEach(i => bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1);
  return {
    file: file_path,
    language,
    total: issues.length,
    critical: bySeverity.error,
    warning: bySeverity.warning,
    info: bySeverity.info,
    message: issues.length > 0
      ? `Found ${issues.length} issue(s). Use verbosity='compact' for details.`
      : "No security issues found."
  };
}

function formatCompact(file_path, language, issues) {
  return {
    file: file_path,
    language,
    issues_count: issues.length,
    issues: issues.map(i => ({
      line: i.line + 1,
      ruleId: i.ruleId,
      severity: i.severity,
      message: i.message,
      fix: i.suggested_fix?.fixed ? i.suggested_fix.fixed.trim() : null
    }))
  };
}

function formatFull(file_path, language, issues) {
  return {
    file: file_path,
    language,
    issues_count: issues.length,
    issues: issues
  };
}

export async function scanSecurity({ file_path, output_format, verbosity, include_context, project_context, resolve_imports }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  const issues = runAnalyzer(file_path);

  if (issues.error) {
    return {
      content: [{ type: "text", text: JSON.stringify(issues) }]
    };
  }

  // Read file content for fix suggestions
  const content = readFileSync(file_path, 'utf-8');
  const lines = content.split('\n');
  const language = detectLanguage(file_path);

  // Enhance issues with fix suggestions (and optional context)
  const enhancedIssues = issues.map(issue => {
    const line = lines[issue.line] || '';
    const fix = generateFix(issue, line, language);
    const enhanced = {
      ...issue,
      line_content: line.trim(),
      suggested_fix: fix
    };

    if (include_context) {
      const start = Math.max(0, issue.line - 3);
      const end = Math.min(lines.length - 1, issue.line + 3);
      enhanced.context_before = lines.slice(start, issue.line).map((l, i) => ({
        line: start + i + 1,
        content: l
      }));
      enhanced.context_after = lines.slice(issue.line + 1, end + 1).map((l, i) => ({
        line: issue.line + 2 + i,
        content: l
      }));
    }

    return enhanced;
  });

  // Determine verbosity (default: compact)
  const level = verbosity || 'compact';

  // Return SARIF format if requested (always full detail)
  if (output_format === 'sarif') {
    return {
      content: [{
        type: "text",
        text: JSON.stringify(toSarif(file_path, language, enhancedIssues), null, 2)
      }]
    };
  }

  // Format based on verbosity
  let result;
  switch (level) {
    case 'minimal':
      result = formatMinimal(file_path, language, enhancedIssues);
      break;
    case 'full':
      result = formatFull(file_path, language, enhancedIssues);
      break;
    case 'compact':
    default:
      result = formatCompact(file_path, language, enhancedIssues);
  }

  // Attach project context if requested
  if (project_context) {
    const projectRoot = findProjectRoot(file_path);
    result.project = discoverProjectContext(projectRoot);
    result.is_test_file = isTestFile(file_path);
    result.file_imports = extractImports(content, language);

    // Attach import graph if requested
    if (resolve_imports) {
      try {
        result.import_graph = resolveImportGraph(file_path, projectRoot);
      } catch {
        // Import graph resolution failed — skip silently
      }
    }
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}

// Walk up from a file path to find the project root (has package.json, go.mod, etc.)
function findProjectRoot(filePath) {
  const depFiles = ['package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Gemfile', 'pom.xml'];
  let dir = dirname(filePath);
  const root = dir.split('/')[0] || '/';
  while (dir && dir !== root) {
    for (const depFile of depFiles) {
      try {
        // Use platform-agnostic join
        const candidate = dir + '/' + depFile;
        if (existsSync(candidate)) return dir;
        // Also try with backslash for Windows
        const candidateWin = dir + '\\' + depFile;
        if (existsSync(candidateWin)) return dir;
      } catch {
        // ignore
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dirname(filePath);
}
