// src/tools/scan-skill.js — 6-layer deep scanner for OpenClaw skills
// Orchestrates prompt scanning, code analysis, ClawHavoc signatures,
// supply chain verification, and rug pull detection.

import { z } from "zod";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync, mkdirSync, unlinkSync } from "fs";
import { resolve, basename, dirname, extname, join, sep } from "path";
import { createHash } from "crypto";
import { tmpdir, homedir } from "os";
import { fileURLToPath } from "url";
import { scanAgentPrompt } from './scan-prompt.js';
import { scanAgentAction } from './scan-action.js';
import { runAnalyzerAsync } from '../utils.js';
import { isHallucinated } from './check-package.js';

// Handle both ESM and CJS bundling
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export const scanSkillSchema = {
  skill_path: z.string().describe("Path to skill directory or SKILL.md file"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level"),
  baseline: z.boolean().optional().describe("Save current scan as baseline for rug pull detection"),
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LANG_EXT_MAP = {
  javascript: 'js', js: 'js',
  python: 'py', py: 'py',
  typescript: 'ts', ts: 'ts',
  ruby: 'rb', rb: 'rb',
  go: 'go',
  java: 'java',
  php: 'php',
  c: 'c',
  cpp: 'cpp',
  rust: 'rs', rs: 'rs',
  csharp: 'cs', cs: 'cs',
};

const CODE_FILE_EXTENSIONS = new Set([
  '.js', '.py', '.ts', '.tsx', '.jsx', '.rb', '.go',
  '.java', '.php', '.c', '.cpp', '.rs', '.cs', '.h', '.hpp',
]);

const MAX_FILE_SIZE = 500 * 1024; // 500 KB
const MAX_SUPPORTING_FILES = 20;
const SCAN_TIMEOUT_MS = 120_000; // 120s total scan timeout

const PYTHON_BUILTINS = new Set([
  'os', 'sys', 'socket', 'json', 're', 'math', 'time', 'datetime',
  'random', 'hashlib', 'base64', 'struct', 'io', 'collections',
  'itertools', 'functools', 'operator', 'string', 'textwrap',
  'unicodedata', 'difflib', 'typing', 'abc', 'contextlib',
  'decimal', 'fractions', 'statistics', 'pathlib', 'tempfile',
  'glob', 'fnmatch', 'shutil', 'pickle', 'shelve', 'sqlite3',
  'csv', 'configparser', 'argparse', 'logging', 'warnings',
  'traceback', 'threading', 'multiprocessing', 'subprocess',
  'asyncio', 'concurrent', 'signal', 'copy', 'pprint', 'enum',
  'dataclasses', 'inspect', 'dis', 'ast', 'token', 'tokenize',
  'urllib', 'http', 'email', 'html', 'xml', 'webbrowser',
  'unittest', 'doctest', 'pdb', 'profile', 'timeit',
  'platform', 'errno', 'ctypes', 'array', 'queue', 'heapq',
  'bisect', 'weakref', 'types', 'importlib', 'pkgutil',
  'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib',
  'ssl', 'select', 'selectors', 'mmap', 'codecs',
  'builtins', '__future__', 'site', 'sysconfig',
]);

const NODE_BUILTINS = new Set([
  'fs', 'path', 'crypto', 'http', 'https', 'net', 'os', 'url',
  'util', 'stream', 'events', 'buffer', 'child_process', 'cluster',
  'dgram', 'dns', 'domain', 'querystring', 'readline', 'repl',
  'string_decoder', 'tls', 'tty', 'v8', 'vm', 'zlib', 'assert',
  'async_hooks', 'console', 'constants', 'module', 'perf_hooks',
  'process', 'punycode', 'timers', 'worker_threads', 'wasi',
  'diagnostics_channel', 'inspector', 'trace_events',
  'node:fs', 'node:path', 'node:crypto', 'node:http', 'node:https',
  'node:net', 'node:os', 'node:url', 'node:util', 'node:stream',
  'node:events', 'node:buffer', 'node:child_process', 'node:cluster',
  'node:dgram', 'node:dns', 'node:querystring', 'node:readline',
  'node:string_decoder', 'node:tls', 'node:tty', 'node:v8', 'node:vm',
  'node:zlib', 'node:assert', 'node:async_hooks', 'node:console',
  'node:module', 'node:perf_hooks', 'node:process', 'node:timers',
  'node:worker_threads', 'node:diagnostics_channel', 'node:test',
]);

const SOURCE_WEIGHTS = {
  code_analysis: 3.0,
  clawhavoc: 2.5,
  rug_pull: 3.0,
  prompt_scanner: 2.0,
  supply_chain: 2.0,
  action_scanner: 2.0,
};

const SEVERITY_MULTIPLIER = { CRITICAL: 4, HIGH: 2, MEDIUM: 1 };

// ---------------------------------------------------------------------------
// Layer 4: ClawHavoc YAML loader (cached)
// ---------------------------------------------------------------------------

let _clawHavocRules = null;

function loadClawHavocRules() {
  if (_clawHavocRules !== null) return _clawHavocRules;

  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'clawhavoc.yaml');
    if (!existsSync(rulesPath)) {
      _clawHavocRules = [];
      return _clawHavocRules;
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];
    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {},
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          pattern = pattern.replace(/^\(\?i\)/, '');
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        } else if (line.match(/^\s+languages:/)) {
          inPatterns = false;
          inMetadata = false;
        }
      }

      if (rule.id && rule.patterns.length > 0) {
        rules.push(rule);
      }
    }

    _clawHavocRules = rules;
    return _clawHavocRules;
  } catch (error) {
    console.error("Error loading ClawHavoc rules:", error.message);
    _clawHavocRules = [];
    return _clawHavocRules;
  }
}

// ---------------------------------------------------------------------------
// Layer 1: Prompt Scan
// ---------------------------------------------------------------------------

async function runPromptScan(content) {
  try {
    const result = await scanAgentPrompt({ prompt_text: content, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    return (parsed.findings || []).map(f => ({
      category: f.category || 'prompt_injection',
      severity: f.severity === 'ERROR' ? 'CRITICAL' : f.severity === 'WARNING' ? 'HIGH' : 'MEDIUM',
      message: f.message,
      matched_text: (f.matched_text || '').substring(0, 200),
      file: 'SKILL.md',
      source: 'prompt_scanner',
      rule_id: f.rule_id || '',
      confidence: f.confidence || 'MEDIUM',
    }));
  } catch (error) {
    console.error("Layer 1 (prompt scan) failed:", error.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// Layer 2: Code Block Extraction + Scan
// ---------------------------------------------------------------------------

function extractCodeBlocks(content) {
  const blocks = [];
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g;
  let match;
  while ((match = codeBlockRegex.exec(content)) !== null) {
    const lang = (match[1] || '').toLowerCase();
    const code = match[2];
    if (code.length < 10) continue;
    blocks.push({ lang, code });
  }
  return blocks;
}

async function runCodeBlockScan(blocks) {
  const findings = [];

  for (const { lang, code } of blocks) {
    try {
      // Shell blocks -> scanAgentAction
      if (['bash', 'sh', 'shell', 'zsh'].includes(lang)) {
        const result = await scanAgentAction({
          action_type: 'bash',
          action_value: code,
          verbosity: 'full',
        });
        const parsed = JSON.parse(result.content[0].text);
        for (const f of (parsed.findings || [])) {
          findings.push({
            category: 'code_execution',
            severity: f.severity || 'HIGH',
            message: f.message,
            matched_text: (code).substring(0, 200),
            file: `code_block:${lang}`,
            source: 'action_scanner',
            rule_id: f.rule || '',
            confidence: 'HIGH',
          });
        }
        continue;
      }

      // Programming language blocks -> runAnalyzerAsync via temp file
      const ext = LANG_EXT_MAP[lang];
      if (!ext) continue;

      const tmpName = `skill-scan-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
      const tmpPath = join(tmpdir(), tmpName);

      try {
        writeFileSync(tmpPath, code, 'utf-8');
        const issues = await runAnalyzerAsync(tmpPath);
        if (Array.isArray(issues)) {
          for (const issue of issues) {
            findings.push({
              category: issue.ruleId || 'code_vulnerability',
              severity: issue.severity === 'error' ? 'HIGH' : issue.severity === 'warning' ? 'MEDIUM' : 'MEDIUM',
              message: issue.message,
              matched_text: (issue.line_content || '').substring(0, 200),
              file: `code_block:${lang}`,
              source: 'code_analysis',
              rule_id: issue.ruleId || '',
              confidence: 'HIGH',
            });
          }
        }
      } finally {
        try { unlinkSync(tmpPath); } catch { /* best effort cleanup */ }
      }
    } catch (error) {
      console.error(`Layer 2 (code block scan) failed for ${lang}:`, error.message);
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Layer 3: Supporting Files
// ---------------------------------------------------------------------------

async function runSupportingFilesScan(skillDir, skillFile) {
  const findings = [];

  try {
    const entries = readdirSync(skillDir);
    let scannedCount = 0;

    for (const entry of entries) {
      if (scannedCount >= MAX_SUPPORTING_FILES) break;

      const filePath = join(skillDir, entry);

      try {
        const stat = statSync(filePath);
        if (!stat.isFile()) continue;
        if (stat.size > MAX_FILE_SIZE) continue;

        // Skip the SKILL.md itself — already scanned by L1/L2
        if (resolve(filePath) === resolve(skillFile)) continue;

        const ext = extname(entry).toLowerCase();
        if (!CODE_FILE_EXTENSIONS.has(ext)) continue;

        const issues = await runAnalyzerAsync(filePath);
        scannedCount++;
        if (Array.isArray(issues)) {
          for (const issue of issues) {
            findings.push({
              category: issue.ruleId || 'code_vulnerability',
              severity: issue.severity === 'error' ? 'HIGH' : issue.severity === 'warning' ? 'MEDIUM' : 'MEDIUM',
              message: issue.message,
              matched_text: (issue.line_content || '').substring(0, 200),
              file: entry,
              source: 'code_analysis',
              rule_id: issue.ruleId || '',
              confidence: 'HIGH',
            });
          }
        }
      } catch (error) {
        console.error(`Layer 3 (supporting file) failed for ${entry}:`, error.message);
      }
    }
  } catch (error) {
    console.error("Layer 3 (supporting files scan) failed:", error.message);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Layer 4: ClawHavoc Signature Matching
// ---------------------------------------------------------------------------

function runClawHavocScan(content, codeBlocks) {
  const findings = [];

  try {
    const rules = loadClawHavocRules();
    // Concatenate all code block content for matching
    const allCode = codeBlocks.map(b => b.code).join('\n');
    const scanText = content + '\n' + allCode;

    for (const rule of rules) {
      let matched = false;
      for (const pattern of rule.patterns) {
        try {
          const regex = new RegExp(pattern, 'im');
          const match = scanText.match(regex);
          if (match) {
            findings.push({
              category: rule.metadata.category || 'malware_signature',
              severity: rule.severity || 'CRITICAL',
              message: rule.message,
              matched_text: match[0].substring(0, 200),
              file: 'SKILL.md',
              source: 'clawhavoc',
              rule_id: rule.id,
              confidence: rule.metadata.confidence || 'HIGH',
            });
            matched = true;
            break; // One match per rule
          }
        } catch {
          // Skip invalid regex
        }
      }
      if (matched) continue;
    }
  } catch (error) {
    console.error("Layer 4 (ClawHavoc scan) failed:", error.message);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Layer 5: Package Supply Chain
// ---------------------------------------------------------------------------

async function runSupplyChainScan(codeBlocks) {
  const findings = [];
  const checked = new Set();

  try {
    for (const { lang, code } of codeBlocks) {
      let packages = [];
      let ecosystem = null;

      // JS/TS imports
      if (['javascript', 'js', 'typescript', 'ts'].includes(lang)) {
        ecosystem = 'npm';
        // require('pkg')
        const requireMatches = code.matchAll(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/g);
        for (const m of requireMatches) packages.push(m[1]);
        // import ... from 'pkg'
        const importFromMatches = code.matchAll(/import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g);
        for (const m of importFromMatches) packages.push(m[1]);
      }

      // Python imports
      if (['python', 'py'].includes(lang)) {
        ecosystem = 'pypi';
        const importMatches = code.matchAll(/^\s*import\s+(\S+)/gm);
        for (const m of importMatches) packages.push(m[1]);
        const fromMatches = code.matchAll(/^\s*from\s+(\S+)\s+import/gm);
        for (const m of fromMatches) packages.push(m[1]);
      }

      if (!ecosystem || packages.length === 0) continue;

      for (let pkg of packages) {
        // Skip relative imports
        if (pkg.startsWith('.') || pkg.startsWith('/')) continue;

        // Normalize package names
        if (ecosystem === 'npm') {
          // Scoped packages: @scope/name -> @scope/name
          // Non-scoped: take first segment before /
          if (pkg.startsWith('@')) {
            const parts = pkg.split('/');
            pkg = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : pkg;
          } else {
            pkg = pkg.split('/')[0];
          }
          // Skip Node builtins
          if (NODE_BUILTINS.has(pkg)) continue;
        }

        if (ecosystem === 'pypi') {
          // Take the top-level module name
          pkg = pkg.split('.')[0];
          // Skip Python builtins
          if (PYTHON_BUILTINS.has(pkg)) continue;
        }

        const key = `${ecosystem}:${pkg}`;
        if (checked.has(key)) continue;
        checked.add(key);

        try {
          const result = isHallucinated(pkg, ecosystem);
          if (result.hallucinated) {
            findings.push({
              category: 'hallucinated_package',
              severity: 'CRITICAL',
              message: `Package "${pkg}" not found in ${ecosystem} registry — possible hallucinated or malicious dependency`,
              matched_text: pkg,
              file: `code_block:${lang}`,
              source: 'supply_chain',
              rule_id: `supply_chain.hallucinated.${ecosystem}`,
              confidence: result.bloomFilter ? 'MEDIUM' : 'HIGH',
            });
          }
        } catch (error) {
          console.error(`Layer 5 (supply chain) check failed for ${pkg}:`, error.message);
        }
      }
    }
  } catch (error) {
    console.error("Layer 5 (supply chain scan) failed:", error.message);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Layer 6: Rug Pull Detection
// ---------------------------------------------------------------------------

function getBaselineDir() {
  return join(homedir(), '.openclaw', '.scanner-baselines');
}

function getBaselinePath(skillDir) {
  const name = basename(skillDir);
  return join(getBaselineDir(), `${name}.json`);
}

function computeHash(content) {
  return createHash('sha256').update(content).digest('hex');
}

function runRugPullCheck(content, skillDir, saveBaseline) {
  const findings = [];
  const hash = computeHash(content);

  try {
    const baselinePath = getBaselinePath(skillDir);

    if (saveBaseline) {
      // Save baseline
      const baselineDir = getBaselineDir();
      if (!existsSync(baselineDir)) {
        mkdirSync(baselineDir, { recursive: true });
      }
      writeFileSync(baselinePath, JSON.stringify({
        hash,
        skill_path: skillDir,
        saved_at: new Date().toISOString(),
        content_length: content.length,
      }, null, 2), 'utf-8');
    } else if (existsSync(baselinePath)) {
      // Compare against baseline
      try {
        const baseline = JSON.parse(readFileSync(baselinePath, 'utf-8'));
        if (baseline.hash && baseline.hash !== hash) {
          findings.push({
            category: 'rug_pull',
            severity: 'CRITICAL',
            message: `SKILL.md content has changed since baseline was saved on ${baseline.saved_at || 'unknown date'} — possible rug pull attack`,
            matched_text: `hash changed: ${baseline.hash.substring(0, 16)}... -> ${hash.substring(0, 16)}...`,
            file: 'SKILL.md',
            source: 'rug_pull',
            rule_id: 'rug_pull.content_changed',
            confidence: 'HIGH',
          });
        }
      } catch {
        // Corrupt baseline — ignore
      }
    }
  } catch (error) {
    console.error("Layer 6 (rug pull check) failed:", error.message);
  }

  return { findings, hash };
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

function deduplicateFindings(findings) {
  const seen = new Set();
  const unique = [];

  for (const f of findings) {
    const key = `${f.rule_id || f.message}::${f.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(f);
  }

  return unique;
}

// ---------------------------------------------------------------------------
// Weighted Grade Calculation
// ---------------------------------------------------------------------------

function calculateGrade(findings) {
  // Hard-fail: ClawHavoc, rug pull, critical prompt injection, or critical supply chain → F
  for (const f of findings) {
    if (f.source === 'clawhavoc') return 'F';
    if (f.source === 'rug_pull') return 'F';
    if (f.source === 'prompt_scanner' && f.severity === 'CRITICAL') return 'F';
    if (f.source === 'supply_chain' && f.severity === 'CRITICAL') return 'F';
  }

  // Weighted model for remaining findings
  let score = 0;

  for (const f of findings) {
    const weight = SOURCE_WEIGHTS[f.source] || 1.0;
    const severityMul = SEVERITY_MULTIPLIER[f.severity] || 1;
    const confidenceDiscount = f.confidence === 'LOW' ? 0.5 : 1.0;
    score += weight * severityMul * confidenceDiscount;
  }

  if (score === 0) return 'A';
  if (score <= 2) return 'B';
  if (score <= 6) return 'C';
  if (score <= 12) return 'D';
  return 'F';
}

function generateRecommendation(grade) {
  switch (grade) {
    case 'F': return 'DO NOT INSTALL - This skill contains critical security threats that pose immediate risk';
    case 'D': return 'CAUTION - This skill has notable security concerns that should be reviewed before installing';
    case 'C': return 'MODERATE RISK - This skill has some findings that warrant review';
    default: return 'OK to install';
  }
}

// ---------------------------------------------------------------------------
// Main Orchestrator
// ---------------------------------------------------------------------------

export async function scanSkill({ skill_path, verbosity, baseline }) {
  // Path resolution
  const resolvedPath = resolve(skill_path);

  // Path containment — only allow paths within cwd or ~/.openclaw/skills/
  const cwd = process.cwd();
  const openclawSkills = resolve(homedir(), '.openclaw', 'skills');
  const isAllowed = resolvedPath === cwd || resolvedPath.startsWith(cwd + sep)
    || resolvedPath === openclawSkills || resolvedPath.startsWith(openclawSkills + sep);
  if (!isAllowed) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: "skill_path must be within the current working directory or ~/.openclaw/skills/",
        skill_path: resolvedPath
      }) }]
    };
  }

  if (!existsSync(resolvedPath)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "Skill path not found", skill_path: resolvedPath }) }]
    };
  }

  const stat = statSync(resolvedPath);
  let skillDir, skillFile;

  if (stat.isDirectory()) {
    skillDir = resolvedPath;
    skillFile = resolve(resolvedPath, 'SKILL.md');
  } else {
    skillDir = dirname(resolvedPath);
    skillFile = resolvedPath;
  }

  if (!existsSync(skillFile)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "SKILL.md not found", checked: skillFile }) }]
    };
  }

  const content = readFileSync(skillFile, 'utf-8');
  const codeBlocks = extractCodeBlocks(content);

  // ---------------------------------------------------------------------------
  // Execute layers with total timeout protection
  // L1, L2, L3, L5 run in parallel. L4 and L6 are synchronous — run after.
  // ---------------------------------------------------------------------------

  const scanPromise = (async () => {
    const [promptFindings, codeBlockFindings, supportingFindings, supplyChainFindings] =
      await Promise.all([
        runPromptScan(content),                          // L1
        runCodeBlockScan(codeBlocks),                    // L2
        runSupportingFilesScan(skillDir, skillFile),     // L3
        runSupplyChainScan(codeBlocks),                  // L5
      ]);

    const clawHavocFindings = runClawHavocScan(content, codeBlocks);           // L4 (sync)
    const { findings: rugPullFindings, hash: contentHash } =
      runRugPullCheck(content, skillDir, !!baseline);                           // L6 (sync)

    return { promptFindings, codeBlockFindings, supportingFindings, clawHavocFindings, supplyChainFindings, rugPullFindings, contentHash };
  })();

  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error('Scan timed out after 120s')), SCAN_TIMEOUT_MS);
  });

  let layerResults;
  try {
    layerResults = await Promise.race([scanPromise, timeoutPromise]);
  } catch (error) {
    clearTimeout(timeoutId);
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: error.message,
        skill_path: resolvedPath,
        grade: 'F',
        recommendation: 'Scan failed — could not complete analysis within time limit',
      }, null, 2) }]
    };
  }
  clearTimeout(timeoutId);

  const { promptFindings, codeBlockFindings, supportingFindings, clawHavocFindings, supplyChainFindings, rugPullFindings, contentHash } = layerResults;

  // ---------------------------------------------------------------------------
  // Merge, deduplicate, grade
  // ---------------------------------------------------------------------------

  const allFindings = deduplicateFindings([
    ...promptFindings,
    ...codeBlockFindings,
    ...supportingFindings,
    ...clawHavocFindings,
    ...supplyChainFindings,
    ...rugPullFindings,
  ]);

  const grade = calculateGrade(allFindings);
  const recommendation = generateRecommendation(grade);

  const layersExecuted = {
    prompt_scan: promptFindings.length,
    code_blocks: codeBlockFindings.length,
    supporting_files: supportingFindings.length,
    clawhavoc: clawHavocFindings.length,
    supply_chain: supplyChainFindings.length,
    rug_pull: rugPullFindings.length,
  };

  // ---------------------------------------------------------------------------
  // Build result based on verbosity
  // ---------------------------------------------------------------------------

  const level = verbosity || 'compact';

  const result = {
    skill_path: resolvedPath,
    grade,
    findings_count: allFindings.length,
    recommendation,
  };

  if (level === 'full') {
    result.content_hash = contentHash;
    result.layers_executed = layersExecuted;
    result.findings = allFindings;
  } else if (level === 'compact') {
    result.findings = allFindings;
  }
  // 'minimal' — omit findings array and layers_executed

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
  };
}
