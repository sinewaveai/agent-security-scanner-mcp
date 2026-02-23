// src/tools/scan-skill.js — 6-layer deep scanner for OpenClaw skills
// Orchestrates prompt scanning, code analysis, ClawHavoc signatures,
// supply chain verification, and rug pull detection.

import { z } from "zod";
import { existsSync, readFileSync, readdirSync, statSync, lstatSync, realpathSync, writeFileSync, mkdirSync, unlinkSync, renameSync, chmodSync } from "fs";
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

// Manifest / dependency files for supply-chain scanning
const MANIFEST_FILES = new Set([
  'package.json', 'package-lock.json',
  'requirements.txt', 'setup.py', 'setup.cfg', 'pyproject.toml',
  'gemfile', 'gemfile.lock',
  'cargo.toml', 'cargo.lock',
  'go.mod', 'go.sum',
  'composer.json', 'composer.lock',
]);

const MAX_FILE_SIZE = 500 * 1024; // 500 KB
const MAX_SKILL_MD_SIZE = 1024 * 1024; // 1 MB cap for SKILL.md
const MAX_SUPPORTING_FILES = 50;
const MAX_WALK_DEPTH = 5;
const MAX_TOTAL_WALK_BYTES = 5 * 1024 * 1024; // 5 MB cumulative
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

// On Windows, paths are case-insensitive; normalize for containment checks.
const IS_WIN = process.platform === 'win32';
function normPath(p) { return IS_WIN ? p.toLowerCase() : p; }
function pathStartsWith(child, parent) {
  return normPath(child) === normPath(parent) || normPath(child).startsWith(normPath(parent) + sep);
}
const MAX_CLAWHAVOC_SCAN_LEN = 2 * 1024 * 1024; // 2 MB cap for regex matching

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
    // Strip YAML frontmatter (---\n...\n---) to reduce false positives from
    // benign metadata keys.  However, we still scan the frontmatter VALUES
    // separately so that malicious content hidden in metadata is not missed.
    let textToScan = content;
    let frontmatterValues = '';
    if (textToScan.startsWith('---\n') || textToScan.startsWith('---\r\n')) {
      const endMarker = textToScan.match(/\r?\n---\s*(?:\r?\n|$)/);
      if (endMarker) {
        const rawFrontmatter = textToScan.substring(0, endMarker.index + endMarker[0].length);
        textToScan = textToScan.substring(endMarker.index + endMarker[0].length);
        // Extract YAML values (everything after the colon on each line)
        for (const line of rawFrontmatter.split('\n')) {
          const colonIdx = line.indexOf(':');
          if (colonIdx > 0) {
            const val = line.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
            if (val.length > 10) frontmatterValues += val + '\n';
          }
        }
      }
    }

    // Scan body + frontmatter values together
    const combinedText = frontmatterValues ? textToScan + '\n' + frontmatterValues : textToScan;
    const result = await scanAgentPrompt({ prompt_text: combinedText, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);

    // Handle oversized-input or error responses from the prompt scanner
    if (parsed.error) {
      return [{
        category: 'prompt_scan_error',
        severity: 'CRITICAL',
        message: parsed.error,
        matched_text: '',
        file: 'SKILL.md',
        source: 'prompt_scanner',
        rule_id: 'prompt_scanner.oversized_or_error',
        confidence: 'HIGH',
      }];
    }

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
    // Fail-closed: a crashed prompt scanner should not silently improve the grade
    return [{
      category: 'prompt_scan_error',
      severity: 'HIGH',
      message: `Prompt scanner failed: ${error.message}`,
      matched_text: '',
      file: 'SKILL.md',
      source: 'prompt_scanner',
      rule_id: 'prompt_scanner.layer_failure',
      confidence: 'MEDIUM',
    }];
  }
}

// ---------------------------------------------------------------------------
// Layer 2: Code Block Extraction + Scan
// ---------------------------------------------------------------------------

function extractCodeBlocks(content) {
  const blocks = [];
  // Match both backtick (```) and tilde (~~~) fenced code blocks.
  // Uses backreference (\1) to ensure closing fence uses the same character as opening.
  const codeBlockRegex = /(`{3,}|~{3,})(\w*)\r?\n([\s\S]*?)\1/g;
  let match;
  while ((match = codeBlockRegex.exec(content)) !== null) {
    const lang = (match[2] || '').toLowerCase();
    const code = match[3];
    if (code.length < 10) continue;
    blocks.push({ lang, code });
  }
  return blocks;
}

async function runCodeBlockScan(blocks, signal) {
  const findings = [];

  for (const { lang, code } of blocks) {
    if (signal && signal.aborted) break;
    try {
      // Shell-like blocks -> scanAgentAction
      if (['bash', 'sh', 'shell', 'zsh', 'powershell', 'ps1', 'bat', 'cmd', 'fish'].includes(lang)) {
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
        const issues = await runAnalyzerAsync(tmpPath, 'auto', signal);
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

/**
 * Recursively collect scannable files under skillDir, respecting limits.
 * Skips symlinks, hidden dirs, node_modules, and __pycache__.
 */
function collectSupportingFiles(dir, skillFile, depth, state) {
  if (depth > MAX_WALK_DEPTH) return;
  if (state.files.length >= MAX_SUPPORTING_FILES) return;
  if (state.totalBytes >= MAX_TOTAL_WALK_BYTES) return;

  let entries;
  try { entries = readdirSync(dir); } catch { return; }

  for (const entry of entries) {
    if (state.files.length >= MAX_SUPPORTING_FILES) break;
    if (state.totalBytes >= MAX_TOTAL_WALK_BYTES) break;

    // Skip most hidden entries, node_modules, __pycache__.
    // Allow security-sensitive hidden files (.env*, .npmrc) through.
    if (entry === 'node_modules' || entry === '__pycache__') continue;
    if (entry.startsWith('.') && !entry.startsWith('.env') && entry !== '.npmrc' && entry !== '.github') continue;

    const filePath = join(dir, entry);
    let lst;
    try { lst = lstatSync(filePath); } catch { continue; }

    // Reject symlinks
    if (lst.isSymbolicLink()) continue;

    if (lst.isDirectory()) {
      collectSupportingFiles(filePath, skillFile, depth + 1, state);
      continue;
    }

    if (!lst.isFile()) continue;
    if (lst.size > MAX_FILE_SIZE) continue;

    // Skip SKILL.md — already scanned by L1/L2
    if (resolve(filePath) === resolve(skillFile)) continue;

    const ext = extname(entry).toLowerCase();
    const lowerEntry = entry.toLowerCase();
    // Accept code files, manifest files, and security-sensitive dotfiles
    const isSecurityDotfile = lowerEntry.startsWith('.env') || lowerEntry === '.npmrc';
    if (!CODE_FILE_EXTENSIONS.has(ext) && !MANIFEST_FILES.has(lowerEntry) && !isSecurityDotfile) continue;

    state.totalBytes += lst.size;
    // Relative path from skillDir for the file field
    const relPath = filePath.substring(state.rootLen).replace(/\\/g, '/').replace(/^\//, '');
    state.files.push({ filePath, relPath, size: lst.size });
  }
}

async function runSupportingFilesScan(skillDir, skillFile, preCollected, signal) {
  const findings = [];

  try {
    const fileList = preCollected || (() => {
      const state = { files: [], totalBytes: 0, rootLen: skillDir.length };
      collectSupportingFiles(skillDir, skillFile, 0, state);
      return state.files;
    })();

    for (const { filePath, relPath } of fileList) {
      if (signal && signal.aborted) break;
      try {
        const ext = extname(filePath).toLowerCase();

        // Manifest / dependency files are handled by supply-chain layer — skip code analysis
        if (MANIFEST_FILES.has(basename(filePath).toLowerCase())) continue;

        const issues = await runAnalyzerAsync(filePath, 'auto', signal);
        if (Array.isArray(issues)) {
          for (const issue of issues) {
            findings.push({
              category: issue.ruleId || 'code_vulnerability',
              severity: issue.severity === 'error' ? 'HIGH' : issue.severity === 'warning' ? 'MEDIUM' : 'MEDIUM',
              message: issue.message,
              matched_text: (issue.line_content || '').substring(0, 200),
              file: relPath,
              line: issue.line ?? undefined,
              source: 'code_analysis',
              rule_id: issue.ruleId || '',
              confidence: 'HIGH',
            });
          }
        }
      } catch (error) {
        console.error(`Layer 3 (supporting file) failed for ${relPath}:`, error.message);
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
    // Cap total text to prevent ReDoS on pathological input
    const raw = content + '\n' + allCode;
    const scanText = raw.length > MAX_CLAWHAVOC_SCAN_LEN ? raw.substring(0, MAX_CLAWHAVOC_SCAN_LEN) : raw;

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

/**
 * Extract packages from a manifest file and return {ecosystem, packages[]} pairs.
 */
function extractPackagesFromManifest(filePath, content) {
  const fileName = basename(filePath).toLowerCase();
  const packages = [];

  try {
    if (fileName === 'package.json') {
      const pkg = JSON.parse(content);
      for (const depKey of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        if (pkg[depKey] && typeof pkg[depKey] === 'object') {
          packages.push(...Object.keys(pkg[depKey]));
        }
      }
      return { ecosystem: 'npm', packages };
    }

    if (fileName === 'requirements.txt') {
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
        const pkg = trimmed.split(/[><=!~\[\s;]/)[0].trim();
        if (pkg) packages.push(pkg);
      }
      return { ecosystem: 'pypi', packages };
    }

    if (fileName === 'gemfile') {
      const gemMatches = content.matchAll(/^\s*gem\s+['"]([^'"]+)['"]/gm);
      for (const m of gemMatches) packages.push(m[1]);
      return { ecosystem: 'rubygems', packages };
    }

    if (fileName === 'cargo.toml') {
      // Section-aware: only extract keys under [dependencies], [dev-dependencies],
      // [build-dependencies], or [*dependencies.*] (e.g. [target.'...'.dependencies])
      let inDepSection = false;
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        // Detect section headers
        const sectionMatch = trimmed.match(/^\[([^\]]+)\]/);
        if (sectionMatch) {
          const section = sectionMatch[1].toLowerCase();
          inDepSection = /(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)$/.test(section);
          continue;
        }
        if (!inDepSection) continue;
        // Extract "name = ..." lines within dependency sections
        const depMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=/);
        if (depMatch) {
          packages.push(depMatch[1]);
        }
      }
      return { ecosystem: 'crates', packages };
    }

    // go.mod: Go ecosystem not yet supported by the hallucination bloom filter.
    // Return a sentinel so callers can surface an informational finding.
    if (fileName === 'go.mod') {
      return { ecosystem: 'go', packages: [], unsupported: true };
    }
  } catch {
    // Parse failed — return empty
  }

  return { ecosystem: null, packages: [] };
}

async function runSupplyChainScan(codeBlocks, skillDir, skillFile, preCollected, signal) {
  const findings = [];
  const checked = new Set();

  try {
    // 1. Scan code blocks (existing behavior)
    for (const { lang, code } of codeBlocks) {
      if (signal && signal.aborted) break;
      let packages = [];
      let ecosystem = null;

      if (['javascript', 'js', 'typescript', 'ts'].includes(lang)) {
        ecosystem = 'npm';
        const requireMatches = code.matchAll(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/g);
        for (const m of requireMatches) packages.push(m[1]);
        const importFromMatches = code.matchAll(/import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g);
        for (const m of importFromMatches) packages.push(m[1]);
      }

      if (['python', 'py'].includes(lang)) {
        ecosystem = 'pypi';
        const importMatches = code.matchAll(/^\s*import\s+(\S+)/gm);
        for (const m of importMatches) packages.push(m[1]);
        const fromMatches = code.matchAll(/^\s*from\s+(\S+)\s+import/gm);
        for (const m of fromMatches) packages.push(m[1]);
      }

      if (!ecosystem || packages.length === 0) continue;

      for (let pkg of packages) {
        if (pkg.startsWith('.') || pkg.startsWith('/')) continue;

        if (ecosystem === 'npm') {
          if (pkg.startsWith('@')) {
            const parts = pkg.split('/');
            pkg = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : pkg;
          } else {
            pkg = pkg.split('/')[0];
          }
          if (NODE_BUILTINS.has(pkg)) continue;
        }

        if (ecosystem === 'pypi') {
          pkg = pkg.split('.')[0];
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

    // 2. Scan manifest / dependency files in skill directory
    const fileList = preCollected || (() => {
      const state = { files: [], totalBytes: 0, rootLen: skillDir.length };
      collectSupportingFiles(skillDir, skillFile, 0, state);
      return state.files;
    })();
    for (const { filePath } of fileList) {
      if (signal && signal.aborted) break;
      const fname = basename(filePath).toLowerCase();
      if (!MANIFEST_FILES.has(fname)) continue;

      try {
        const content = readFileSync(filePath, 'utf-8');
        const manifest = extractPackagesFromManifest(filePath, content);
        const { ecosystem, packages } = manifest;
        if (!ecosystem) continue;

        // Surface unsupported ecosystems as informational finding
        if (manifest.unsupported) {
          const relPath = filePath.substring(skillDir.length).replace(/\\/g, '/').replace(/^\//, '');
          findings.push({
            category: 'unsupported_ecosystem',
            severity: 'MEDIUM',
            message: `${fname} found but "${ecosystem}" ecosystem is not yet supported for supply-chain verification`,
            matched_text: fname,
            file: relPath,
            source: 'supply_chain',
            rule_id: `supply_chain.unsupported.${ecosystem}`,
            confidence: 'HIGH',
          });
          continue;
        }

        if (packages.length === 0) continue;

        for (let pkg of packages) {
          if (ecosystem === 'npm' && NODE_BUILTINS.has(pkg)) continue;
          if (ecosystem === 'pypi' && PYTHON_BUILTINS.has(pkg)) continue;

          const key = `${ecosystem}:${pkg}`;
          if (checked.has(key)) continue;
          checked.add(key);

          try {
            const result = isHallucinated(pkg, ecosystem);
            if (result.hallucinated) {
              const relPath = filePath.substring(skillDir.length).replace(/\\/g, '/').replace(/^\//, '');
              findings.push({
                category: 'hallucinated_package',
                severity: 'CRITICAL',
                message: `Package "${pkg}" not found in ${ecosystem} registry — possible hallucinated or malicious dependency`,
                matched_text: pkg,
                file: relPath,
                source: 'supply_chain',
                rule_id: `supply_chain.hallucinated.${ecosystem}`,
                confidence: result.bloomFilter ? 'MEDIUM' : 'HIGH',
              });
            }
          } catch (error) {
            console.error(`Layer 5 (supply chain) manifest check failed for ${pkg}:`, error.message);
          }
        }
      } catch {
        // Skip unreadable manifests
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
  // Use slug + hash of canonical path to avoid collisions between skills with
  // the same folder name in different locations.
  const slug = basename(skillDir).replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 64);
  const pathHash = createHash('sha256').update(skillDir).digest('hex').substring(0, 12);
  return join(getBaselineDir(), `${slug}-${pathHash}.json`);
}

function runRugPullCheck(content, skillDir, saveBaseline, collectedFiles) {
  const findings = [];
  // Hash SKILL.md + all supporting files with path boundaries and sorted
  // order so the hash is canonical and structural changes are detected.
  const hasher = createHash('sha256');
  hasher.update('SKILL.md\0');
  hasher.update(content);
  if (collectedFiles) {
    // Sort by relative path for deterministic ordering (readdirSync order is OS-dependent)
    const sorted = [...collectedFiles].sort((a, b) => a.relPath.localeCompare(b.relPath));
    for (const { filePath, relPath } of sorted) {
      try {
        hasher.update('\0' + relPath + '\0');
        hasher.update(readFileSync(filePath));
      } catch { /* skip unreadable */ }
    }
  }
  const hash = hasher.digest('hex');

  try {
    const baselinePath = getBaselinePath(skillDir);

    if (saveBaseline) {
      // Save baseline with atomic write (temp + rename) and restrictive perms
      const baselineDir = getBaselineDir();
      if (!existsSync(baselineDir)) {
        mkdirSync(baselineDir, { recursive: true, mode: 0o700 });
      }
      const data = JSON.stringify({
        hash,
        skill_path: skillDir,
        saved_at: new Date().toISOString(),
        content_length: content.length,
      }, null, 2);
      const tmpFile = baselinePath + `.tmp.${process.pid}.${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
      writeFileSync(tmpFile, data, { encoding: 'utf-8', mode: 0o600 });
      try {
        renameSync(tmpFile, baselinePath);
      } catch (renameErr) {
        try { unlinkSync(tmpFile); } catch { /* best effort cleanup */ }
        throw renameErr;
      }
      // On platforms where rename doesn't preserve mode, enforce it
      try { chmodSync(baselinePath, 0o600); } catch { /* best effort */ }
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
    // Include source, line, and normalized matched_text so that distinct
    // findings on different lines are not collapsed.
    const normText = (f.matched_text || '').trim().substring(0, 80).toLowerCase();
    const key = `${f.rule_id || f.message}::${f.source || ''}::${f.file}::${f.line ?? ''}::${normText}`;
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

  // Path containment — check on resolved path FIRST (before existence)
  // so that invalid external paths get rejected with the right error message.
  // Use raw cwd here (resolvedPath is also non-canonical at this point).
  const rawCwd = process.cwd();
  const allowedSkillRoots = [
    resolve(homedir(), '.openclaw', 'skills'),
    resolve(homedir(), '.openclaw', 'workspace', 'skills'),
  ];
  const isAllowed = pathStartsWith(resolvedPath, rawCwd)
    || allowedSkillRoots.some(root => pathStartsWith(resolvedPath, root));
  if (!isAllowed) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: "skill_path must be within the current working directory or ~/.openclaw/skills/ (or ~/.openclaw/workspace/skills/)",
        skill_path: resolvedPath
      }) }]
    };
  }

  if (!existsSync(resolvedPath)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "Skill path not found", skill_path: resolvedPath }) }]
    };
  }

  // Reject symlinks at the top level to prevent symlink-based path escapes
  const topStat = lstatSync(resolvedPath);
  if (topStat.isSymbolicLink()) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: "Symbolic links are not allowed as skill_path — resolve the real path first",
        skill_path: resolvedPath
      }) }]
    };
  }

  // Resolve to real path and re-verify containment (defeats symlink escapes)
  // Use canonical cwd here since realPath is also canonical.
  const realPath = realpathSync(resolvedPath);
  let canonCwd;
  try { canonCwd = realpathSync(rawCwd); } catch { canonCwd = rawCwd; }
  const canonRoots = allowedSkillRoots.map(root => {
    try { return realpathSync(root); } catch { return root; }
  });
  const realAllowed = pathStartsWith(realPath, canonCwd)
    || canonRoots.some(root => pathStartsWith(realPath, root));
  if (!realAllowed) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: "skill_path must be within the current working directory or ~/.openclaw/skills/ (or ~/.openclaw/workspace/skills/)",
        skill_path: realPath
      }) }]
    };
  }

  const stat = statSync(realPath);
  let skillDir, skillFile;

  if (stat.isDirectory()) {
    skillDir = realPath;
    skillFile = resolve(realPath, 'SKILL.md');
  } else {
    skillDir = dirname(realPath);
    skillFile = realPath;
  }

  if (!existsSync(skillFile)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "SKILL.md not found", checked: skillFile }) }]
    };
  }

  // Enforce size cap before reading to prevent OOM on adversarial inputs
  const skillStat = statSync(skillFile);
  if (skillStat.size > MAX_SKILL_MD_SIZE) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: `SKILL.md exceeds size limit (${(skillStat.size / 1024 / 1024).toFixed(1)} MB > 1 MB)`,
        skill_path: realPath,
        grade: 'F',
        recommendation: 'SKILL.md is abnormally large — possible resource exhaustion attack',
      }, null, 2) }]
    };
  }

  const content = readFileSync(skillFile, 'utf-8');
  const codeBlocks = extractCodeBlocks(content);

  // ---------------------------------------------------------------------------
  // Execute layers with total timeout protection
  // L1, L2, L3, L5 run in parallel. L4 and L6 are synchronous — run after.
  // ---------------------------------------------------------------------------

  // Collect supporting files once and share between L3 and L5
  const supportingState = { files: [], totalBytes: 0, rootLen: skillDir.length };
  collectSupportingFiles(skillDir, skillFile, 0, supportingState);
  const collectedFiles = supportingState.files;

  // AbortController allows layers to check signal.aborted between iterations
  // so they stop starting new work after the timeout fires.
  const abortController = new AbortController();
  const { signal } = abortController;

  const scanPromise = (async () => {
    const timings = {};
    const wallStart = Date.now();

    // Timed wrapper
    async function timed(label, fn) {
      const start = Date.now();
      const result = await fn();
      timings[label] = Date.now() - start;
      return result;
    }
    function timedSync(label, fn) {
      const start = Date.now();
      const result = fn();
      timings[label] = Date.now() - start;
      return result;
    }

    const [promptFindings, codeBlockFindings, supportingFindings, supplyChainFindings] =
      await Promise.all([
        timed('prompt_scan', () => runPromptScan(content)),                                                  // L1
        timed('code_blocks', () => runCodeBlockScan(codeBlocks, signal)),                                    // L2
        timed('supporting_files', () => runSupportingFilesScan(skillDir, skillFile, collectedFiles, signal)), // L3
        timed('supply_chain', () => runSupplyChainScan(codeBlocks, skillDir, skillFile, collectedFiles, signal)), // L5
      ]);

    if (signal.aborted) throw new Error('Scan timed out after 120s');

    const clawHavocFindings = timedSync('clawhavoc', () => runClawHavocScan(content, codeBlocks));  // L4
    const { findings: rugPullFindings, hash: contentHash } =
      timedSync('rug_pull', () => runRugPullCheck(content, skillDir, !!baseline, collectedFiles));    // L6

    timings.total = Date.now() - wallStart;

    return { promptFindings, codeBlockFindings, supportingFindings, clawHavocFindings, supplyChainFindings, rugPullFindings, contentHash, timings };
  })();

  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      abortController.abort();
      reject(new Error('Scan timed out after 120s'));
    }, SCAN_TIMEOUT_MS);
  });

  let layerResults;
  try {
    layerResults = await Promise.race([scanPromise, timeoutPromise]);
  } catch (error) {
    clearTimeout(timeoutId);
    return {
      content: [{ type: "text", text: JSON.stringify({
        error: error.message,
        skill_path: realPath,
        grade: 'F',
        recommendation: 'Scan failed — could not complete analysis within time limit',
      }, null, 2) }]
    };
  }
  clearTimeout(timeoutId);

  const { promptFindings, codeBlockFindings, supportingFindings, clawHavocFindings, supplyChainFindings, rugPullFindings, contentHash, timings } = layerResults;

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
    skill_path: realPath,
    grade,
    findings_count: allFindings.length,
    recommendation,
  };

  if (level === 'full') {
    result.content_hash = contentHash;
    result.layers_executed = layersExecuted;
    result.timings_ms = timings;
    result.findings = allFindings;
  } else if (level === 'compact') {
    result.findings = allFindings;
  }
  // 'minimal' — omit findings array, layers_executed, and timings

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
  };
}
