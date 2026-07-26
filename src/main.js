import { Actor } from 'apify';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, extname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { scanSecurity } from './tools/scan-security.js';
import { scanMcpServer } from './tools/scan-mcp.js';

const execFileAsync = promisify(execFile);
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEFAULT_RULE_SETS = ['all'];
const DEFAULT_REPOSITORY_SCAN_FILE_LIMIT = 150;
const MAX_REPOSITORY_SCAN_FILE_LIMIT = 500;
const DEFAULT_REPOSITORY_FILE_TIMEOUT_SECONDS = 30;
const MAX_REPOSITORY_FILE_TIMEOUT_SECONDS = 120;
const DEFAULT_INCLUDE_TEST_FILES = false;
const REPOSITORY_SCAN_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php',
  '.rs', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.cs',
  '.tf', '.hcl', '.sql'
]);
const REPOSITORY_SCAN_SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', 'dist', 'build', 'coverage', '.next',
  '.nuxt', '.venv', 'venv', 'env', '__pycache__', '.pytest_cache'
]);
const REPOSITORY_TEST_DIRS = new Set([
  '__fixtures__', '__mocks__', '__tests__', 'benchmark', 'benchmarks',
  'demo', 'demos', 'fixture', 'fixtures', 'mock', 'mocks', 'spec',
  'test', 'tests'
]);
const REPOSITORY_TEST_FILE_PATTERNS = [
  /\.(?:test|spec)\.[cm]?[jt]sx?$/i,
  /(?:^|[\\/])test_[^\\/]+\.py$/i,
  /(?:^|[\\/])[^\\/]+_test\.py$/i,
  /(?:^|[\\/])conftest\.py$/i
];
const DEFAULT_REPOSITORY_SCAN_MODE = 'quick';
const REPOSITORY_SCAN_MODES = new Set(['quick', 'analyzer']);
const QUICK_FINDINGS_PER_FILE_LIMIT = 20;
const QUICK_REPOSITORY_RULES = [
  {
    id: 'eval-detected',
    severity: 'error',
    category: 'code-execution',
    pattern: /\beval\s*\(/,
    message: 'eval() can execute attacker-controlled code.'
  },
  {
    id: 'new-function-detected',
    severity: 'error',
    category: 'code-execution',
    pattern: /\bnew\s+Function\s*\(/,
    message: 'new Function() can execute attacker-controlled code.'
  },
  {
    id: 'child-process-exec',
    severity: 'error',
    category: 'command-injection',
    pattern: /\bexec(?:Sync)?\s*\(/,
    message: 'child_process exec-style calls can lead to command injection when input is not fixed.'
  },
  {
    id: 'shell-true',
    severity: 'error',
    category: 'command-injection',
    pattern: /\bshell\s*[:=]\s*true\b/i,
    message: 'shell:true or shell=True increases command injection risk.'
  },
  {
    id: 'hardcoded-secret',
    severity: 'warning',
    category: 'secrets',
    pattern: /\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['"][^'"\n]{12,}['"]/i,
    message: 'Possible hardcoded secret or credential.'
  },
  {
    id: 'innerhtml-assignment',
    severity: 'warning',
    category: 'xss',
    pattern: /\.innerHTML\s*=/,
    message: 'innerHTML assignment can introduce XSS when content is user-controlled.'
  },
  {
    id: 'document-write',
    severity: 'warning',
    category: 'xss',
    pattern: /\bdocument\.write\s*\(/,
    message: 'document.write() can introduce XSS when content is user-controlled.'
  },
  {
    id: 'python-pickle-loads',
    severity: 'error',
    category: 'deserialization',
    pattern: /\bpickle\.loads?\s*\(/,
    message: 'pickle load operations can execute code when data is untrusted.'
  },
  {
    id: 'python-yaml-load',
    severity: 'warning',
    category: 'deserialization',
    pattern: /\byaml\.load\s*\(/,
    message: 'yaml.load() can deserialize unsafe objects. Prefer safe_load().'
  },
  {
    id: 'terraform-public-acl',
    severity: 'warning',
    category: 'cloud-misconfiguration',
    pattern: /\bacl\s*=\s*["']public-read["']/,
    message: 'Public cloud storage ACL detected.'
  },
  {
    id: 'curl-pipe-shell',
    severity: 'warning',
    category: 'supply-chain',
    pattern: /\bcurl\b.+\|\s*(?:sh|bash)\b/,
    message: 'Piping downloaded scripts into a shell is a supply-chain risk.'
  }
];

function parseToolResult(result) {
  const text = result?.content?.[0]?.text;
  if (!text) return {};
  return JSON.parse(text);
}

function scannerLineToOutputLine(finding) {
  const rawLine = typeof finding.line === 'number' ? finding.line : finding.location?.line;
  if (typeof rawLine !== 'number') return undefined;
  return finding.line_content !== undefined ? rawLine + 1 : rawLine;
}

function stableId(finding, index) {
  const ruleId = finding.ruleId || finding.rule || finding.rule_id || finding.id || 'unknown-rule';
  const file = finding.file || finding.path || finding.location?.file || 'target';
  const line = scannerLineToOutputLine(finding) ?? 0;
  return `${ruleId}:${file}:${line}:${index}`;
}

export function normalizeSeverity(rawSeverity) {
  const severity = String(rawSeverity || 'info').toLowerCase();
  if (severity === 'error') return 'high';
  if (severity === 'warning' || severity === 'warn') return 'medium';
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') return severity;
  return 'info';
}

function inferOwaspLlm(finding) {
  const text = `${finding.ruleId || finding.rule || ''} ${finding.category || ''} ${finding.message || ''}`.toLowerCase();
  if (text.includes('prompt') || text.includes('description-injection') || text.includes('instruction')) return ['LLM01'];
  if (text.includes('supply') || text.includes('package') || text.includes('dependency')) return ['LLM05'];
  if (text.includes('data-exfiltration') || text.includes('secret') || text.includes('credential')) return ['LLM06'];
  if (text.includes('permission') || text.includes('shell') || text.includes('exec') || text.includes('eval')) return ['LLM07'];
  return [];
}

function inferMitreAtlas(finding) {
  const text = `${finding.ruleId || finding.rule || ''} ${finding.category || ''} ${finding.message || ''}`.toLowerCase();
  if (text.includes('prompt') || text.includes('instruction')) return ['AML.T0051'];
  if (text.includes('exfiltrat') || text.includes('secret') || text.includes('credential')) return ['AML.T0024'];
  if (text.includes('exec') || text.includes('eval') || text.includes('shell')) return ['AML.T0005'];
  return [];
}

function remediationFor(finding) {
  if (finding.suggested_fix?.description) return finding.suggested_fix.description;
  if (finding.suggested_fix?.fixed) return finding.suggested_fix.fixed.trim();
  if (finding.recommendation) return finding.recommendation;

  const text = `${finding.ruleId || finding.rule || ''} ${finding.category || ''} ${finding.message || ''}`.toLowerCase();
  if (text.includes('eval')) {
    return 'Remove eval-style execution. Parse explicit commands or expressions with a constrained interpreter instead.';
  }
  if (/\bexec\b|\bshell\b/.test(text)) {
    return 'Avoid shell execution for user-controlled input. Use fixed command allowlists, execFile/spawn with argument arrays, and strict validation.';
  }
  if (text.includes('description') || text.includes('prompt') || text.includes('instruction')) {
    return 'Remove hidden instructions from tool descriptions and keep tool metadata concise, factual, and scoped to user-visible behavior.';
  }
  if (text.includes('url') || text.includes('exfiltrat')) {
    return 'Validate outbound destinations with an allowlist and avoid sending secrets or user data to third-party endpoints.';
  }
  return 'Review the finding, constrain the affected input or capability, and add a regression test for the unsafe path.';
}

export function normalizeFinding(finding, index, options = {}) {
  const ruleId = finding.ruleId || finding.rule || finding.rule_id || finding.id || 'unknown-rule';
  const severity = normalizeSeverity(finding.severity);
  const line = scannerLineToOutputLine(finding);
  const file = finding.file || finding.path || finding.location?.file || options.targetLabel || 'target';
  const description = finding.message || finding.description || finding.explanation || 'Security finding detected by ProofLayer.';

  return {
    id: stableId(finding, index),
    severity,
    category: finding.category || finding.metadata?.category || ruleId.split('.')[0] || 'security',
    ruleId,
    title: ruleId,
    description,
    location: {
      file,
      line: typeof line === 'number' ? line : undefined
    },
    confidence: finding.confidence || finding.metadata?.confidence,
    sourceContext: finding.sourceContext || finding.metadata?.source_context,
    owaspLlm: finding.owaspLlm || finding.owasp_llm || finding.metadata?.owasp_llm || inferOwaspLlm(finding),
    mitreAtlas: finding.mitreAtlas || finding.mitre_atlas || finding.metadata?.mitre_atlas || inferMitreAtlas(finding),
    remediation: options.includeRemediation ? remediationFor(finding) : undefined
  };
}

export function normalizeScannerOutput(scannerOutput, options = {}) {
  const rawFindings = [
    ...(Array.isArray(scannerOutput.findings) ? scannerOutput.findings : []),
    ...(Array.isArray(scannerOutput.issues) ? scannerOutput.issues : [])
  ];
  const threshold = normalizeSeverity(options.severityThreshold || 'info');
  const minRank = SEVERITY_RANK[threshold] ?? 0;

  return rawFindings
    .map((finding, index) => normalizeFinding(finding, index, options))
    .filter((finding) => (SEVERITY_RANK[finding.severity] ?? 0) >= minRank);
}

export function createSarif(findings) {
  const ruleMap = new Map();
  for (const finding of findings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.remediation || 'Review and remediate this security finding.' }
      });
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ProofLayer Agent Security Scanner',
          informationUri: 'https://github.com/sinewaveai/agent-security-scanner-mcp',
          rules: [...ruleMap.values()]
        }
      },
      results: findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: finding.severity === 'critical' || finding.severity === 'high' ? 'error'
          : finding.severity === 'medium' ? 'warning'
            : 'note',
        message: { text: finding.description },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.location.file || 'target' },
            region: finding.location.line ? { startLine: finding.location.line } : undefined
          }
        }]
      }))
    }]
  };
}

export function createSummary({ input, scannerOutput, findings, source }) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
  }

  const postureScore = Math.max(
    0,
    100
      - bySeverity.critical * 25
      - bySeverity.high * 12
      - bySeverity.medium * 5
      - bySeverity.low * 2
      - bySeverity.info
  );

  return {
    target: input.target,
    source,
    grade: scannerOutput.grade || null,
    filesScanned: scannerOutput.files_scanned || 0,
    findingsCount: findings.length,
    bySeverity,
    byCategory,
    postureScore,
    frameworkCoverage: {
      owaspLlm: [...new Set(findings.flatMap((finding) => finding.owaspLlm || []))],
      mitreAtlas: [...new Set(findings.flatMap((finding) => finding.mitreAtlas || []))]
    },
    ruleSets: input.ruleSets || DEFAULT_RULE_SETS,
    severityThreshold: input.severityThreshold || 'info',
    sarifKey: 'report.sarif',
    scanMode: scannerOutput.scan_mode || null,
    repositoryScanMode: scannerOutput.repository_scan_mode || null,
    includeTestFiles: scannerOutput.include_test_files ?? null,
    excludedFiles: scannerOutput.excluded_files || 0,
    capped: Boolean(scannerOutput.capped),
    scanLimit: scannerOutput.scan_limit || null,
    perFileTimeoutSeconds: scannerOutput.per_file_timeout_seconds || null,
    scanErrors: Array.isArray(scannerOutput.scan_errors) ? scannerOutput.scan_errors : []
  };
}

async function cloneRepository(input, workDir) {
  if (!input.repoUrl) throw new Error('repoUrl is required when target is repository or mcpServer.');
  const repoDir = join(workDir, 'repo');
  const args = ['clone', '--depth', '1'];
  if (input.branch) args.push('--branch', input.branch);
  args.push(input.repoUrl, repoDir);
  await execFileAsync('git', args, { timeout: 180000, maxBuffer: 1024 * 1024 * 10 });
  return repoDir;
}

async function writeJsonTarget(input, workDir) {
  await mkdir(workDir, { recursive: true });
  let config;
  if (input.mcpConfigUrl) {
    const response = await fetch(input.mcpConfigUrl);
    if (!response.ok) throw new Error(`Failed to fetch mcpConfigUrl: HTTP ${response.status}`);
    config = await response.text();
  } else if (typeof input.mcpConfigJson === 'string') {
    config = input.mcpConfigJson;
  } else if (input.mcpConfigJson) {
    config = JSON.stringify(input.mcpConfigJson, null, 2);
  } else {
    throw new Error('mcpConfigUrl or mcpConfigJson is required for mcpServer or agentConfig JSON scans.');
  }

  const configPath = join(workDir, 'server.json');
  await writeFile(configPath, config, 'utf8');
  return workDir;
}

async function writeInlineCode(input, workDir) {
  if (!input.sourceCode) throw new Error('sourceCode is required when target is code.');
  const filePath = join(workDir, 'inline-agent-code.js');
  await writeFile(filePath, input.sourceCode, 'utf8');
  return filePath;
}

export async function prepareTarget(input, workDir) {
  switch (input.target) {
    case 'repository':
      return { kind: 'repository', path: await cloneRepository(input, workDir) };
    case 'mcpServer':
      if (input.repoUrl) return { kind: 'mcpServer', path: await cloneRepository(input, workDir) };
      return { kind: 'mcpServer', path: await writeJsonTarget(input, workDir) };
    case 'agentConfig':
      return { kind: 'agentConfig', path: await writeJsonTarget(input, workDir) };
    case 'code':
      return { kind: 'code', path: await writeInlineCode(input, workDir) };
    default:
      throw new Error(`Unsupported target: ${input.target || '(missing)'}`);
  }
}

function isScannableRepositoryFile(filePath) {
  const base = basename(filePath).toLowerCase();
  return base === 'dockerfile' || REPOSITORY_SCAN_EXTENSIONS.has(extname(filePath).toLowerCase());
}

function normalizeRepositoryFileLimit(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_REPOSITORY_SCAN_FILE_LIMIT;
  return Math.min(parsed, MAX_REPOSITORY_SCAN_FILE_LIMIT);
}

function normalizeRepositoryFileTimeout(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_REPOSITORY_FILE_TIMEOUT_SECONDS;
  return Math.min(parsed, MAX_REPOSITORY_FILE_TIMEOUT_SECONDS);
}

function normalizeRepositoryScanMode(value) {
  return REPOSITORY_SCAN_MODES.has(value) ? value : DEFAULT_REPOSITORY_SCAN_MODE;
}

function normalizeBooleanOption(value, defaultValue) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  }
  return defaultValue;
}

function isRepositoryTestPath(relativeFile) {
  const normalizedPath = relativeFile.replaceAll('\\', '/');
  const parts = normalizedPath.split('/').map((part) => part.toLowerCase());
  if (parts.some((part) => REPOSITORY_TEST_DIRS.has(part))) return true;
  return REPOSITORY_TEST_FILE_PATTERNS.some((pattern) => pattern.test(normalizedPath));
}

async function collectRepositoryFiles(rootDir, fileLimit = DEFAULT_REPOSITORY_SCAN_FILE_LIMIT, options = {}) {
  const files = [];
  const skipped = [];
  const excluded = [];
  const includeTestFiles = normalizeBooleanOption(options.includeTestFiles, DEFAULT_INCLUDE_TEST_FILES);

  async function walk(currentDir) {
    if (files.length >= fileLimit) return;
    let entries;
    try {
      entries = (await readdir(currentDir, { withFileTypes: true }))
        .sort((a, b) => {
          if (a.isDirectory() !== b.isDirectory()) return a.isDirectory() ? 1 : -1;
          return a.name.localeCompare(b.name);
        });
    } catch (error) {
      skipped.push({ path: relative(rootDir, currentDir) || '.', reason: error.message });
      return;
    }

    for (const entry of entries) {
      if (files.length >= fileLimit) return;
      const fullPath = join(currentDir, entry.name);
      const relativePath = relative(rootDir, fullPath) || entry.name;
      if (entry.isDirectory()) {
        if (REPOSITORY_SCAN_SKIP_DIRS.has(entry.name)) continue;
        if (!includeTestFiles && isRepositoryTestPath(relativePath)) {
          excluded.push(relativePath);
          continue;
        }
        await walk(fullPath);
        continue;
      }
      if (!entry.isFile() || !isScannableRepositoryFile(fullPath)) continue;
      if (!includeTestFiles && isRepositoryTestPath(relativePath)) {
        excluded.push(relativePath);
        continue;
      }

      try {
        const fileStat = await stat(fullPath);
        if (fileStat.size > 1024 * 1024) {
          skipped.push({ path: relativePath, reason: 'File larger than 1MB' });
          continue;
        }
      } catch (error) {
        skipped.push({ path: relativePath, reason: error.message });
        continue;
      }

      files.push(fullPath);
    }
  }

  await walk(rootDir);
  return { files, skipped, excluded, capped: files.length >= fileLimit };
}

function calculateRepositoryGrade(issueCount, fileCount, errorCount) {
  if (fileCount === 0 || issueCount === 0) return 'A';
  const density = issueCount / fileCount;
  if (errorCount === 0 && density < 0.5) return 'B';
  if (errorCount <= 2 && density < 1.5) return 'C';
  if (errorCount <= 5 && density < 3) return 'D';
  return 'F';
}

async function writeRepositoryProgress(progress) {
  if (!Actor.isAtHome()) return;
  try {
    await Actor.setValue('PROGRESS', progress);
    const current = progress.currentFile ? `: ${progress.currentFile}` : '';
    const label = progress.status === 'scanning_file'
      ? `Scanning file ${progress.currentFileIndex}/${progress.filesDiscovered}${current}`
      : `Scanning repository: ${progress.filesScanned}/${progress.filesDiscovered} files, ${progress.issuesCount} issue(s)`;
    await Actor.setStatusMessage(label.slice(0, 250));
  } catch {
    // Progress reporting is best-effort so local smoke tests can call runScanner directly.
  }
}

async function scanSecurityWithTimeout(args, timeoutSeconds) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutSeconds * 1000);
  try {
    return await scanSecurity({ ...args, signal: controller.signal, use_daemon: false });
  } finally {
    clearTimeout(timer);
  }
}

async function scanRepositoryFileQuick(filePath, relativeFile) {
  const content = await readFile(filePath, 'utf8');
  const findings = [];
  const lines = content.split(/\r?\n/);
  const isTestPath = isRepositoryTestPath(relativeFile);

  for (const [lineIndex, line] of lines.entries()) {
    if (findings.length >= QUICK_FINDINGS_PER_FILE_LIMIT) break;
    for (const rule of QUICK_REPOSITORY_RULES) {
      if (findings.length >= QUICK_FINDINGS_PER_FILE_LIMIT) break;
      if (!rule.pattern.test(line)) continue;
      findings.push({
        line: lineIndex + 1,
        ruleId: `apify.quick.${rule.id}`,
        severity: rule.severity,
        confidence: isTestPath ? 'LOW' : 'MEDIUM',
        message: rule.message,
        file: relativeFile,
        metadata: {
          category: rule.category,
          source_context: isTestPath ? 'test_or_fixture' : 'source'
        }
      });
    }
  }

  return findings;
}

async function scanRepositoryForActor(directoryPath, options = {}) {
  const fileLimit = normalizeRepositoryFileLimit(options.maxRepositoryFiles);
  const perFileTimeoutSeconds = normalizeRepositoryFileTimeout(options.perFileTimeoutSeconds);
  const scanMode = normalizeRepositoryScanMode(options.repositoryScanMode);
  const includeTestFiles = normalizeBooleanOption(options.includeTestFiles, DEFAULT_INCLUDE_TEST_FILES);
  const { files, skipped, excluded, capped } = await collectRepositoryFiles(directoryPath, fileLimit, { includeTestFiles });
  const issues = [];
  const scanErrors = [...skipped];
  const bySeverity = { error: 0, warning: 0, info: 0 };
  const byCategory = {};
  const byFile = {};

  console.log(`[Apify] Repository scan discovered ${files.length} file(s); mode=${scanMode}; includeTestFiles=${includeTestFiles}; excluded=${excluded.length}; limit=${fileLimit}; capped=${capped}; perFileTimeout=${perFileTimeoutSeconds}s`);
  if (skipped.length > 0) console.log(`[Apify] Skipped ${skipped.length} file(s) before scan.`);
  if (excluded.length > 0) console.log(`[Apify] Excluded ${excluded.length} test/demo/benchmark/fixture path(s).`);

  await writeRepositoryProgress({
    scanMode: scanMode === 'quick' ? 'apify-repository-quick' : 'apify-repository-analyzer',
    status: 'running',
    filesDiscovered: files.length,
    filesScanned: 0,
    issuesCount: 0,
    capped,
    scanLimit: fileLimit,
    includeTestFiles,
    excludedFiles: excluded.length,
    perFileTimeoutSeconds,
    scanErrors: scanErrors.slice(0, 25)
  });

  for (const [index, filePath] of files.entries()) {
    const relativeFile = relative(directoryPath, filePath) || basename(filePath);
    const currentFileIndex = index + 1;
    console.log(`[Apify] Scanning ${currentFileIndex}/${files.length}: ${relativeFile}`);
    await writeRepositoryProgress({
      scanMode: scanMode === 'quick' ? 'apify-repository-quick' : 'apify-repository-analyzer',
      status: 'scanning_file',
      filesDiscovered: files.length,
      filesScanned: index,
      currentFileIndex,
      currentFile: relativeFile,
      issuesCount: issues.length,
      capped,
      scanLimit: fileLimit,
      includeTestFiles,
      excludedFiles: excluded.length,
      perFileTimeoutSeconds,
      scanErrors: scanErrors.slice(0, 25)
    });

    try {
      let fileIssues;
      if (scanMode === 'quick') {
        fileIssues = await scanRepositoryFileQuick(filePath, relativeFile);
      } else {
        const result = await scanSecurityWithTimeout({
          file_path: filePath,
          verbosity: 'compact',
          engine: 'regex',
          enable_semantic: false
        }, perFileTimeoutSeconds);
        const parsed = parseToolResult(result);
        fileIssues = Array.isArray(parsed.issues) ? parsed.issues : [];
      }
      byFile[relativeFile] = fileIssues.length;

      for (const issue of fileIssues) {
        issues.push({ ...issue, file: relativeFile });
        const severity = String(issue.severity || 'info').toLowerCase();
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;
        const category = issue.metadata?.category || issue.ruleId?.split('.')[0] || 'security';
        byCategory[category] = (byCategory[category] || 0) + 1;
      }
    } catch (error) {
      const timedOut = error?.name === 'AbortError';
      scanErrors.push({
        path: relativeFile,
        reason: timedOut ? `Timed out after ${perFileTimeoutSeconds}s` : error?.message || String(error)
      });
    }

    const filesScanned = index + 1;
    console.log(`[Apify] Scanned ${filesScanned}/${files.length} file(s), issues=${issues.length}`);
    await writeRepositoryProgress({
      scanMode: scanMode === 'quick' ? 'apify-repository-quick' : 'apify-repository-analyzer',
      status: filesScanned === files.length ? 'finalizing' : 'running',
      filesDiscovered: files.length,
      filesScanned,
      issuesCount: issues.length,
      capped,
      scanLimit: fileLimit,
      includeTestFiles,
      excludedFiles: excluded.length,
      perFileTimeoutSeconds,
      currentFile: relativeFile,
      scanErrors: scanErrors.slice(0, 25)
    });
  }

  return {
    directory: directoryPath,
    scan_mode: scanMode === 'quick' ? 'apify-repository-quick' : 'apify-repository-analyzer',
    repository_scan_mode: scanMode,
    include_test_files: includeTestFiles,
    excluded_files: excluded.length,
    excluded_file_examples: excluded.slice(0, 25),
    files_scanned: files.length,
    scan_limit: fileLimit,
    per_file_timeout_seconds: perFileTimeoutSeconds,
    issues_count: issues.length,
    grade: calculateRepositoryGrade(issues.length, files.length, bySeverity.error || 0),
    by_severity: bySeverity,
    by_category: byCategory,
    by_file: byFile,
    issues,
    scanned_files: files.map((filePath) => relative(directoryPath, filePath) || basename(filePath)),
    scan_errors: scanErrors.length > 0 ? scanErrors : undefined,
    capped
  };
}

export async function runScanner(preparedTarget) {
  if (preparedTarget.kind === 'code') {
    return parseToolResult(await scanSecurity({
      file_path: preparedTarget.path,
      verbosity: 'full',
      include_context: true
    }));
  }

  if (preparedTarget.kind === 'mcpServer' || preparedTarget.kind === 'agentConfig') {
    return parseToolResult(await scanMcpServer({
      server_path: preparedTarget.path,
      verbosity: 'full',
      manifest: true
    }));
  }

  return scanRepositoryForActor(preparedTarget.path, preparedTarget.options);
}

export async function runActor(input) {
  const normalizedInput = {
    target: input?.target || 'repository',
    ruleSets: input?.ruleSets || DEFAULT_RULE_SETS,
    severityThreshold: input?.severityThreshold || 'info',
    includeRemediation: input?.includeRemediation !== false,
    ...input
  };

  const workDir = await mkdtemp(join(tmpdir(), 'prooflayer-apify-'));
  try {
    const preparedTarget = await prepareTarget(normalizedInput, workDir);
    if (preparedTarget.kind === 'repository') {
      preparedTarget.options = {
        maxRepositoryFiles: normalizedInput.maxRepositoryFiles,
        perFileTimeoutSeconds: normalizedInput.perFileTimeoutSeconds,
        repositoryScanMode: normalizedInput.repositoryScanMode,
        includeTestFiles: normalizedInput.includeTestFiles
      };
    }
    const scannerOutput = await runScanner(preparedTarget);
    if (scannerOutput.error) throw new Error(scannerOutput.error);

    const findings = normalizeScannerOutput(scannerOutput, {
      includeRemediation: normalizedInput.includeRemediation,
      severityThreshold: normalizedInput.severityThreshold,
      targetLabel: basename(preparedTarget.path)
    });
    const sarif = createSarif(findings);
    const summary = createSummary({
      input: normalizedInput,
      scannerOutput,
      findings,
      source: {
        kind: preparedTarget.kind,
        path: preparedTarget.path,
        repoUrl: normalizedInput.repoUrl || undefined,
        branch: normalizedInput.branch || undefined
      }
    });

    for (const finding of findings) {
      await Actor.pushData(finding);
    }
    await Actor.setValue('OUTPUT', summary);
    await Actor.setValue('report.sarif', JSON.stringify(sarif, null, 2), { contentType: 'application/sarif+json' });
    await Actor.setValue('PROGRESS', {
      scanMode: summary.scanMode,
      repositoryScanMode: summary.repositoryScanMode,
      status: 'complete',
      filesDiscovered: summary.filesScanned,
      filesScanned: summary.filesScanned,
      issuesCount: summary.findingsCount,
      capped: summary.capped,
      scanLimit: summary.scanLimit,
      includeTestFiles: summary.includeTestFiles,
      excludedFiles: summary.excludedFiles,
      perFileTimeoutSeconds: summary.perFileTimeoutSeconds,
      scanErrors: summary.scanErrors.slice(0, 25)
    });
    return { summary, findings, sarif };
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

async function main() {
  await Actor.init();
  try {
    const input = await Actor.getInput();
    await runActor(input);
    await Actor.exit();
  } catch (error) {
    await Actor.fail(error?.message || String(error));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
