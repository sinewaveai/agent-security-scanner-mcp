import { Actor } from 'apify';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { scanSecurity } from './tools/scan-security.js';
import { scanProject } from './tools/scan-project.js';
import { scanMcpServer } from './tools/scan-mcp.js';

const execFileAsync = promisify(execFile);
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const DEFAULT_RULE_SETS = ['all'];

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
    sarifKey: 'report.sarif'
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

  return parseToolResult(await scanProject({
    directory_path: preparedTarget.path,
    recursive: true,
    cross_file: true,
    verbosity: 'full'
  }));
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
