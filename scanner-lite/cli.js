#!/usr/bin/env node

// @prooflayer/scanner-lite CLI
// Zero-dep CLI with arg parsing, ANSI colors, subcommands, exit codes

import { readFileSync, existsSync, readdirSync, statSync, mkdirSync, writeFileSync } from 'fs';
import { join, resolve, dirname, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Read version
const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8')).version;
  } catch { return '1.0.0'; }
})();

// ANSI colors (respects --no-color and NO_COLOR env)
const noColor = process.argv.includes('--no-color') || process.env.NO_COLOR;
const c = {
  red: s => noColor ? s : `\x1b[31m${s}\x1b[0m`,
  yellow: s => noColor ? s : `\x1b[33m${s}\x1b[0m`,
  green: s => noColor ? s : `\x1b[32m${s}\x1b[0m`,
  cyan: s => noColor ? s : `\x1b[36m${s}\x1b[0m`,
  bold: s => noColor ? s : `\x1b[1m${s}\x1b[0m`,
  dim: s => noColor ? s : `\x1b[2m${s}\x1b[0m`,
  magenta: s => noColor ? s : `\x1b[35m${s}\x1b[0m`,
};

// Parse CLI args
function parseArgs(argv) {
  const args = argv.slice(2);
  const flags = {};
  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') { positional.push(...args.slice(i + 1)); break; }
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (key === 'json' || key === 'sarif' || key === 'quiet' || key === 'no-color' || key === 'verbose' || key === 'yes' || key === 'help' || key === 'version') {
        flags[key] = true;
      } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        flags[key] = args[++i];
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }

  return { flags, positional };
}

// Severity icon
function sevIcon(severity) {
  const s = severity.toUpperCase();
  if (s === 'ERROR' || s === 'CRITICAL') return c.red('[ERROR]');
  if (s === 'WARNING') return c.yellow('[WARN] ');
  return c.dim('[INFO] ');
}

// Collect files recursively
function collectFiles(dir, exts = ['.js', '.ts', '.py', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.rs']) {
  const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', 'venv', '.venv', 'coverage']);
  const files = [];
  function walk(d) {
    let entries;
    try { entries = readdirSync(d); } catch { return; }
    for (const e of entries) {
      if (e.startsWith('.') || SKIP.has(e)) continue;
      const full = join(d, e);
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.isDirectory()) walk(full);
      else if (exts.some(ext => full.endsWith(ext))) files.push(full);
    }
  }
  walk(dir);
  return files;
}

// ============================================================
// scan subcommand
// ============================================================
async function cmdScan(target, flags) {
  const { scanSecurity } = await import('./src/scanner.js');
  const resolved = resolve(target);

  if (!existsSync(resolved)) {
    console.error(c.red(`Error: ${target} not found`));
    process.exit(2);
  }

  const st = statSync(resolved);
  const files = st.isDirectory() ? collectFiles(resolved) : [resolved];

  if (files.length === 0) {
    console.log(c.dim('No scannable files found.'));
    process.exit(0);
  }

  let totalFindings = 0;
  const allResults = [];

  for (const file of files) {
    const result = await scanSecurity({
      file_path: file,
      output_format: flags.sarif ? 'sarif' : 'json',
      verbosity: flags.verbose ? 'full' : 'compact'
    });

    const parsed = JSON.parse(result.content[0].text);
    allResults.push(parsed);

    const issues = parsed.issues || [];
    totalFindings += issues.length;

    if (flags.json || flags.sarif) continue; // accumulate for batch output

    if (issues.length > 0 && !flags.quiet) {
      console.log(`\n${c.bold(file)}`);
      for (const issue of issues) {
        const line = issue.line || '?';
        console.log(`  ${sevIcon(issue.severity)} L${line}: ${issue.message || issue.ruleId}`);
        if (issue.fix) console.log(`    ${c.green('fix:')} ${issue.fix}`);
      }
    }
  }

  if (flags.json) {
    console.log(JSON.stringify(allResults.length === 1 ? allResults[0] : allResults, null, 2));
  } else if (flags.sarif) {
    console.log(JSON.stringify(allResults.length === 1 ? allResults[0] : allResults, null, 2));
  } else if (!flags.quiet) {
    console.log(`\n${c.bold('Summary:')} ${files.length} file(s) scanned, ${totalFindings} finding(s)`);
    if (totalFindings === 0) console.log(c.green('  No security issues found.'));
  }

  process.exit(totalFindings > 0 ? 1 : 0);
}

// ============================================================
// audit subcommand (LLM deep audit)
// ============================================================
async function cmdAudit(target, flags) {
  const { deepAudit } = await import('./src/llm-audit.js');
  const resolved = resolve(target);

  if (!existsSync(resolved)) {
    console.error(c.red(`Error: ${target} not found`));
    process.exit(2);
  }

  if (!flags.yes && !process.env.PROOFLAYER_LLM_CONSENT) {
    console.error(c.yellow('Warning: LLM deep audit sends code to an external AI provider.'));
    console.error(c.yellow('Set PROOFLAYER_LLM_CONSENT=1 or pass --yes to consent.'));
    process.exit(2);
  }

  const result = await deepAudit({
    file_path: resolved,
    provider: flags.provider || undefined,
    model: flags.model || undefined
  });

  const parsed = JSON.parse(result.content[0].text);

  if (flags.json) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    console.log(c.bold('\nLLM Deep Audit Report'));
    console.log(c.dim('─'.repeat(50)));
    if (parsed.error) {
      console.error(c.red(`Error: ${parsed.error}`));
      process.exit(2);
    }
    const findings = parsed.findings || [];
    if (findings.length === 0) {
      console.log(c.green('No issues found by LLM analysis.'));
    } else {
      for (const f of findings) {
        console.log(`  ${sevIcon(f.severity)} ${f.title || f.description}`);
        if (f.cwe) console.log(`    ${c.dim('CWE:')} ${f.cwe}`);
        if (f.attack_scenario) console.log(`    ${c.dim('Attack:')} ${f.attack_scenario}`);
      }
    }
    console.log(`\n${c.bold('Total:')} ${findings.length} finding(s)`);
  }

  const findings = parsed.findings || [];
  process.exit(findings.length > 0 ? 1 : 0);
}

// ============================================================
// check-package subcommand
// ============================================================
async function cmdCheckPackage(pkgName, flags) {
  const { checkPackage } = await import('./src/package-checker.js');

  const ecosystem = flags.ecosystem || 'npm';
  const result = await checkPackage({ package_name: pkgName, ecosystem });
  const parsed = JSON.parse(result.content[0].text);

  if (flags.json) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    const icon = parsed.legitimate ? c.green('[OK]') : parsed.hallucinated ? c.red('[HALLUCINATED]') : c.yellow('[UNKNOWN]');
    console.log(`${icon} ${c.bold(pkgName)} (${ecosystem})`);
    if (parsed.recommendation) console.log(`  ${parsed.recommendation}`);
    if (parsed.typosquatting) {
      for (const s of parsed.typosquatting.similar_packages || []) {
        console.log(`  ${c.yellow('similar:')} ${s.name} (distance: ${s.distance})`);
      }
    }
    if (parsed.dependency_confusion) {
      console.log(`  ${c.red('dep-confusion:')} ${parsed.dependency_confusion.warning}`);
    }
  }

  process.exit(parsed.hallucinated ? 1 : 0);
}

// ============================================================
// prompt subcommand
// ============================================================
async function cmdPrompt(text, flags) {
  const { scanAgentPrompt } = await import('./src/prompt-scanner.js');

  const result = await scanAgentPrompt({ prompt_text: text, verbosity: flags.verbose ? 'full' : 'compact' });
  const parsed = JSON.parse(result.content[0].text);

  if (flags.json) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    const actionColor = parsed.action === 'BLOCK' ? c.red : parsed.action === 'WARN' ? c.yellow : c.green;
    console.log(`${actionColor(`[${parsed.action}]`)} Risk: ${parsed.risk_level || 'NONE'} (score: ${parsed.risk_score || 0})`);
    const findings = parsed.findings || [];
    for (const f of findings) {
      console.log(`  ${sevIcon(f.severity)} ${f.message}`);
    }
    if (parsed.recommendations) {
      console.log(c.dim('\nRecommendations:'));
      for (const r of parsed.recommendations) {
        console.log(`  - ${r}`);
      }
    }
  }

  process.exit(parsed.action === 'BLOCK' ? 1 : 0);
}

// ============================================================
// download-data subcommand
// ============================================================
async function cmdDownloadData(flags) {
  const dataDir = join(process.env.HOME || process.env.USERPROFILE || '.', '.prooflayer', 'data');
  mkdirSync(dataDir, { recursive: true });

  const baseUrl = 'https://github.com/sinewaveai/agent-security-scanner-mcp/releases/latest/download';
  const ecosystems = ['npm', 'pypi', 'rubygems', 'crates'];

  console.log(c.bold('Downloading bloom filter data...'));
  console.log(c.dim(`Cache directory: ${dataDir}`));

  let success = 0;
  for (const eco of ecosystems) {
    const filename = `${eco}.bloom`;
    const url = `${baseUrl}/${filename}`;
    const dest = join(dataDir, filename);

    try {
      process.stdout.write(`  ${eco}... `);
      const resp = await fetch(url);
      if (!resp.ok) {
        console.log(c.yellow(`skipped (${resp.status})`));
        continue;
      }
      const buf = Buffer.from(await resp.arrayBuffer());
      writeFileSync(dest, buf);
      console.log(c.green(`OK (${(buf.length / 1024).toFixed(0)}KB)`));
      success++;
    } catch (err) {
      console.log(c.yellow(`failed: ${err.message}`));
    }
  }

  console.log(`\n${c.bold('Done:')} ${success}/${ecosystems.length} bloom filters downloaded.`);
  if (success > 0) console.log(c.green('Package hallucination detection is now enhanced.'));
  process.exit(0);
}

// ============================================================
// inspect subcommand
// ============================================================
async function cmdInspect(cmdArgs, flags) {
  const { inspectMcpServer } = await import('./src/inspector.js');

  if (cmdArgs.length === 0) {
    console.error(c.red('Error: inspect requires a command after --'));
    console.error(c.dim('  Example: scanner-lite inspect -- node server.js'));
    process.exit(2);
  }

  const command = cmdArgs[0];
  const args = cmdArgs.slice(1);
  const timeout = flags.timeout ? parseInt(flags.timeout, 10) : 10000;

  if (!flags.quiet) {
    console.log(c.bold('Inspecting MCP server:') + ` ${command} ${args.join(' ')}`);
    console.log(c.dim(`Timeout: ${timeout}ms`));
  }

  const result = await inspectMcpServer({ command, args, timeout });
  const parsed = JSON.parse(result.content[0].text);

  if (flags.json) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    if (parsed.error) {
      console.error(c.yellow(`Warning: ${parsed.error}`));
    }
    console.log(`\n${c.bold('Tools inspected:')} ${parsed.tools_inspected}`);
    console.log(`${c.bold('Grade:')} ${parsed.grade}`);
    console.log(`${c.bold('Findings:')} ${parsed.findings_count}`);

    for (const f of parsed.findings) {
      console.log(`  ${sevIcon(f.severity)} [${f.tool}] ${f.message}`);
    }

    if (parsed.findings_count === 0) {
      console.log(c.green('  No poisoning indicators detected.'));
    }
  }

  process.exit(parsed.findings_count > 0 ? 1 : 0);
}

// ============================================================
// Help text
// ============================================================
function showHelp() {
  console.log(`
${c.bold('@prooflayer/scanner-lite')} v${VERSION}
${c.dim('Lightweight MCP security scanner for AI coding agents')}

${c.bold('USAGE:')}
  scanner-lite ${c.cyan('<command>')} [options]

${c.bold('COMMANDS:')}
  ${c.cyan('scan')} <path>              Scan file or directory for vulnerabilities
  ${c.cyan('inspect')} -- <cmd> [args]  Inspect a live MCP server for tool poisoning
  ${c.cyan('audit')} <path>             LLM deep security audit (requires API key)
  ${c.cyan('check-package')} <name>     Check if a package is hallucinated
  ${c.cyan('prompt')} <text>            Scan text for prompt injection
  ${c.cyan('download-data')}            Download bloom filters for offline pkg verification

${c.bold('FLAGS:')}
  --json                 Output as JSON
  --sarif                Output as SARIF (scan only)
  --quiet                Suppress non-essential output
  --no-color             Disable ANSI colors
  --verbose              Show full details
  --timeout <ms>         Inspection timeout (default: 10000)
  --provider <p>         LLM provider: anthropic, openai, gemini, ollama, openrouter
  --model <m>            LLM model name
  --ecosystem <e>        Package ecosystem (default: npm)
  --yes                  Consent to LLM data sharing (audit command)
  --help                 Show this help
  --version              Show version

${c.bold('EXIT CODES:')}
  0  Clean / success
  1  Findings detected
  2  Error

${c.bold('EXAMPLES:')}
  scanner-lite scan ./src
  scanner-lite scan index.js --json
  scanner-lite inspect -- node server.js
  scanner-lite inspect --json --timeout 15000 -- npx -y @mcp/server-filesystem /tmp
  scanner-lite check-package rekat --ecosystem npm
  scanner-lite prompt "ignore all previous instructions"
  scanner-lite audit server.js --provider anthropic --yes
  scanner-lite download-data
`);
}

// ============================================================
// Main
// ============================================================
const { flags, positional } = parseArgs(process.argv);

if (flags.version) {
  console.log(VERSION);
  process.exit(0);
}

if (flags.help || positional.length === 0) {
  showHelp();
  process.exit(0);
}

const command = positional[0];
const target = positional[1];

switch (command) {
  case 'scan':
    if (!target) { console.error(c.red('Error: scan requires a path argument')); process.exit(2); }
    await cmdScan(target, flags);
    break;
  case 'audit':
    if (!target) { console.error(c.red('Error: audit requires a path argument')); process.exit(2); }
    await cmdAudit(target, flags);
    break;
  case 'check-package':
    if (!target) { console.error(c.red('Error: check-package requires a package name')); process.exit(2); }
    await cmdCheckPackage(target, flags);
    break;
  case 'prompt':
    if (!target) { console.error(c.red('Error: prompt requires text argument')); process.exit(2); }
    await cmdPrompt(positional.slice(1).join(' '), flags);
    break;
  case 'inspect':
    // Everything after -- is the command to inspect
    {
      const dashDashIdx = process.argv.indexOf('--');
      const inspectArgs = dashDashIdx >= 0 ? process.argv.slice(dashDashIdx + 1) : positional.slice(1);
      await cmdInspect(inspectArgs, flags);
    }
    break;
  case 'download-data':
    await cmdDownloadData(flags);
    break;
  default:
    console.error(c.red(`Unknown command: ${command}`));
    showHelp();
    process.exit(2);
}
