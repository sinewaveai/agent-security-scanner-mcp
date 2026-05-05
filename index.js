#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync, execFileSync, spawn as spawnProcess } from "child_process";
import { readFileSync, existsSync, writeFileSync, copyFileSync, mkdirSync, createReadStream, unlinkSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { homedir, platform } from "os";
import { createInterface } from "readline";
import { createHash } from "crypto";
import { envVarReplacement, FIX_TEMPLATES } from './src/fix-patterns.js';
import { detectLanguage, runAnalyzer, generateFix, toSarif, shutdownDaemon } from './src/utils.js';
import { scanSecuritySchema, scanSecurity } from './src/tools/scan-security.js';
import { fixSecuritySchema, fixSecurity } from './src/tools/fix-security.js';
import { loadPackageLists, checkPackageSchema, checkPackage, getPackageStats } from './src/tools/check-package.js';
import { scanPackagesSchema, scanPackages } from './src/tools/scan-packages.js';
import { scanAgentPromptSchema, scanAgentPrompt } from './src/tools/scan-prompt.js';
import { scanDiffSchema, scanDiff } from './src/tools/scan-diff.js';
import { scanProjectSchema, scanProject } from './src/tools/scan-project.js';
import { scanAgentActionSchema, scanAgentAction } from './src/tools/scan-action.js';
import { scanMcpServerSchema, scanMcpServer } from './src/tools/scan-mcp.js';
import { runInit } from './src/cli/init.js';
import { runDoctor } from './src/cli/doctor.js';
import { runDemo } from './src/cli/demo.js';
import { runInitHooks } from './src/cli/init-hooks.js';
import { runReport } from './src/cli/report.js';
import { scoreAivssSchema, scoreAivssTool } from './src/tools/score-aivss.js';
import { complianceControlsSchema, getComplianceControls } from './src/tools/compliance-controls.js';
import { sbomGenerateSchema, sbomGenerate } from './src/tools/sbom-generate.js';
import { sbomVulnerabilitiesSchema, sbomScanVulnerabilities } from './src/tools/sbom-vulnerabilities.js';
import { sbomHallucinationsSchema, sbomCheckHallucinations } from './src/tools/sbom-hallucinations.js';
import { sbomDiffSchema, sbomDiff } from './src/tools/sbom-diff.js';
import { sbomReportSchema, sbomExportReport } from './src/tools/sbom-report.js';
import { evaluateComplianceSchema, evaluateCompliance } from './src/tools/evaluate-compliance.js';

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Read version from package.json
let _pkgVersion = '0.0.0';
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8'));
  _pkgVersion = pkg.version || '0.0.0';
} catch { /* fallback */ }

// Create MCP Server
const server = new McpServer(
  {
    name: "agent-security-scanner-mcp",
    version: _pkgVersion,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Export for Smithery sandbox scanning
export function createSandboxServer() {
  return server;
}

// Register scan_security tool
server.tool(
  "scan_security",
  "Scan a file for security vulnerabilities. Use verbosity='minimal' for counts only (~50 tokens), 'compact' (default) for actionable info (~200 tokens), 'full' for complete metadata.",
  scanSecuritySchema,
  scanSecurity
);

// Register fix_security tool
server.tool(
  "fix_security",
  "Scan a file and return fixes. Use verbosity='minimal' for summary only, 'compact' (default) for fix list, 'full' for complete fixed file content.",
  fixSecuritySchema,
  fixSecurity
);

// Register list_security_rules tool
server.tool(
  "list_security_rules",
  "List all available security fix templates and their descriptions",
  {},
  async () => {
    const rules = Object.entries(FIX_TEMPLATES).map(([id, template]) => ({
      pattern: id,
      description: template.description
    }));

    return {
      content: [{
        type: "text",
        text: JSON.stringify({ rules }, null, 2)
      }]
    };
  }
);

// ===========================================
// PACKAGE HALLUCINATION DETECTION
// ===========================================

// Register check_package tool
server.tool(
  "check_package",
  "Check if a package name is legitimate or potentially hallucinated (AI-invented)",
  checkPackageSchema,
  checkPackage
);

// Register scan_packages tool
server.tool(
  "scan_packages",
  "Scan code for package imports and check for hallucinated (AI-invented) packages. Use verbosity='minimal' for counts, 'compact' (default) for flagged packages, 'full' for all details.",
  scanPackagesSchema,
  scanPackages
);

// Register list_package_stats tool
server.tool(
  "list_package_stats",
  "List statistics about loaded package lists for hallucination detection",
  {},
  async () => {
    const stats = getPackageStats();
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          ...stats,
          usage: "Use check_package or scan_packages to detect hallucinated packages"
        }, null, 2)
      }]
    };
  }
);

// ===========================================
// AGENT PROMPT SECURITY SCANNING
// ===========================================

// Register scan_agent_prompt tool
server.tool(
  "scan_agent_prompt",
  "Scan a prompt for malicious intent. Returns BLOCK/WARN/LOG/ALLOW. Use verbosity='minimal' for action only, 'compact' (default) for findings, 'full' for audit details.",
  scanAgentPromptSchema,
  scanAgentPrompt
);

// Register scan_git_diff tool
server.tool(
  "scan_git_diff",
  "Scan git diff for new security vulnerabilities. Only reports issues on changed lines. Use for PR reviews.",
  scanDiffSchema,
  scanDiff
);

// Register scan_project tool
server.tool(
  "scan_project",
  "Scan an entire directory for security vulnerabilities with .gitignore support and security grading. Use verbosity='minimal' for grade + counts, 'compact' (default) for top issues, 'full' for all details.",
  scanProjectSchema,
  scanProject
);

// ===========================================
// AGENT ACTION MONITORING
// ===========================================

// Register scan_agent_action tool
server.tool(
  "scan_agent_action",
  "Pre-execution security check for agent actions (bash, file_write, file_read, http_request, file_delete, cron, process_spawn, git, docker). Returns ALLOW/WARN/BLOCK.",
  scanAgentActionSchema,
  scanAgentAction
);

// ===========================================
// MCP SERVER SECURITY SCANNING
// ===========================================

// Register scan_mcp_server tool
server.tool(
  "scan_mcp_server",
  "Scan an MCP server's source code for security vulnerabilities: overly broad permissions, missing input validation, data exfiltration, insecure patterns. Returns grade (A-F) and recommendations.",
  scanMcpServerSchema,
  scanMcpServer
);

// ===========================================
// OPENCLAW SKILL SCANNING
// ===========================================

server.tool(
  "scan_skill",
  "Deep security scan of an OpenClaw skill. Multi-layer analysis: prompt injection detection, code analysis (AST+taint), ClawHavoc malware signatures, package supply chain verification, rug pull detection. Returns security grade A-F with detailed findings.",
  {
    skill_path: z.string().describe("Path to skill directory or SKILL.md file"),
    verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level"),
    baseline: z.boolean().optional().describe("Save current scan as baseline for rug pull detection"),
  },
  async ({ skill_path, verbosity, baseline }) => {
    const { scanSkill } = await import('./src/tools/scan-skill.js');
    return scanSkill({ skill_path, verbosity, baseline });
  }
);

// ===========================================
// PLUGIN HEALTH CHECK
// ===========================================

const _healthHandler = async () => {
  const { getHealthStatus } = await import('./src/plugin-health.js');
  const health = await getHealthStatus();
  return {
    content: [{ type: "text", text: JSON.stringify(health, null, 2) }]
  };
};

server.tool(
  "scanner_health",
  "Check plugin health: engine status, daemon status, package data availability",
  {},
  _healthHandler
);

// Backward-compatible alias (will be removed in a future major version)
server.tool(
  "clawproof_health",
  "Alias for scanner_health (deprecated, use scanner_health instead)",
  {},
  _healthHandler
);

// ===========================================
// AIVSS SCORING + COMPLIANCE
// ===========================================

server.tool(
  "score_aivss",
  "Score findings using OWASP AIVSS v2. Accepts any scanner output or raw findings JSON. Returns per-finding AIVSS scores (0-10) and aggregate posture. Use verbosity='minimal' for posture only, 'compact' (default) for scores, 'full' for all metrics.",
  scoreAivssSchema,
  scoreAivssTool
);

server.tool(
  "get_compliance_controls",
  "Look up compliance controls with evaluation criteria. Supports multiple frameworks: aiuc-1 (default), soc2-technical, gdpr-technical. Filter by domain, control IDs, or OWASP LLM tags.",
  complianceControlsSchema,
  getComplianceControls
);

server.tool(
  "evaluate_compliance",
  "Evaluate a project against compliance frameworks (SOC2-technical, GDPR-technical, AIUC-1). Collects evidence from code scans, SBOM, vulnerability checks, and hallucination detection, then evaluates controls. Optionally saves timestamped evidence bundle.",
  evaluateComplianceSchema,
  evaluateCompliance
);

// ===========================================
// SBOM / SUPPLY CHAIN ANALYSIS
// ===========================================

server.tool(
  "sbom_generate",
  "Generate a CycloneDX v1.5 SBOM for a project. Discovers all dependencies (direct + transitive) from lock files and manifests across Node.js, Python, Go, Rust, Ruby, Java. Use verbosity='minimal' for counts, 'compact' (default) for component list, 'full' for complete CycloneDX JSON.",
  sbomGenerateSchema,
  sbomGenerate
);

server.tool(
  "sbom_scan_vulnerabilities",
  "Cross-reference SBOM components against OSV.dev vulnerability database. Returns CVE IDs, CVSS scores, severity, and fix recommendations. Accepts directory_path (generates fresh) or sbom_path (loads saved artifact).",
  sbomVulnerabilitiesSchema,
  sbomScanVulnerabilities
);

server.tool(
  "sbom_check_hallucinations",
  "Check all packages in an SBOM against official registries to detect hallucinated (AI-invented) package names. Supports npm, pypi, rubygems, dart, perl, raku, crates. Go/Java marked as unsupported.",
  sbomHallucinationsSchema,
  sbomCheckHallucinations
);

server.tool(
  "sbom_diff",
  "Compare current project SBOM against a stored baseline. Reports added, removed, and version-changed packages. Use save_baseline=true to create initial baseline.",
  sbomDiffSchema,
  sbomDiff
);

server.tool(
  "sbom_export_report",
  "Generate an HTML or JSON audit report from SBOM data, optionally enriched with vulnerability scan results. Suitable for PCI-DSS and compliance audits.",
  sbomReportSchema,
  sbomExportReport
);

// ===========================================
// CLI COMMANDS - Extracted to src/cli/
// ===========================================
// See src/cli/init.js, src/cli/doctor.js, src/cli/demo.js

// Handle CLI arguments before loading heavy package data
// Security: Wrap in async IIFE to prevent unhandled promise rejections and race conditions
const cliArgs = process.argv.slice(2);

(async () => {
  if (cliArgs[0] === 'init') {
    try {
      await runInit(cliArgs.slice(1));
      process.exit(0);
    } catch (err) {
      console.error(`  Error: ${err.message}\n`);
      process.exit(1);
    }
  } else if (cliArgs[0] === 'doctor') {
    try {
      await runDoctor(cliArgs.slice(1));
      process.exit(0);
    } catch (err) {
      console.error(`  Error: ${err.message}\n`);
      process.exit(1);
    }
  } else if (cliArgs[0] === 'demo') {
    try {
      await runDemo(cliArgs.slice(1));
      process.exit(0);
    } catch (err) {
      console.error(`  Error: ${err.message}\n`);
      process.exit(1);
    }
  } else if (cliArgs[0] === 'init-hooks') {
    try {
      await runInitHooks(cliArgs.slice(1));
      process.exit(0);
    } catch (err) {
      console.error(`  Error: ${err.message}\n`);
      process.exit(1);
    }
  } else if (cliArgs[0] === 'report') {
    try {
      await runReport(cliArgs.slice(1));
      process.exit(0);
    } catch (err) {
      console.error(`  Error: ${err.message}\n`);
      process.exit(1);
    }
  } else if (cliArgs[0] === 'scan-prompt') {
    // CLI mode: scan-prompt <text> [--verbosity minimal|compact|full]
    const text = cliArgs[1];
    if (!text) {
      console.error('Usage: agent-security-scanner-mcp scan-prompt <text> [--verbosity minimal|compact|full]');
      process.exit(1);
    }
    const verbosityIdx = cliArgs.indexOf('--verbosity');
    const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

    try {
      loadPackageLists();
      const result = await scanAgentPrompt({ prompt_text: text, verbosity });
      const output = JSON.parse(result.content[0].text);
      console.log(JSON.stringify(output, null, 2));
      process.exit(output.action === 'BLOCK' ? 1 : 0);
    } catch (err) {
      console.error(JSON.stringify({ error: err.message }));
      process.exit(1);
    }
} else if (cliArgs[0] === 'scan-security') {
  // CLI mode: scan-security <file> [--verbosity minimal|compact|full] [--format json|sarif]
  const filePath = cliArgs[1];
  if (!filePath) {
    console.error('Usage: agent-security-scanner-mcp scan-security <file> [--verbosity minimal|compact|full] [--format json|sarif]');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const formatIdx = cliArgs.indexOf('--format');
  const outputFormat = formatIdx !== -1 ? cliArgs[formatIdx + 1] : 'json';

  loadPackageLists();
  scanSecurity({ file_path: filePath, verbosity, output_format: outputFormat }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.issues_count > 0 || output.total > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'check-package') {
  // CLI mode: check-package <name> <ecosystem>
  const packageName = cliArgs[1];
  const ecosystem = cliArgs[2];
  if (!packageName || !ecosystem) {
    console.error('Usage: agent-security-scanner-mcp check-package <name> <ecosystem>');
    console.error('Ecosystems: npm, pypi, rubygems, crates, dart, perl, raku');
    process.exit(1);
  }

  loadPackageLists();
  checkPackage({ package_name: packageName, ecosystem }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.legitimate ? 0 : 1);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-packages') {
  // CLI mode: scan-packages <file> <ecosystem> [--verbosity minimal|compact|full]
  const filePath = cliArgs[1];
  const ecosystem = cliArgs[2];
  if (!filePath || !ecosystem) {
    console.error('Usage: agent-security-scanner-mcp scan-packages <file> <ecosystem> [--verbosity minimal|compact|full]');
    console.error('Ecosystems: npm, pypi, rubygems, crates, dart, perl, raku');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  loadPackageLists();
  scanPackages({ file_path: filePath, ecosystem, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.hallucinated_count > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-project') {
  // CLI mode: scan-project <dir> [--recursive] [--diff-only] [--cross-file] [--include '*.py'] [--exclude '*.test.js'] [--verbosity minimal|compact|full]
  const dirPath = cliArgs[1];
  if (!dirPath || dirPath.startsWith('--')) {
    console.error('Usage: agent-security-scanner-mcp scan-project <directory> [--recursive] [--diff-only] [--cross-file] [--include <pattern>] [--exclude <pattern>] [--verbosity minimal|compact|full]');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const recursive = !cliArgs.includes('--no-recursive');
  const diffOnly = cliArgs.includes('--diff-only');
  const crossFile = cliArgs.includes('--cross-file');
  const includeIdx = cliArgs.indexOf('--include');
  const includePatterns = includeIdx !== -1 ? [cliArgs[includeIdx + 1]] : undefined;
  const excludeIdx = cliArgs.indexOf('--exclude');
  const excludePatterns = excludeIdx !== -1 ? [cliArgs[excludeIdx + 1]] : undefined;

  scanProject({ directory_path: dirPath, recursive, diff_only: diffOnly, cross_file: crossFile, include_patterns: includePatterns, exclude_patterns: excludePatterns, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    const total = output.issues_count || output.total || 0;
    process.exit(total > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-diff') {
  // CLI mode: scan-diff [base] [target] [--verbosity minimal|compact|full]
  // Parse positional args, skipping flag values
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const flagValueIndices = new Set(verbosityIdx !== -1 ? [verbosityIdx, verbosityIdx + 1] : []);
  const positionalArgs = cliArgs.slice(1).filter((arg, idx) => !arg.startsWith('--') && !flagValueIndices.has(idx + 1));
  const baseRef = positionalArgs[0];
  const targetRef = positionalArgs[1];
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  scanDiff({ base_ref: baseRef, target_ref: targetRef, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.issues_count > 0 || output.total > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'benchmark') {
  // CLI mode: benchmark [--save] [--json-only] [--compare-latest] [--corpus <path>]
  const { resolvePythonCommand, pythonArgs } = await import('./src/python.js');
  const benchmarkPath = join(__dirname, 'benchmarks', 'benchmark_runner.py');
  const benchArgs = [...pythonArgs(), benchmarkPath];

  // Pass through supported flags
  for (let i = 1; i < cliArgs.length; i++) {
    if (['--save', '--json-only', '--compare-latest'].includes(cliArgs[i])) {
      benchArgs.push(cliArgs[i]);
    } else if (cliArgs[i] === '--corpus' && cliArgs[i + 1]) {
      benchArgs.push('--corpus', cliArgs[i + 1]);
      i++;
    }
  }

  try {
    execFileSync(resolvePythonCommand(), benchArgs, { stdio: 'inherit', timeout: 300000 });
  } catch (err) {
    if (err.status) process.exit(err.status);
    console.error(`Benchmark error: ${err.message}`);
    process.exit(1);
  }
  process.exit(0);
} else if (cliArgs[0] === 'scan-mcp') {
  // CLI mode: scan-mcp <path> [--verbosity minimal|compact|full]
  const serverPath = cliArgs[1];
  if (!serverPath) {
    console.error('Usage: agent-security-scanner-mcp scan-mcp <server-path> [--verbosity minimal|compact|full]');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  scanMcpServer({ server_path: serverPath, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.findings_count > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-action') {
  // CLI mode: scan-action <type> <value> [--verbosity minimal|compact|full]
  const actionType = cliArgs[1];
  const actionValue = cliArgs[2];
  if (!actionType || !actionValue) {
    console.error('Usage: agent-security-scanner-mcp scan-action <type> <value> [--verbosity minimal|compact|full]');
    console.error('Types: bash, file_write, file_read, http_request, file_delete, cron, process_spawn, git, docker');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  scanAgentAction({ action_type: actionType, action_value: actionValue, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.action === 'BLOCK' ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-skill') {
  const skillPath = cliArgs[1];
  if (!skillPath) {
    console.error('Usage: agent-security-scanner-mcp scan-skill <skill-path> [--verbosity minimal|compact|full] [--baseline]');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const baseline = cliArgs.includes('--baseline');

  // Load package lists for supply chain scanning
  const { loadPackageLists } = await import('./src/tools/check-package.js');
  loadPackageLists();

  const { scanSkill } = await import('./src/tools/scan-skill.js');
  scanSkill({ skill_path: skillPath, verbosity, baseline }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.grade === 'F' || output.grade === 'D' ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'audit') {
  const { runAudit } = await import('./src/cli/audit.js');
  runAudit(cliArgs.slice(1)).then(() => process.exit(0)).catch(err => {
    console.error(`  Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (cliArgs[0] === 'harden') {
  const { runHarden } = await import('./src/cli/harden.js');
  runHarden(cliArgs.slice(1)).then(() => process.exit(0)).catch(err => {
    console.error(`  Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (cliArgs[0] === 'sbom-generate') {
  const dirPath = cliArgs[1] || '.';
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const save = cliArgs.includes('--save');
  const outIdx = cliArgs.indexOf('--output');
  const outputPath = outIdx !== -1 ? cliArgs[outIdx + 1] : (save ? join(dirPath, '.scanner', 'sbom.json') : undefined);

  sbomGenerate({ directory_path: dirPath, output_path: outputPath, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'sbom-vulnerabilities') {
  const dirPath = cliArgs[1] || '.';
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const sbomIdx = cliArgs.indexOf('--sbom-path');
  const sbomPath = sbomIdx !== -1 ? cliArgs[sbomIdx + 1] : undefined;

  sbomScanVulnerabilities({
    directory_path: sbomPath ? undefined : dirPath,
    sbom_path: sbomPath,
    verbosity,
  }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.total_vulnerabilities > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'sbom-check-hallucinations') {
  const dirPath = cliArgs[1] || '.';
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  loadPackageLists();
  sbomCheckHallucinations({ directory_path: dirPath, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.hallucinated_count > 0 ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'sbom-diff') {
  const dirPath = cliArgs[1] || '.';
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const saveBaseline = cliArgs.includes('--save-baseline');
  const baselineIdx = cliArgs.indexOf('--baseline-path');
  const baselinePath = baselineIdx !== -1 ? cliArgs[baselineIdx + 1] : undefined;

  sbomDiff({ directory_path: dirPath, baseline_path: baselinePath, save_baseline: saveBaseline, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'sbom-report') {
  const dirPath = cliArgs[1] || '.';
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';
  const formatIdx = cliArgs.indexOf('--format');
  const format = formatIdx !== -1 ? cliArgs[formatIdx + 1] : 'html';
  const outIdx = cliArgs.indexOf('--output');
  const outputPath = outIdx !== -1 ? cliArgs[outIdx + 1] : join(dirPath, '.scanner', 'sbom-report.html');
  const noVulns = cliArgs.includes('--no-vulnerabilities');

  sbomExportReport({
    directory_path: dirPath,
    format,
    include_vulnerabilities: !noVulns,
    output_path: outputPath,
    verbosity,
  }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-clawhub') {
  // Import and run SAFE ClawHub scanner (no code execution)
  await import('./src/cli/scan-clawhub-safe.js');
  // Exit is handled by scan-clawhub-safe.js
} else if (cliArgs[0] === '--help' || cliArgs[0] === '-h' || cliArgs[0] === 'help') {
  console.log('\n  agent-security-scanner-mcp\n');
  console.log('  Commands:');
  console.log('    init [client]        Set up MCP config for a client');
  console.log('    init-hooks           Install Claude Code hooks for auto-scanning');
  console.log('    doctor [--fix]       Check environment & client configs');
  console.log('    demo [--lang js]     Generate vulnerable file + scan it');
  console.log('    report <dir>         Generate HTML security report with history [--threat-model]');
  console.log('    benchmark [flags]      Run accuracy benchmarks\n');
  console.log('  CLI Tools (for scripts & OpenClaw):');
  console.log('    scan-prompt <text>   Scan prompt for injection attacks');
  console.log('    scan-security <file> Scan file for vulnerabilities');
  console.log('    scan-skill <path>    Scan OpenClaw skill for security threats [--baseline]');
  console.log('    scan-clawhub         Batch scan all ClawHub skills and generate report');
  console.log('    check-package <n> <e> Check if package exists in ecosystem');
  console.log('    scan-packages <f> <e> Scan file imports for hallucinated packages');
  console.log('    scan-project <dir>   Scan directory for vulnerabilities with grading');
  console.log('    scan-diff [base] [target] Scan git diff for new vulnerabilities');
  console.log('    scan-mcp <path>      Scan MCP server source for security issues');
  console.log('    scan-action <t> <v>  Check agent action before execution');
  console.log('    audit [--config-path] Audit OpenClaw config for security issues [experimental]');
  console.log('    harden [--fix]       Auto-harden OpenClaw configuration [experimental]\n');
  console.log('  SBOM / Supply Chain:');
  console.log('    sbom-generate <dir>  Generate CycloneDX SBOM [--save] [--output <path>]');
  console.log('    sbom-vulnerabilities <dir> Scan SBOM against OSV.dev [--sbom-path <path>]');
  console.log('    sbom-check-hallucinations <dir> Check SBOM packages against registries');
  console.log('    sbom-diff <dir>      Compare SBOM against baseline [--save-baseline]');
  console.log('    sbom-report <dir>    Generate SBOM audit report [--format html|json]\n');
  console.log('    (no args)            Start MCP server on stdio\n');
  console.log('  Options:');
  console.log('    --verbosity <level>  minimal|compact|full (default: compact)');
  console.log('    --format <type>      json|sarif (scan-security only)');
  console.log('    --include <pattern>  Include only matching files (scan-project)');
  console.log('    --exclude <pattern>  Exclude matching files (scan-project)\n');
  console.log('  Examples:');
  console.log('    npx agent-security-scanner-mcp init');
  console.log('    npx agent-security-scanner-mcp scan-prompt "ignore previous instructions"');
  console.log('    npx agent-security-scanner-mcp scan-security ./app.py --verbosity minimal');
  console.log('    npx agent-security-scanner-mcp check-package flask pypi');
  console.log('    npx agent-security-scanner-mcp scan-project ./src --verbosity minimal');
  console.log('    npx agent-security-scanner-mcp scan-diff HEAD~1');
  console.log('    npx agent-security-scanner-mcp report ./src --json');
  console.log('    npx agent-security-scanner-mcp benchmark --save --compare-latest\n');
  process.exit(0);
} else {
  // Normal MCP server mode
  loadPackageLists();

  async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Security Scanner MCP Server running on stdio");

    // Pre-warm daemon in background (non-blocking)
    if (process.env.SCANNER_PREWARM !== '0') {
      import('./src/daemon-client.js').then(({ getDaemonClient }) => {
        getDaemonClient().preWarm().catch(() => {});
      }).catch(() => {});
    }

    // Shutdown daemon when MCP server closes
    server.server.onclose = async () => {
      await shutdownDaemon();
    };
  }

  // Graceful shutdown on signals
  const shutdownHandler = async () => {
    await shutdownDaemon();
    process.exit(0);
  };
  process.on('SIGTERM', shutdownHandler);
  process.on('SIGINT', shutdownHandler);

  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
})(); // Close async IIFE
