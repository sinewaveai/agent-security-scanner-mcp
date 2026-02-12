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
import { detectLanguage, runAnalyzer, generateFix, toSarif } from './src/utils.js';
import { scanSecuritySchema, scanSecurity } from './src/tools/scan-security.js';
import { fixSecuritySchema, fixSecurity } from './src/tools/fix-security.js';
import { loadPackageLists, checkPackageSchema, checkPackage, getPackageStats } from './src/tools/check-package.js';
import { scanPackagesSchema, scanPackages } from './src/tools/scan-packages.js';
import { scanAgentPromptSchema, scanAgentPrompt } from './src/tools/scan-prompt.js';
import { runInit } from './src/cli/init.js';
import { runDoctor } from './src/cli/doctor.js';
import { runDemo } from './src/cli/demo.js';

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Create MCP Server
const server = new McpServer(
  {
    name: "security-scanner",
    version: "1.0.0",
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

// ===========================================
// CLI COMMANDS - Extracted to src/cli/
// ===========================================
// See src/cli/init.js, src/cli/doctor.js, src/cli/demo.js

// Handle CLI arguments before loading heavy package data
const cliArgs = process.argv.slice(2);
if (cliArgs[0] === 'init') {
  runInit(cliArgs.slice(1)).then(() => process.exit(0)).catch((err) => {
    console.error(`  Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (cliArgs[0] === 'doctor') {
  runDoctor(cliArgs.slice(1)).then(() => process.exit(0)).catch((err) => {
    console.error(`  Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (cliArgs[0] === 'demo') {
  runDemo(cliArgs.slice(1)).then(() => process.exit(0)).catch((err) => {
    console.error(`  Error: ${err.message}\n`);
    process.exit(1);
  });
} else if (cliArgs[0] === 'scan-prompt') {
  // CLI mode: scan-prompt <text> [--verbosity minimal|compact|full]
  const text = cliArgs[1];
  if (!text) {
    console.error('Usage: agent-security-scanner-mcp scan-prompt <text> [--verbosity minimal|compact|full]');
    process.exit(1);
  }
  const verbosityIdx = cliArgs.indexOf('--verbosity');
  const verbosity = verbosityIdx !== -1 ? cliArgs[verbosityIdx + 1] : 'compact';

  loadPackageLists();
  scanAgentPrompt({ prompt_text: text, verbosity }).then(result => {
    const output = JSON.parse(result.content[0].text);
    console.log(JSON.stringify(output, null, 2));
    process.exit(output.action === 'BLOCK' ? 1 : 0);
  }).catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
  });
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
} else if (cliArgs[0] === '--help' || cliArgs[0] === '-h' || cliArgs[0] === 'help') {
  console.log('\n  agent-security-scanner-mcp\n');
  console.log('  Commands:');
  console.log('    init [client]        Set up MCP config for a client');
  console.log('    doctor [--fix]       Check environment & client configs');
  console.log('    demo [--lang js]     Generate vulnerable file + scan it\n');
  console.log('  CLI Tools (for scripts & OpenClaw):');
  console.log('    scan-prompt <text>   Scan prompt for injection attacks');
  console.log('    scan-security <file> Scan file for vulnerabilities');
  console.log('    check-package <n> <e> Check if package exists in ecosystem');
  console.log('    scan-packages <f> <e> Scan file imports for hallucinated packages\n');
  console.log('    (no args)            Start MCP server on stdio\n');
  console.log('  Options:');
  console.log('    --verbosity <level>  minimal|compact|full (default: compact)');
  console.log('    --format <type>      json|sarif (scan-security only)\n');
  console.log('  Examples:');
  console.log('    npx agent-security-scanner-mcp init');
  console.log('    npx agent-security-scanner-mcp scan-prompt "ignore previous instructions"');
  console.log('    npx agent-security-scanner-mcp scan-security ./app.py --verbosity minimal');
  console.log('    npx agent-security-scanner-mcp check-package flask pypi\n');
  process.exit(0);
} else {
  // Normal MCP server mode
  loadPackageLists();

  async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Security Scanner MCP Server running on stdio");
  }

  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
