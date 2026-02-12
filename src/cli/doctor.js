import { execFileSync } from "child_process";
import { readFileSync, existsSync, writeFileSync, copyFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { homedir, platform } from "os";
import { fileURLToPath } from "url";

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

function vscodeBase() {
  const os = platform();
  if (os === 'darwin') return join(homedir(), 'Library', 'Application Support');
  if (os === 'win32') return process.env.APPDATA || homedir();
  return join(homedir(), '.config');
}

const MCP_SERVER_ENTRY = {
  command: "npx",
  args: ["-y", "agent-security-scanner-mcp"]
};

const CLIENT_CONFIGS = {
  'claude-desktop': {
    name: 'Claude Desktop',
    configKey: 'mcpServers',
    configPath: () => {
      const os = platform();
      if (os === 'darwin') return join(homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
      if (os === 'win32') return join(process.env.APPDATA || homedir(), 'Claude', 'claude_desktop_config.json');
      return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
    },
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  },
  'claude-code': {
    name: 'Claude Code',
    configKey: 'mcpServers',
    configPath: () => join(homedir(), '.claude', 'settings.json'),
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  },
  'cursor': {
    name: 'Cursor',
    configKey: 'mcpServers',
    configPath: () => join(homedir(), '.cursor', 'mcp.json'),
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  },
  'windsurf': {
    name: 'Windsurf',
    configKey: 'mcpServers',
    configPath: () => {
      const os = platform();
      if (os === 'darwin') return join(homedir(), '.codeium', 'windsurf', 'mcp_config.json');
      if (os === 'win32') return join(process.env.APPDATA || homedir(), '.codeium', 'windsurf', 'mcp_config.json');
      return join(homedir(), '.codeium', 'windsurf', 'mcp_config.json');
    },
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  },
  'cline': {
    name: 'Cline',
    configKey: 'mcpServers',
    configPath: () => join(vscodeBase(), 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  },
  'kilo-code': {
    name: 'Kilo Code',
    configKey: 'mcpServers',
    configPath: () => join(vscodeBase(), 'Code', 'User', 'globalStorage', 'kilocode.kilo-code', 'settings', 'mcp_settings.json'),
    buildEntry: () => ({ ...MCP_SERVER_ENTRY, alwaysAllow: ["scan_security", "scan_agent_prompt", "check_package"], disabled: false })
  },
  'opencode': {
    name: 'OpenCode',
    configKey: 'mcp',
    configPath: () => join(process.cwd(), 'opencode.jsonc'),
    buildEntry: () => ({ type: "local", command: ["npx", "-y", "agent-security-scanner-mcp"], enabled: true })
  },
  'cody': {
    name: 'Cody (Sourcegraph)',
    configKey: 'mcpServers',
    configPath: () => join(vscodeBase(), 'Code', 'User', 'globalStorage', 'sourcegraph.cody-ai', 'mcp_settings.json'),
    buildEntry: () => ({ ...MCP_SERVER_ENTRY })
  }
};

// Timestamp for backup filenames
function backupTimestamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function checkCommand(cmd, args) {
  try {
    const out = execFileSync(cmd, args, { timeout: 10000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    return { ok: true, output: out.trim() };
  } catch {
    return { ok: false, output: null };
  }
}

export async function runDoctor(args) {
  const fix = args.includes('--fix') || false;
  let issues = 0;
  let fixed = 0;

  console.log('\n  agent-security-scanner-mcp doctor\n');

  // --- Environment checks ---
  console.log('  Environment');

  // 1. Node version
  const nodeVer = process.versions.node;
  const nodeMajor = parseInt(nodeVer.split('.')[0], 10);
  if (nodeMajor >= 18) {
    console.log(`    \u2713 Node.js v${nodeVer} (>= 18 required)`);
  } else {
    console.log(`    \u2717 Node.js v${nodeVer} — version 18+ required`);
    console.log(`      Install: https://nodejs.org/`);
    issues++;
  }

  // 2. Python 3
  let pythonCmd = null;
  const py3 = checkCommand('python3', ['--version']);
  if (py3.ok) {
    pythonCmd = 'python3';
    console.log(`    \u2713 ${py3.output}`);
  } else {
    const py = checkCommand('python', ['--version']);
    if (py.ok && py.output.includes('3.')) {
      pythonCmd = 'python';
      console.log(`    \u2713 ${py.output}`);
    } else {
      console.log(`    \u2717 Python 3 not found`);
      console.log(`      Install: https://python.org/downloads/`);
      issues++;
    }
  }

  // 3. analyzer.py reachable
  const analyzerPath = join(__dirname, '..', '..', 'analyzer.py');
  if (existsSync(analyzerPath)) {
    console.log(`    \u2713 analyzer.py found`);
  } else {
    console.log(`    \u2717 analyzer.py not found at ${analyzerPath}`);
    console.log(`      Try reinstalling: npm install -g agent-security-scanner-mcp`);
    issues++;
  }

  // 4. Python can import yaml (analyzer dependency check)
  if (pythonCmd && existsSync(analyzerPath)) {
    const yamlCheck = checkCommand(pythonCmd, ['-c', 'import yaml; print("ok")']);
    if (yamlCheck.ok && yamlCheck.output === 'ok') {
      console.log(`    \u2713 Analyzer engine ready (PyYAML installed)`);
    } else {
      // PyYAML missing but analyzer has fallback rules - still works
      console.log(`    \u2713 Analyzer engine ready (using fallback rules)`);
    }
  }

  // 5. tree-sitter AST engine (optional but recommended)
  if (pythonCmd) {
    const tsCheck = checkCommand(pythonCmd, ['-c', 'import tree_sitter; print(tree_sitter.__version__)']);
    if (tsCheck.ok && tsCheck.output) {
      console.log(`    \u2713 AST engine ready (tree-sitter ${tsCheck.output})`);
    } else {
      console.log(`    \u26a0 tree-sitter not installed (regex-only mode)`);
      console.log(`      For enhanced detection: pip install tree-sitter tree-sitter-python tree-sitter-javascript`);
    }
  }

  // --- Client configuration checks ---
  console.log('\n  Client Configurations');

  for (const [key, client] of Object.entries(CLIENT_CONFIGS)) {
    let configPath;
    try { configPath = client.configPath(); } catch { continue; }

    const configDir = dirname(configPath);

    // Check if the tool appears installed (config dir exists)
    if (!existsSync(configDir)) {
      console.log(`    \u2014 ${client.name.padEnd(20)} not installed (no config dir)`);
      continue;
    }

    // Config file exists?
    if (!existsSync(configPath)) {
      console.log(`    \u2717 ${client.name.padEnd(20)} config file not found: ${configPath}`);
      if (fix) {
        // Auto-fix: run init for this client
        const entry = client.buildEntry();
        const config = { [client.configKey]: { 'security-scanner': entry } };
        mkdirSync(dirname(configPath), { recursive: true });
        writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
        console.log(`      \u2713 Fixed: created config with security-scanner entry`);
        fixed++;
      } else {
        console.log(`      Fix: npx agent-security-scanner-mcp init ${key}`);
        issues++;
      }
      continue;
    }

    // Valid JSON?
    let config;
    try {
      const raw = readFileSync(configPath, 'utf-8');
      // Only strip comments for .jsonc files (avoid breaking URLs with //)
      let stripped = raw;
      if (configPath.endsWith('.jsonc')) {
        stripped = raw.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      }
      config = JSON.parse(stripped);
    } catch (e) {
      console.log(`    \u2717 ${client.name.padEnd(20)} invalid JSON in config`);
      console.log(`      Error: ${e.message}`);
      issues++;
      continue;
    }

    // Has config section?
    const section = config[client.configKey];
    if (!section) {
      console.log(`    \u2717 ${client.name.padEnd(20)} missing "${client.configKey}" section`);
      if (fix) {
        config[client.configKey] = { 'security-scanner': client.buildEntry() };
        const backupPath = `${configPath}.bak-${backupTimestamp()}`;
        copyFileSync(configPath, backupPath);
        writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
        console.log(`      \u2713 Fixed: added ${client.configKey} with security-scanner entry`);
        fixed++;
      } else {
        console.log(`      Fix: npx agent-security-scanner-mcp init ${key}`);
        issues++;
      }
      continue;
    }

    // Has our entry? Check common key names
    const ourEntry = section['security-scanner'] || section['agentic-security'] || section['agent-security-scanner-mcp'];
    if (ourEntry) {
      const entryName = section['security-scanner'] ? 'security-scanner' : section['agentic-security'] ? 'agentic-security' : 'agent-security-scanner-mcp';
      console.log(`    \u2713 ${client.name.padEnd(20)} configured (${entryName})`);
    } else {
      console.log(`    \u2717 ${client.name.padEnd(20)} entry missing from config`);
      if (fix) {
        config[client.configKey]['security-scanner'] = client.buildEntry();
        const backupPath = `${configPath}.bak-${backupTimestamp()}`;
        copyFileSync(configPath, backupPath);
        writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
        console.log(`      \u2713 Fixed: added security-scanner entry`);
        fixed++;
      } else {
        console.log(`      Fix: npx agent-security-scanner-mcp init ${key}`);
        issues++;
      }
    }
  }

  // Summary
  console.log('');
  if (issues === 0 && fixed === 0) {
    console.log('  All checks passed. You\'re good to go!\n');
  } else if (fixed > 0) {
    console.log(`  Fixed ${fixed} issue(s). ${issues > 0 ? `${issues} remaining issue(s) need manual attention.` : 'All clear!'}\n`);
  } else {
    console.log(`  ${issues} issue(s) found. Run with --fix to auto-repair, or use init <client>.\n`);
  }
}
