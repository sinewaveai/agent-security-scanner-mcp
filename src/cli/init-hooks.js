// src/cli/init-hooks.js
// CLI command: init-hooks
// Installs Claude Code hooks for automatic security scanning on file write/edit.

import { existsSync, readFileSync, writeFileSync, copyFileSync, mkdirSync } from 'fs';
import { join } from 'path';

const SCANNER_HOOK_MARKER = 'agent-security-scanner-mcp';

function buildHooksConfig(withPromptGuard) {
  const hooks = {
    'post-tool-use': [
      {
        matcher: 'Write|Edit|MultiEdit',
        command: `npx agent-security-scanner-mcp scan-security "$TOOL_INPUT_FILE_PATH" --verbosity minimal`,
      },
    ],
  };

  if (withPromptGuard) {
    hooks['pre-tool-use'] = [
      {
        matcher: 'Bash',
        command: `npx agent-security-scanner-mcp scan-prompt "$TOOL_INPUT_COMMAND" --verbosity minimal`,
      },
    ];
  }

  return hooks;
}

function backupTimestamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function parseFlags(args) {
  const flags = { dryRun: false, path: null, withPromptGuard: false };
  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if (arg === '--dry-run') flags.dryRun = true;
    else if (arg === '--path' && i + 1 < args.length) flags.path = args[++i];
    else if (arg === '--with-prompt-guard') flags.withPromptGuard = true;
    i++;
  }
  return flags;
}

function containsScannerHook(hooksObj) {
  if (!hooksObj || typeof hooksObj !== 'object') return false;
  for (const eventHooks of Object.values(hooksObj)) {
    if (!Array.isArray(eventHooks)) continue;
    if (eventHooks.some(h => h.command && h.command.includes(SCANNER_HOOK_MARKER))) {
      return true;
    }
  }
  return false;
}

function mergeHooks(existingHooks, newHooks) {
  const merged = { ...existingHooks };

  for (const [event, hooks] of Object.entries(newHooks)) {
    if (!merged[event]) {
      merged[event] = hooks;
      continue;
    }

    // Filter out existing scanner hooks for this event
    const nonScanner = merged[event].filter(h =>
      !h.command || !h.command.includes(SCANNER_HOOK_MARKER)
    );

    merged[event] = [...nonScanner, ...hooks];
  }

  return merged;
}

export async function runInitHooks(args) {
  const flags = parseFlags(args);

  console.log('\n  Agentic Security - Claude Code Hooks Setup\n');

  const settingsDir = flags.path || join(process.cwd(), '.claude');
  const settingsPath = join(settingsDir, 'settings.json');

  console.log(`  Settings: ${settingsPath}`);
  console.log(`  Prompt guard: ${flags.withPromptGuard ? 'enabled' : 'disabled (use --with-prompt-guard to enable)'}`);
  console.log('');

  const newHooks = buildHooksConfig(flags.withPromptGuard);

  // Read existing settings
  let existing = {};
  let fileExisted = false;
  if (existsSync(settingsPath)) {
    fileExisted = true;
    try {
      existing = JSON.parse(readFileSync(settingsPath, 'utf-8'));
    } catch (e) {
      console.error(`  ERROR: Invalid JSON in ${settingsPath}`);
      console.error(`  ${e.message}\n`);
      process.exit(1);
    }
  }

  if (containsScannerHook(existing.hooks)) {
    console.log('  Scanner hooks already configured. Updating...');
  }

  // Merge hooks non-destructively
  const mergedHooks = mergeHooks(existing.hooks || {}, newHooks);
  const merged = { ...existing, hooks: mergedHooks };
  const output = JSON.stringify(merged, null, 2) + '\n';

  if (flags.dryRun) {
    console.log('  [dry-run] Would write:\n');
    console.log('  ' + output.split('\n').join('\n  '));
    console.log('  No changes made.\n');
    return;
  }

  if (!existsSync(settingsDir)) {
    mkdirSync(settingsDir, { recursive: true });
    console.log(`  Created directory: ${settingsDir}`);
  }

  if (fileExisted) {
    const backupPath = `${settingsPath}.bak-${backupTimestamp()}`;
    copyFileSync(settingsPath, backupPath);
    console.log(`  Backup: ${backupPath}`);
  }

  writeFileSync(settingsPath, output);
  console.log(`  Wrote: ${settingsPath}\n`);

  console.log('  Hooks installed:');
  for (const [event, hooks] of Object.entries(newHooks)) {
    for (const hook of hooks) {
      console.log(`    - [${event}] Matcher: ${hook.matcher}`);
    }
  }

  console.log('\n  Security scanning is now automatic for file writes and edits.');
  console.log('  Restart Claude Code for hooks to take effect.\n');

  if (!existsSync(join(process.cwd(), '.scannerrc.yaml')) &&
      !existsSync(join(process.cwd(), '.scannerrc.yml')) &&
      !existsSync(join(process.cwd(), '.scannerrc.json'))) {
    console.log('  Tip: Create a .scannerrc.yaml to customize scanning:');
    console.log('');
    console.log('    version: 1');
    console.log('    suppress:');
    console.log('      - rule: "insecure-random"');
    console.log('    exclude:');
    console.log('      - "node_modules/**"');
    console.log('      - "dist/**"');
    console.log('    severity_threshold: "warning"');
    console.log('');
  }
}
