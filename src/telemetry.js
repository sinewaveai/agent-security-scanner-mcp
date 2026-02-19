// src/telemetry.js — Anonymous telemetry for agent-security-scanner-mcp
// Zero external dependencies. Uses node:crypto, node:fs, node:os, node:path, global fetch.
// See TELEMETRY.md for full transparency documentation.

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir, hostname, userInfo, platform, arch } from 'node:os';
import { join } from 'node:path';

// --- Constants ---

const TELEMETRY_ENDPOINT = 'https://telemetry.prooflayer.com/v1/events';
const BATCH_SIZE = 10;
const FLUSH_INTERVAL_MS = 30_000;
const FETCH_TIMEOUT_MS = 5_000;
const SCHEMA_VERSION = 1;
const _DEFAULT_STATE_DIR = join(homedir(), '.agent-security-scanner-mcp');
let STATE_DIR = _DEFAULT_STATE_DIR;
let STATE_FILE = join(STATE_DIR, 'telemetry.json');

// --- Module-level state ---

let _machineId = null;
const _sessionId = randomUUID();
let _invocationMode = 'mcp';
let _queue = [];
let _flushTimer = null;
let _noticeShown = false;
let _scannerVersion = null;
let _isEnabledCache = null;

// --- Version ---

function getScannerVersion() {
  if (_scannerVersion) return _scannerVersion;
  try {
    const pkgPath = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    _scannerVersion = pkg.version || '0.0.0';
  } catch {
    _scannerVersion = '0.0.0';
  }
  return _scannerVersion;
}

// --- Machine ID (SHA-256 hash, deterministic, irreversible) ---

export function getMachineId() {
  if (_machineId) return _machineId;

  // Try to load from state file first
  const state = _loadState();
  if (state.machine_id) {
    _machineId = state.machine_id;
    return _machineId;
  }

  // Generate deterministic machine ID
  const raw = [
    hostname(),
    homedir(),
    _safeUsername(),
    platform(),
    arch(),
  ].join('|');
  _machineId = createHash('sha256').update(raw).digest('hex');

  // Persist to state file
  _saveState({ ...state, machine_id: _machineId });
  return _machineId;
}

function _safeUsername() {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

// --- State file management ---

function _loadState() {
  try {
    if (existsSync(STATE_FILE)) {
      return JSON.parse(readFileSync(STATE_FILE, 'utf-8'));
    }
  } catch {
    // Corrupted state — start fresh
  }
  return {};
}

function _saveState(state) {
  try {
    if (!existsSync(STATE_DIR)) {
      mkdirSync(STATE_DIR, { recursive: true });
    }
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + '\n');
  } catch {
    // Non-critical — ignore
  }
}

// --- Opt-out check ---

export function isEnabled() {
  if (_isEnabledCache !== null) return _isEnabledCache;

  // 1. DO_NOT_TRACK universal standard
  if (process.env.DO_NOT_TRACK === '1') return (_isEnabledCache = false);

  // 2. Scanner-specific env var
  if (process.env.SCANNER_TELEMETRY_DISABLED === '1') return (_isEnabledCache = false);

  // 3. CI environment auto-disable
  if (process.env.CI === 'true' || process.env.CI === '1') return (_isEnabledCache = false);

  // 4. State file opt-out
  const state = _loadState();
  if (state.telemetry_enabled === false) return (_isEnabledCache = false);

  return (_isEnabledCache = true);
}

// --- First-run notice ---

export function showFirstRunNotice() {
  if (_noticeShown) return;

  const state = _loadState();
  if (state.notice_shown) {
    _noticeShown = true;
    return;
  }

  // Write to stderr only — never stdout (MCP JSON integrity)
  process.stderr.write(`
  Telemetry Notice
  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  agent-security-scanner-mcp collects anonymous usage statistics
  to improve the tool. No file paths, code, or personal data are collected.

  Disable: set DO_NOT_TRACK=1, SCANNER_TELEMETRY_DISABLED=1,
           or run: npx agent-security-scanner-mcp telemetry --off

  Details: https://github.com/sinewaveai/agent-security-scanner-mcp/blob/main/TELEMETRY.md

`);

  _noticeShown = true;
  _saveState({ ...state, notice_shown: true, first_seen: state.first_seen || new Date().toISOString() });
}

// --- Event tracking ---

export function track(eventName, properties = {}) {
  if (!isEnabled()) return;

  // Debug mode: print to stderr, don't send
  if (process.env.SCANNER_TELEMETRY_DEBUG === '1') {
    process.stderr.write(`[telemetry:debug] ${eventName} ${JSON.stringify(properties)}\n`);
    return;
  }

  const event = {
    schema_version: SCHEMA_VERSION,
    event: eventName,
    timestamp: new Date().toISOString(),
    machine_id: getMachineId(),
    session_id: _sessionId,
    scanner_version: getScannerVersion(),
    os_platform: platform(),
    os_arch: arch(),
    node_version: process.versions.node,
    invocation_mode: _invocationMode,
    ...properties,
  };

  _queue.push(event);

  // Auto-flush at batch size
  if (_queue.length >= BATCH_SIZE) {
    flush();
  } else {
    _scheduleFlush();
  }
}

// --- Flush ---

export function flush() {
  if (_queue.length === 0) return;

  const batch = _queue.splice(0);

  // Clear pending timer
  if (_flushTimer) {
    clearTimeout(_flushTimer);
    _flushTimer = null;
  }

  // Fire-and-forget — never block, never throw
  _sendBatch(batch).catch(() => {});
}

async function _sendBatch(events) {
  try {
    await fetch(TELEMETRY_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    // Silently discard — telemetry failure never impacts scans
  }
}

function _scheduleFlush() {
  if (_flushTimer) return;
  _flushTimer = setTimeout(() => {
    _flushTimer = null;
    flush();
  }, FLUSH_INTERVAL_MS);
  // unref() so timer never prevents process exit
  if (_flushTimer.unref) _flushTimer.unref();
}

// --- Invocation mode ---

export function setInvocationMode(mode) {
  _invocationMode = mode;
}

// --- Tool wrapper ---

export function withTelemetry(toolName, handler) {
  return async (args, extra) => {
    const start = Date.now();
    let success = true;
    let errorCode = null;

    try {
      const result = await handler(args, extra);

      track('tool.invoked', {
        tool_name: toolName,
        duration_ms: Date.now() - start,
        success: true,
      });

      return result;
    } catch (err) {
      success = false;
      errorCode = err.code || err.constructor?.name || 'UnknownError';

      track('tool.invoked', {
        tool_name: toolName,
        duration_ms: Date.now() - start,
        success: false,
        error_code: errorCode,
      });

      track('error', {
        error_code: errorCode,
        error_class: err.constructor?.name || 'Error',
      });

      throw err;
    }
  };
}

// --- CLI sub-command ---

export function handleTelemetryCli(args) {
  const cmd = args[0];

  if (cmd === '--off' || cmd === 'off') {
    const state = _loadState();
    _saveState({ ...state, telemetry_enabled: false });
    _isEnabledCache = null;
    console.log('Telemetry disabled. No data will be collected.');
    return;
  }

  if (cmd === '--on' || cmd === 'on') {
    const state = _loadState();
    _saveState({ ...state, telemetry_enabled: true });
    _isEnabledCache = null;
    console.log('Telemetry enabled. Anonymous usage statistics will be collected.');
    return;
  }

  if (cmd === '--status' || cmd === 'status' || !cmd) {
    const enabled = isEnabled();
    const state = _loadState();
    console.log(`\n  Telemetry Status`);
    console.log(`  ${'─'.repeat(16)}`);
    console.log(`  Enabled:    ${enabled ? 'yes' : 'no'}`);
    if (process.env.DO_NOT_TRACK === '1') console.log('  Reason:     DO_NOT_TRACK=1');
    if (process.env.SCANNER_TELEMETRY_DISABLED === '1') console.log('  Reason:     SCANNER_TELEMETRY_DISABLED=1');
    if (process.env.CI === 'true' || process.env.CI === '1') console.log('  Reason:     CI environment detected');
    if (state.telemetry_enabled === false) console.log('  Reason:     Disabled via CLI');
    console.log(`  Machine ID: ${getMachineId().substring(0, 12)}...`);
    console.log(`  State file: ${STATE_FILE}`);
    console.log(`\n  Manage:`);
    console.log(`    npx agent-security-scanner-mcp telemetry --off`);
    console.log(`    npx agent-security-scanner-mcp telemetry --on`);
    console.log(`    DO_NOT_TRACK=1  (universal standard)\n`);
    return;
  }

  console.log('Usage: npx agent-security-scanner-mcp telemetry [--on|--off|--status]');
}

// --- Exports for testing ---

export function _getQueue() {
  return _queue;
}

export function _resetForTesting(testDir) {
  _queue = [];
  _isEnabledCache = null;
  _machineId = null;
  _noticeShown = false;
  _scannerVersion = null;
  if (_flushTimer) {
    clearTimeout(_flushTimer);
    _flushTimer = null;
  }

  // Redirect state file to test-specific directory (or reset to default)
  if (testDir) {
    STATE_DIR = testDir;
    STATE_FILE = join(STATE_DIR, 'telemetry.json');
  } else {
    STATE_DIR = _DEFAULT_STATE_DIR;
    STATE_FILE = join(STATE_DIR, 'telemetry.json');
  }
}

// Flush remaining events before process exits (CLI mode)
process.on('beforeExit', () => flush());

export { _sessionId as getSessionId };
export { STATE_FILE, STATE_DIR, BATCH_SIZE, _DEFAULT_STATE_DIR };
