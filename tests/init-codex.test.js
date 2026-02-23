/**
 * Tests for codex client support in init command
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Mocks ──────────────────────────────────────────────────────────────────

// Mock child_process spawnSync so tests never actually invoke 'codex'
vi.mock('child_process', () => ({
  spawnSync: vi.fn()
}));

// Mock fs so tests never touch the real filesystem
vi.mock('fs', () => ({
  readFileSync: vi.fn(),
  existsSync: vi.fn(() => false),
  writeFileSync: vi.fn(),
  copyFileSync: vi.fn(),
  mkdirSync: vi.fn()
}));

import { spawnSync } from 'child_process';
import { runInit } from '../src/cli/init.js';

// ── Helpers ────────────────────────────────────────────────────────────────

function captureOutput(fn) {
  const logs = [];
  const errors = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...args) => logs.push(args.join(' '));
  console.error = (...args) => errors.push(args.join(' '));
  const restore = () => { console.log = origLog; console.error = origErr; };
  return { logs, errors, restore };
}

// ── Test suite ─────────────────────────────────────────────────────────────

describe('init codex — CLIENT_CONFIGS registration', () => {
  it('lists codex in the usage/help output for unknown client', async () => {
    const exitMock = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit'); });
    const { logs, errors, restore } = captureOutput();

    try {
      await runInit(['unknown-client-xyz']);
    } catch (e) {
      // process.exit throws in test
    }

    restore();
    exitMock.mockRestore();

    const allOutput = [...logs, ...errors].join('\n');
    expect(allOutput).toContain('codex');
  });
});

describe('init codex — dry-run (no codex CLI required)', () => {
  let exitMock;

  beforeEach(() => {
    exitMock = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit'); });
    // spawnSync for 'which codex' returns success
    spawnSync.mockReturnValue({ status: 0, stdout: '/usr/local/bin/codex', stderr: '' });
  });

  afterEach(() => {
    exitMock.mockRestore();
    vi.clearAllMocks();
  });

  it('prints the codex mcp add command it would run', async () => {
    const { logs, restore } = captureOutput();

    try {
      await runInit(['codex', '--dry-run']);
    } catch (e) {
      // process.exit throws in test
    }

    restore();
    const output = logs.join('\n');
    expect(output).toContain('dry-run');
    expect(output).toContain('codex mcp add');
    expect(output).toContain('npx -y agent-security-scanner-mcp');
  });

  it('dry-run uses the default server name agentic-security', async () => {
    const { logs, restore } = captureOutput();

    try {
      await runInit(['codex', '--dry-run']);
    } catch (e) {}

    restore();
    const output = logs.join('\n');
    expect(output).toContain('agentic-security');
  });

  it('dry-run respects --name override', async () => {
    const { logs, restore } = captureOutput();

    try {
      await runInit(['codex', '--dry-run', '--name', 'my-scanner']);
    } catch (e) {}

    restore();
    const output = logs.join('\n');
    expect(output).toContain('my-scanner');
  });

  it('dry-run does not invoke codex mcp add', async () => {
    const { restore } = captureOutput();
    // Reset call count before test
    spawnSync.mockClear();

    // Only 'which codex' should be called (status check), not 'codex mcp add'
    try {
      await runInit(['codex', '--dry-run']);
    } catch (e) {}

    restore();
    // spawnSync called once for 'which codex', never for 'codex mcp add'
    const mcpAddCalls = spawnSync.mock.calls.filter(
      args => args[0] === 'codex' && args[1]?.includes('mcp')
    );
    expect(mcpAddCalls).toHaveLength(0);
  });
});

describe('init codex — codex CLI not installed', () => {
  let exitMock;

  beforeEach(() => {
    exitMock = vi.spyOn(process, 'exit').mockImplementation((code) => { throw new Error(`process.exit(${code})`); });
    // Simulate 'which codex' failing (codex not in PATH)
    spawnSync.mockReturnValue({ status: 1, stdout: '', stderr: '' });
  });

  afterEach(() => {
    exitMock.mockRestore();
    vi.clearAllMocks();
  });

  it('prints a clear error when codex CLI is not found', async () => {
    const { errors, restore } = captureOutput();

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    const output = errors.join('\n');
    expect(output).toContain('codex');
    expect(output).toContain('not found');
  });

  it('exits with non-zero when codex CLI is missing', async () => {
    const { restore } = captureOutput();

    let exitCode = null;
    exitMock.mockImplementation((code) => { exitCode = code; throw new Error('process.exit'); });

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    expect(exitCode).toBe(1);
  });
});

describe('init codex — successful registration', () => {
  let exitMock;

  beforeEach(() => {
    exitMock = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit'); });
    // 'which codex' succeeds, 'codex mcp add' succeeds
    spawnSync.mockImplementation((cmd, args) => {
      if (cmd === 'which') return { status: 0, stdout: '/usr/local/bin/codex', stderr: '' };
      if (cmd === 'codex') return { status: 0, stdout: '', stderr: '' };
      return { status: 1 };
    });
  });

  afterEach(() => {
    exitMock.mockRestore();
    vi.clearAllMocks();
  });

  it('invokes codex mcp add with the server name', async () => {
    const { restore } = captureOutput();

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    // Skip the --version probe; find the 'codex mcp add' invocation
    const codexCall = spawnSync.mock.calls.find(args => args[0] === 'codex' && args[1]?.includes('mcp'));
    expect(codexCall).toBeDefined();
    expect(codexCall[1]).toContain('mcp');
    expect(codexCall[1]).toContain('add');
    expect(codexCall[1]).toContain('agentic-security');
  });

  it('invokes codex mcp add with npx -y agent-security-scanner-mcp', async () => {
    const { restore } = captureOutput();

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    const codexCall = spawnSync.mock.calls.find(args => args[0] === 'codex' && args[1]?.includes('mcp'));
    expect(codexCall[1]).toContain('npx');
    expect(codexCall[1]).toContain('-y');
    expect(codexCall[1]).toContain('agent-security-scanner-mcp');
  });

  it('prints success message after registration', async () => {
    const { logs, restore } = captureOutput();

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    const output = logs.join('\n');
    expect(output.toLowerCase()).toContain('success');
  });

  it('respects --name flag when calling codex mcp add', async () => {
    const { restore } = captureOutput();

    try {
      await runInit(['codex', '--name', 'custom-name']);
    } catch (e) {}

    restore();
    const codexCall = spawnSync.mock.calls.find(args => args[0] === 'codex' && args[1]?.includes('mcp'));
    expect(codexCall[1]).toContain('custom-name');
  });
});

describe('init codex — codex mcp add failure', () => {
  let exitMock;

  beforeEach(() => {
    exitMock = vi.spyOn(process, 'exit').mockImplementation((code) => { throw new Error(`process.exit(${code})`); });
    spawnSync.mockImplementation((cmd, args) => {
      if (cmd === 'which') return { status: 0, stdout: '/usr/local/bin/codex', stderr: '' };
      // codex --version succeeds (CLI is installed)
      if (cmd === 'codex' && args?.[0] === '--version') return { status: 0, stdout: '1.0.0', stderr: '' };
      // codex mcp add fails
      return { status: 2, stdout: '', stderr: 'error: server already exists' };
    });
  });

  afterEach(() => {
    exitMock.mockRestore();
    vi.clearAllMocks();
  });

  it('prints manual TOML instructions on codex mcp add failure', async () => {
    const { errors, restore } = captureOutput();

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    const output = errors.join('\n');
    expect(output).toContain('config.toml');
    expect(output).toContain('mcp_servers');
    expect(output).toContain('npx');
  });

  it('exits with code 1 when codex mcp add fails', async () => {
    const { restore } = captureOutput();

    let exitCode = null;
    exitMock.mockImplementation((code) => { exitCode = code; throw new Error('process.exit'); });

    try {
      await runInit(['codex']);
    } catch (e) {}

    restore();
    expect(exitCode).toBe(1);
  });
});
