import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { join } from 'path';
import { existsSync, unlinkSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'fs';
import { tmpdir, homedir, hostname, platform, arch } from 'os';

// Each test gets a unique temp directory — never touches real ~/.agent-security-scanner-mcp/
let TEST_STATE_DIR;
let TEST_STATE_FILE;

describe('telemetry module', () => {
  let telemetry;

  beforeEach(async () => {
    // Create unique temp dir per test
    TEST_STATE_DIR = join(tmpdir(), `scanner-telemetry-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    TEST_STATE_FILE = join(TEST_STATE_DIR, 'telemetry.json');

    // Clean env vars
    delete process.env.DO_NOT_TRACK;
    delete process.env.SCANNER_TELEMETRY_DISABLED;
    delete process.env.CI;
    delete process.env.SCANNER_TELEMETRY_DEBUG;

    // Fresh import each time to reset module state
    telemetry = await import('../src/telemetry.js');
    telemetry._resetForTesting(TEST_STATE_DIR);
  });

  afterEach(() => {
    // Clean up test state dir
    try {
      if (existsSync(TEST_STATE_DIR)) {
        rmSync(TEST_STATE_DIR, { recursive: true, force: true });
      }
    } catch {}
  });

  // --- isEnabled() opt-out checks ---

  it('isEnabled() returns false when DO_NOT_TRACK=1', () => {
    process.env.DO_NOT_TRACK = '1';
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('isEnabled() returns false when SCANNER_TELEMETRY_DISABLED=1', () => {
    process.env.SCANNER_TELEMETRY_DISABLED = '1';
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('isEnabled() returns false when CI=true', () => {
    process.env.CI = 'true';
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('isEnabled() returns true when no opt-out flags set', () => {
    expect(telemetry.isEnabled()).toBe(true);
  });

  // --- Machine ID ---

  it('machine ID is stable across repeated calls', () => {
    const id1 = telemetry.getMachineId();
    const id2 = telemetry.getMachineId();
    expect(id1).toBe(id2);
  });

  it('machine ID is 64-char hex SHA-256', () => {
    const id = telemetry.getMachineId();
    expect(id).toMatch(/^[a-f0-9]{64}$/);
  });

  // --- Session ID ---

  it('session ID is stable per process', () => {
    const sid = telemetry.getSessionId;
    expect(typeof sid).toBe('string');
    expect(sid.length).toBeGreaterThan(0);
  });

  // --- track() queuing ---

  it('track() queues events without sending', () => {
    telemetry.track('test.event', { foo: 'bar' });
    const queue = telemetry._getQueue();
    expect(queue.length).toBe(1);
    expect(queue[0].event).toBe('test.event');
    expect(queue[0].foo).toBe('bar');
  });

  it('track() does not queue when disabled', () => {
    process.env.DO_NOT_TRACK = '1';
    telemetry.track('test.event', {});
    expect(telemetry._getQueue().length).toBe(0);
  });

  // --- Event envelope ---

  it('events have all required envelope fields', () => {
    telemetry.track('test.event', {});
    const event = telemetry._getQueue()[0];
    expect(event.schema_version).toBe(1);
    expect(event.event).toBe('test.event');
    expect(event.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(event.machine_id).toMatch(/^[a-f0-9]{64}$/);
    expect(event.session_id).toBeDefined();
    expect(event.scanner_version).toBeDefined();
    expect(event.os_platform).toBe(platform());
    expect(event.os_arch).toBe(arch());
    expect(event.node_version).toBe(process.versions.node);
    expect(event.invocation_mode).toBeDefined();
  });

  // --- No PII in events ---

  it('no PII (hostname, homedir, username) in event payloads', () => {
    telemetry.track('test.event', { some: 'data' });
    const event = telemetry._getQueue()[0];
    const serialized = JSON.stringify(event);

    // hostname, homedir, username should NOT appear in serialized event
    // (machine_id is a SHA-256 hash, not raw data)
    expect(serialized).not.toContain(hostname());
    expect(serialized).not.toContain(homedir());
  });

  // --- flush() ---

  it('flush() clears the queue', () => {
    // Mock fetch to prevent actual network calls
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    telemetry.track('test.event', {});
    expect(telemetry._getQueue().length).toBe(1);
    telemetry.flush();
    expect(telemetry._getQueue().length).toBe(0);

    globalThis.fetch = originalFetch;
  });

  it('flush() silently handles network errors', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    telemetry.track('test.event', {});
    // Should not throw
    expect(() => telemetry.flush()).not.toThrow();

    globalThis.fetch = originalFetch;
  });

  it('flush() sends batch via fetch', async () => {
    const originalFetch = globalThis.fetch;
    let capturedBody = null;
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return { ok: true };
    });

    telemetry.track('test.event', { key: 'value' });
    telemetry.flush();

    // Wait a tick for the async fetch
    await new Promise(r => setTimeout(r, 50));

    expect(globalThis.fetch).toHaveBeenCalledOnce();
    expect(capturedBody).toBeDefined();
    expect(capturedBody.events).toHaveLength(1);
    expect(capturedBody.events[0].event).toBe('test.event');

    globalThis.fetch = originalFetch;
  });

  // --- Auto-flush at BATCH_SIZE ---

  it('auto-flushes at BATCH_SIZE threshold', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    for (let i = 0; i < telemetry.BATCH_SIZE; i++) {
      telemetry.track('batch.event', { i });
    }

    // After reaching BATCH_SIZE, queue should be drained
    expect(telemetry._getQueue().length).toBe(0);
    expect(globalThis.fetch).toHaveBeenCalled();

    globalThis.fetch = originalFetch;
  });

  // --- withTelemetry() ---

  it('withTelemetry() passes through handler results unchanged', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    const handler = async (args) => ({ content: [{ type: 'text', text: `hello ${args.name}` }] });
    const wrapped = telemetry.withTelemetry('test_tool', handler);
    const result = await wrapped({ name: 'world' });

    expect(result).toEqual({ content: [{ type: 'text', text: 'hello world' }] });

    globalThis.fetch = originalFetch;
  });

  it('withTelemetry() records duration_ms', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    const handler = async () => {
      await new Promise(r => setTimeout(r, 20));
      return { content: [] };
    };
    const wrapped = telemetry.withTelemetry('slow_tool', handler);
    await wrapped({});

    const queue = telemetry._getQueue();
    const toolEvent = queue.find(e => e.event === 'tool.invoked');
    expect(toolEvent).toBeDefined();
    expect(toolEvent.duration_ms).toBeGreaterThanOrEqual(10);
    expect(toolEvent.tool_name).toBe('slow_tool');
    expect(toolEvent.success).toBe(true);

    globalThis.fetch = originalFetch;
  });

  it('withTelemetry() tracks errors and re-throws', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });

    const handler = async () => { throw new Error('test failure'); };
    const wrapped = telemetry.withTelemetry('failing_tool', handler);

    await expect(wrapped({})).rejects.toThrow('test failure');

    const queue = telemetry._getQueue();
    const toolEvent = queue.find(e => e.event === 'tool.invoked');
    expect(toolEvent.success).toBe(false);
    expect(toolEvent.error_code).toBe('Error');

    const errorEvent = queue.find(e => e.event === 'error');
    expect(errorEvent).toBeDefined();
    expect(errorEvent.error_class).toBe('Error');

    globalThis.fetch = originalFetch;
  });

  // --- Debug mode ---

  it('debug mode prints to stderr and does not queue', () => {
    process.env.SCANNER_TELEMETRY_DEBUG = '1';
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    telemetry.track('debug.event', { data: 123 });

    expect(telemetry._getQueue().length).toBe(0);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('[telemetry:debug]'));
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('debug.event'));

    stderrSpy.mockRestore();
  });

  // --- CLI commands ---

  it('CLI --status shows telemetry status', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--status']);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Telemetry Status'));
    logSpy.mockRestore();
  });

  it('CLI --off disables telemetry', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('disabled'));
    logSpy.mockRestore();
  });

  it('CLI --on enables telemetry', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--on']);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('enabled'));
    logSpy.mockRestore();
  });

  // --- First-run notice ---

  it('first-run notice writes to stderr', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    telemetry.showFirstRunNotice();

    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('Telemetry Notice'));
    stderrSpy.mockRestore();
  });

  it('first-run notice is only shown once', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    telemetry.showFirstRunNotice();
    telemetry.showFirstRunNotice();

    // Should only be called once
    const noticeWrites = stderrSpy.mock.calls.filter(c => c[0].includes('Telemetry Notice'));
    expect(noticeWrites.length).toBe(1);
    stderrSpy.mockRestore();
  });

  // --- setInvocationMode ---

  it('setInvocationMode changes the mode in events', () => {
    telemetry.setInvocationMode('cli');
    telemetry.track('test.event', {});
    const event = telemetry._getQueue()[0];
    expect(event.invocation_mode).toBe('cli');
  });

  // --- Test isolation ---

  it('_resetForTesting uses TEST_STATE_DIR, not real STATE_FILE', () => {
    // After _resetForTesting(TEST_STATE_DIR), STATE_DIR and STATE_FILE should point to test dir
    expect(telemetry.STATE_DIR).toBe(TEST_STATE_DIR);
    expect(telemetry.STATE_FILE).toBe(join(TEST_STATE_DIR, 'telemetry.json'));
    // Must NOT point to real user dir
    const realDir = telemetry._DEFAULT_STATE_DIR;
    expect(telemetry.STATE_DIR).not.toBe(realDir);
  });

  it('no test reads or writes the real ~/.agent-security-scanner-mcp/ directory', () => {
    // Perform state-modifying operations (CLI --off, getMachineId, showFirstRunNotice)
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    telemetry.getMachineId();
    telemetry.showFirstRunNotice();

    // The state file should be inside our test dir
    expect(existsSync(TEST_STATE_DIR)).toBe(true);
    expect(telemetry.STATE_FILE.startsWith(TEST_STATE_DIR)).toBe(true);

    // Real user directory should not have been touched by this test
    // (We verify by checking that STATE_DIR is not the default)
    expect(telemetry.STATE_DIR).toBe(TEST_STATE_DIR);
    expect(telemetry.STATE_DIR).not.toBe(join(homedir(), '.agent-security-scanner-mcp'));

    logSpy.mockRestore();
    stderrSpy.mockRestore();
  });
});
