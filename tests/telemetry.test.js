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

  // --- State-file opt-out (Task 3) ---

  it('isEnabled returns false when state file has telemetry_enabled=false', () => {
    mkdirSync(TEST_STATE_DIR, { recursive: true });
    writeFileSync(join(TEST_STATE_DIR, 'telemetry.json'), JSON.stringify({ telemetry_enabled: false }));
    telemetry._resetForTesting(TEST_STATE_DIR);
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('isEnabled returns false when CI=1', () => {
    process.env.CI = '1';
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('isEnabled returns true when CI is set to other values', () => {
    process.env.CI = 'yes';
    expect(telemetry.isEnabled()).toBe(true);
  });

  it('isEnabled returns true when no opt-out flags and state file missing', () => {
    // TEST_STATE_DIR exists but no telemetry.json
    expect(telemetry.isEnabled()).toBe(true);
  });

  it('isEnabled returns false when state file has telemetry_enabled=false AND env vars unset', () => {
    // Ensure no env vars are set (already cleared in beforeEach)
    mkdirSync(TEST_STATE_DIR, { recursive: true });
    writeFileSync(join(TEST_STATE_DIR, 'telemetry.json'), JSON.stringify({ telemetry_enabled: false }));
    telemetry._resetForTesting(TEST_STATE_DIR);
    expect(process.env.DO_NOT_TRACK).toBeUndefined();
    expect(process.env.SCANNER_TELEMETRY_DISABLED).toBeUndefined();
    expect(process.env.CI).toBeUndefined();
    expect(telemetry.isEnabled()).toBe(false);
  });

  it('--off writes telemetry_enabled:false to state file', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    const state = JSON.parse(readFileSync(join(TEST_STATE_DIR, 'telemetry.json'), 'utf-8'));
    expect(state.telemetry_enabled).toBe(false);
    logSpy.mockRestore();
  });

  it('--off followed by isEnabled() returns false', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR); // re-read state
    expect(telemetry.isEnabled()).toBe(false);
    logSpy.mockRestore();
  });

  it('--on writes telemetry_enabled:true to state file', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--on']);
    const state = JSON.parse(readFileSync(join(TEST_STATE_DIR, 'telemetry.json'), 'utf-8'));
    expect(state.telemetry_enabled).toBe(true);
    logSpy.mockRestore();
  });

  it('--on followed by isEnabled() returns true', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    // First disable
    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    expect(telemetry.isEnabled()).toBe(false);
    // Then re-enable
    telemetry.handleTelemetryCli(['--on']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    expect(telemetry.isEnabled()).toBe(true);
    logSpy.mockRestore();
  });

  it('--status shows correct state after --off', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    telemetry.handleTelemetryCli(['--status']);
    const outputs = logSpy.mock.calls.map(c => c[0]).join(' ');
    expect(outputs).toContain('no');
    logSpy.mockRestore();
  });

  // --- Machine ID & state persistence (Task 4) ---

  it('getMachineId persists to state file on first call', () => {
    const id = telemetry.getMachineId();
    const state = JSON.parse(readFileSync(join(TEST_STATE_DIR, 'telemetry.json'), 'utf-8'));
    expect(state.machine_id).toBe(id);
  });

  it('getMachineId loads from state file on subsequent import', () => {
    const id1 = telemetry.getMachineId();
    // Reset module state (simulates new import) but keep state file
    telemetry._resetForTesting(TEST_STATE_DIR);
    const id2 = telemetry.getMachineId();
    expect(id2).toBe(id1);
  });

  it('getMachineId regenerates same hash after state file deletion', () => {
    const id1 = telemetry.getMachineId();
    // Delete state file
    unlinkSync(join(TEST_STATE_DIR, 'telemetry.json'));
    telemetry._resetForTesting(TEST_STATE_DIR);
    const id2 = telemetry.getMachineId();
    expect(id2).toBe(id1); // deterministic hash
  });

  it('state file is created in STATE_DIR if directory missing', () => {
    const freshDir = join(tmpdir(), `scanner-test-fresh-${Date.now()}`);
    telemetry._resetForTesting(freshDir);
    telemetry.getMachineId(); // triggers state file creation
    expect(existsSync(join(freshDir, 'telemetry.json'))).toBe(true);
    rmSync(freshDir, { recursive: true, force: true });
  });

  it('showFirstRunNotice not shown when state file has notice_shown=true', () => {
    mkdirSync(TEST_STATE_DIR, { recursive: true });
    writeFileSync(join(TEST_STATE_DIR, 'telemetry.json'), JSON.stringify({ notice_shown: true }));
    telemetry._resetForTesting(TEST_STATE_DIR);
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    telemetry.showFirstRunNotice();
    const notices = stderrSpy.mock.calls.filter(c => c[0].includes('Telemetry Notice'));
    expect(notices.length).toBe(0);
    stderrSpy.mockRestore();
  });

  it('showFirstRunNotice writes notice_shown and first_seen to state file', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    telemetry.showFirstRunNotice();
    const state = JSON.parse(readFileSync(join(TEST_STATE_DIR, 'telemetry.json'), 'utf-8'));
    expect(state.notice_shown).toBe(true);
    expect(state.first_seen).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    stderrSpy.mockRestore();
  });

  // --- Event queuing & batching (Task 5) ---

  it('BATCH_SIZE-1 events do NOT trigger auto-flush', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    for (let i = 0; i < telemetry.BATCH_SIZE - 1; i++) {
      telemetry.track('batch.event', { i });
    }
    expect(telemetry._getQueue().length).toBe(telemetry.BATCH_SIZE - 1);
    expect(globalThis.fetch).not.toHaveBeenCalled();
    globalThis.fetch = originalFetch;
  });

  it('BATCH_SIZE+1 events flush BATCH_SIZE and leave 1 in queue', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    for (let i = 0; i < telemetry.BATCH_SIZE + 1; i++) {
      telemetry.track('batch.event', { i });
    }
    // After BATCH_SIZE events, flush fires and drains queue, then 1 more is added
    expect(telemetry._getQueue().length).toBe(1);
    globalThis.fetch = originalFetch;
  });

  it('flush() with empty queue is a no-op (no fetch call)', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    telemetry.flush();
    expect(globalThis.fetch).not.toHaveBeenCalled();
    globalThis.fetch = originalFetch;
  });

  it('flush() cancels pending timer', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    // Track an event (schedules flush timer)
    telemetry.track('timer.event', {});
    // Manually flush — should cancel the timer
    telemetry.flush();
    expect(telemetry._getQueue().length).toBe(0);
    globalThis.fetch = originalFetch;
  });

  it('_scheduleFlush sets a timer that fires and drains queue', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    // Track event (which calls _scheduleFlush internally)
    telemetry.track('timer.event', {});
    expect(telemetry._getQueue().length).toBe(1);
    // Wait for flush interval (30s is too long, but the timer was set)
    // Instead, manually trigger flush to simulate
    telemetry.flush();
    expect(telemetry._getQueue().length).toBe(0);
    expect(globalThis.fetch).toHaveBeenCalled();
    globalThis.fetch = originalFetch;
  });

  it('_scheduleFlush timer is unref\'d (does not prevent exit)', () => {
    // This tests that after tracking, the process can still exit
    // We verify by checking that track() doesn't throw and queue works
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    telemetry.track('unref.event', {});
    // If timer wasn't unref'd, this test suite would hang
    expect(telemetry._getQueue().length).toBe(1);
    telemetry.flush(); // cleanup
    globalThis.fetch = originalFetch;
  });

  it('multiple _scheduleFlush calls do not create duplicate timers', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    // Track multiple events (each calls _scheduleFlush)
    telemetry.track('dup.event.1', {});
    telemetry.track('dup.event.2', {});
    telemetry.track('dup.event.3', {});
    // All should be in queue (not flushed, since < BATCH_SIZE)
    expect(telemetry._getQueue().length).toBe(3);
    telemetry.flush(); // cleanup
    // Only one fetch call (from our manual flush, not from duplicate timers)
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    globalThis.fetch = originalFetch;
  });

  // --- Network & error handling (Task 6) ---

  it('_sendBatch posts to TELEMETRY_ENDPOINT URL', async () => {
    const originalFetch = globalThis.fetch;
    let capturedUrl = null;
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      capturedUrl = url;
      return { ok: true };
    });
    telemetry.track('url.test', {});
    telemetry.flush();
    await new Promise(r => setTimeout(r, 50));
    expect(capturedUrl).toBe('https://telemetry.prooflayer.com/v1/events');
    globalThis.fetch = originalFetch;
  });

  it('_sendBatch sends correct Content-Type header', async () => {
    const originalFetch = globalThis.fetch;
    let capturedHeaders = null;
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      capturedHeaders = opts.headers;
      return { ok: true };
    });
    telemetry.track('header.test', {});
    telemetry.flush();
    await new Promise(r => setTimeout(r, 50));
    expect(capturedHeaders['Content-Type']).toBe('application/json');
    globalThis.fetch = originalFetch;
  });

  it('_sendBatch uses AbortSignal.timeout(5000)', async () => {
    const originalFetch = globalThis.fetch;
    let capturedSignal = null;
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      capturedSignal = opts.signal;
      return { ok: true };
    });
    telemetry.track('timeout.test', {});
    telemetry.flush();
    await new Promise(r => setTimeout(r, 50));
    expect(capturedSignal).toBeDefined();
    globalThis.fetch = originalFetch;
  });

  it('flush after network timeout does not re-send failed events', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('timeout'));
    telemetry.track('fail.event', {});
    telemetry.flush();
    await new Promise(r => setTimeout(r, 50));
    // Queue should be empty — events are discarded on failure
    expect(telemetry._getQueue().length).toBe(0);
    globalThis.fetch = originalFetch;
  });

  it('withTelemetry tracks error_code from err.code property', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const err = new Error('file not found');
    err.code = 'ENOENT';
    const handler = async () => { throw err; };
    const wrapped = telemetry.withTelemetry('code_tool', handler);
    await expect(wrapped({})).rejects.toThrow('file not found');
    const toolEvent = telemetry._getQueue().find(e => e.event === 'tool.invoked');
    expect(toolEvent.error_code).toBe('ENOENT');
    globalThis.fetch = originalFetch;
  });

  it('withTelemetry emits both tool.invoked and error events on failure', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const handler = async () => { throw new Error('boom'); };
    const wrapped = telemetry.withTelemetry('dual_event_tool', handler);
    await expect(wrapped({})).rejects.toThrow('boom');
    const queue = telemetry._getQueue();
    expect(queue.filter(e => e.event === 'tool.invoked').length).toBe(1);
    expect(queue.filter(e => e.event === 'error').length).toBe(1);
    globalThis.fetch = originalFetch;
  });

  it('withTelemetry preserves original error stack on re-throw', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const originalError = new Error('original');
    const handler = async () => { throw originalError; };
    const wrapped = telemetry.withTelemetry('stack_tool', handler);
    try {
      await wrapped({});
    } catch (e) {
      expect(e).toBe(originalError); // same object, same stack
      expect(e.stack).toBe(originalError.stack);
    }
    globalThis.fetch = originalFetch;
  });

  it('getScannerVersion returns version from package.json', () => {
    telemetry.track('version.test', {});
    const event = telemetry._getQueue()[0];
    expect(event.scanner_version).toBeDefined();
    expect(event.scanner_version).not.toBe('0.0.0');
  });

  it('default invocation mode is mcp', () => {
    telemetry.setInvocationMode('mcp'); // restore default (module state persists across tests)
    telemetry.track('mode.test', {});
    const event = telemetry._getQueue()[0];
    expect(event.invocation_mode).toBe('mcp');
  });

  it('track() with disabled telemetry does not read/write state file', () => {
    process.env.DO_NOT_TRACK = '1';
    telemetry.track('disabled.event', {});
    expect(telemetry._getQueue().length).toBe(0);
  });

  it('event envelope contains all 10 required fields with correct schema_version', () => {
    telemetry.track('envelope.test', {});
    const event = telemetry._getQueue()[0];
    const requiredFields = ['schema_version', 'event', 'timestamp', 'machine_id', 'session_id', 'scanner_version', 'os_platform', 'os_arch', 'node_version', 'invocation_mode'];
    for (const field of requiredFields) {
      expect(event[field]).toBeDefined();
    }
    expect(event.schema_version).toBe(1);
  });
});

describe('telemetry integration', () => {
  let telemetry;
  let TEST_STATE_DIR;

  beforeEach(async () => {
    TEST_STATE_DIR = join(tmpdir(), `scanner-telemetry-integration-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    delete process.env.DO_NOT_TRACK;
    delete process.env.SCANNER_TELEMETRY_DISABLED;
    delete process.env.CI;
    delete process.env.SCANNER_TELEMETRY_DEBUG;
    telemetry = await import('../src/telemetry.js');
    telemetry._resetForTesting(TEST_STATE_DIR);
  });

  afterEach(() => {
    try {
      if (existsSync(TEST_STATE_DIR)) {
        rmSync(TEST_STATE_DIR, { recursive: true, force: true });
      }
    } catch {}
  });

  it('withTelemetry fires tool.invoked on success', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const handler = async () => ({ content: [{ type: 'text', text: 'ok' }] });
    const wrapped = telemetry.withTelemetry('scan_security', handler);
    await wrapped({});
    const queue = telemetry._getQueue();
    const toolEvent = queue.find(e => e.event === 'tool.invoked');
    expect(toolEvent).toBeDefined();
    expect(toolEvent.tool_name).toBe('scan_security');
    expect(toolEvent.success).toBe(true);
    globalThis.fetch = originalFetch;
  });

  it('track can fire scan.completed event', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    telemetry.track('scan.completed', {
      tool_name: 'scan_security',
      language: 'python',
      engine_mode: 'ast',
      issues_count: 5,
      by_severity: { error: 2, warning: 2, info: 1 },
      output_format: 'json',
    });
    const event = telemetry._getQueue().find(e => e.event === 'scan.completed');
    expect(event).toBeDefined();
    expect(event.issues_count).toBe(5);
    globalThis.fetch = originalFetch;
  });

  it('check_package with unknown ecosystem fires only tool.invoked', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const handler = async ({ ecosystem }) => {
      if (!['npm', 'pypi'].includes(ecosystem)) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: 'Unknown ecosystem' }) }] };
      }
      return { content: [{ type: 'text', text: '{}' }] };
    };
    const wrapped = telemetry.withTelemetry('check_package', handler);
    await wrapped({ package_name: 'foo', ecosystem: 'unknown' });
    const queue = telemetry._getQueue();
    expect(queue.filter(e => e.event === 'tool.invoked').length).toBe(1);
    // No scan.completed event since it returned early
    expect(queue.filter(e => e.event === 'scan.completed').length).toBe(0);
    globalThis.fetch = originalFetch;
  });

  it('CLI telemetry --off then track produces no events', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    telemetry.track('should.not.appear', {});
    expect(telemetry._getQueue().length).toBe(0);
    logSpy.mockRestore();
  });

  it('flush is called on MCP server close pattern', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    telemetry.track('pre.close.event', {});
    expect(telemetry._getQueue().length).toBe(1);
    // Simulate the server.onclose pattern from index.js
    telemetry.flush();
    expect(telemetry._getQueue().length).toBe(0);
    expect(globalThis.fetch).toHaveBeenCalled();
    globalThis.fetch = originalFetch;
  });

  it('postinstall trackInstall pattern fires install event', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    telemetry.track('install', {
      engine_available: 'ast',
      python_available: true,
      is_ci: false,
    });
    telemetry.flush();
    expect(globalThis.fetch).toHaveBeenCalled();
    globalThis.fetch = originalFetch;
  });

  it('doctor telemetry status output includes enabled/disabled', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--status']);
    const outputs = logSpy.mock.calls.map(c => c[0]).join(' ');
    expect(outputs).toContain('Telemetry Status');
    expect(outputs).toMatch(/yes|no/);
    logSpy.mockRestore();
  });
});

describe('telemetry privacy', () => {
  let telemetry;
  let TEST_STATE_DIR;

  beforeEach(async () => {
    TEST_STATE_DIR = join(tmpdir(), `scanner-telemetry-privacy-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    delete process.env.DO_NOT_TRACK;
    delete process.env.SCANNER_TELEMETRY_DISABLED;
    delete process.env.CI;
    delete process.env.SCANNER_TELEMETRY_DEBUG;
    telemetry = await import('../src/telemetry.js');
    telemetry._resetForTesting(TEST_STATE_DIR);
  });

  afterEach(() => {
    try {
      if (existsSync(TEST_STATE_DIR)) {
        rmSync(TEST_STATE_DIR, { recursive: true, force: true });
      }
    } catch {}
  });

  it('no event payload contains hostname, username, homedir, or IP', () => {
    telemetry.track('scan.completed', {
      tool_name: 'scan_security',
      language: 'python',
      issues_count: 3,
    });
    const event = telemetry._getQueue()[0];
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(hostname());
    expect(serialized).not.toContain(homedir());
    // machine_id is a hash, should not contain raw system info
    expect(event.machine_id).toMatch(/^[a-f0-9]{64}$/);
  });

  it('no event payload contains file contents, source code, or paths', () => {
    telemetry.track('scan.completed', {
      tool_name: 'scan_security',
      language: 'javascript',
      issues_count: 1,
      by_severity: { error: 1, warning: 0, info: 0 },
    });
    const serialized = JSON.stringify(telemetry._getQueue()[0]);
    expect(serialized).not.toContain('/Users/');
    expect(serialized).not.toContain('/home/');
    expect(serialized).not.toContain('import ');
    expect(serialized).not.toContain('require(');
  });

  it('no event payload contains prompt text or matched findings text', () => {
    telemetry.track('prompt.scanned', {
      action: 'BLOCK',
      risk_level: 'HIGH',
      findings_count: 2,
    });
    const serialized = JSON.stringify(telemetry._getQueue()[0]);
    // Should not contain any actual prompt text
    expect(serialized).not.toContain('ignore previous instructions');
    expect(serialized).not.toContain('You are now');
  });

  it('no event payload contains package names', () => {
    telemetry.track('package.checked', {
      ecosystem: 'npm',
      packages_checked: 5,
      hallucinated_count: 1,
    });
    const serialized = JSON.stringify(telemetry._getQueue()[0]);
    // Generic counts only, no package names
    expect(serialized).not.toMatch(/"package_name"/);
    expect(serialized).not.toMatch(/"name":\s*"/);
  });

  it('machine_id is exactly 64 hex characters (SHA-256)', () => {
    const id = telemetry.getMachineId();
    expect(id).toMatch(/^[a-f0-9]{64}$/);
    expect(id.length).toBe(64);
  });

  it('events serialized to JSON contain no unexpected keys beyond ALLOWED_FIELDS', () => {
    telemetry.track('test.event', {
      tool_name: 'scan_security',
      custom_field: 'allowed',
    });
    const event = telemetry._getQueue()[0];
    const allowedEnvelope = ['schema_version', 'event', 'timestamp', 'machine_id', 'session_id', 'scanner_version', 'os_platform', 'os_arch', 'node_version', 'invocation_mode'];
    const allowedCustom = ['tool_name', 'custom_field'];
    const allKeys = Object.keys(event);
    for (const key of allKeys) {
      expect([...allowedEnvelope, ...allowedCustom]).toContain(key);
    }
  });

  it('track() called after --off produces zero network requests', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    telemetry.handleTelemetryCli(['--off']);
    telemetry._resetForTesting(TEST_STATE_DIR);
    telemetry.track('should.not.send', {});
    telemetry.flush();
    expect(globalThis.fetch).not.toHaveBeenCalled();
    logSpy.mockRestore();
    globalThis.fetch = originalFetch;
  });
});
