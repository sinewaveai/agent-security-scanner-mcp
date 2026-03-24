import { describe, it, expect } from 'vitest';
import { resolveOptions } from '../src/types/config.js';
import type { AnalysisOptions } from '../src/types/config.js';

describe('mode configuration', () => {
  it('defaults mode to review', () => {
    const options = resolveOptions({}, null, {});
    expect(options.mode).toBe('review');
  });

  it('accepts mode from CLI flags', () => {
    const options = resolveOptions({ mode: 'security' }, null, {});
    expect(options.mode).toBe('security');
  });

  it('accepts mode from config file', () => {
    const options = resolveOptions({}, { mode: 'security' }, {});
    expect(options.mode).toBe('security');
  });

  it('accepts mode from environment variable', () => {
    const options = resolveOptions({}, null, { CR_AGENT_MODE: 'security' });
    expect(options.mode).toBe('security');
  });

  it('CLI flags take priority over config', () => {
    const options = resolveOptions(
      { mode: 'review' },
      { mode: 'security' },
      {},
    );
    expect(options.mode).toBe('review');
  });

  it('config takes priority over env var', () => {
    const options = resolveOptions(
      {},
      { mode: 'security' },
      { CR_AGENT_MODE: 'review' },
    );
    expect(options.mode).toBe('security');
  });

  it('env var wins when CLI mode is omitted (no Commander default)', () => {
    // This tests the fix: CLI flags.mode is undefined when --mode not passed
    const options = resolveOptions(
      { mode: undefined },
      null,
      { CR_AGENT_MODE: 'security' },
    );
    expect(options.mode).toBe('security');
  });

  it('config wins when CLI mode is omitted', () => {
    const options = resolveOptions(
      { mode: undefined },
      { mode: 'security' },
      {},
    );
    expect(options.mode).toBe('security');
  });

  it('explicit CLI --mode review overrides env and config', () => {
    const options = resolveOptions(
      { mode: 'review' },
      { mode: 'security' },
      { CR_AGENT_MODE: 'security' },
    );
    expect(options.mode).toBe('review');
  });
});
