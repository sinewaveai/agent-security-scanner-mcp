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
});
