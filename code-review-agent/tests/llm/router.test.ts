import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ModelRouter } from '../../src/llm/router.js';
import type { AnalysisOptions } from '../../src/types/config.js';

function makeOptions(overrides: Partial<AnalysisOptions> = {}): AnalysisOptions {
  return {
    provider: 'anthropic',
    confidenceThreshold: 0.7,
    format: 'text',
    verbose: false,
    projectRoot: process.cwd(),
    exclude: [],
    concurrencyLimit: 5,
    maxFileSize: 512 * 1024,
    ...overrides,
  };
}

describe('ModelRouter', () => {
  beforeEach(() => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'test-key');
    vi.stubEnv('OPENAI_API_KEY', 'test-key');
  });

  it('creates anthropic triage provider with haiku model', () => {
    const router = new ModelRouter(makeOptions({ provider: 'anthropic' }));
    const provider = router.getTriageProvider();
    expect(provider.providerName).toBe('anthropic');
    expect(provider.modelId).toBe('claude-haiku-4-5-20251001');
  });

  it('creates anthropic analysis provider with sonnet model', () => {
    const router = new ModelRouter(makeOptions({ provider: 'anthropic' }));
    const provider = router.getAnalysisProvider();
    expect(provider.providerName).toBe('anthropic');
    expect(provider.modelId).toBe('claude-sonnet-4-20250514');
  });

  it('creates openai triage provider with gpt-4o-mini', () => {
    const router = new ModelRouter(makeOptions({ provider: 'openai' }));
    const provider = router.getTriageProvider();
    expect(provider.providerName).toBe('openai');
    expect(provider.modelId).toBe('gpt-4o-mini');
  });

  it('creates openai analysis provider with gpt-4o', () => {
    const router = new ModelRouter(makeOptions({ provider: 'openai' }));
    const provider = router.getAnalysisProvider();
    expect(provider.providerName).toBe('openai');
    expect(provider.modelId).toBe('gpt-4o');
  });

  it('uses custom model override', () => {
    const router = new ModelRouter(makeOptions({ provider: 'anthropic', model: 'claude-opus-4-20250514' }));
    const provider = router.getAnalysisProvider();
    expect(provider.modelId).toBe('claude-opus-4-20250514');
  });

  it('caches providers', () => {
    const router = new ModelRouter(makeOptions());
    const a = router.getTriageProvider();
    const b = router.getTriageProvider();
    expect(a).toBe(b);
  });

  it('estimates cost', () => {
    const router = new ModelRouter(makeOptions());
    const cost = router.estimateCost(1_000_000);
    expect(cost).toBeGreaterThan(0);
  });

  it('throws on missing API key', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', '');
    const router = new ModelRouter(makeOptions({ provider: 'anthropic' }));
    expect(() => router.getAnalysisProvider()).toThrow('Missing API key');
  });
});
