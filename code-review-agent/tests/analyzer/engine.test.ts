import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as path from 'node:path';
import { AnalysisEngine } from '../../src/analyzer/engine.js';
import type { AnalysisOptions } from '../../src/types/config.js';

// We need to mock the ModelRouter to return our MockLLMProvider
// Since the engine creates its own router, we mock at the module level
const mockAnalysisResponse = {
  findings: [
    {
      title: 'SQL Injection via string concatenation',
      severity: 'critical' as const,
      category: 'security' as const,
      location: { file: 'server.js', startLine: 15, endLine: 15 },
      reasoning: 'User input directly concatenated into SQL query',
      intentAlignment: 'violates-intent' as const,
      confidence: 0.95,
      suggestedAction: 'Use parameterized queries',
      cwe: 'CWE-89',
    },
    {
      title: 'eval() on user input',
      severity: 'critical' as const,
      category: 'security' as const,
      location: { file: 'server.js', startLine: 23, endLine: 23 },
      reasoning: 'eval() with user-controlled input',
      intentAlignment: 'violates-intent' as const,
      confidence: 0.92,
      suggestedAction: 'Remove eval, use a safe parser',
      cwe: 'CWE-94',
    },
  ],
};

const mockIntentResponse = {
  purpose: 'REST API server for user management',
  expectedBehaviors: ['Handle HTTP requests', 'Query database'],
  unexpectedBehaviors: ['Execute eval on user input', 'Write arbitrary files'],
  framework: 'express',
  riskDomain: 'web-api' as const,
};

const mockTriageAnalyze = {
  action: 'analyze' as const,
  reason: 'Contains HTTP handlers with database queries',
  areasOfInterest: [{ startLine: 1, endLine: 50, reason: 'HTTP handler code' }],
};

// Mock the LLM modules to avoid needing real API keys
vi.mock('../../src/llm/anthropic.js', () => ({
  AnthropicProvider: class {
    modelId = 'mock-model';
    providerName = 'anthropic';
    async chat() { return 'mock'; }
    async chatStructured(_msgs: unknown, schema: { safeParse: (data: unknown) => { success: boolean; data: unknown } }, schemaName: string) {
      const responses: Record<string, unknown> = {
        intent_profile: mockIntentResponse,
        file_analysis: mockAnalysisResponse,
        triage_decision: mockTriageAnalyze,
      };
      const response = responses[schemaName];
      const result = schema.safeParse(response);
      if (!result.success) throw new Error('Schema validation failed');
      return result.data;
    }
    countTokens(text: string) { return Math.ceil(text.length / 4); }
  },
}));

vi.mock('../../src/llm/openai.js', () => ({
  OpenAIProvider: class {
    modelId = 'mock-model';
    providerName = 'openai';
    async chat() { return 'mock'; }
    async chatStructured() { return {}; }
    countTokens(text: string) { return Math.ceil(text.length / 4); }
  },
}));

const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

describe('AnalysisEngine', () => {
  beforeEach(() => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'test-key');
  });

  it('analyzes vuln-api-server and finds vulnerabilities', async () => {
    const options: AnalysisOptions = {
      provider: 'anthropic',
      confidenceThreshold: 0.7,
      format: 'text',
      verbose: false,
      projectRoot: path.join(FIXTURES_DIR, 'vuln-api-server'),
      exclude: ['node_modules', 'dist', '.git'],
      concurrencyLimit: 5,
      maxFileSize: 512 * 1024,
    };

    const engine = new AnalysisEngine(options);
    const result = await engine.analyze('.');

    expect(result.intentProfile).toBeTruthy();
    expect(result.intentProfile?.riskDomain).toBe('web-api');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.stats.filesAnalyzed).toBeGreaterThan(0);
    expect(result.stats.durationMs).toBeGreaterThan(0);
  });

  it('returns sorted findings (critical first)', async () => {
    const options: AnalysisOptions = {
      provider: 'anthropic',
      confidenceThreshold: 0.5,
      format: 'text',
      verbose: false,
      projectRoot: path.join(FIXTURES_DIR, 'vuln-api-server'),
      exclude: ['node_modules', 'dist', '.git'],
      concurrencyLimit: 5,
      maxFileSize: 512 * 1024,
    };

    const engine = new AnalysisEngine(options);
    const result = await engine.analyze('.');

    if (result.findings.length >= 2) {
      const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
      for (let i = 1; i < result.findings.length; i++) {
        const prevIdx = severityOrder.indexOf(result.findings[i - 1].severity);
        const currIdx = severityOrder.indexOf(result.findings[i].severity);
        expect(currIdx).toBeGreaterThanOrEqual(prevIdx);
      }
    }
  });

  it('filters findings below confidence threshold', async () => {
    const options: AnalysisOptions = {
      provider: 'anthropic',
      confidenceThreshold: 0.99,
      format: 'text',
      verbose: false,
      projectRoot: path.join(FIXTURES_DIR, 'vuln-api-server'),
      exclude: ['node_modules', 'dist', '.git'],
      concurrencyLimit: 5,
      maxFileSize: 512 * 1024,
    };

    const engine = new AnalysisEngine(options);
    const result = await engine.analyze('.');

    // All remaining findings should be above threshold
    for (const f of result.findings) {
      expect(f.confidence).toBeGreaterThanOrEqual(0.99);
    }
  });

  it('computes stats correctly', async () => {
    const options: AnalysisOptions = {
      provider: 'anthropic',
      confidenceThreshold: 0.7,
      format: 'text',
      verbose: false,
      projectRoot: path.join(FIXTURES_DIR, 'vuln-api-server'),
      exclude: ['node_modules', 'dist', '.git'],
      concurrencyLimit: 5,
      maxFileSize: 512 * 1024,
    };

    const engine = new AnalysisEngine(options);
    const result = await engine.analyze('.');

    expect(result.stats.filesAnalyzed + result.stats.filesSkipped).toBeGreaterThan(0);
    expect(result.stats.totalFindings).toBe(result.findings.length);
    expect(typeof result.stats.estimatedCost).toBe('number');
  });

  it('clamps private worker count when concurrency is zero', async () => {
    const options: AnalysisOptions = {
      provider: 'anthropic',
      confidenceThreshold: 0.7,
      format: 'text',
      verbose: false,
      projectRoot: path.join(FIXTURES_DIR, 'vuln-api-server'),
      exclude: ['node_modules', 'dist', '.git'],
      concurrencyLimit: 0,
      maxFileSize: 512 * 1024,
    };

    const engine = new AnalysisEngine(options);
    const results = await (engine as unknown as {
      runParallel<T, R>(items: T[], fn: (item: T) => Promise<R>, limit: number): Promise<R[]>;
    }).runParallel([1, 2, 3], async (value) => value * 2, 0);

    expect(results).toEqual([2, 4, 6]);
  });
});
