// tests/llm-audit.test.js — Tests for deep_audit tool
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { deepAudit } from '../src/llm-audit.js';

const TMP = join(import.meta.dirname, '..', '.tmp-test-llm');

beforeAll(() => { mkdirSync(TMP, { recursive: true }); });
afterAll(() => { try { rmSync(TMP, { recursive: true }); } catch {} });

function writeTemp(name, content) {
  const p = join(TMP, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

describe('deepAudit', () => {
  it('should require consent (PROOFLAYER_LLM_CONSENT)', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    delete process.env.PROOFLAYER_LLM_CONSENT;

    const file = writeTemp('consent.js', 'const x = 1;');
    const result = await deepAudit({ file_path: file });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('consent');
    expect(parsed.action_required).toBeDefined();

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
  });

  it('should return error for non-existent file', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    process.env.PROOFLAYER_LLM_CONSENT = '1';

    const result = await deepAudit({ file_path: '/nonexistent/file.js' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('File not found');

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
  });

  it('should return error when no API key is available (non-ollama)', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    const origKey = process.env.ANTHROPIC_API_KEY;
    process.env.PROOFLAYER_LLM_CONSENT = '1';
    delete process.env.ANTHROPIC_API_KEY;

    const file = writeTemp('nokey.js', 'const x = 1;');
    const result = await deepAudit({ file_path: file, provider: 'anthropic' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('API key');

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
    if (origKey) process.env.ANTHROPIC_API_KEY = origKey;
  });

  it('should return error for unknown provider', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    process.env.PROOFLAYER_LLM_CONSENT = '1';

    const file = writeTemp('badprovider.js', 'const x = 1;');
    const result = await deepAudit({ file_path: file, provider: 'nonexistent' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('Unknown provider');

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
  });

  it('should handle ollama connection failure gracefully', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    process.env.PROOFLAYER_LLM_CONSENT = '1';

    const file = writeTemp('ollama-fail.js', 'const x = eval(input);');
    const result = await deepAudit({ file_path: file, provider: 'ollama' });
    const parsed = JSON.parse(result.content[0].text);
    // Should fail gracefully since ollama is likely not running in CI
    expect(parsed.error || parsed.findings).toBeDefined();

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
  });
});

describe('deepAudit schema', () => {
  it('should export schema with required fields', async () => {
    const { deepAuditSchema } = await import('../src/llm-audit.js');
    expect(deepAuditSchema.file_path).toBeDefined();
    expect(deepAuditSchema.provider).toBeDefined();
    expect(deepAuditSchema.model).toBeDefined();
  });
});

describe('bloom-loader', () => {
  it('should export loadBloomFilter function', async () => {
    const { loadBloomFilter } = await import('../src/bloom-loader.js');
    expect(typeof loadBloomFilter).toBe('function');
  });

  it('should return null for unavailable ecosystems', async () => {
    const { loadBloomFilter } = await import('../src/bloom-loader.js');
    const result = loadBloomFilter('npm');
    // Without downloaded data, should return null
    expect(result).toBeNull();
  });

  it('should export clearBloomCache function', async () => {
    const { clearBloomCache } = await import('../src/bloom-loader.js');
    expect(typeof clearBloomCache).toBe('function');
    clearBloomCache(); // Should not throw
  });
});

describe('utils', () => {
  it('should detect JavaScript language', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('file.js')).toBe('javascript');
    expect(detectLanguage('file.jsx')).toBe('javascript');
  });

  it('should detect TypeScript language', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('file.ts')).toBe('typescript');
    expect(detectLanguage('file.tsx')).toBe('typescript');
  });

  it('should detect Python language', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('file.py')).toBe('python');
  });

  it('should detect Dockerfile', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('Dockerfile')).toBe('dockerfile');
    expect(detectLanguage('Dockerfile.prod')).toBe('dockerfile');
  });

  it('should detect Go, Ruby, PHP, Java, C, Rust', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('main.go')).toBe('go');
    expect(detectLanguage('app.rb')).toBe('ruby');
    expect(detectLanguage('index.php')).toBe('php');
    expect(detectLanguage('Main.java')).toBe('java');
    expect(detectLanguage('main.c')).toBe('c');
    expect(detectLanguage('lib.rs')).toBe('rust');
  });

  it('should return generic for unknown extensions', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('file.xyz')).toBe('generic');
  });

  it('should generate valid SARIF structure', async () => {
    const { toSarif } = await import('../src/utils.js');
    const findings = [{ ruleId: 'test.rule', message: 'Test issue', severity: 'error', line: 5, column: 0 }];
    const sarif = toSarif(findings, 'test.js', 'javascript');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('ProofLayer Security Scanner');
    expect(sarif.runs[0].results[0].ruleId).toBe('test.rule');
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(6);
  });

  it('should identify test files', async () => {
    const { isTestFile } = await import('../src/utils.js');
    expect(isTestFile('src/__tests__/foo.js')).toBe(true);
    expect(isTestFile('foo.test.js')).toBe(true);
    expect(isTestFile('foo.spec.ts')).toBe(true);
    expect(isTestFile('foo_test.py')).toBe(true);
    expect(isTestFile('src/main.js')).toBe(false);
  });

  it('should extract JavaScript imports', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
import express from 'express';
const lodash = require('lodash');
`, 'javascript');
    expect(imports).toContain('express');
    expect(imports).toContain('lodash');
  });

  it('should extract Python imports', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
import flask
from requests import get
`, 'python');
    expect(imports).toContain('flask');
    expect(imports).toContain('requests');
  });

  it('should return a version string', async () => {
    const { getVersion } = await import('../src/utils.js');
    const ver = getVersion();
    expect(ver).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
