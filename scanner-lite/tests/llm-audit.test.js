// tests/llm-audit.test.js — Tests for deep_audit tool
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'fs';
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

  it('should detect .tsx as typescript', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('component.tsx')).toBe('typescript');
  });

  it('should detect .jsx as javascript', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('component.jsx')).toBe('javascript');
  });

  it('should detect .yaml and .yml as generic', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('config.yaml')).toBe('generic');
    expect(detectLanguage('config.yml')).toBe('generic');
  });

  it('should detect .sql as sql', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('schema.sql')).toBe('sql');
  });

  it('should detect .cpp and .cs', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('main.cpp')).toBe('cpp');
    expect(detectLanguage('Program.cs')).toBe('csharp');
  });

  it('should detect unknown extensions as generic', async () => {
    const { detectLanguage } = await import('../src/utils.js');
    expect(detectLanguage('file.sh')).toBe('generic');
    expect(detectLanguage('file.bash')).toBe('generic');
    expect(detectLanguage('file.tf')).toBe('terraform');
    expect(detectLanguage('file.hcl')).toBe('terraform');
    expect(detectLanguage('file.swift')).toBe('generic');
    expect(detectLanguage('file.kt')).toBe('generic');
    expect(detectLanguage('file.scala')).toBe('generic');
    expect(detectLanguage('file.hs')).toBe('generic');
  });

  it('toSarif should include correct schema version (2.1.0)', async () => {
    const { toSarif } = await import('../src/utils.js');
    const sarif = toSarif([], 'test.js', 'javascript');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
  });

  it('toSarif should include tool information', async () => {
    const { toSarif } = await import('../src/utils.js');
    const sarif = toSarif([], 'test.js', 'javascript');
    expect(sarif.runs[0].tool.driver.name).toBe('ProofLayer Security Scanner');
    expect(sarif.runs[0].tool.driver.version).toBeDefined();
    expect(sarif.runs[0].tool.driver.informationUri).toBeDefined();
  });

  it('toSarif should handle empty findings array', async () => {
    const { toSarif } = await import('../src/utils.js');
    const sarif = toSarif([], 'empty.js', 'javascript');
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('toSarif should include rule IDs in results', async () => {
    const { toSarif } = await import('../src/utils.js');
    const findings = [
      { ruleId: 'js.eval-detected', message: 'eval usage', severity: 'error', line: 1, column: 0 },
      { ruleId: 'js.sql-injection', message: 'SQL injection', severity: 'warning', line: 5, column: 0 }
    ];
    const sarif = toSarif(findings, 'app.js', 'javascript');
    expect(sarif.runs[0].results[0].ruleId).toBe('js.eval-detected');
    expect(sarif.runs[0].results[1].ruleId).toBe('js.sql-injection');
  });

  it('isTestFile should detect __tests__ directory', async () => {
    const { isTestFile } = await import('../src/utils.js');
    expect(isTestFile('src/__tests__/component.js')).toBe(true);
    expect(isTestFile('app/__tests__/utils.test.js')).toBe(true);
  });

  it('isTestFile should detect .spec files', async () => {
    const { isTestFile } = await import('../src/utils.js');
    expect(isTestFile('component.spec.js')).toBe(true);
    expect(isTestFile('component.spec.ts')).toBe(true);
    expect(isTestFile('utils.spec.tsx')).toBe(true);
  });

  it('isTestFile should not flag regular files', async () => {
    const { isTestFile } = await import('../src/utils.js');
    expect(isTestFile('src/main.js')).toBe(false);
    expect(isTestFile('lib/utils.py')).toBe(false);
    expect(isTestFile('index.ts')).toBe(false);
  });

  it('extractImports should handle ES module imports', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
import React from 'react';
import { useState, useEffect } from 'react';
import axios from 'axios';
`, 'javascript');
    expect(imports).toContain('react');
    expect(imports).toContain('axios');
  });

  it('extractImports should handle require with destructuring', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
const { readFileSync } = require('fs');
const path = require('path');
`, 'javascript');
    expect(imports).toContain('fs');
    expect(imports).toContain('path');
  });

  it('extractImports should handle Python from...import', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
from flask import Flask, jsonify
from os.path import join
import sys
`, 'python');
    expect(imports).toContain('flask');
    expect(imports).toContain('os.path');
    expect(imports).toContain('sys');
  });

  it('extractImports should return empty for non-JS/PY files', async () => {
    const { extractImports } = await import('../src/utils.js');
    const imports = extractImports(`
use std::io;
use serde::Deserialize;
`, 'rust');
    expect(imports).toHaveLength(0);
  });

  it('getVersion should return semver format', async () => {
    const { getVersion } = await import('../src/utils.js');
    const ver = getVersion();
    expect(ver).toMatch(/^\d+\.\d+\.\d+$/);
    // Verify it matches package.json
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'package.json'), 'utf-8'));
    expect(ver).toBe(pkg.version);
  });
});

describe('deepAudit provider errors', () => {
  it('should handle gemini provider error', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    const origKey = process.env.GEMINI_API_KEY;
    process.env.PROOFLAYER_LLM_CONSENT = '1';
    delete process.env.GEMINI_API_KEY;

    const file = writeTemp('gemini-err.js', 'const x = 1;');
    const result = await deepAudit({ file_path: file, provider: 'gemini' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('API key');

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
    if (origKey) process.env.GEMINI_API_KEY = origKey;
  });

  it('should handle openrouter provider error', async () => {
    const origConsent = process.env.PROOFLAYER_LLM_CONSENT;
    const origKey = process.env.OPENROUTER_API_KEY;
    process.env.PROOFLAYER_LLM_CONSENT = '1';
    delete process.env.OPENROUTER_API_KEY;

    const file = writeTemp('openrouter-err.js', 'const x = 1;');
    const result = await deepAudit({ file_path: file, provider: 'openrouter' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toContain('API key');

    if (origConsent) process.env.PROOFLAYER_LLM_CONSENT = origConsent;
    else delete process.env.PROOFLAYER_LLM_CONSENT;
    if (origKey) process.env.OPENROUTER_API_KEY = origKey;
  });
});

describe('deepAudit schema fields', () => {
  it('should have provider field', async () => {
    const { deepAuditSchema } = await import('../src/llm-audit.js');
    expect(deepAuditSchema.provider).toBeDefined();
  });

  it('should have model field', async () => {
    const { deepAuditSchema } = await import('../src/llm-audit.js');
    expect(deepAuditSchema.model).toBeDefined();
  });
});

describe('config module', () => {
  it('loadConfig should handle missing file', async () => {
    const { loadConfig } = await import('../src/config.js');
    const config = loadConfig('/nonexistent/path/file.js');
    expect(config).toBeDefined();
    expect(config.version).toBe(1);
    expect(Array.isArray(config.exclude)).toBe(true);
  });

  it('loadConfig should handle valid JSON', async () => {
    const { loadConfig } = await import('../src/config.js');
    // Create a temp JSON config
    const configDir = join(TMP, 'config-test');
    mkdirSync(configDir, { recursive: true });
    writeFileSync(join(configDir, '.scannerrc.json'), JSON.stringify({
      version: 1,
      suppress: ['test-rule'],
      exclude: ['vendor/**'],
      severity_threshold: 'warning'
    }));
    const file = join(configDir, 'test.js');
    writeFileSync(file, 'const x = 1;');
    const config = loadConfig(file);
    expect(config.suppress).toContain('test-rule');
    expect(config.exclude).toContain('vendor/**');
    expect(config.severity_threshold).toBe('warning');
  });

  it('matchGlob should match simple patterns', async () => {
    const { matchGlob } = await import('../src/config.js');
    expect(matchGlob('node_modules/foo/bar.js', 'node_modules/**')).toBe(true);
    expect(matchGlob('dist/bundle.js', 'dist/**')).toBe(true);
    expect(matchGlob('src/main.js', 'node_modules/**')).toBe(false);
    expect(matchGlob('file.min.js', '**/*.min.js')).toBe(true);
  });
});

describe('dedup module', () => {
  it('should remove duplicate findings', async () => {
    const { deduplicateFindings } = await import('../src/dedup.js');
    const findings = [
      { ruleId: 'js.eval-detected', severity: 'error', line: 5, engine: 'regex', message: 'eval found' },
      { ruleId: 'js.eval-usage', severity: 'warning', line: 5, engine: 'regex', message: 'eval usage' }
    ];
    const result = deduplicateFindings(findings);
    // Both map to 'code-eval' class on the same line, so should be deduped
    expect(result.length).toBe(1);
  });

  it('should keep highest severity', async () => {
    const { deduplicateFindings } = await import('../src/dedup.js');
    const findings = [
      { ruleId: 'js.eval-detected', severity: 'warning', line: 10, engine: 'regex', message: 'eval' },
      { ruleId: 'js.eval-usage', severity: 'error', line: 10, engine: 'regex', message: 'eval usage' }
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
    expect(result[0].severity).toBe('error');
  });
});
