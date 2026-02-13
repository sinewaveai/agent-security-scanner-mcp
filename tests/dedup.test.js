import { describe, it, expect } from 'vitest';
import { classifyFinding, deduplicateFindings } from '../src/dedup.js';

describe('classifyFinding', () => {
  it('should classify innerHTML as xss-innerhtml', () => {
    expect(classifyFinding('innerHTML')).toBe('xss-innerhtml');
    expect(classifyFinding('insecure-innerhtml')).toBe('xss-innerhtml');
  });

  it('should classify sql-injection variants', () => {
    expect(classifyFinding('sql-injection')).toBe('sqli');
    expect(classifyFinding('sql-injection-db-cursor')).toBe('sqli');
  });

  it('should classify command injection variants', () => {
    expect(classifyFinding('child-process-exec')).toBe('cmdi-exec');
    expect(classifyFinding('dangerous-subprocess')).toBe('cmdi-subprocess');
    expect(classifyFinding('command-injection')).toBe('cmdi');
  });

  it('should classify eval and exec separately', () => {
    expect(classifyFinding('eval-detected')).toBe('code-eval');
    expect(classifyFinding('exec-detected')).toBe('code-exec');
  });

  it('should return ruleId as fallback for unknown rules', () => {
    expect(classifyFinding('some-custom-rule')).toBe('some-custom-rule');
  });
});

describe('deduplicateFindings', () => {
  it('should merge findings with same vuln class on same line', () => {
    const findings = [
      { ruleId: 'innerHTML', line: 5, severity: 'warning', engine: 'regex-fallback' },
      { ruleId: 'insecure-innerhtml', line: 5, severity: 'warning', engine: 'ast' },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
  });

  it('should keep findings on different lines', () => {
    const findings = [
      { ruleId: 'innerHTML', line: 5, severity: 'warning', engine: 'regex-fallback' },
      { ruleId: 'innerHTML', line: 10, severity: 'warning', engine: 'regex-fallback' },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('should prefer higher-priority engine (ast over regex)', () => {
    const findings = [
      { ruleId: 'innerHTML', line: 5, severity: 'warning', engine: 'regex-fallback' },
      { ruleId: 'insecure-innerhtml', line: 5, severity: 'warning', engine: 'ast' },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('insecure-innerhtml');
  });

  it('should preserve highest severity across merged group', () => {
    const findings = [
      { ruleId: 'innerHTML', line: 5, severity: 'info', engine: 'regex-fallback' },
      { ruleId: 'insecure-innerhtml', line: 5, severity: 'error', engine: 'ast' },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe('error');
  });

  it('should tag engines_matched when merging', () => {
    const findings = [
      { ruleId: 'innerHTML', line: 5, severity: 'warning', engine: 'regex-fallback' },
      { ruleId: 'insecure-innerhtml', line: 5, severity: 'warning', engine: 'ast' },
    ];
    const result = deduplicateFindings(findings);
    expect(result[0].engines_matched).toBeDefined();
    expect(result[0].engines_matched).toContain('regex-fallback');
    expect(result[0].engines_matched).toContain('ast');
  });

  it('should handle non-array input', () => {
    expect(deduplicateFindings(null)).toBeNull();
    expect(deduplicateFindings({ error: 'test' })).toEqual({ error: 'test' });
  });

  it('should handle single findings without modification', () => {
    const findings = [
      { ruleId: 'eval-detected', line: 3, severity: 'error', engine: 'regex-fallback' },
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('eval-detected');
  });
});
