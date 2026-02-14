import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/config.js';

describe('evaluatePolicy', () => {
  it('should pass with default policy when no issues exist', () => {
    const scanResult = { grade: 'A', by_severity: { error: 0, warning: 0, info: 0 }, issues_count: 0 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should pass with default policy even when warnings exist', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 3, info: 1 }, issues_count: 4 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should block when block_on is warning and warnings exist', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 2, info: 0 }, issues_count: 2 };
    const config = {
      policy: { block_on: 'warning', max_critical: null, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]).toContain('block_on: warning');
  });

  it('should block when block_on is warning and only errors exist', () => {
    const scanResult = { grade: 'D', by_severity: { error: 1, warning: 0, info: 0 }, issues_count: 1 };
    const config = {
      policy: { block_on: 'warning', max_critical: null, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations).toHaveLength(1);
  });

  it('should block when max_critical is 0 and critical issues found', () => {
    const scanResult = { grade: 'D', by_severity: { error: 2, warning: 0, info: 0 }, issues_count: 2 };
    const config = {
      policy: { block_on: 'error', max_critical: 0, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations.some(v => v.includes('max_critical'))).toBe(true);
  });

  it('should pass when max_critical is 0 and no critical issues', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 3, info: 0 }, issues_count: 3 };
    const config = {
      policy: { block_on: 'error', max_critical: 0, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should allow 3 warnings when max_warning is 5', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 3, info: 0 }, issues_count: 3 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: 5, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should block 6 warnings when max_warning is 5', () => {
    const scanResult = { grade: 'C', by_severity: { error: 0, warning: 6, info: 0 }, issues_count: 6 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: 5, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations.some(v => v.includes('max_warning'))).toBe(true);
  });

  it('should block grade C when required_grade is B', () => {
    const scanResult = { grade: 'C', by_severity: { error: 1, warning: 2, info: 0 }, issues_count: 3 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: null, required_grade: 'B' },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations.some(v => v.includes('required_grade'))).toBe(true);
  });

  it('should pass grade B when required_grade is B', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 1, info: 0 }, issues_count: 1 };
    const config = {
      policy: { block_on: 'error', max_critical: null, max_warning: null, required_grade: 'B' },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should collect multiple violations', () => {
    const scanResult = { grade: 'F', by_severity: { error: 10, warning: 20, info: 5 }, issues_count: 35 };
    const config = {
      policy: { block_on: 'error', max_critical: 2, max_warning: 5, required_grade: 'B' },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    // block_on error (10 errors), max_critical exceeded, max_warning exceeded, grade below B
    expect(result.violations.length).toBeGreaterThanOrEqual(3);
    expect(result.violations.some(v => v.includes('block_on'))).toBe(true);
    expect(result.violations.some(v => v.includes('max_critical'))).toBe(true);
    expect(result.violations.some(v => v.includes('max_warning'))).toBe(true);
    expect(result.violations.some(v => v.includes('required_grade'))).toBe(true);
  });

  it('should pass when all conditions are met', () => {
    const scanResult = { grade: 'A', by_severity: { error: 0, warning: 2, info: 1 }, issues_count: 3 };
    const config = {
      policy: { block_on: 'error', max_critical: 0, max_warning: 5, required_grade: 'B' },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should use default policy when config has no policy', () => {
    const scanResult = { grade: 'B', by_severity: { error: 0, warning: 3, info: 1 }, issues_count: 4 };
    const config = {};
    const result = evaluatePolicy(scanResult, config);
    // Default policy: block_on 'error', no max_critical, no max_warning, no required_grade
    // No errors, so should pass
    expect(result.passed).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('should block on info when block_on is info', () => {
    const scanResult = { grade: 'A', by_severity: { error: 0, warning: 0, info: 1 }, issues_count: 1 };
    const config = {
      policy: { block_on: 'info', max_critical: null, max_warning: null, required_grade: null },
    };
    const result = evaluatePolicy(scanResult, config);
    expect(result.passed).toBe(false);
    expect(result.violations[0]).toContain('block_on: info');
  });
});
