import { describe, it, expect } from 'vitest';
import { postFilterFindings, suppressCarrierFindings } from '../../src/analyzer/postprocess.js';
import type { Finding } from '../../src/types/findings.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    title: 'Test finding',
    severity: 'medium',
    category: 'security',
    location: { file: 'app.js', startLine: 10, endLine: 10 },
    reasoning: 'Test reasoning',
    intentAlignment: 'unclear',
    confidence: 0.85,
    suggestedAction: 'Fix it',
    ...overrides,
  };
}

describe('postFilterFindings', () => {
  it('returns all findings unchanged in review mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'logic-bug' }),
      makeFinding({ category: 'type-error' }),
      makeFinding({ category: 'security' }),
    ];

    const result = postFilterFindings(findings, 'review');
    expect(result).toHaveLength(3);
  });

  it('keeps security category findings in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'security', title: 'SQL Injection' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps boundary category findings in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'boundary', title: 'Path traversal' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('drops logic-bug without security evidence in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'logic-bug', title: 'Off-by-one error in loop' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('drops type-error without security evidence in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'type-error', title: 'Wrong type passed to function' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('drops unhandled-exception without security evidence in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'unhandled-exception', title: 'Promise rejection not caught' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('keeps logic-bug with CWE in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'logic-bug', title: 'Integer overflow', cwe: 'CWE-190' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps logic-bug with OWASP mapping in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'logic-bug', title: 'Auth bypass', owasp: 'A01:2021' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps non-security category with security keywords in title', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'logic-bug', title: 'SQL injection via string concat' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps non-security category with security keywords in reasoning', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'null-ref',
        title: 'Null dereference in handler',
        reasoning: 'This could lead to credential leak if error response exposes internal state',
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps violates-intent with high confidence in security mode', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'other',
        title: 'Unexpected file write',
        intentAlignment: 'violates-intent',
        confidence: 0.9,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('drops violates-intent with low confidence in security mode', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'other',
        title: 'Unexpected file write',
        intentAlignment: 'violates-intent',
        confidence: 0.6,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('filters mixed findings correctly in security mode', () => {
    const findings: Finding[] = [
      makeFinding({ category: 'security', title: 'XSS vulnerability' }),
      makeFinding({ category: 'logic-bug', title: 'Off-by-one' }),
      makeFinding({ category: 'type-error', title: 'Wrong return type' }),
      makeFinding({ category: 'null-ref', title: 'Command injection in handler', cwe: 'CWE-78' }),
      makeFinding({ category: 'boundary', title: 'Path traversal' }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(3);
    expect(result.map((f) => f.title)).toEqual([
      'XSS vulnerability',
      'Command injection in handler',
      'Path traversal',
    ]);
  });
});

describe('suppressCarrierFindings', () => {
  it('returns single finding unchanged', () => {
    const findings: Finding[] = [makeFinding()];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
  });

  it('collapses findings with same CWE, keeping highest confidence', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'Input passed to query builder',
        location: { file: 'routes.js', startLine: 5, endLine: 5 },
        cwe: 'CWE-89',
        confidence: 0.75,
      }),
      makeFinding({
        title: 'SQL injection in database query',
        location: { file: 'db.js', startLine: 20, endLine: 20 },
        cwe: 'CWE-89',
        confidence: 0.95,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe('SQL injection in database query');
    expect(result[0].confidence).toBe(0.95);
  });

  it('keeps findings with different CWEs', () => {
    const findings: Finding[] = [
      makeFinding({ cwe: 'CWE-89', confidence: 0.9 }),
      makeFinding({ cwe: 'CWE-79', confidence: 0.85 }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('keeps findings without CWE as separate entries', () => {
    const findings: Finding[] = [
      makeFinding({ title: 'Issue A' }),
      makeFinding({ title: 'Issue B' }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(2);
  });
});
