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

describe('guard finding suppression', () => {
  it('suppresses finding with strong guard evidence and no concrete bypass', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'Command execution in subprocess handler',
        reasoning: 'The function calls subprocess.run with shell=False and a hardcoded allowlist of commands. The allowlist could theoretically be expanded in the future.',
        confidence: 0.65,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('keeps finding with strong guard evidence but concrete bypass', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'Command injection via unsanitized argument',
        reasoning: 'While subprocess.run uses shell=False, the command arguments are constructed from user input without validation, allowing injection of arbitrary flags.',
        confidence: 0.9,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('keeps low-confidence finding with strong guard when bypass is concrete (not theoretical)', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'Argument injection in subprocess.run call',
        reasoning: 'The function uses subprocess.run with shell=False, but the arguments list includes unsanitized user input that can inject additional flags to the command.',
        confidence: 0.6,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('suppresses guard-module finding with weak bypass language', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'Policy validation bypass',
        location: { file: 'src/guard/validator.js', startLine: 10, endLine: 10 },
        reasoning: 'The validator checks against an allowlist but the policy may be bypassed if new entries are added.',
        confidence: 0.7,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
  });

  it('keeps high-confidence guard finding even with guard module path', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'SQL injection in query builder',
        location: { file: 'src/guard/query-builder.js', startLine: 10, endLine: 10 },
        reasoning: 'User input is concatenated directly into the SQL string, bypassing the parameterized query interface.',
        confidence: 0.95,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(1);
  });

  it('suppresses finding about allowlist that could theoretically change', () => {
    const findings: Finding[] = [
      makeFinding({
        category: 'security',
        title: 'Subprocess execution with hardcoded commands',
        reasoning: 'The code executes subprocess commands from a hardcoded allowlist. Future changes could expand this allowlist to include dangerous commands.',
        confidence: 0.6,
      }),
    ];

    const result = postFilterFindings(findings, 'security');
    expect(result).toHaveLength(0);
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

  it('prefers sink-located finding over carrier in router (SSRF case)', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'User-controlled URL passed to fetch handler',
        location: { file: 'src/router/api-handler.js', startLine: 30, endLine: 30 },
        reasoning: 'The URL is forwarded through the router to the fetch service',
        cwe: 'CWE-918',
        confidence: 0.8,
      }),
      makeFinding({
        title: 'SSRF via unvalidated URL in fetch call',
        location: { file: 'src/service/http-client.js', startLine: 15, endLine: 15 },
        reasoning: 'The function executes a fetch request with an attacker-controlled URL',
        cwe: 'CWE-918',
        confidence: 0.85,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].location.file).toBe('src/service/http-client.js');
  });

  it('prefers tool/sink file over planner/wrapper file', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'Command dispatched via planner',
        location: { file: 'planner.py', startLine: 50, endLine: 50 },
        reasoning: 'User input is passed to the tool executor via the planner',
        cwe: 'CWE-78',
        confidence: 0.75,
      }),
      makeFinding({
        title: 'OS command injection in tool executor',
        location: { file: 'tools/executor.py', startLine: 20, endLine: 20 },
        reasoning: 'The tool executor calls subprocess with user-controlled arguments',
        cwe: 'CWE-78',
        confidence: 0.9,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].location.file).toBe('tools/executor.py');
  });

  it('keeps distinct findings even when same CWE in different contexts', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'XSS in admin panel template',
        location: { file: 'src/views/admin.js', startLine: 10, endLine: 10 },
        cwe: 'CWE-79',
        confidence: 0.9,
      }),
    ];

    // Single finding - no suppression should occur
    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
  });

  it('preserves same-title no-CWE findings in different files when neither is carrier/sink', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'Missing authorization check',
        location: { file: 'src/routes/users.js', startLine: 10, endLine: 10 },
        reasoning: 'No authorization check before database write',
        confidence: 0.85,
      }),
      makeFinding({
        title: 'Missing authorization check',
        location: { file: 'src/routes/admin.js', startLine: 20, endLine: 20 },
        reasoning: 'No authorization check before database write',
        confidence: 0.8,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('collapses same-title no-CWE carrier/sink pair when language signals present', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'Unsafe file write',
        location: { file: 'src/router/upload-handler.js', startLine: 10, endLine: 10 },
        reasoning: 'User-uploaded path is forwarded through the handler to the file service',
        confidence: 0.75,
      }),
      makeFinding({
        title: 'Unsafe file write',
        location: { file: 'src/service/file-client.js', startLine: 20, endLine: 20 },
        reasoning: 'The service writes to disk at the user-specified path',
        confidence: 0.85,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].location.file).toBe('src/service/file-client.js');
  });

  it('preserves same-title findings in controller/service without carrier/sink language', () => {
    // Both findings describe distinct issues — no forwarding/routing language
    const findings: Finding[] = [
      makeFinding({
        title: 'Missing authorization check',
        location: { file: 'src/controller/users.js', startLine: 10, endLine: 10 },
        reasoning: 'No authorization check before database write',
        confidence: 0.85,
      }),
      makeFinding({
        title: 'Missing authorization check',
        location: { file: 'src/service/admin.js', startLine: 20, endLine: 20 },
        reasoning: 'No authorization check before database write',
        confidence: 0.8,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(2);
  });

  it('suppresses all carrier duplicates when carrier file has multiple same-title rows', () => {
    const findings: Finding[] = [
      makeFinding({
        title: 'Unsafe file write',
        location: { file: 'src/router/handler.js', startLine: 10, endLine: 10 },
        reasoning: 'User path forwarded through the router to the write service',
        confidence: 0.7,
      }),
      makeFinding({
        title: 'Unsafe file write',
        location: { file: 'src/router/handler.js', startLine: 30, endLine: 30 },
        reasoning: 'Another path forwarded through the router to the write service',
        confidence: 0.65,
      }),
      makeFinding({
        title: 'Unsafe file write',
        location: { file: 'src/service/writer.js', startLine: 20, endLine: 20 },
        reasoning: 'The service writes to disk at the user-specified path',
        confidence: 0.85,
      }),
    ];

    const result = suppressCarrierFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0].location.file).toBe('src/service/writer.js');
  });
});
