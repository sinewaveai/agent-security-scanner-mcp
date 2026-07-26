import { describe, expect, it } from 'vitest';

import {
  createSarif,
  createSummary,
  normalizeScannerOutput,
  normalizeSeverity
} from '../src/main.js';

describe('Apify Actor wrapper', () => {
  it('normalizes existing scanner finding shapes', () => {
    const findings = normalizeScannerOutput({
      findings: [{
        rule: 'mcp.eval-usage',
        severity: 'ERROR',
        category: 'insecure-patterns',
        message: 'eval() executes arbitrary code.',
        file: 'server.js',
        line: 7
      }],
      issues: [{
        ruleId: 'javascript.command-injection',
        severity: 'warning',
        message: 'Shell command injection risk.',
        file: 'agent.js',
        line: 12
      }]
    }, {
      includeRemediation: true,
      severityThreshold: 'info'
    });

    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      severity: 'high',
      category: 'insecure-patterns',
      ruleId: 'mcp.eval-usage',
      location: { file: 'server.js', line: 7 }
    });
    expect(findings[0].owaspLlm).toContain('LLM07');
    expect(findings[0].mitreAtlas).toContain('AML.T0005');
    expect(findings[0].remediation).toContain('eval');
  });

  it('filters by severity threshold after mapping scanner severities', () => {
    const findings = normalizeScannerOutput({
      findings: [
        { rule: 'mcp.info', severity: 'INFO', message: 'Informational.' },
        { rule: 'mcp.warning', severity: 'WARNING', message: 'Warning.' },
        { rule: 'mcp.error', severity: 'ERROR', message: 'Error.' }
      ]
    }, {
      severityThreshold: 'high',
      includeRemediation: false
    });

    expect(findings.map((finding) => finding.ruleId)).toEqual(['mcp.error']);
    expect(findings[0].remediation).toBeUndefined();
  });

  it('creates OUTPUT summary and SARIF from normalized findings', () => {
    const findings = normalizeScannerOutput({
      findings: [{
        rule: 'mcp.manifest-description-injection',
        severity: 'ERROR',
        category: 'description-injection',
        message: 'Tool description contains injection language.',
        file: 'server.json',
        line: 1
      }]
    }, {
      includeRemediation: true
    });

    const summary = createSummary({
      input: { target: 'mcpServer', ruleSets: ['all'], severityThreshold: 'info' },
      scannerOutput: {
        grade: 'D',
        files_scanned: 1,
        scan_mode: 'apify-repository-safe',
        capped: true,
        scan_limit: 150,
        scan_errors: [{ path: 'large-file.js', reason: 'File larger than 1MB' }]
      },
      findings,
      source: { kind: 'mcpServer', path: '/tmp/server' }
    });
    const sarif = createSarif(findings);

    expect(summary.findingsCount).toBe(1);
    expect(summary.bySeverity.high).toBe(1);
    expect(summary.frameworkCoverage.owaspLlm).toContain('LLM01');
    expect(summary.sarifKey).toBe('report.sarif');
    expect(summary.scanMode).toBe('apify-repository-safe');
    expect(summary.capped).toBe(true);
    expect(summary.scanLimit).toBe(150);
    expect(summary.scanErrors).toEqual([{ path: 'large-file.js', reason: 'File larger than 1MB' }]);
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe('mcp.manifest-description-injection');
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('maps scanner severity names to Actor severities', () => {
    expect(normalizeSeverity('ERROR')).toBe('high');
    expect(normalizeSeverity('WARNING')).toBe('medium');
    expect(normalizeSeverity('INFO')).toBe('info');
    expect(normalizeSeverity('critical')).toBe('critical');
  });
});
