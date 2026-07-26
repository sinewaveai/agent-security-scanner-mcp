import { describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createSarif,
  createSummary,
  normalizeScannerOutput,
  normalizeSeverity,
  runScanner
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
        scan_mode: 'apify-repository-quick',
        repository_scan_mode: 'quick',
        capped: true,
        scan_limit: 150,
        per_file_timeout_seconds: 30,
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
    expect(summary.scanMode).toBe('apify-repository-quick');
    expect(summary.repositoryScanMode).toBe('quick');
    expect(summary.includeTestFiles).toBeNull();
    expect(summary.excludedFiles).toBe(0);
    expect(summary.capped).toBe(true);
    expect(summary.scanLimit).toBe(150);
    expect(summary.perFileTimeoutSeconds).toBe(30);
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

  it('excludes test, demo, benchmark, and fixture files from repository quick scans by default', async () => {
    const repoDir = await mkdtemp(join(tmpdir(), 'apify-noise-filter-'));
    try {
      await mkdir(join(repoDir, 'src'), { recursive: true });
      await mkdir(join(repoDir, 'tests'), { recursive: true });
      await mkdir(join(repoDir, 'demo'), { recursive: true });
      await writeFile(join(repoDir, 'src', 'agent.js'), 'eval(userInput);\n', 'utf8');
      await writeFile(join(repoDir, 'tests', 'agent.test.js'), 'eval(testInput);\n', 'utf8');
      await writeFile(join(repoDir, 'demo', 'unsafe-demo.js'), 'eval(demoInput);\n', 'utf8');

      const result = await runScanner({
        kind: 'repository',
        path: repoDir,
        options: { maxRepositoryFiles: 10, repositoryScanMode: 'quick' }
      });

      expect(result.scan_mode).toBe('apify-repository-quick');
      expect(result.include_test_files).toBe(false);
      expect(result.files_scanned).toBe(1);
      expect(result.issues_count).toBe(1);
      expect(result.excluded_files).toBe(2);
      expect(result.scanned_files).toEqual(['src/agent.js']);
      expect(result.issues[0]).toMatchObject({
        file: 'src/agent.js',
        confidence: 'MEDIUM',
        metadata: { source_context: 'source' }
      });
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });

  it('can include test, demo, benchmark, and fixture files with low confidence context', async () => {
    const repoDir = await mkdtemp(join(tmpdir(), 'apify-noise-filter-'));
    try {
      await mkdir(join(repoDir, 'src'), { recursive: true });
      await mkdir(join(repoDir, 'tests'), { recursive: true });
      await mkdir(join(repoDir, 'demo'), { recursive: true });
      await writeFile(join(repoDir, 'src', 'agent.js'), 'eval(userInput);\n', 'utf8');
      await writeFile(join(repoDir, 'tests', 'agent.test.js'), 'eval(testInput);\n', 'utf8');
      await writeFile(join(repoDir, 'demo', 'unsafe-demo.js'), 'eval(demoInput);\n', 'utf8');

      const result = await runScanner({
        kind: 'repository',
        path: repoDir,
        options: { maxRepositoryFiles: 10, repositoryScanMode: 'quick', includeTestFiles: true }
      });

      expect(result.include_test_files).toBe(true);
      expect(result.files_scanned).toBe(3);
      expect(result.issues_count).toBe(3);
      expect(result.excluded_files).toBe(0);
      expect(result.scanned_files).toEqual(['demo/unsafe-demo.js', 'src/agent.js', 'tests/agent.test.js']);
      expect(result.issues.find((issue) => issue.file === 'src/agent.js')?.confidence).toBe('MEDIUM');
      expect(result.issues.find((issue) => issue.file === 'tests/agent.test.js')).toMatchObject({
        confidence: 'LOW',
        metadata: { source_context: 'test_or_fixture' }
      });
      expect(result.issues.find((issue) => issue.file === 'demo/unsafe-demo.js')).toMatchObject({
        confidence: 'LOW',
        metadata: { source_context: 'test_or_fixture' }
      });
    } finally {
      await rm(repoDir, { recursive: true, force: true });
    }
  });
});
