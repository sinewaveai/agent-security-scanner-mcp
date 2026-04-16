import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const SCRIPT = join(process.cwd(), 'scripts', 'project_scan_to_sarif.py');

function convert(inputJson) {
  const dir = mkdtempSync(join(tmpdir(), 'sarif-convert-'));
  const inFile = join(dir, 'project-scan.json');
  const outFile = join(dir, 'results.sarif');
  try {
    writeFileSync(inFile, JSON.stringify(inputJson), 'utf-8');
    execFileSync('python3', [SCRIPT, inFile, outFile], { encoding: 'utf-8' });
    return JSON.parse(readFileSync(outFile, 'utf-8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('project_scan_to_sarif.py', () => {
  it('converts current flat issues[] schema', () => {
    const sarif = convert({
      issues_count: 2,
      issues: [
        {
          file: 'src/a.js',
          line: 9,
          ruleId: 'javascript.security.sql-injection',
          severity: 'error',
          message: 'SQL injection',
        },
        {
          file: 'src/b.py',
          line: 3,
          ruleId: 'python.security.eval-use',
          severity: 'WARNING',
          message: 'Eval usage',
        },
      ],
    });

    const run = sarif.runs[0];
    expect(run.results).toHaveLength(2);
    expect(run.results[0].ruleId).toBe('javascript.security.sql-injection');
    expect(run.results[0].level).toBe('error');
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/a.js');
    expect(run.results[0].locations[0].physicalLocation.region.startLine).toBe(9);
    expect(run.results[1].level).toBe('warning');
    expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(2);
  });

  it('converts legacy nested files[].issues[] schema', () => {
    const sarif = convert({
      files: [
        {
          file: 'legacy/c.js',
          issues: [
            {
              line: 12,
              ruleId: 'c.security.insecure-use-gets-fn',
              severity: 'ERROR',
              message: 'gets() is unsafe',
            },
          ],
        },
      ],
    });

    const run = sarif.runs[0];
    expect(run.results).toHaveLength(1);
    expect(run.results[0].ruleId).toBe('c.security.insecure-use-gets-fn');
    expect(run.results[0].level).toBe('error');
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('legacy/c.js');
  });

  it('writes valid empty SARIF for malformed input', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sarif-convert-'));
    const inFile = join(dir, 'project-scan.json');
    const outFile = join(dir, 'results.sarif');
    try {
      writeFileSync(inFile, 'not-json', 'utf-8');
      execFileSync('python3', [SCRIPT, inFile, outFile], { encoding: 'utf-8' });
      const sarif = JSON.parse(readFileSync(outFile, 'utf-8'));
      expect(sarif.version).toBe('2.1.0');
      expect(Array.isArray(sarif.runs)).toBe(true);
      expect(sarif.runs[0].results).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
