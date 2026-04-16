import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const SCRIPT = join(process.cwd(), 'scripts', 'parse_scan_results.py');

function runParser(filePath) {
  return execFileSync('python3', [SCRIPT, filePath], { encoding: 'utf-8' }).trim();
}

describe('parse_scan_results.py', () => {
  it('parses valid compact/flat issue output', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scan-parse-'));
    const file = join(dir, 'scan-results.json');
    try {
      writeFileSync(file, JSON.stringify({
        issues_count: 3,
        issues: [
          { severity: 'error' },
          { severity: 'WARNING' },
          { severity: 'info' },
        ],
      }), 'utf-8');

      const out = runParser(file);
      expect(out).toBe('3\t1\t1');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('counts nested file issues when files[] schema is used', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scan-parse-'));
    const file = join(dir, 'scan-results.json');
    try {
      writeFileSync(file, JSON.stringify({
        total: 2,
        files: [
          {
            file: 'a.js',
            issues: [{ severity: 'ERROR' }, { severity: 'warning' }],
          },
        ],
      }), 'utf-8');

      const out = runParser(file);
      expect(out).toBe('2\t1\t1');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed on invalid JSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scan-parse-'));
    const file = join(dir, 'scan-results.json');
    try {
      writeFileSync(file, 'not-json', 'utf-8');
      expect(() => runParser(file)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed when scanner returns error object', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scan-parse-'));
    const file = join(dir, 'scan-results.json');
    try {
      writeFileSync(file, JSON.stringify({ error: 'boom' }), 'utf-8');
      expect(() => runParser(file)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed when schema is not recognized', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scan-parse-'));
    const file = join(dir, 'scan-results.json');
    try {
      writeFileSync(file, JSON.stringify({ hello: 'world' }), 'utf-8');
      expect(() => runParser(file)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
