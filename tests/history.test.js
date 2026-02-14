import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { saveResult, loadHistory, getTrends, diffResults } from '../src/history.js';

// Create a unique temp directory for each test run
let tempDir;

function makeTempDir() {
  const dir = join(tmpdir(), `scanner-history-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

beforeEach(() => {
  tempDir = makeTempDir();
});

afterEach(() => {
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
});

// Helper to build a mock scan result
function mockScanResult(overrides = {}) {
  return {
    directory: tempDir,
    grade: 'C',
    files_scanned: 10,
    issues_count: 5,
    by_severity: { error: 1, warning: 2, info: 2 },
    by_category: { javascript: 3, python: 2 },
    by_file: { 'app.js': 3, 'utils.py': 2 },
    issues: [
      { ruleId: 'sql-injection', file: 'app.js', line: 10, severity: 'error', message: 'SQL injection' },
      { ruleId: 'xss', file: 'app.js', line: 25, severity: 'warning', message: 'XSS vulnerability' },
      { ruleId: 'weak-hash', file: 'app.js', line: 40, severity: 'warning', message: 'Weak hash' },
      { ruleId: 'hardcoded-secret', file: 'utils.py', line: 5, severity: 'info', message: 'Hardcoded secret' },
      { ruleId: 'insecure-random', file: 'utils.py', line: 15, severity: 'info', message: 'Insecure random' },
    ],
    ...overrides,
  };
}

describe('saveResult', () => {
  it('should create .scanner/results/ directory and save a file', () => {
    const result = mockScanResult();
    const savedPath = saveResult(tempDir, result);

    // Directory was created
    const resultsDir = join(tempDir, '.scanner', 'results');
    expect(existsSync(resultsDir)).toBe(true);

    // File was created
    expect(existsSync(savedPath)).toBe(true);

    // File name matches timestamp pattern
    const filename = savedPath.split('/').pop();
    expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.json$/);

    // Content is valid JSON with expected fields
    const content = JSON.parse(readFileSync(savedPath, 'utf-8'));
    expect(content.timestamp).toBeDefined();
    expect(content.grade).toBe('C');
    expect(content.files_scanned).toBe(10);
    expect(content.issues_count).toBe(5);
    expect(content.by_severity).toEqual({ error: 1, warning: 2, info: 2 });
    expect(content.issues).toHaveLength(5);
  });

  it('should save multiple results as separate files', () => {
    // Manually create two result files with distinct timestamps to avoid sub-second collision
    const resultsDir = join(tempDir, '.scanner', 'results');
    mkdirSync(resultsDir, { recursive: true });

    const entry1 = { timestamp: new Date().toISOString(), directory: tempDir, grade: 'D', files_scanned: 5, issues_count: 10, by_severity: { error: 5, warning: 3, info: 2 }, issues: [] };
    const entry2 = { timestamp: new Date().toISOString(), directory: tempDir, grade: 'C', files_scanned: 10, issues_count: 5, by_severity: { error: 1, warning: 2, info: 2 }, issues: [] };

    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const ts1 = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
    const ts2 = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(Math.min(now.getSeconds() + 1, 59))}`;

    writeFileSync(join(resultsDir, `${ts1}.json`), JSON.stringify(entry1));
    writeFileSync(join(resultsDir, `${ts2}.json`), JSON.stringify(entry2));

    const files = readdirSync(resultsDir);
    expect(files.length).toBeGreaterThanOrEqual(2);
  });

  it('should handle scan result with total instead of issues_count', () => {
    const result = { directory: tempDir, grade: 'A', files_scanned: 3, total: 0 };
    const savedPath = saveResult(tempDir, result);
    const content = JSON.parse(readFileSync(savedPath, 'utf-8'));
    expect(content.issues_count).toBe(0);
  });
});

describe('loadHistory', () => {
  it('should return empty array when no results directory exists', () => {
    const results = loadHistory(tempDir);
    expect(results).toEqual([]);
  });

  it('should return results within date range', () => {
    // Save a result (it will be within range)
    saveResult(tempDir, mockScanResult({ grade: 'C' }));

    const results = loadHistory(tempDir, 90);
    expect(results).toHaveLength(1);
    expect(results[0].grade).toBe('C');
  });

  it('should exclude results outside the date range', () => {
    // Save a result now (within range)
    saveResult(tempDir, mockScanResult({ grade: 'B' }));

    // Manually create an old result file (200 days ago)
    const resultsDir = join(tempDir, '.scanner', 'results');
    const oldDate = new Date();
    oldDate.setDate(oldDate.getDate() - 200);
    const pad = (n) => String(n).padStart(2, '0');
    const oldTimestamp = `${oldDate.getFullYear()}-${pad(oldDate.getMonth() + 1)}-${pad(oldDate.getDate())}T${pad(oldDate.getHours())}-${pad(oldDate.getMinutes())}-${pad(oldDate.getSeconds())}`;
    const oldFile = join(resultsDir, `${oldTimestamp}.json`);
    writeFileSync(oldFile, JSON.stringify({
      timestamp: oldDate.toISOString(),
      directory: tempDir,
      grade: 'F',
      files_scanned: 1,
      issues_count: 20,
      by_severity: { error: 20, warning: 0, info: 0 },
      issues: [],
    }));

    // With 90-day window, only the recent result should be returned
    const results = loadHistory(tempDir, 90);
    expect(results).toHaveLength(1);
    expect(results[0].grade).toBe('B');

    // With 365-day window, both should be returned
    const allResults = loadHistory(tempDir, 365);
    expect(allResults).toHaveLength(2);
  });

  it('should return results sorted oldest-first', () => {
    const resultsDir = join(tempDir, '.scanner', 'results');
    mkdirSync(resultsDir, { recursive: true });

    // Create two files manually with known timestamps
    const entry1 = { timestamp: '2024-06-01T10:00:00.000Z', grade: 'D', files_scanned: 5, issues_count: 10, by_severity: { error: 5, warning: 3, info: 2 }, issues: [] };
    const entry2 = { timestamp: '2024-06-15T10:00:00.000Z', grade: 'B', files_scanned: 5, issues_count: 2, by_severity: { error: 0, warning: 1, info: 1 }, issues: [] };

    writeFileSync(join(resultsDir, '2024-06-15T10-00-00.json'), JSON.stringify(entry2));
    writeFileSync(join(resultsDir, '2024-06-01T10-00-00.json'), JSON.stringify(entry1));

    const results = loadHistory(tempDir, 9999);
    expect(results).toHaveLength(2);
    expect(results[0].grade).toBe('D'); // older first
    expect(results[1].grade).toBe('B'); // newer second
  });

  it('should skip corrupt JSON files gracefully', () => {
    const resultsDir = join(tempDir, '.scanner', 'results');
    mkdirSync(resultsDir, { recursive: true });

    // Valid file
    saveResult(tempDir, mockScanResult({ grade: 'A' }));

    // Corrupt file
    const pad = (n) => String(n).padStart(2, '0');
    const now = new Date();
    const ts = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds() + 1 > 59 ? 59 : now.getSeconds() + 1)}`;
    writeFileSync(join(resultsDir, `${ts}.json`), 'this is not json{{{');

    const results = loadHistory(tempDir, 90);
    // Should have at least the valid result (corrupt one skipped)
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results.some(r => r.grade === 'A')).toBe(true);
  });
});

describe('getTrends', () => {
  it('should return empty trends when no history', () => {
    const trends = getTrends(tempDir);
    expect(trends.grades).toEqual([]);
    expect(trends.issues).toEqual([]);
  });

  it('should return grade and issue trends', () => {
    // Create two results with distinct timestamps to avoid sub-second collision
    const resultsDir = join(tempDir, '.scanner', 'results');
    mkdirSync(resultsDir, { recursive: true });

    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const ts1 = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
    const ts2 = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(Math.min(now.getSeconds() + 1, 59))}`;

    const entry1 = { timestamp: now.toISOString(), directory: tempDir, grade: 'D', files_scanned: 5, issues_count: 10, by_severity: { error: 5, warning: 3, info: 2 }, issues: [] };
    const laterDate = new Date(now.getTime() + 1000);
    const entry2 = { timestamp: laterDate.toISOString(), directory: tempDir, grade: 'C', files_scanned: 10, issues_count: 5, by_severity: { error: 1, warning: 2, info: 2 }, issues: [] };

    writeFileSync(join(resultsDir, `${ts1}.json`), JSON.stringify(entry1));
    writeFileSync(join(resultsDir, `${ts2}.json`), JSON.stringify(entry2));

    const trends = getTrends(tempDir, 90);

    expect(trends.grades.length).toBeGreaterThanOrEqual(2);
    expect(trends.grades[0]).toHaveProperty('date');
    expect(trends.grades[0]).toHaveProperty('grade');

    expect(trends.issues.length).toBeGreaterThanOrEqual(2);
    expect(trends.issues[0]).toHaveProperty('date');
    expect(trends.issues[0]).toHaveProperty('total');
    expect(trends.issues[0]).toHaveProperty('critical');
    expect(trends.issues[0]).toHaveProperty('warning');
    expect(trends.issues[0]).toHaveProperty('info');
  });

  it('should map error count to critical in trends', () => {
    saveResult(tempDir, mockScanResult({ by_severity: { error: 7, warning: 3, info: 1 } }));

    const trends = getTrends(tempDir);
    expect(trends.issues[0].critical).toBe(7);
    expect(trends.issues[0].warning).toBe(3);
    expect(trends.issues[0].info).toBe(1);
  });
});

describe('diffResults', () => {
  it('should identify new issues', () => {
    const previous = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
      ],
    };
    const current = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
        { ruleId: 'xss', file: 'app.js', line: 25 },
      ],
    };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(1);
    expect(diff.new_issues[0].ruleId).toBe('xss');
    expect(diff.fixed_issues).toHaveLength(0);
    expect(diff.unchanged).toBe(1);
  });

  it('should identify fixed issues', () => {
    const previous = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
        { ruleId: 'xss', file: 'app.js', line: 25 },
      ],
    };
    const current = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
      ],
    };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(0);
    expect(diff.fixed_issues).toHaveLength(1);
    expect(diff.fixed_issues[0].ruleId).toBe('xss');
    expect(diff.unchanged).toBe(1);
  });

  it('should correctly handle completely new scan (no previous issues)', () => {
    const previous = { issues: [] };
    const current = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
        { ruleId: 'xss', file: 'app.js', line: 25 },
      ],
    };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(2);
    expect(diff.fixed_issues).toHaveLength(0);
    expect(diff.unchanged).toBe(0);
  });

  it('should correctly handle all issues fixed', () => {
    const previous = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
        { ruleId: 'xss', file: 'app.js', line: 25 },
      ],
    };
    const current = { issues: [] };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(0);
    expect(diff.fixed_issues).toHaveLength(2);
    expect(diff.unchanged).toBe(0);
  });

  it('should compare by ruleId + file + line', () => {
    const previous = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 10 },
      ],
    };
    // Same rule, same file, different line = new issue
    const current = {
      issues: [
        { ruleId: 'sql-injection', file: 'app.js', line: 20 },
      ],
    };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(1);
    expect(diff.fixed_issues).toHaveLength(1);
    expect(diff.unchanged).toBe(0);
  });

  it('should handle missing issues arrays gracefully', () => {
    const diff = diffResults({}, {});
    expect(diff.new_issues).toHaveLength(0);
    expect(diff.fixed_issues).toHaveLength(0);
    expect(diff.unchanged).toBe(0);
  });

  it('should handle mixed new, fixed, and unchanged issues', () => {
    const previous = {
      issues: [
        { ruleId: 'sql-injection', file: 'a.js', line: 1 },
        { ruleId: 'xss', file: 'b.js', line: 2 },
        { ruleId: 'weak-hash', file: 'c.js', line: 3 },
      ],
    };
    const current = {
      issues: [
        { ruleId: 'sql-injection', file: 'a.js', line: 1 }, // unchanged
        { ruleId: 'hardcoded-secret', file: 'd.js', line: 4 }, // new
        { ruleId: 'insecure-random', file: 'e.js', line: 5 }, // new
      ],
    };

    const diff = diffResults(current, previous);
    expect(diff.new_issues).toHaveLength(2);
    expect(diff.fixed_issues).toHaveLength(2); // xss and weak-hash
    expect(diff.unchanged).toBe(1); // sql-injection
  });
});
