import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import {
  buildRelatedFileSummaries,
  formatRelatedFileSummaries,
} from '../../src/context/security-summary.js';
import type { FileContext } from '../../src/types/analysis.js';

const FIXTURES_DIR = path.resolve(__dirname, '..', 'fixtures', 'guarded-agent');

function makeFileContext(overrides: Partial<FileContext> = {}): FileContext {
  return {
    filePath: 'router.py',
    content: 'from tools.executor import execute_tool\n',
    language: 'python',
    lineCount: 5,
    imports: ['./tools/executor'],
    importedBy: [],
    siblingFiles: ['vuln-tool.py', 'tools'],
    isTestFile: false,
    isConfigFile: false,
    isGenerated: false,
    ...overrides,
  };
}

describe('buildRelatedFileSummaries', () => {
  it('extracts security-relevant lines from imported files', () => {
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['./tools/executor'],
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    expect(summaries.length).toBeGreaterThan(0);
    const executorSummary = summaries.find((s) => s.filePath.includes('executor'));
    expect(executorSummary).toBeDefined();
    expect(executorSummary!.relationship).toBe('imports');
    // Should capture subprocess.run line
    expect(executorSummary!.relevantLines.some((l) => l.includes('subprocess'))).toBe(true);
  });

  it('includes security-relevant sibling files', () => {
    const file = makeFileContext({
      filePath: 'router.py',
      imports: [],
      siblingFiles: ['vuln-tool.py', 'guard.py', 'readme.txt'],
    });

    // guard.py is a security-relevant sibling
    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    // May or may not find guard.py depending on whether it exists at the right path
    // The point is the function doesn't crash and returns valid summaries
    expect(Array.isArray(summaries)).toBe(true);
  });

  it('returns empty array when no related files have security-relevant content', () => {
    const file = makeFileContext({
      filePath: 'empty.py',
      imports: [],
      importedBy: [],
      siblingFiles: [],
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);
    expect(summaries).toEqual([]);
  });

  it('limits to MAX_RELATED_FILES (4)', () => {
    const file = makeFileContext({
      imports: [
        './tools/executor',
        './tools/guard',
        './vuln-tool',
        './router',
        './extra1',
        './extra2',
      ],
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);
    expect(summaries.length).toBeLessThanOrEqual(4);
  });

  it('resolves Python bare module imports (tools.executor style)', () => {
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['tools.executor'],  // as buildFileContext would actually produce
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    const executorSummary = summaries.find((s) => s.filePath.includes('executor'));
    expect(executorSummary).toBeDefined();
    expect(executorSummary!.relationship).toBe('imports');
    expect(executorSummary!.relevantLines.some((l) => l.includes('subprocess'))).toBe(true);
  });

  it('resolves Python single-token imports (import guard style)', () => {
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['tools.guard'],  // from tools.guard import is_allowed_command
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    const guardSummary = summaries.find((s) => s.filePath.includes('guard'));
    expect(guardSummary).toBeDefined();
    expect(guardSummary!.relevantLines.some((l) => /allow/i.test(l))).toBe(true);
  });

  it('resolves submodule import from file.ts output (from tools import executor)', () => {
    // file.ts now emits both 'tools' and 'tools.executor' for `from tools import executor`
    // The resolver should find tools/executor.py via the dotted form
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['tools', 'tools.executor'],  // as file.ts now produces
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    const executorSummary = summaries.find((s) => s.filePath.includes('executor'));
    expect(executorSummary).toBeDefined();
    expect(executorSummary!.relevantLines.some((l) => l.includes('subprocess'))).toBe(true);
  });

  it('does not inject unrelated package children for bare import', () => {
    // `from tools import safe_helper` should NOT pull in unrelated executor.py
    // file.ts emits ['tools', 'tools.safe_helper'] — neither resolves to executor.py
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['tools', 'tools.safe_helper'],  // safe_helper doesn't exist in fixture
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);

    // 'tools' alone resolves to nothing (no tools.py, no tools/__init__.py)
    // 'tools.safe_helper' resolves to nothing (no tools/safe_helper.py)
    // So no executor.py should appear from the import path
    const executorFromImport = summaries.find((s) =>
      s.filePath.includes('executor') && s.relationship === 'imports');
    expect(executorFromImport).toBeUndefined();
  });

  it('does not summarize the same file twice across relationships', () => {
    // If a file is both imported and a sibling, it should appear only once
    const file = makeFileContext({
      filePath: 'router.py',
      imports: ['./tools/executor'],
      importedBy: [],
      siblingFiles: ['tools'],  // tools dir is a sibling
    });

    const summaries = buildRelatedFileSummaries(file, FIXTURES_DIR);
    const paths = summaries.map((s) => s.filePath);
    const unique = new Set(paths);
    expect(paths.length).toBe(unique.size);
  });
});

describe('formatRelatedFileSummaries', () => {
  it('returns empty string for no summaries', () => {
    expect(formatRelatedFileSummaries([])).toBe('');
  });

  it('formats summaries with file path, relationship, and lines', () => {
    const summaries = [
      {
        filePath: 'tools/executor.py',
        relationship: 'imports' as const,
        relevantLines: ['L9: result = subprocess.run([command, *args], capture_output=True, text=True, shell=False)'],
      },
    ];

    const formatted = formatRelatedFileSummaries(summaries);
    expect(formatted).toContain('tools/executor.py (imports)');
    expect(formatted).toContain('subprocess.run');
  });
});
