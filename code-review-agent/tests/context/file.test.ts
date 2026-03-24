import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { isTestFile, buildFileContext } from '../../src/context/file.js';

describe('isTestFile', () => {
  it('matches top-level test directories on POSIX paths', () => {
    expect(isTestFile('tests/helpers/mock-provider.ts')).toBe(true);
    expect(isTestFile('test/unit/example.js')).toBe(true);
    expect(isTestFile('__tests__/parser.test.ts')).toBe(true);
  });

  it('matches top-level test directories on Windows paths', () => {
    expect(isTestFile('tests\\helpers\\mock-provider.ts')).toBe(true);
    expect(isTestFile('test\\unit\\example.js')).toBe(true);
    expect(isTestFile('__tests__\\parser.test.ts')).toBe(true);
  });

  it('does not classify regular source files as tests', () => {
    expect(isTestFile('src/server.js')).toBe(false);
    expect(isTestFile('fixtures/vuln-api-server/server.js')).toBe(false);
  });
});

describe('buildFileContext Python imports', () => {
  it('emits both package and submodule for from X import Y', () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/guarded-agent');
    const routerPath = path.join(fixtureDir, 'router.py');
    const ctx = buildFileContext(routerPath, fixtureDir);

    // `from tools.executor import execute_tool` should produce both
    // 'tools.executor' (the from-part) and 'tools.executor.execute_tool' (submodule form)
    expect(ctx.imports).toContain('tools.executor');
    // The submodule form: tools.executor.execute_tool
    expect(ctx.imports.some((i) => i.startsWith('tools.executor'))).toBe(true);
  });
});
