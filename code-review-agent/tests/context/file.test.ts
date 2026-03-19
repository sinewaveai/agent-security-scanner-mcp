import { describe, it, expect } from 'vitest';
import { isTestFile } from '../../src/context/file.js';

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
