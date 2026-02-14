import { describe, it, expect } from 'vitest';
import { levenshteinDistance, findSimilarPackages, checkDependencyConfusion } from '../src/typosquat.js';

describe('levenshteinDistance', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshteinDistance('lodash', 'lodash')).toBe(0);
  });

  it('returns correct distance for single character difference', () => {
    expect(levenshteinDistance('lodash', 'lodas')).toBe(1);
    expect(levenshteinDistance('express', 'expresss')).toBe(1);
    expect(levenshteinDistance('react', 'reakt')).toBe(1);
  });

  it('returns correct distance for multiple differences', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
    expect(levenshteinDistance('abc', 'xyz')).toBe(3);
  });

  it('handles empty strings', () => {
    expect(levenshteinDistance('', '')).toBe(0);
    expect(levenshteinDistance('', 'hello')).toBe(5);
    expect(levenshteinDistance('hello', '')).toBe(5);
  });

  it('is symmetric', () => {
    expect(levenshteinDistance('abc', 'def')).toBe(levenshteinDistance('def', 'abc'));
  });
});

describe('findSimilarPackages', () => {
  it('finds typosquatting candidates for npm packages', () => {
    const results = findSimilarPackages('expresss', 'npm');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('express');
    expect(results[0].distance).toBe(1);
    expect(results[0].warning).toContain('typosquatting');
  });

  it('finds typosquatting candidates for pypi packages', () => {
    const results = findSimilarPackages('requets', 'pypi');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('requests');
    expect(results[0].distance).toBeLessThanOrEqual(2);
  });

  it('returns empty for exact matches', () => {
    const results = findSimilarPackages('express', 'npm');
    expect(results.length).toBe(0);
  });

  it('returns empty for unknown ecosystems', () => {
    const results = findSimilarPackages('something', 'unknown');
    expect(results.length).toBe(0);
  });

  it('returns empty for very different names', () => {
    const results = findSimilarPackages('xyzzy-totally-unrelated', 'npm');
    expect(results.length).toBe(0);
  });

  it('respects maxDistance parameter', () => {
    const loose = findSimilarPackages('reqest', 'npm', 3);
    const strict = findSimilarPackages('reqest', 'npm', 1);
    expect(loose.length).toBeGreaterThanOrEqual(strict.length);
  });

  it('respects limit parameter', () => {
    const results = findSimilarPackages('re', 'npm', 10, 2);
    expect(results.length).toBeLessThanOrEqual(2);
  });

  it('sorts by distance then alphabetically', () => {
    const results = findSimilarPackages('expresss', 'npm', 3);
    for (let i = 1; i < results.length; i++) {
      if (results[i].distance === results[i - 1].distance) {
        expect(results[i].name.localeCompare(results[i - 1].name)).toBeGreaterThanOrEqual(0);
      } else {
        expect(results[i].distance).toBeGreaterThanOrEqual(results[i - 1].distance);
      }
    }
  });
});

describe('checkDependencyConfusion', () => {
  it('flags scoped packages containing known public packages', () => {
    const result = checkDependencyConfusion('@company/express');
    expect(result.risk).toBe(true);
    expect(result.warning).toContain('express');
    expect(result.warning).toContain('known public package');
  });

  it('flags scoped packages with internal naming pattern', () => {
    const result = checkDependencyConfusion('@acme/my-utils');
    expect(result.risk).toBe(true);
    expect(result.warning).toContain('internal naming pattern');
  });

  it('flags internal-prefixed packages', () => {
    const prefixes = ['internal-', 'private-', 'corp-', 'company-'];
    for (const prefix of prefixes) {
      const result = checkDependencyConfusion(`${prefix}auth`);
      expect(result.risk).toBe(true);
      expect(result.warning).toContain(prefix);
    }
  });

  it('does not flag normal public packages', () => {
    const result = checkDependencyConfusion('my-normal-package');
    expect(result.risk).toBe(false);
    expect(result.warning).toBeNull();
  });
});
