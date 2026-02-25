// tests/package-checker.test.js — Tests for check_package tool
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { checkPackage } from '../src/package-checker.js';
import { findSimilarPackages, checkDependencyConfusion, levenshteinDistance } from '../src/typosquat.js';

describe('checkPackage', () => {
  it('should return result for a package check', async () => {
    const result = await checkPackage({ package_name: 'express', ecosystem: 'npm' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.package).toBe('express');
    expect(parsed.ecosystem).toBe('npm');
  });

  it('should detect typosquatting for similar package names', async () => {
    const result = await checkPackage({ package_name: 'expresss', ecosystem: 'npm' });
    const parsed = JSON.parse(result.content[0].text);
    // Should find typosquatting similarities
    expect(parsed.typosquatting || parsed.status === 'heuristic-only').toBeTruthy();
  });

  it('should detect dependency confusion for scoped packages', async () => {
    const result = await checkPackage({ package_name: '@company/express', ecosystem: 'npm' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.dependency_confusion).toBeDefined();
    expect(parsed.dependency_confusion.risk).toBe(true);
  });

  it('should handle pypi ecosystem', async () => {
    const result = await checkPackage({ package_name: 'flaskk', ecosystem: 'pypi' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ecosystem).toBe('pypi');
  });

  it('should handle rubygems ecosystem', async () => {
    const result = await checkPackage({ package_name: 'raills', ecosystem: 'rubygems' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ecosystem).toBe('rubygems');
  });

  it('should handle crates ecosystem', async () => {
    const result = await checkPackage({ package_name: 'tokioo', ecosystem: 'crates' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ecosystem).toBe('crates');
  });
});

describe('findSimilarPackages', () => {
  it('should find packages similar to a typo', () => {
    const similar = findSimilarPackages('expresss', 'npm');
    expect(similar.length).toBeGreaterThan(0);
    expect(similar[0].name).toBe('express');
    expect(similar[0].distance).toBe(1);
  });

  it('should not match packages that are too different', () => {
    const similar = findSimilarPackages('zzzzzzzzz', 'npm');
    expect(similar.length).toBe(0);
  });

  it('should not return exact matches', () => {
    const similar = findSimilarPackages('express', 'npm');
    expect(similar.every(s => s.name !== 'express')).toBe(true);
  });

  it('should return results sorted by distance', () => {
    const similar = findSimilarPackages('reques', 'pypi');
    if (similar.length >= 2) {
      expect(similar[0].distance).toBeLessThanOrEqual(similar[1].distance);
    }
  });

  it('should respect maxDistance parameter', () => {
    const similar = findSimilarPackages('expresss', 'npm', 1);
    expect(similar.every(s => s.distance <= 1)).toBe(true);
  });

  it('should respect limit parameter', () => {
    const similar = findSimilarPackages('reac', 'npm', 3, 2);
    expect(similar.length).toBeLessThanOrEqual(2);
  });

  it('should handle unknown ecosystems', () => {
    const similar = findSimilarPackages('express', 'unknown_eco');
    expect(similar).toEqual([]);
  });
});

describe('checkDependencyConfusion', () => {
  it('should flag scoped packages with known unscoped names', () => {
    const result = checkDependencyConfusion('@company/express');
    expect(result.risk).toBe(true);
    expect(result.warning).toContain('express');
  });

  it('should flag internal-prefixed packages', () => {
    const result = checkDependencyConfusion('internal-auth');
    expect(result.risk).toBe(true);
    expect(result.warning).toContain('internal-');
  });

  it('should flag private-prefixed packages', () => {
    const result = checkDependencyConfusion('private-utils');
    expect(result.risk).toBe(true);
  });

  it('should not flag regular package names', () => {
    const result = checkDependencyConfusion('my-awesome-lib');
    expect(result.risk).toBe(false);
  });
});

describe('levenshteinDistance', () => {
  it('should return 0 for identical strings', () => {
    expect(levenshteinDistance('hello', 'hello')).toBe(0);
  });

  it('should return 1 for single character difference', () => {
    expect(levenshteinDistance('hello', 'helo')).toBe(1);
  });

  it('should return string length for empty comparison', () => {
    expect(levenshteinDistance('', 'hello')).toBe(5);
    expect(levenshteinDistance('hello', '')).toBe(5);
  });

  it('should be commutative', () => {
    expect(levenshteinDistance('abc', 'axc')).toBe(levenshteinDistance('axc', 'abc'));
  });

  it('should handle substitutions', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
  });
});

describe('scan_packages integration', () => {
  let scanPackages, extractPackages;
  const TMP = join(import.meta.dirname, '..', '.tmp-test-scanpkg');

  beforeAll(async () => {
    const mod = await import('../src/scan-packages.js');
    scanPackages = mod.scanPackages;
    extractPackages = mod.extractPackages;
    mkdirSync(TMP, { recursive: true });
  });
  afterAll(() => { try { rmSync(TMP, { recursive: true }); } catch {} });

  it('should extract npm imports', () => {
    const pkgs = extractPackages(`
const express = require('express');
import lodash from 'lodash';
import fs from 'fs';
`, 'npm');
    expect(pkgs).toContain('express');
    expect(pkgs).toContain('lodash');
  });

  it('should extract Python imports', () => {
    const pkgs = extractPackages(`
import flask
from requests import get
import os
`, 'pypi');
    expect(pkgs).toContain('flask');
    expect(pkgs).toContain('requests');
  });

  it('should handle scan_packages on a file', async () => {
    const file = join(TMP, 'imports.js');
    writeFileSync(file, `
const express = require('express');
const lodash = require('lodash');
`);
    const result = await scanPackages({ file_path: file, ecosystem: 'npm', verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.total_packages_found).toBeGreaterThanOrEqual(2);
  });

  it('should return error for non-existent file', async () => {
    const result = await scanPackages({ file_path: '/nonexistent.js', ecosystem: 'npm' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('File not found');
  });

  it('should support minimal verbosity', async () => {
    const file = join(TMP, 'min.js');
    writeFileSync(file, `const x = require('express');`);
    const result = await scanPackages({ file_path: file, ecosystem: 'npm', verbosity: 'minimal' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('total');
    expect(parsed).toHaveProperty('message');
  });

  it('should filter out relative imports', () => {
    const pkgs = extractPackages(`
const a = require('./local');
const b = require('../parent');
const c = require('express');
`, 'npm');
    expect(pkgs).not.toContain('./local');
    expect(pkgs).not.toContain('../parent');
    expect(pkgs).toContain('express');
  });

  it('should handle Rust/crates imports', () => {
    const pkgs = extractPackages(`
use tokio;
extern crate serde;
use std;
`, 'crates');
    expect(pkgs).toContain('tokio');
    expect(pkgs).toContain('serde');
  });
});
