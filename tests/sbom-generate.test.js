import { describe, it, expect } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { sbomGenerate } from '../src/tools/sbom-generate.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-gen-'));
}

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

describe('sbom-generate', () => {
  it('generates SBOM from package-lock.json with compact verbosity', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    return sbomGenerate({ directory_path: tmp, verbosity: 'compact' }).then(result => {
      const output = parseResult(result);
      expect(output.total_components).toBeGreaterThanOrEqual(5);
      expect(output.ecosystems).toContain('npm');
      expect(output.components.npm).toBeDefined();
      expect(output.components.npm.length).toBeGreaterThanOrEqual(5);

      const express = output.components.npm.find(c => c.name === 'express');
      expect(express.version).toBe('4.18.2');

      rmSync(tmp, { recursive: true });
    });
  });

  it('generates SBOM with minimal verbosity', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    return sbomGenerate({ directory_path: tmp, verbosity: 'minimal' }).then(result => {
      const output = parseResult(result);
      expect(output.total_components).toBeGreaterThanOrEqual(5);
      expect(output.ecosystems).toContain('npm');
      // minimal should NOT include component details
      expect(output.components).toBeUndefined();

      rmSync(tmp, { recursive: true });
    });
  });

  it('generates full CycloneDX BOM with full verbosity', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    return sbomGenerate({ directory_path: tmp, verbosity: 'full' }).then(result => {
      const output = parseResult(result);
      expect(output.bom).toBeDefined();
      expect(output.bom.bomFormat).toBe('CycloneDX');
      expect(output.bom.specVersion).toBe('1.5');
      expect(output.bom.components.length).toBeGreaterThanOrEqual(5);

      rmSync(tmp, { recursive: true });
    });
  });

  it('saves SBOM to output_path', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));
    const outPath = join(tmp, '.scanner', 'sbom.json');

    return sbomGenerate({ directory_path: tmp, output_path: outPath, verbosity: 'minimal' }).then(result => {
      const output = parseResult(result);
      expect(output.saved_to).toBe(outPath);
      expect(existsSync(outPath)).toBe(true);

      const saved = JSON.parse(readFileSync(outPath, 'utf-8'));
      expect(saved.bomFormat).toBe('CycloneDX');

      rmSync(tmp, { recursive: true });
    });
  });

  it('filters dev dependencies when include_dev is false', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    return Promise.all([
      sbomGenerate({ directory_path: tmp, include_dev: true, verbosity: 'minimal' }),
      sbomGenerate({ directory_path: tmp, include_dev: false, verbosity: 'minimal' }),
    ]).then(([withDev, withoutDev]) => {
      const withDevOut = parseResult(withDev);
      const withoutDevOut = parseResult(withoutDev);
      expect(withDevOut.total_components).toBeGreaterThan(withoutDevOut.total_components);

      rmSync(tmp, { recursive: true });
    });
  });

  it('returns error for non-existent directory', () => {
    return sbomGenerate({ directory_path: '/nonexistent/path' }).then(result => {
      const output = parseResult(result);
      expect(output.error).toBeDefined();
    });
  });

  it('handles empty directory gracefully', () => {
    const tmp = makeTmp();

    return sbomGenerate({ directory_path: tmp, verbosity: 'minimal' }).then(result => {
      const output = parseResult(result);
      expect(output.total_components).toBe(0);

      rmSync(tmp, { recursive: true });
    });
  });

  it('discovers multi-ecosystem project', () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));
    copyFileSync(join(fixturesDir, 'poetry.lock'), join(tmp, 'poetry.lock'));

    return sbomGenerate({ directory_path: tmp, verbosity: 'compact' }).then(result => {
      const output = parseResult(result);
      expect(output.ecosystems).toContain('npm');
      expect(output.ecosystems).toContain('pypi');
      expect(output.components.npm).toBeDefined();
      expect(output.components.pypi).toBeDefined();

      rmSync(tmp, { recursive: true });
    });
  });
});
