import { describe, it, expect } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { sbomDiff } from '../src/tools/sbom-diff.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-diff-'));
}

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

describe('sbom-diff', () => {
  it('reports no baseline found when none exists', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomDiff({ directory_path: tmp });
    const output = parseResult(result);
    expect(output.message).toContain('No baseline found');
    expect(output.current.total_components).toBeGreaterThan(0);

    rmSync(tmp, { recursive: true });
  });

  it('saves baseline and reports save path', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomDiff({ directory_path: tmp, save_baseline: true });
    const output = parseResult(result);
    expect(output.baseline_saved).toBeDefined();
    expect(existsSync(output.baseline_saved)).toBe(true);

    rmSync(tmp, { recursive: true });
  });

  it('detects no changes when baseline matches current', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    // First run: save baseline
    await sbomDiff({ directory_path: tmp, save_baseline: true });

    // Second run: compare (same lock file)
    const result = await sbomDiff({ directory_path: tmp, verbosity: 'minimal' });
    const output = parseResult(result);

    expect(output.added).toBe(0);
    expect(output.removed).toBe(0);
    expect(output.version_changed).toBe(0);
    expect(output.unchanged).toBeGreaterThan(0);

    rmSync(tmp, { recursive: true });
  });

  it('detects added and removed packages', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    // Save baseline with v2 lock file (express, lodash, mocha, body-parser, accepts)
    await sbomDiff({ directory_path: tmp, save_baseline: true });

    // Replace with v3 lock file (axios, zod, vitest, follow-redirects)
    copyFileSync(join(fixturesDir, 'package-lock-v3.json'), join(tmp, 'package-lock.json'));

    const result = await sbomDiff({ directory_path: tmp, verbosity: 'compact' });
    const output = parseResult(result);

    expect(output.added_packages.length).toBeGreaterThan(0);
    expect(output.removed_packages.length).toBeGreaterThan(0);
    expect(output.summary).toMatch(/\+\d+ added, -\d+ removed/);

    rmSync(tmp, { recursive: true });
  });

  it('returns error for non-existent directory', async () => {
    const result = await sbomDiff({ directory_path: '/nonexistent/path' });
    const output = parseResult(result);
    expect(output.error).toBeDefined();
  });

  it('first-run save_baseline returns save message, not zero-diff', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomDiff({ directory_path: tmp, save_baseline: true });
    const output = parseResult(result);

    // Should return a save message, not a diff result
    expect(output.message).toContain('Baseline saved');
    expect(output.message).toContain('Run again to compare');
    expect(output.baseline_saved).toBeDefined();
    // Should NOT have diff fields
    expect(output.added).toBeUndefined();
    expect(output.unchanged).toBeUndefined();
    expect(output.summary).toBeUndefined();

    rmSync(tmp, { recursive: true });
  });

  it('supports custom baseline_path', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));
    const customBaseline = join(tmp, 'custom-baseline.json');

    await sbomDiff({ directory_path: tmp, baseline_path: customBaseline, save_baseline: true });
    expect(existsSync(customBaseline)).toBe(true);

    const result = await sbomDiff({ directory_path: tmp, baseline_path: customBaseline, verbosity: 'full' });
    const output = parseResult(result);
    expect(output.unchanged_count).toBeGreaterThan(0);
    expect(output.baseline_timestamp).toBeDefined();

    rmSync(tmp, { recursive: true });
  });
});
