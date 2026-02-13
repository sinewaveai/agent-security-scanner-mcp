import { describe, it, expect } from 'vitest';
import { existsSync } from 'fs';
import { join } from 'path';

describe('scan-project module', () => {
  it('should export scanProjectSchema and scanProject', async () => {
    const mod = await import('../src/tools/scan-project.js');
    expect(mod.scanProjectSchema).toBeDefined();
    expect(mod.scanProjectSchema.directory_path).toBeDefined();
    expect(mod.scanProjectSchema.recursive).toBeDefined();
    expect(mod.scanProjectSchema.verbosity).toBeDefined();
    expect(mod.scanProjectSchema.diff_only).toBeDefined();
    expect(mod.scanProjectSchema.cross_file).toBeDefined();
    expect(typeof mod.scanProject).toBe('function');
  });

  it('should return error for non-existent directory', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    const result = await scanProject({ directory_path: '/nonexistent/path/12345', verbosity: 'minimal' });
    const output = JSON.parse(result.content[0].text);
    expect(output.error).toContain('not found');
  });

  it('should scan single fixture file with minimal verbosity', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    const fixturesDir = join(process.cwd(), 'tests', 'fixtures');
    if (!existsSync(fixturesDir)) return;

    // Use include_patterns to scan only one file for speed
    const result = await scanProject({
      directory_path: fixturesDir,
      include_patterns: ['vuln-python.py'],
      verbosity: 'minimal'
    });
    const output = JSON.parse(result.content[0].text);
    expect(output.files_scanned).toBe(1);
    expect(output.grade).toBeDefined();
    expect(['A', 'B', 'C', 'D', 'F']).toContain(output.grade);
    expect(output.total).toBeGreaterThan(0);
  }, 30000);

  it('should scan single fixture with compact verbosity', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    const fixturesDir = join(process.cwd(), 'tests', 'fixtures');
    if (!existsSync(fixturesDir)) return;

    const result = await scanProject({
      directory_path: fixturesDir,
      include_patterns: ['clean-python.py'],
      verbosity: 'compact'
    });
    const output = JSON.parse(result.content[0].text);
    expect(output.files_scanned).toBe(1);
    expect(output.grade).toBeDefined();
    expect(output.by_severity).toBeDefined();
  }, 30000);

  it('should respect include_patterns filter', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    const fixturesDir = join(process.cwd(), 'tests', 'fixtures');
    if (!existsSync(fixturesDir)) return;

    const result = await scanProject({
      directory_path: fixturesDir,
      include_patterns: ['clean-*.py'],
      verbosity: 'minimal'
    });
    const output = JSON.parse(result.content[0].text);
    // Only clean-python.py should match
    expect(output.files_scanned).toBe(1);
  }, 30000);

  it('should handle empty directory', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    const result = await scanProject({ directory_path: process.cwd(), recursive: false, include_patterns: ['**/*.xyz'], verbosity: 'minimal' });
    const output = JSON.parse(result.content[0].text);
    expect(output.files_scanned).toBe(0);
    expect(output.grade).toBe('A');
  });
});
