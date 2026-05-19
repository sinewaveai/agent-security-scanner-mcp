import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

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

// Regression: scan-project blanket dotfile skip missed security-relevant
// dotpaths such as .github/. See issue #68.
describe('scan-project dotpath traversal', () => {
  let tmp;

  afterEach(() => {
    if (tmp) {
      try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
      tmp = undefined;
    }
  });

  it('scans scannable files inside security-relevant dotpaths (.github)', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    tmp = mkdtempSync(join(tmpdir(), 'scanproj-dotpath-'));
    mkdirSync(join(tmp, '.github', 'scripts'), { recursive: true });
    writeFileSync(
      join(tmp, '.github', 'scripts', 'deploy.py'),
      'import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n'
    );

    const result = await scanProject({ directory_path: tmp, verbosity: 'full' });
    const output = JSON.parse(result.content[0].text);
    expect(output.scanned_files).toContain(join('.github', 'scripts', 'deploy.py'));
  }, 30000);

  it('still prunes .git and other heavy directories', async () => {
    const { scanProject } = await import('../src/tools/scan-project.js');
    tmp = mkdtempSync(join(tmpdir(), 'scanproj-deny-'));

    mkdirSync(join(tmp, '.git', 'hooks'), { recursive: true });
    writeFileSync(join(tmp, '.git', 'hooks', 'evil.py'), 'import os\nos.system("rm -rf /tmp/x")\n');

    mkdirSync(join(tmp, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(tmp, 'node_modules', 'pkg', 'index.js'), 'eval(globalThis.userInput)\n');

    // A real source file so the scan has something to traverse.
    writeFileSync(join(tmp, 'app.py'), 'print("hello")\n');

    const result = await scanProject({ directory_path: tmp, verbosity: 'full' });
    const output = JSON.parse(result.content[0].text);
    const scanned = output.scanned_files || [];
    expect(scanned.some(f => f.split(/[\\/]/).includes('.git'))).toBe(false);
    expect(scanned.some(f => f.split(/[\\/]/).includes('node_modules'))).toBe(false);
    expect(scanned).toContain('app.py');
  }, 30000);
});
