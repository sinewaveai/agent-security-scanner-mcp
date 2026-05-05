import { describe, it, expect } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { loadPackageLists } from '../src/tools/check-package.js';
import { sbomCheckHallucinations } from '../src/tools/sbom-hallucinations.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

// Load package lists once for all tests
loadPackageLists();

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-hall-'));
}

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

describe('sbom-hallucinations', () => {
  it('errors when both directory_path and sbom_path provided', async () => {
    const result = await sbomCheckHallucinations({ directory_path: '.', sbom_path: './sbom.json' });
    const output = parseResult(result);
    expect(output.error).toContain('not both');
  });

  it('errors when neither provided', async () => {
    const result = await sbomCheckHallucinations({});
    const output = parseResult(result);
    expect(output.error).toContain('Provide either');
  });

  it('reports unsupported ecosystems for Go packages', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'go.sum'), join(tmp, 'go.sum'));

    const result = await sbomCheckHallucinations({ directory_path: tmp, verbosity: 'compact' });
    const output = parseResult(result);

    expect(output.unsupported_count).toBeGreaterThan(0);
    expect(output.unsupported_packages.length).toBeGreaterThan(0);
    expect(output.unsupported_packages[0].status).toBe('unsupported_ecosystem');
    expect(output.unsupported_packages[0].ecosystem).toBe('go');
    expect(output.unsupported_packages[0].message).toContain('not available');

    rmSync(tmp, { recursive: true });
  });

  it('reports unsupported ecosystems for Java packages', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'pom.xml'), join(tmp, 'pom.xml'));

    const result = await sbomCheckHallucinations({ directory_path: tmp, verbosity: 'compact' });
    const output = parseResult(result);

    expect(output.unsupported_count).toBeGreaterThan(0);
    expect(output.unsupported_packages.some(p => p.ecosystem === 'java')).toBe(true);

    rmSync(tmp, { recursive: true });
  });

  it('checks npm packages against registry', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomCheckHallucinations({ directory_path: tmp, verbosity: 'minimal' });
    const output = parseResult(result);

    expect(output.total_checked).toBeGreaterThan(0);
    expect(output.legitimate_count).toBeGreaterThan(0);
    // All packages in the v2 fixture are real npm packages
    expect(output.hallucinated_count).toBe(0);

    rmSync(tmp, { recursive: true });
  });
});
