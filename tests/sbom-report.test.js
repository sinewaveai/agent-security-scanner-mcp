import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { sbomExportReport } from '../src/tools/sbom-report.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-report-'));
}

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

describe('sbom-report', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    // Mock fetch to avoid real OSV calls
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ results: Array(10).fill({ vulns: [] }) }),
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('errors when both directory_path and sbom_path provided', async () => {
    const result = await sbomExportReport({ directory_path: '.', sbom_path: './sbom.json' });
    const output = parseResult(result);
    expect(output.error).toContain('not both');
  });

  it('generates HTML report and saves to output_path', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));
    const outPath = join(tmp, 'report.html');

    const result = await sbomExportReport({
      directory_path: tmp,
      format: 'html',
      output_path: outPath,
      verbosity: 'minimal',
    });
    const output = parseResult(result);

    expect(output.total_components).toBeGreaterThan(0);
    expect(output.saved_to).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);

    const html = readFileSync(outPath, 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('SBOM Report');
    expect(html).toContain('CycloneDX');

    rmSync(tmp, { recursive: true });
  });

  it('generates JSON report', async () => {
    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomExportReport({
      directory_path: tmp,
      format: 'json',
    });
    const output = parseResult(result);

    expect(output.bom).toBeDefined();
    expect(output.bom.bomFormat).toBe('CycloneDX');
    expect(output.total_components).toBeGreaterThan(0);

    rmSync(tmp, { recursive: true });
  });

  it('works from saved SBOM file', async () => {
    const tmp = makeTmp();
    const sbomPath = join(tmp, 'sbom.json');
    writeFileSync(sbomPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: { component: { name: 'test-from-file', version: '1.0.0' } },
      components: [
        { name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', properties: [{ name: 'cdx:ecosystem', value: 'npm' }] },
        { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', properties: [{ name: 'cdx:ecosystem', value: 'npm' }] },
      ],
    }));

    const result = await sbomExportReport({
      sbom_path: sbomPath,
      format: 'json',
    });
    const output = parseResult(result);
    expect(output.project).toBe('test-from-file');
    expect(output.total_components).toBe(2);

    rmSync(tmp, { recursive: true });
  });

  it('includes vulnerability data when include_vulnerabilities is true', async () => {
    // Mock with actual vulnerability data
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        results: [
          { vulns: [{ id: 'GHSA-1', aliases: ['CVE-2024-0001'], summary: 'test', severity: [{ type: 'CVSS_V3', score: 7.5 }] }] },
          ...Array(4).fill({ vulns: [] }),
        ],
      }),
    });

    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomExportReport({
      directory_path: tmp,
      format: 'json',
      include_vulnerabilities: true,
    });
    const output = parseResult(result);

    expect(output.total_vulnerabilities).toBeGreaterThan(0);
    expect(output.vulnerabilities.length).toBeGreaterThan(0);

    rmSync(tmp, { recursive: true });
  });

  it('preserves Maven namespace and canonical PURL when enriching a saved SBOM report', async () => {
    let capturedBody;
    globalThis.fetch = async (url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => ({
          results: [{
            vulns: [{ id: 'GHSA-java-1', summary: 'java vuln' }],
          }],
        }),
      };
    };

    const tmp = makeTmp();
    const sbomPath = join(tmp, 'sbom.json');
    writeFileSync(sbomPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: { component: { name: 'java-report', version: '1.0.0' } },
      components: [{
        name: 'guava',
        version: '32.1.3-jre',
        group: 'com.google.guava',
        purl: 'pkg:maven/com.google.guava/guava@32.1.3-jre',
        properties: [{ name: 'cdx:ecosystem', value: 'java' }],
      }],
    }));

    const result = await sbomExportReport({
      sbom_path: sbomPath,
      format: 'json',
      include_vulnerabilities: true,
    });
    const output = parseResult(result);

    expect(capturedBody.queries[0].package.name).toBe('com.google.guava:guava');
    expect(output.vulnerabilities[0].affects[0].ref).toBe('pkg:maven/com.google.guava/guava@32.1.3-jre');

    rmSync(tmp, { recursive: true });
  });
});
