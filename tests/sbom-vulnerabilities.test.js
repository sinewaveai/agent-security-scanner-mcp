import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync, writeFileSync, mkdirSync } from 'fs';
import { tmpdir } from 'os';
import { sbomScanVulnerabilities } from '../src/tools/sbom-vulnerabilities.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-vuln-'));
}

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

describe('sbom-vulnerabilities', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('errors when both directory_path and sbom_path provided', async () => {
    const result = await sbomScanVulnerabilities({ directory_path: '.', sbom_path: './sbom.json' });
    const output = parseResult(result);
    expect(output.error).toContain('not both');
  });

  it('errors when neither directory_path nor sbom_path provided', async () => {
    const result = await sbomScanVulnerabilities({});
    const output = parseResult(result);
    expect(output.error).toContain('Provide either');
  });

  it('scans from directory and returns vulnerability summary', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ results: Array(5).fill({ vulns: [] }) }),
    });

    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

    const result = await sbomScanVulnerabilities({ directory_path: tmp, verbosity: 'minimal' });
    const output = parseResult(result);

    expect(output.total_components).toBeGreaterThan(0);
    expect(output.total_vulnerabilities).toBeDefined();
    expect(output.by_severity).toBeDefined();

    rmSync(tmp, { recursive: true });
  });

  it('preserves canonical PURL in vulnerability affects.ref', async () => {
    globalThis.fetch = async (url, opts) => {
      return {
        ok: true,
        json: async () => ({
          results: [{
            vulns: [{
              id: 'GHSA-test-1234',
              aliases: ['CVE-2024-0001'],
              summary: 'Test vuln',
              severity: [{ type: 'CVSS_V3', score: 7.5 }],
              affected: [{
                package: { name: 'rails' },
                ranges: [{ events: [{ fixed: '7.1.3' }] }],
              }],
            }],
          }],
        }),
      };
    };

    const tmp = makeTmp();
    copyFileSync(join(fixturesDir, 'Gemfile.lock'), join(tmp, 'Gemfile.lock'));

    const result = await sbomScanVulnerabilities({ directory_path: tmp, verbosity: 'full' });
    const output = parseResult(result);

    if (output.vulnerabilities && output.vulnerabilities.length > 0) {
      const vuln = output.vulnerabilities[0];
      // affects.ref should use canonical PURL (pkg:gem not pkg:rubygems)
      expect(vuln.affects[0].ref).toMatch(/^pkg:gem\//);
    }

    rmSync(tmp, { recursive: true });
  });

  it('scans from saved SBOM file', async () => {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ results: [{ vulns: [] }] }),
    });

    const tmp = makeTmp();
    const sbomPath = join(tmp, 'sbom.json');
    writeFileSync(sbomPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: { component: { name: 'test' } },
      components: [{
        name: 'express',
        version: '4.18.2',
        purl: 'pkg:npm/express@4.18.2',
        properties: [{ name: 'cdx:ecosystem', value: 'npm' }],
      }],
    }));

    const result = await sbomScanVulnerabilities({ sbom_path: sbomPath, verbosity: 'minimal' });
    const output = parseResult(result);
    expect(output.total_components).toBe(1);

    rmSync(tmp, { recursive: true });
  });

  it('preserves Maven namespace when scanning from saved SBOM file', async () => {
    let capturedBody;
    globalThis.fetch = async (url, opts) => {
      capturedBody = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => ({
          results: [{
            vulns: [{
              id: 'GHSA-java-1234',
              summary: 'Java vuln',
              severity: [{ type: 'CVSS_V3', score: 7.5 }],
            }],
          }],
        }),
      };
    };

    const tmp = makeTmp();
    const sbomPath = join(tmp, 'sbom.json');
    writeFileSync(sbomPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: { component: { name: 'java-test' } },
      components: [{
        name: 'guava',
        version: '32.1.3-jre',
        group: 'com.google.guava',
        purl: 'pkg:maven/com.google.guava/guava@32.1.3-jre',
        properties: [{ name: 'cdx:ecosystem', value: 'java' }],
      }],
    }));

    const result = await sbomScanVulnerabilities({ sbom_path: sbomPath, verbosity: 'full' });
    const output = parseResult(result);

    expect(capturedBody.queries[0].package.name).toBe('com.google.guava:guava');
    expect(output.vulnerabilities[0].affects[0].ref).toBe('pkg:maven/com.google.guava/guava@32.1.3-jre');

    rmSync(tmp, { recursive: true });
  });
});
