import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { queryBatch, scoreToLevel } from '../src/lib/osv-client.js';

describe('osv-client', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('queryBatch', () => {
    it('sends correct request format to OSV API', async () => {
      let capturedBody;
      globalThis.fetch = async (url, opts) => {
        capturedBody = JSON.parse(opts.body);
        return {
          ok: true,
          json: async () => ({ results: [{ vulns: [] }] }),
        };
      };

      await queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);

      expect(capturedBody.queries).toHaveLength(1);
      expect(capturedBody.queries[0].package.name).toBe('lodash');
      expect(capturedBody.queries[0].package.ecosystem).toBe('npm');
      expect(capturedBody.queries[0].version).toBe('4.17.20');
    });

    it('maps ecosystem names to OSV format', async () => {
      let capturedBody;
      globalThis.fetch = async (url, opts) => {
        capturedBody = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ results: [{vulns:[]}, {vulns:[]}, {vulns:[]}] }) };
      };

      await queryBatch([
        { name: 'flask', version: '2.0.0', ecosystem: 'pypi' },
        { name: 'rails', version: '7.0.0', ecosystem: 'rubygems' },
        { name: 'serde', version: '1.0.0', ecosystem: 'crates' },
      ]);

      expect(capturedBody.queries[0].package.ecosystem).toBe('PyPI');
      expect(capturedBody.queries[1].package.ecosystem).toBe('RubyGems');
      expect(capturedBody.queries[2].package.ecosystem).toBe('crates.io');
    });

    it('returns mapped vulnerabilities', async () => {
      globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({
          results: [{
            vulns: [{
              id: 'GHSA-xxxx-yyyy-zzzz',
              aliases: ['CVE-2021-23337'],
              summary: 'Prototype Pollution in lodash',
              severity: [{ type: 'CVSS_V3', score: 7.5 }],
              affected: [{
                package: { name: 'lodash' },
                ranges: [{ events: [{ fixed: '4.17.21' }] }],
              }],
            }],
          }],
        }),
      });

      const results = await queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);

      expect(results.size).toBe(1);
      const vulns = [...results.values()][0];
      expect(vulns[0].id).toBe('CVE-2021-23337');
      expect(vulns[0].ratings[0].severity).toBe('high');
      expect(vulns[0].recommendation).toBe('Upgrade to 4.17.21');
    });

    it('handles network errors gracefully', async () => {
      globalThis.fetch = async () => { throw new Error('Network error'); };

      const results = await queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
      expect(results.size).toBe(0);
    });

    it('handles non-ok response gracefully', async () => {
      globalThis.fetch = async () => ({ ok: false, status: 500 });

      const results = await queryBatch([{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]);
      expect(results.size).toBe(0);
    });

    it('uses cache on repeated queries', async () => {
      const tmp = mkdtempSync(join(tmpdir(), 'osv-cache-'));
      let fetchCount = 0;

      globalThis.fetch = async () => {
        fetchCount++;
        return {
          ok: true,
          json: async () => ({ results: [{ vulns: [{ id: 'OSV-1', aliases: ['CVE-2024-0001'], summary: 'test' }] }] }),
        };
      };

      const pkg = [{ name: 'test-pkg', version: '1.0.0', ecosystem: 'npm' }];
      await queryBatch(pkg, { cacheDir: tmp });
      const firstCount = fetchCount;

      await queryBatch(pkg, { cacheDir: tmp });
      expect(fetchCount).toBe(firstCount); // no new fetch — cache hit

      rmSync(tmp, { recursive: true });
    });

    it('returns empty map for empty package list', async () => {
      const results = await queryBatch([]);
      expect(results.size).toBe(0);
    });

    it('keeps namespaced Maven packages distinct in query and result keys', async () => {
      let capturedBody;
      globalThis.fetch = async (url, opts) => {
        capturedBody = JSON.parse(opts.body);
        return {
          ok: true,
          json: async () => ({
            results: [
              { vulns: [{ id: 'OSV-1', summary: 'first' }] },
              { vulns: [{ id: 'OSV-2', summary: 'second' }] },
            ],
          }),
        };
      };

      const results = await queryBatch([
        { name: 'core', version: '1.0.0', ecosystem: 'java', namespace: 'com.foo', purl: 'pkg:maven/com.foo/core@1.0.0' },
        { name: 'core', version: '1.0.0', ecosystem: 'java', namespace: 'org.bar', purl: 'pkg:maven/org.bar/core@1.0.0' },
      ]);

      expect(capturedBody.queries[0].package.name).toBe('com.foo:core');
      expect(capturedBody.queries[1].package.name).toBe('org.bar:core');
      expect([...results.keys()]).toEqual([
        'pkg:maven/com.foo/core@1.0.0',
        'pkg:maven/org.bar/core@1.0.0',
      ]);
      expect(results.get('pkg:maven/com.foo/core@1.0.0')[0].id).toBe('OSV-1');
      expect(results.get('pkg:maven/org.bar/core@1.0.0')[0].id).toBe('OSV-2');
    });
  });

  describe('scoreToLevel', () => {
    it('maps CVSS scores to severity levels', () => {
      expect(scoreToLevel(9.8)).toBe('critical');
      expect(scoreToLevel(9.0)).toBe('critical');
      expect(scoreToLevel(7.5)).toBe('high');
      expect(scoreToLevel(7.0)).toBe('high');
      expect(scoreToLevel(5.0)).toBe('medium');
      expect(scoreToLevel(4.0)).toBe('medium');
      expect(scoreToLevel(2.5)).toBe('low');
      expect(scoreToLevel(0.1)).toBe('low');
      expect(scoreToLevel(0)).toBe('unknown');
    });
  });
});
