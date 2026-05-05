import { describe, it, expect } from 'vitest';
import { buildPurl, parsePurl, ECOSYSTEM_TO_PURL_TYPE } from '../src/lib/purl.js';

describe('purl', () => {
  describe('buildPurl', () => {
    it('builds npm purl', () => {
      expect(buildPurl('npm', 'express', '4.18.2')).toBe('pkg:npm/express@4.18.2');
    });

    it('builds scoped npm purl', () => {
      const purl = buildPurl('npm', '@types/node', '20.10.0');
      expect(purl).toBe('pkg:npm/%40types/node@20.10.0');
    });

    it('builds pypi purl', () => {
      expect(buildPurl('pypi', 'flask', '2.3.3')).toBe('pkg:pypi/flask@2.3.3');
    });

    it('builds rubygems purl', () => {
      expect(buildPurl('rubygems', 'rails', '7.1.2')).toBe('pkg:gem/rails@7.1.2');
    });

    it('builds crates purl', () => {
      expect(buildPurl('crates', 'serde', '1.0.193')).toBe('pkg:cargo/serde@1.0.193');
    });

    it('builds go purl with full module path', () => {
      expect(buildPurl('go', 'github.com/gin-gonic/gin', 'v1.9.1'))
        .toBe('pkg:golang/github.com/gin-gonic/gin@v1.9.1');
    });

    it('builds maven purl with namespace', () => {
      expect(buildPurl('java', 'spring-boot-starter-web', '3.2.0', 'org.springframework.boot'))
        .toBe('pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.0');
    });

    it('builds purl without version', () => {
      expect(buildPurl('npm', 'express')).toBe('pkg:npm/express');
    });

    it('returns empty string for empty name', () => {
      expect(buildPurl('npm', '', '1.0.0')).toBe('');
    });

    it('handles dart ecosystem', () => {
      expect(buildPurl('dart', 'flutter_bloc', '8.1.3')).toBe('pkg:pub/flutter_bloc@8.1.3');
    });

    it('handles unknown ecosystem gracefully', () => {
      expect(buildPurl('unknown', 'foo', '1.0')).toBe('pkg:unknown/foo@1.0');
    });
  });

  describe('parsePurl', () => {
    it('parses simple npm purl', () => {
      const result = parsePurl('pkg:npm/express@4.18.2');
      expect(result).toEqual({ type: 'npm', name: 'express', version: '4.18.2' });
    });

    it('parses scoped npm purl', () => {
      const result = parsePurl('pkg:npm/%40types/node@20.10.0');
      expect(result).toEqual({ type: 'npm', namespace: '@types', name: 'node', version: '20.10.0' });
    });

    it('parses maven purl with namespace', () => {
      const result = parsePurl('pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.0');
      expect(result).toEqual({
        type: 'maven',
        namespace: 'org.springframework.boot',
        name: 'spring-boot-starter-web',
        version: '3.2.0',
      });
    });

    it('parses purl without version', () => {
      const result = parsePurl('pkg:npm/express');
      expect(result).toEqual({ type: 'npm', name: 'express' });
    });

    it('returns null for invalid purl', () => {
      expect(parsePurl('not-a-purl')).toBeNull();
      expect(parsePurl('')).toBeNull();
    });
  });

  describe('ECOSYSTEM_TO_PURL_TYPE', () => {
    it('has mappings for all supported ecosystems', () => {
      const expected = ['npm', 'pypi', 'rubygems', 'crates', 'go', 'java', 'dart', 'perl', 'raku'];
      for (const eco of expected) {
        expect(ECOSYSTEM_TO_PURL_TYPE).toHaveProperty(eco);
      }
    });
  });
});
