import { describe, it, expect, afterEach } from 'vitest';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, copyFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import {
  parsePackageLockJson,
  parseYarnLock,
  parsePnpmLock,
  parsePoetryLock,
  parsePipfileLock,
  parseCargoLock,
  parseGoSum,
  parseGemfileLock,
  parseManifestWithVersions,
  discoverDependencies,
} from '../src/lib/lockfile-parsers.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmp() {
  return mkdtempSync(join(tmpdir(), 'sbom-test-'));
}

describe('lockfile-parsers', () => {

  describe('parsePackageLockJson', () => {
    it('parses package-lock.json v2', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

      const result = parsePackageLockJson(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('npm');
      expect(result.deps.length).toBe(5);

      const names = result.deps.map(d => d.name);
      expect(names).toContain('express');
      expect(names).toContain('lodash');
      expect(names).toContain('mocha');
      expect(names).toContain('body-parser');
      expect(names).toContain('accepts');

      const mocha = result.deps.find(d => d.name === 'mocha');
      expect(mocha.isDev).toBe(true);

      const express = result.deps.find(d => d.name === 'express');
      expect(express.isDev).toBe(false);
      expect(express.version).toBe('4.18.2');

      expect(result.edges.length).toBeGreaterThan(0);

      rmSync(tmp, { recursive: true });
    });

    it('parses package-lock.json v3', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'package-lock-v3.json'), join(tmp, 'package-lock.json'));

      const result = parsePackageLockJson(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('npm');
      expect(result.deps.length).toBe(4);

      const vitest = result.deps.find(d => d.name === 'vitest');
      expect(vitest.isDev).toBe(true);

      const axios = result.deps.find(d => d.name === 'axios');
      expect(axios.version).toBe('1.6.2');

      expect(result.projectName).toBe('v3-project');
      expect(result.projectVersion).toBe('2.0.0');

      rmSync(tmp, { recursive: true });
    });

    it('returns null when no package-lock.json', () => {
      const tmp = makeTmp();
      expect(parsePackageLockJson(tmp)).toBeNull();
      rmSync(tmp, { recursive: true });
    });
  });

  describe('parseYarnLock', () => {
    it('parses Yarn Classic format', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'yarn-classic.lock'), join(tmp, 'yarn.lock'));

      const result = parseYarnLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('npm');
      expect(result.deps.length).toBeGreaterThanOrEqual(3);

      const names = result.deps.map(d => d.name);
      expect(names).toContain('express');
      expect(names).toContain('lodash');

      rmSync(tmp, { recursive: true });
    });

    it('parses Yarn Berry format', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'yarn-berry.lock'), join(tmp, 'yarn.lock'));

      const result = parseYarnLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('npm');

      const names = result.deps.map(d => d.name);
      expect(names).toContain('express');
      expect(names).toContain('lodash');
      expect(names).toContain('chalk');

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parsePnpmLock', () => {
    it('parses pnpm-lock.yaml', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'pnpm-lock.yaml'), join(tmp, 'pnpm-lock.yaml'));

      const result = parsePnpmLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('npm');
      expect(result.deps.length).toBeGreaterThanOrEqual(3);

      const names = result.deps.map(d => d.name);
      expect(names).toContain('express');

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parsePoetryLock', () => {
    it('parses poetry.lock', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'poetry.lock'), join(tmp, 'poetry.lock'));

      const result = parsePoetryLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('pypi');
      expect(result.deps.length).toBe(5);

      const flask = result.deps.find(d => d.name === 'flask');
      expect(flask.version).toBe('2.3.3');
      expect(flask.isDev).toBe(false);

      const pytest = result.deps.find(d => d.name === 'pytest');
      expect(pytest.isDev).toBe(true);

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parsePipfileLock', () => {
    it('parses Pipfile.lock', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'Pipfile.lock'), join(tmp, 'Pipfile.lock'));

      const result = parsePipfileLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('pypi');
      expect(result.deps.length).toBe(5);

      const django = result.deps.find(d => d.name === 'django');
      expect(django.version).toBe('4.2.7');
      expect(django.isDev).toBe(false);

      const black = result.deps.find(d => d.name === 'black');
      expect(black.isDev).toBe(true);

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parseCargoLock', () => {
    it('parses Cargo.lock', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'Cargo.lock'), join(tmp, 'Cargo.lock'));

      const result = parseCargoLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('crates');
      expect(result.deps.length).toBe(4);

      const serde = result.deps.find(d => d.name === 'serde');
      expect(serde.version).toBe('1.0.193');
      expect(serde.purl).toBe('pkg:cargo/serde@1.0.193');

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parseGoSum', () => {
    it('parses go.sum and deduplicates', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'go.sum'), join(tmp, 'go.sum'));

      const result = parseGoSum(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('go');
      expect(result.deps.length).toBe(4);

      const gin = result.deps.find(d => d.name === 'github.com/gin-gonic/gin');
      expect(gin.version).toBe('v1.9.1');

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parseGemfileLock', () => {
    it('parses Gemfile.lock', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'Gemfile.lock'), join(tmp, 'Gemfile.lock'));

      const result = parseGemfileLock(tmp);
      expect(result).not.toBeNull();
      expect(result.ecosystem).toBe('rubygems');
      expect(result.deps.length).toBe(5);

      const rails = result.deps.find(d => d.name === 'rails');
      expect(rails.version).toBe('7.1.2');
      expect(rails.purl).toBe('pkg:gem/rails@7.1.2');

      rmSync(tmp, { recursive: true });
    });
  });

  describe('parseManifestWithVersions', () => {
    it('parses pom.xml with groupId + artifactId + version', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'pom.xml'), join(tmp, 'pom.xml'));

      const results = parseManifestWithVersions(tmp);
      const javaResults = results.filter(r => r.ecosystem === 'java');
      expect(javaResults.length).toBe(3);

      const springBoot = javaResults.find(d => d.name === 'spring-boot-starter-web');
      expect(springBoot.version).toBe('3.2.0');
      expect(springBoot.namespace).toBe('org.springframework.boot');

      rmSync(tmp, { recursive: true });
    });

    it('parses build.gradle', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'build.gradle'), join(tmp, 'build.gradle'));

      const results = parseManifestWithVersions(tmp);
      const javaResults = results.filter(r => r.ecosystem === 'java');
      expect(javaResults.length).toBeGreaterThanOrEqual(3);

      const guava = javaResults.find(d => d.name === 'guava');
      expect(guava.version).toBe('32.1.3-jre');
      expect(guava.namespace).toBe('com.google.guava');

      const junit = javaResults.find(d => d.name === 'junit-jupiter');
      expect(junit.isDev).toBe(true);

      rmSync(tmp, { recursive: true });
    });

    it('parses pyproject.toml with PEP 621 and Poetry', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'pyproject.toml'), join(tmp, 'pyproject.toml'));

      const results = parseManifestWithVersions(tmp);
      const pyResults = results.filter(r => r.ecosystem === 'pypi');

      const fastapi = pyResults.find(d => d.name === 'fastapi');
      expect(fastapi).toBeDefined();

      const pydantic = pyResults.find(d => d.name === 'pydantic');
      expect(pydantic).toBeDefined();

      rmSync(tmp, { recursive: true });
    });
  });

  describe('discoverDependencies', () => {
    it('discovers dependencies from package-lock.json', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

      const componentList = discoverDependencies(tmp);
      expect(componentList.components.length).toBeGreaterThanOrEqual(5);
      expect(componentList.metadata.ecosystems).toContain('npm');
      expect(componentList.metadata.total).toBeGreaterThanOrEqual(5);

      rmSync(tmp, { recursive: true });
    });

    it('filters dev dependencies when includeDev is false', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

      const withDev = discoverDependencies(tmp, { includeDev: true });
      const withoutDev = discoverDependencies(tmp, { includeDev: false });

      expect(withDev.components.length).toBeGreaterThan(withoutDev.components.length);

      rmSync(tmp, { recursive: true });
    });

    it('direct count reflects manifest deps, not all non-dev packages', () => {
      const tmp = makeTmp();
      copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));

      const componentList = discoverDependencies(tmp);
      const nonDevCount = componentList.components.filter(c => !c.isDev).length;
      const directCount = componentList.metadata.direct;

      // direct should be strictly less than total (transitive deps exist)
      expect(directCount).toBeLessThan(componentList.metadata.total);
      // v2 fixture: express + lodash (non-dev direct) + mocha (dev direct) = 3
      // body-parser and accepts are transitive (not direct)
      expect(directCount).toBe(3);

      rmSync(tmp, { recursive: true });
    });

    it('returns empty component list for empty directory', () => {
      const tmp = makeTmp();

      const result = discoverDependencies(tmp);
      expect(result.components.length).toBe(0);
      expect(result.metadata.total).toBe(0);

      rmSync(tmp, { recursive: true });
    });
  });
});
