import { describe, it, expect } from 'vitest';
import { serialize, addVulnerabilities } from '../src/lib/cyclonedx.js';
import { createComponent, createEdge, createComponentList } from '../src/lib/sbom-component.js';

describe('cyclonedx', () => {
  function makeTestComponents() {
    const components = [
      createComponent({ name: 'express', version: '4.18.2', ecosystem: 'npm' }),
      createComponent({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }),
      createComponent({ name: 'mocha', version: '10.2.0', ecosystem: 'npm', isDev: true }),
    ];
    const edges = [
      createEdge('pkg:npm/test-app@1.0.0', 'pkg:npm/express@4.18.2'),
      createEdge('pkg:npm/test-app@1.0.0', 'pkg:npm/lodash@4.17.21'),
    ];
    return createComponentList(components, edges, { name: 'test-app', version: '1.0.0' });
  }

  describe('serialize', () => {
    it('produces valid CycloneDX v1.5 structure', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList);

      expect(bom.bomFormat).toBe('CycloneDX');
      expect(bom.specVersion).toBe('1.5');
      expect(bom.version).toBe(1);
      expect(bom.serialNumber).toMatch(/^urn:uuid:/);
    });

    it('includes metadata with tools and component', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList, [], { toolVersion: '4.0.1' });

      expect(bom.metadata.timestamp).toBeDefined();
      expect(bom.metadata.tools[0].name).toBe('agent-security-scanner-mcp');
      expect(bom.metadata.tools[0].version).toBe('4.0.1');
      expect(bom.metadata.component.name).toBe('test-app');
      expect(bom.metadata.component.version).toBe('1.0.0');
      expect(bom.metadata.component.type).toBe('application');
    });

    it('serializes components with correct fields', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList);

      expect(bom.components.length).toBe(3);

      const express = bom.components.find(c => c.name === 'express');
      expect(express.type).toBe('library');
      expect(express.version).toBe('4.18.2');
      expect(express.purl).toBe('pkg:npm/express@4.18.2');
      expect(express['bom-ref']).toBe('pkg:npm/express@4.18.2');
      expect(express.scope).toBe('required');

      const mocha = bom.components.find(c => c.name === 'mocha');
      expect(mocha.scope).toBe('optional');
      expect(mocha.properties).toContainEqual({ name: 'cdx:development', value: 'true' });
    });

    it('serializes dependency edges', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList);

      expect(bom.dependencies).toBeDefined();
      expect(bom.dependencies.length).toBeGreaterThan(0);

      const rootDep = bom.dependencies.find(d => d.ref === 'pkg:npm/test-app@1.0.0');
      expect(rootDep).toBeDefined();
      expect(rootDep.dependsOn).toContain('pkg:npm/express@4.18.2');
      expect(rootDep.dependsOn).toContain('pkg:npm/lodash@4.17.21');
    });

    it('handles empty edges gracefully', () => {
      const componentList = createComponentList(
        [createComponent({ name: 'foo', version: '1.0.0', ecosystem: 'npm' })],
        [],
        { name: 'test', version: '1.0.0' }
      );
      const bom = serialize(componentList);

      expect(bom.dependencies).toBeDefined();
      expect(bom.dependencies[0].dependsOn).toEqual([]);
    });

    it('does not include vulnerabilities when none provided', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList);
      expect(bom.vulnerabilities).toBeUndefined();
    });

    it('includes vulnerabilities when provided', () => {
      const componentList = makeTestComponents();
      const vulns = [{ id: 'CVE-2021-44228', source: { name: 'OSV' } }];
      const bom = serialize(componentList, vulns);
      expect(bom.vulnerabilities).toHaveLength(1);
      expect(bom.vulnerabilities[0].id).toBe('CVE-2021-44228');
    });

    it('includes group for namespaced components', () => {
      const components = [
        createComponent({
          name: 'spring-boot-starter-web',
          version: '3.2.0',
          ecosystem: 'java',
          namespace: 'org.springframework.boot',
        }),
      ];
      const componentList = createComponentList(components, [], { name: 'test', version: '1.0.0' });
      const bom = serialize(componentList);

      expect(bom.components[0].group).toBe('org.springframework.boot');
    });
  });

  describe('addVulnerabilities', () => {
    it('adds vulnerabilities to existing BOM', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList);

      const vuln = { id: 'CVE-2024-1234', source: { name: 'OSV' } };
      addVulnerabilities(bom, [vuln]);

      expect(bom.vulnerabilities).toHaveLength(1);
      expect(bom.vulnerabilities[0].id).toBe('CVE-2024-1234');
    });

    it('appends to existing vulnerabilities', () => {
      const componentList = makeTestComponents();
      const bom = serialize(componentList, [{ id: 'CVE-2024-0001' }]);

      addVulnerabilities(bom, [{ id: 'CVE-2024-0002' }]);
      expect(bom.vulnerabilities).toHaveLength(2);
    });
  });
});
