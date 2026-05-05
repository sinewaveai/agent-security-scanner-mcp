// CycloneDX v1.5 JSON serializer.
// Consumes the normalized ComponentList model from sbom-component.js.

import { randomUUID } from 'crypto';

const SPEC_VERSION = '1.5';
const TOOL_NAME = 'agent-security-scanner-mcp';

/**
 * Serialize a ComponentList into a CycloneDX v1.5 BOM.
 * @param {import('./sbom-component.js').ComponentList} componentList
 * @param {object[]} [vulnerabilities=[]]
 * @param {{ toolVersion?: string }} [options={}]
 * @returns {object} CycloneDX JSON object
 */
export function serialize(componentList, vulnerabilities = [], options = {}) {
  const { toolVersion = '0.0.0' } = options;
  const { components, edges, metadata } = componentList;

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: SPEC_VERSION,
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{
        name: TOOL_NAME,
        version: toolVersion,
      }],
      component: {
        type: 'application',
        name: metadata.name || 'unknown',
        version: metadata.version || '0.0.0',
        'bom-ref': `pkg:npm/${metadata.name}@${metadata.version}`,
      },
    },
    components: components.map(c => serializeComponent(c)),
    dependencies: serializeDependencies(edges, components),
  };

  if (vulnerabilities.length > 0) {
    bom.vulnerabilities = vulnerabilities;
  }

  return bom;
}

function serializeComponent(component) {
  const result = {
    type: 'library',
    name: component.name,
    version: component.version,
    purl: component.purl,
    'bom-ref': component.purl,
    scope: component.scope === 'optional' ? 'optional' : 'required',
  };

  if (component.namespace) {
    result.group = component.namespace;
  }

  const properties = [];
  if (component.isDev) {
    properties.push({ name: 'cdx:development', value: 'true' });
  }
  if (component.ecosystem) {
    properties.push({ name: 'cdx:ecosystem', value: component.ecosystem });
  }
  if (properties.length > 0) {
    result.properties = properties;
  }

  return result;
}

function serializeDependencies(edges, components) {
  if (!edges || edges.length === 0) {
    // Return flat list — each component depends on nothing
    return components.map(c => ({ ref: c.purl, dependsOn: [] }));
  }

  // Group edges by source
  const depMap = new Map();
  for (const edge of edges) {
    if (!depMap.has(edge.from)) depMap.set(edge.from, []);
    depMap.get(edge.from).push(edge.to);
  }

  // Include all components as refs, merge edges
  const allRefs = new Set(components.map(c => c.purl));
  for (const [from, tos] of depMap) {
    allRefs.add(from);
    for (const to of tos) allRefs.add(to);
  }

  return [...allRefs].map(ref => ({
    ref,
    dependsOn: depMap.get(ref) || [],
  }));
}

/**
 * Add vulnerability entries to an existing BOM.
 * @param {object} bom - CycloneDX BOM object
 * @param {object[]} vulnerabilities - Array of CycloneDX vulnerability objects
 * @returns {object} The mutated BOM
 */
export function addVulnerabilities(bom, vulnerabilities) {
  if (!bom.vulnerabilities) bom.vulnerabilities = [];
  bom.vulnerabilities.push(...vulnerabilities);
  return bom;
}
