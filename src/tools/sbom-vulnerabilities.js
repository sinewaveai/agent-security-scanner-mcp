import { z } from 'zod';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { discoverDependencies } from '../lib/lockfile-parsers.js';
import { componentFromBomComponent } from '../lib/sbom-component.js';
import { queryBatch } from '../lib/osv-client.js';

export const sbomVulnerabilitiesSchema = {
  directory_path: z.string().optional().describe('Path to project root (generates fresh SBOM)'),
  sbom_path: z.string().optional().describe('Path to existing SBOM file'),
  severity_threshold: z.enum(['critical', 'high', 'medium', 'low']).optional()
    .describe('Only report vulnerabilities at or above this severity (default: low)'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function sbomScanVulnerabilities({ directory_path, sbom_path, severity_threshold, verbosity }) {
  // Enforce exactly one of directory_path or sbom_path
  if (directory_path && sbom_path) {
    return error('Provide either directory_path or sbom_path, not both.');
  }
  if (!directory_path && !sbom_path) {
    return error('Provide either directory_path or sbom_path.');
  }

  // Load or generate components
  let components;
  let projectName = 'unknown';
  if (sbom_path) {
    if (!existsSync(sbom_path)) return error(`SBOM file not found: ${sbom_path}`);
    let bom;
    try {
      bom = JSON.parse(readFileSync(sbom_path, 'utf-8'));
    } catch {
      return error(`Failed to parse SBOM: ${sbom_path}`);
    }
    components = (bom.components || []).map(componentFromBomComponent);
    projectName = bom.metadata?.component?.name || 'unknown';
  } else {
    if (!existsSync(directory_path)) return error(`Directory not found: ${directory_path}`);
    const componentList = discoverDependencies(directory_path);
    components = componentList.components;
    projectName = componentList.metadata.name;
  }

  // Query OSV — pass normalized components to preserve purl and namespace
  const cacheDir = directory_path ? join(directory_path, '.scanner', 'cache', 'vuln') : null;
  const results = await queryBatch(components, { cacheDir });

  // Flatten and apply severity filter
  const threshold = severity_threshold || 'low';
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  const minLevel = severityOrder[threshold] || 0;

  const allVulns = [];
  const affectedPackages = new Set();
  for (const [key, vulns] of results) {
    for (const vuln of vulns) {
      const level = vuln.ratings?.[0]?.severity || 'unknown';
      if ((severityOrder[level] || 0) >= minLevel) {
        allVulns.push(vuln);
        affectedPackages.add(key);
      }
    }
  }

  // Count by severity
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of allVulns) {
    const level = v.ratings?.[0]?.severity || 'unknown';
    bySeverity[level] = (bySeverity[level] || 0) + 1;
  }

  const level = verbosity || 'compact';
  let response;
  switch (level) {
    case 'minimal':
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: allVulns.length,
        affected_packages: affectedPackages.size,
        by_severity: bySeverity,
      };
      break;
    case 'full':
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: allVulns.length,
        affected_packages: [...affectedPackages],
        by_severity: bySeverity,
        vulnerabilities: allVulns,
      };
      break;
    case 'compact':
    default:
      response = {
        project: projectName,
        total_components: components.length,
        total_vulnerabilities: allVulns.length,
        affected_packages: [...affectedPackages],
        by_severity: bySeverity,
        vulnerabilities: allVulns.map(v => ({
          id: v.id,
          severity: v.ratings?.[0]?.severity || 'unknown',
          score: v.ratings?.[0]?.score || 0,
          description: v.description?.substring(0, 200) || '',
          recommendation: v.recommendation || '',
        })),
      };
      break;
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
  };
}

function error(msg) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
}
