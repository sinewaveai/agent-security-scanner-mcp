import { z } from 'zod';
import { existsSync, readFileSync } from 'fs';
import { discoverDependencies } from '../lib/lockfile-parsers.js';
import { componentFromBomComponent } from '../lib/sbom-component.js';
import { isHallucinated } from './check-package.js';

// Ecosystems supported by the hallucination checker (bloom filters + text sets)
const SUPPORTED_ECOSYSTEMS = new Set(['npm', 'pypi', 'rubygems', 'dart', 'perl', 'raku', 'crates']);

export const sbomHallucinationsSchema = {
  directory_path: z.string().optional().describe('Path to project root (generates fresh SBOM)'),
  sbom_path: z.string().optional().describe('Path to existing SBOM file'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function sbomCheckHallucinations({ directory_path, sbom_path, verbosity }) {
  // Enforce exactly one of directory_path or sbom_path
  if (directory_path && sbom_path) {
    return error('Provide either directory_path or sbom_path, not both.');
  }
  if (!directory_path && !sbom_path) {
    return error('Provide either directory_path or sbom_path.');
  }

  // Load or generate components
  let components;
  if (sbom_path) {
    if (!existsSync(sbom_path)) return error(`SBOM file not found: ${sbom_path}`);
    let bom;
    try {
      bom = JSON.parse(readFileSync(sbom_path, 'utf-8'));
    } catch {
      return error(`Failed to parse SBOM: ${sbom_path}`);
    }
    components = (bom.components || []).map(componentFromBomComponent);
  } else {
    if (!existsSync(directory_path)) return error(`Directory not found: ${directory_path}`);
    const componentList = discoverDependencies(directory_path);
    components = componentList.components;
  }

  const hallucinated = [];
  const unsupported = [];
  const legitimate = [];

  for (const component of components) {
    const eco = component.ecosystem;

    // Check if ecosystem is supported
    if (!SUPPORTED_ECOSYSTEMS.has(eco)) {
      unsupported.push({
        name: component.name,
        version: component.version,
        ecosystem: eco,
        status: 'unsupported_ecosystem',
        message: `Registry verification not available for ${eco} ecosystem.`,
      });
      continue;
    }

    const result = isHallucinated(component.name, eco);
    if (result && result.hallucinated) {
      hallucinated.push({
        name: component.name,
        version: component.version,
        ecosystem: eco,
        confidence: result.confidence || 'medium',
        similar_packages: result.similar_packages || [],
      });
    } else {
      legitimate.push({ name: component.name, ecosystem: eco });
    }
  }

  const level = verbosity || 'compact';
  let response;
  switch (level) {
    case 'minimal':
      response = {
        total_checked: components.length,
        legitimate_count: legitimate.length,
        hallucinated_count: hallucinated.length,
        unsupported_count: unsupported.length,
      };
      break;
    case 'full':
      response = {
        total_checked: components.length,
        legitimate_count: legitimate.length,
        hallucinated_count: hallucinated.length,
        unsupported_count: unsupported.length,
        hallucinated_packages: hallucinated,
        unsupported_packages: unsupported,
        legitimate_packages: legitimate,
      };
      break;
    case 'compact':
    default:
      response = {
        total_checked: components.length,
        legitimate_count: legitimate.length,
        hallucinated_count: hallucinated.length,
        unsupported_count: unsupported.length,
        hallucinated_packages: hallucinated,
        unsupported_packages: unsupported,
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
