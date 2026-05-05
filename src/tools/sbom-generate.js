import { z } from 'zod';
import { existsSync, writeFileSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { discoverDependencies } from '../lib/lockfile-parsers.js';
import { serialize } from '../lib/cyclonedx.js';

// Read tool version from package.json
let toolVersion = '0.0.0';
try {
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));
  toolVersion = pkg.version || '0.0.0';
} catch { /* fallback */ }

export const sbomGenerateSchema = {
  directory_path: z.string().describe('Path to project root directory'),
  include_dev: z.boolean().optional().describe('Include dev dependencies (default: true)'),
  output_path: z.string().optional().describe('Path to write SBOM file. Absent = no write, present = write to that path.'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function sbomGenerate({ directory_path, include_dev, output_path, verbosity }) {
  if (!existsSync(directory_path)) {
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: `Directory not found: ${directory_path}` }) }],
    };
  }

  const includeDev = include_dev !== false; // default true
  const level = verbosity || 'compact';

  // Discover dependencies
  const componentList = discoverDependencies(directory_path, { includeDev });

  // Serialize to CycloneDX
  const bom = serialize(componentList, [], { toolVersion });

  // Optionally write to file
  let savedPath = null;
  if (output_path) {
    const dir = join(directory_path, '.scanner');
    const resolvedPath = output_path.includes('/') || output_path.includes('\\')
      ? output_path
      : join(dir, output_path);

    const parentDir = resolvedPath.substring(0, resolvedPath.lastIndexOf('/'));
    if (parentDir && !existsSync(parentDir)) {
      mkdirSync(parentDir, { recursive: true, mode: 0o700 });
    }
    writeFileSync(resolvedPath, JSON.stringify(bom, null, 2), { mode: 0o600 });
    savedPath = resolvedPath;
  }

  // Format response based on verbosity
  let response;
  switch (level) {
    case 'minimal':
      response = formatMinimal(componentList, savedPath);
      break;
    case 'full':
      response = formatFull(bom, componentList, savedPath);
      break;
    case 'compact':
    default:
      response = formatCompact(componentList, savedPath);
      break;
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
  };
}

function formatMinimal(componentList, savedPath) {
  const { metadata } = componentList;
  return {
    total_components: metadata.total,
    direct: metadata.direct,
    dev: metadata.dev,
    ecosystems: metadata.ecosystems,
    ...(savedPath && { saved_to: savedPath }),
  };
}

function formatCompact(componentList, savedPath) {
  const { components, metadata } = componentList;

  const byEcosystem = {};
  for (const c of components) {
    if (!byEcosystem[c.ecosystem]) byEcosystem[c.ecosystem] = [];
    byEcosystem[c.ecosystem].push({ name: c.name, version: c.version, isDev: c.isDev });
  }

  return {
    project: metadata.name,
    version: metadata.version,
    total_components: metadata.total,
    direct: metadata.direct,
    dev: metadata.dev,
    ecosystems: metadata.ecosystems,
    components: byEcosystem,
    ...(savedPath && { saved_to: savedPath }),
  };
}

function formatFull(bom, componentList, savedPath) {
  return {
    project: componentList.metadata.name,
    version: componentList.metadata.version,
    total_components: componentList.metadata.total,
    direct: componentList.metadata.direct,
    dev: componentList.metadata.dev,
    ecosystems: componentList.metadata.ecosystems,
    bom,
    ...(savedPath && { saved_to: savedPath }),
  };
}
