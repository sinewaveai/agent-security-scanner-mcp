import { z } from 'zod';
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync } from 'fs';
import { join } from 'path';
import { discoverDependencies } from '../lib/lockfile-parsers.js';
import { serialize } from '../lib/cyclonedx.js';
import { ecosystemFromPurlType } from '../lib/purl.js';

export const sbomDiffSchema = {
  directory_path: z.string().describe('Path to project root directory'),
  baseline_path: z.string().optional().describe('Path to baseline SBOM file (default: .scanner/sbom-baseline.json)'),
  save_baseline: z.boolean().optional().describe('Save current SBOM as the new baseline'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function sbomDiff({ directory_path, baseline_path, save_baseline, verbosity }) {
  if (!existsSync(directory_path)) {
    return error(`Directory not found: ${directory_path}`);
  }

  // Generate current SBOM
  const componentList = discoverDependencies(directory_path);
  const currentBom = serialize(componentList);

  // Resolve baseline path
  const resolvedBaseline = baseline_path || join(directory_path, '.scanner', 'sbom-baseline.json');

  // Check if baseline exists BEFORE potentially overwriting it
  const baselineExists = existsSync(resolvedBaseline);

  // If no baseline exists and save_baseline requested: save and return immediately
  if (!baselineExists && save_baseline) {
    atomicWrite(resolvedBaseline, JSON.stringify(currentBom, null, 2));
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          message: `Baseline saved to ${resolvedBaseline}. Run again to compare.`,
          baseline_saved: resolvedBaseline,
          current: {
            total_components: componentList.metadata.total,
            ecosystems: componentList.metadata.ecosystems,
          },
        }, null, 2),
      }],
    };
  }

  // If no baseline exists and save_baseline not requested: tell user
  if (!baselineExists) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          message: `No baseline found at ${resolvedBaseline}. Run with save_baseline=true to create one.`,
          current: {
            total_components: componentList.metadata.total,
            ecosystems: componentList.metadata.ecosystems,
          },
        }, null, 2),
      }],
    };
  }

  let baselineBom;
  try {
    baselineBom = JSON.parse(readFileSync(resolvedBaseline, 'utf-8'));
  } catch {
    return error(`Failed to parse baseline: ${resolvedBaseline}`);
  }

  // Build component maps by name+ecosystem (PURL without version for matching)
  const currentMap = buildComponentMap(currentBom.components || []);
  const baselineMap = buildComponentMap(baselineBom.components || []);

  const added = [];
  const removed = [];
  const versionChanged = [];
  const unchanged = [];

  // Find added and version-changed
  for (const [key, comp] of currentMap) {
    const baseComp = baselineMap.get(key);
    if (!baseComp) {
      added.push(comp);
    } else if (baseComp.version !== comp.version) {
      versionChanged.push({
        name: comp.name,
        ecosystem: extractEcosystem(comp),
        old_version: baseComp.version,
        new_version: comp.version,
      });
    } else {
      unchanged.push(comp);
    }
  }

  // Find removed
  for (const [key, comp] of baselineMap) {
    if (!currentMap.has(key)) {
      removed.push(comp);
    }
  }

  // If save_baseline requested and baseline already existed: compare first, then overwrite
  if (save_baseline) {
    atomicWrite(resolvedBaseline, JSON.stringify(currentBom, null, 2));
  }

  const level = verbosity || 'compact';
  let response;
  switch (level) {
    case 'minimal':
      response = {
        added: added.length,
        removed: removed.length,
        version_changed: versionChanged.length,
        unchanged: unchanged.length,
        ...(save_baseline && { baseline_saved: resolvedBaseline }),
      };
      break;
    case 'full':
      response = {
        added_packages: added.map(formatComponent),
        removed_packages: removed.map(formatComponent),
        version_changed: versionChanged,
        unchanged_count: unchanged.length,
        current_total: currentMap.size,
        baseline_total: baselineMap.size,
        baseline_timestamp: baselineBom.metadata?.timestamp || 'unknown',
        ...(save_baseline && { baseline_saved: resolvedBaseline }),
      };
      break;
    case 'compact':
    default:
      response = {
        summary: `+${added.length} added, -${removed.length} removed, ~${versionChanged.length} changed, ${unchanged.length} unchanged`,
        added_packages: added.map(c => ({ name: c.name, version: c.version })),
        removed_packages: removed.map(c => ({ name: c.name, version: c.version })),
        version_changed: versionChanged,
        ...(save_baseline && { baseline_saved: resolvedBaseline }),
      };
      break;
  }

  return {
    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
  };
}

function buildComponentMap(components) {
  const map = new Map();
  for (const comp of components) {
    // Key by name + ecosystem (from purl type or properties)
    const eco = extractEcosystem(comp);
    const key = `${eco}:${comp.name}`;
    map.set(key, comp);
  }
  return map;
}

function extractEcosystem(component) {
  if (component.properties) {
    const eco = component.properties.find(p => p.name === 'cdx:ecosystem');
    if (eco) return eco.value;
  }
  if (component.purl) {
    const match = component.purl.match(/^pkg:([^/]+)/);
    if (match) return ecosystemFromPurlType(match[1]);
  }
  return 'unknown';
}

function formatComponent(comp) {
  return {
    name: comp.name,
    version: comp.version,
    purl: comp.purl || '',
  };
}

// Atomic write: temp file + rename (pattern from scan-skill.js:785)
function atomicWrite(filePath, data) {
  const dir = filePath.substring(0, filePath.lastIndexOf('/'));
  if (dir && !existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const tmpFile = `${filePath}.tmp.${process.pid}.${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  writeFileSync(tmpFile, data, { encoding: 'utf-8', mode: 0o600 });
  try {
    renameSync(tmpFile, filePath);
  } catch (renameErr) {
    try { unlinkSync(tmpFile); } catch { /* best effort cleanup */ }
    throw renameErr;
  }
}

function error(msg) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: msg }) }] };
}
