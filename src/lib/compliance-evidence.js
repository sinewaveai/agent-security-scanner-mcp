// src/lib/compliance-evidence.js — Collect normalized evidence bundle from scan + SBOM tooling.
// Uses JS imports only — no CLI shelling, no HTML parsing.

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { scanProject } from '../tools/scan-project.js';
import { normalizeFindings } from './normalize-finding.js';
import { scoreBatch } from './aivss.js';
import { discoverDependencies } from './lockfile-parsers.js';
import { serialize } from './cyclonedx.js';
import { componentFromBomComponent } from './sbom-component.js';
import { queryBatch } from './osv-client.js';
import { isHallucinated } from '../tools/check-package.js';
import { ecosystemFromPurlType } from './purl.js';

const HALLUCINATION_ECOSYSTEMS = new Set(['npm', 'pypi', 'rubygems', 'dart', 'perl', 'raku', 'crates']);
const CATEGORY_DEFAULTS = [
  'exfiltration', 'info-exposure', 'crypto', 'permissions', 'auth',
  'prompt-injection', 'supply-chain', 'injection', 'xss', 'ssrf',
  'deserialization', 'secrets', 'path-traversal', 'logging',
];
const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * Build a compliance evidence bundle from a project directory.
 *
 * Collects scan results, SBOM data, vulnerability info, hallucination checks, and drift analysis.
 * Each data source is collected independently — partial failures produce null sections, not aborts.
 *
 * @param {object} opts
 * @param {string} opts.directory - Project root to scan
 * @param {string} [opts.sbomPath] - Pre-existing SBOM file (skips discovery)
 * @param {string} [opts.baselinePath] - SBOM baseline for drift comparison
 * @param {string} [opts.toolVersion] - Scanner version for metadata
 * @param {'minimal'|'compact'|'full'} [opts.verbosity='compact'] - Detail level
 * @returns {Promise<object>} Evidence bundle
 */
export async function collectEvidence({ directory, sbomPath, baselinePath, toolVersion, verbosity = 'compact' }) {
  const toolsRun = [];
  const errors = [];

  // --- 1. Scan project ---
  let scanData = null;
  try {
    const result = await scanProject({ directory_path: directory, verbosity: 'full' });
    const raw = JSON.parse(result.content[0].text);
    scanData = raw;
    toolsRun.push('scan_project', 'scan_security');
  } catch (err) {
    errors.push({ source: 'scan_project', message: err.message });
  }

  // --- 2. Normalize findings + AIVSS ---
  // scan_project wraps scan_security — duplicate findings under both source_tools
  // so AIUC-1 controls scoped to either tool see them correctly.
  let normalized = [];
  let aivssResult = null;
  if (scanData) {
    const base = normalizeFindings(scanData.issues || [], 'scan_security');
    const duped = base.map(f => ({ ...f, source_tool: 'scan_project' }));
    normalized = [...base, ...duped];
    aivssResult = scoreBatch(base); // score deduplicated set
  }

  // --- 3. SBOM generation ---
  let components = null;
  let componentList = null;
  let bom = null;
  try {
    if (sbomPath) {
      // Explicit sbom_path: error if it doesn't exist (don't silently fall through)
      if (!existsSync(sbomPath)) {
        throw new Error(`SBOM file not found: ${sbomPath}`);
      }
      bom = JSON.parse(readFileSync(sbomPath, 'utf-8'));
      components = (bom.components || []).map(componentFromBomComponent);
    } else if (existsSync(directory)) {
      componentList = discoverDependencies(directory);
      components = componentList.components;
      bom = serialize(componentList);
    }
    if (components) toolsRun.push('sbom_generate');
  } catch (err) {
    errors.push({ source: 'sbom_generate', message: err.message });
  }

  // --- 4. Vulnerability scan ---
  let vulnData = null;
  if (components && components.length > 0) {
    try {
      const cacheDir = directory ? join(directory, '.scanner', 'cache', 'vuln') : null;
      const results = await queryBatch(components, { cacheDir });

      const allVulns = [];
      const affectedPackages = new Set();
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

      for (const [key, vulns] of results) {
        for (const vuln of vulns) {
          const level = vuln.ratings?.[0]?.severity || 'unknown';
          allVulns.push(vuln);
          affectedPackages.add(key);
          bySeverity[level] = (bySeverity[level] || 0) + 1;
        }
      }

      vulnData = {
        total: allVulns.length,
        affected_packages: affectedPackages.size,
        by_severity: bySeverity,
        vulnerabilities: allVulns,
      };
      toolsRun.push('sbom_scan_vulnerabilities');
    } catch (err) {
      errors.push({ source: 'sbom_scan_vulnerabilities', message: err.message });
    }
  }

  // --- 5. Hallucination check ---
  let hallucinationData = null;
  if (components && components.length > 0) {
    try {
      const hallucinated = [];
      const unsupported = [];
      let legitimateCount = 0;

      for (const comp of components) {
        if (!HALLUCINATION_ECOSYSTEMS.has(comp.ecosystem)) {
          unsupported.push({ name: comp.name, ecosystem: comp.ecosystem });
          continue;
        }
        const result = isHallucinated(comp.name, comp.ecosystem);
        if (result && result.hallucinated) {
          hallucinated.push({ name: comp.name, ecosystem: comp.ecosystem, confidence: result.confidence || 'medium' });
        } else {
          legitimateCount++;
        }
      }

      hallucinationData = {
        hallucinated_count: hallucinated.length,
        unsupported_count: unsupported.length,
        legitimate_count: legitimateCount,
        hallucinated_packages: hallucinated,
        unsupported_packages: unsupported,
      };
      toolsRun.push('sbom_check_hallucinations');
    } catch (err) {
      errors.push({ source: 'sbom_check_hallucinations', message: err.message });
    }
  }

  // --- 6. SBOM drift ---
  let driftData = null;
  if (bom) {
    try {
      const resolvedBaseline = baselinePath || join(directory, '.scanner', 'sbom-baseline.json');
      const baselineExists = existsSync(resolvedBaseline);

      if (baselineExists) {
        const baselineBom = JSON.parse(readFileSync(resolvedBaseline, 'utf-8'));
        const currentMap = buildComponentMap(bom.components || []);
        const baselineMap = buildComponentMap(baselineBom.components || []);

        let added = 0, removed = 0, versionChanged = 0;
        for (const [key, comp] of currentMap) {
          const baseComp = baselineMap.get(key);
          if (!baseComp) added++;
          else if (baseComp.version !== comp.version) versionChanged++;
        }
        for (const key of baselineMap.keys()) {
          if (!currentMap.has(key)) removed++;
        }

        driftData = {
          baseline_exists: true,
          added,
          removed,
          version_changed: versionChanged,
          summary: `+${added} added, -${removed} removed, ~${versionChanged} changed`,
        };
      } else {
        driftData = { baseline_exists: false, added: 0, removed: 0, version_changed: 0, summary: '' };
      }
      toolsRun.push('sbom_diff');
    } catch (err) {
      errors.push({ source: 'sbom_diff', message: err.message });
    }
  }

  // --- Build the evidence bundle ---
  const grade = scanData?.grade || null;
  const bySeverity = buildSeverityMap(normalized);
  const byCategory = buildCategoryMap(normalized);
  const byCategorySeverity = buildCategorySeverityMap(normalized);

  const bundle = {
    metadata: {
      generated_at: new Date().toISOString(),
      directory,
      tool_version: toolVersion || 'unknown',
    },
    tools_run: [...new Set(toolsRun)],
    errors: errors.length > 0 ? errors : undefined,
    scan: scanData ? {
      grade,
      findings: normalized,
      by_severity: bySeverity,
      by_category: byCategory,
      by_category_severity: byCategorySeverity,
    } : null,
    aivss: aivssResult ? {
      posture: aivssResult.posture,
      findings: aivssResult.findings,
    } : null,
    sbom: components ? {
      component_count: components.length,
      ecosystems: [...new Set(components.map(c => c.ecosystem))],
      direct_count: components.filter(c => c.isDirect).length,
      dev_count: components.filter(c => c.isDev).length,
      bom: verbosity === 'full' ? bom : undefined,
    } : null,
    supply_chain: {
      vulnerabilities: vulnData ? {
        total: vulnData.total,
        affected_packages: vulnData.affected_packages,
        by_severity: vulnData.by_severity,
        vulnerabilities: verbosity === 'full' ? vulnData.vulnerabilities : undefined,
      } : null,
      hallucinations: hallucinationData ? {
        hallucinated_count: hallucinationData.hallucinated_count,
        unsupported_count: hallucinationData.unsupported_count,
        legitimate_count: hallucinationData.legitimate_count,
        hallucinated_packages: hallucinationData.hallucinated_packages,
        unsupported_packages: hallucinationData.unsupported_packages,
      } : null,
      drift: driftData,
    },
  };

  return bundle;
}

/**
 * Build the legacy-compatible evidence object for the compliance evaluator.
 * This converts the evidence bundle into the shape expected by evaluateControl/evaluateAll.
 */
export function buildEvaluatorEvidence(bundle) {
  const grade = bundle.scan?.grade || null;
  return {
    aivssPosture: bundle.aivss?.posture || null,
    findings: bundle.scan?.findings || [],
    grades: { scan_project: grade, scan_security: grade, project: grade },
    toolsRun: bundle.tools_run,
  };
}

// --- Internal helpers ---

function buildSeverityMap(findings) {
  const map = {};
  for (const level of SEVERITY_LEVELS) map[level] = 0;
  for (const f of findings) {
    if (f.source_tool === 'scan_project') continue; // avoid double-counting
    const sev = f.severity || 'INFO';
    map[sev] = (map[sev] || 0) + 1;
  }
  return map;
}

function buildCategoryMap(findings) {
  const map = {};
  for (const cat of CATEGORY_DEFAULTS) map[cat] = 0;
  for (const f of findings) {
    if (f.source_tool === 'scan_project') continue;
    const cat = f.category || 'unknown';
    map[cat] = (map[cat] || 0) + 1;
  }
  return map;
}

function buildCategorySeverityMap(findings) {
  const map = {};
  for (const cat of CATEGORY_DEFAULTS) {
    map[cat] = {};
    for (const sev of SEVERITY_LEVELS) map[cat][sev] = 0;
  }
  for (const f of findings) {
    if (f.source_tool === 'scan_project') continue;
    const cat = f.category || 'unknown';
    const sev = f.severity || 'INFO';
    if (!map[cat]) {
      map[cat] = {};
      for (const s of SEVERITY_LEVELS) map[cat][s] = 0;
    }
    map[cat][sev] = (map[cat][sev] || 0) + 1;
  }
  return map;
}

function buildComponentMap(components) {
  const map = new Map();
  for (const comp of components) {
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
  return component.ecosystem || 'unknown';
}
