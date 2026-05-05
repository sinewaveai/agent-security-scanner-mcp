// src/tools/evaluate-compliance.js — evaluate_compliance MCP tool.
// Collects evidence from scan + SBOM, evaluates controls per framework, persists optionally.

import { z } from 'zod';
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { collectEvidence, buildEvaluatorEvidence } from '../lib/compliance-evidence.js';
import { loadControls } from '../lib/compliance-controls.js';
import { evaluateAll } from '../lib/compliance-evaluator.js';
function formatTimestamp(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
}

export const evaluateComplianceSchema = {
  directory_path: z.string().describe('Path to project root directory to evaluate'),
  frameworks: z.array(z.string()).optional()
    .describe('Compliance frameworks to evaluate (default: ["aiuc-1"]). Options: aiuc-1, soc2-technical, gdpr-technical'),
  sbom_path: z.string().optional().describe('Path to existing SBOM file (skips SBOM generation)'),
  baseline_path: z.string().optional().describe('Path to SBOM baseline file for drift comparison'),
  save_evidence: z.boolean().optional().describe('Save evidence bundle to .scanner/evidence/ (default: false)'),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe('Response detail level (default: compact)'),
};

export async function evaluateCompliance({ directory_path, frameworks, sbom_path, baseline_path, save_evidence, verbosity }) {
  if (!existsSync(directory_path)) {
    return error(`Directory not found: ${directory_path}`);
  }

  const fws = (frameworks && frameworks.length > 0) ? frameworks : ['aiuc-1'];
  const level = verbosity || 'compact';

  // Collect evidence once, evaluate against all requested frameworks
  let bundle;
  try {
    bundle = await collectEvidence({
      directory: directory_path,
      sbomPath: sbom_path,
      baselinePath: baseline_path,
      toolVersion: process.env.npm_package_version || 'unknown',
      verbosity: level,
    });
  } catch (err) {
    return error(`Evidence collection failed: ${err.message}`);
  }

  // Add requested frameworks to metadata
  bundle.metadata.frameworks = fws;

  // Build legacy evaluator evidence (for AIUC-1 backward compat)
  const legacyEvidence = buildEvaluatorEvidence(bundle);

  // Evaluate each framework
  const frameworkResults = [];
  for (const fw of fws) {
    try {
      const registry = loadControls(fw);
      const result = evaluateAll(registry.controls, legacyEvidence, bundle);
      frameworkResults.push({
        framework: registry.framework,
        controls_evaluated: result.controls_evaluated,
        summary: {
          pass: result.pass,
          partial: result.partial,
          fail: result.fail,
          not_evaluated: result.not_evaluated,
        },
        results: result.results,
      });
    } catch (err) {
      frameworkResults.push({
        framework: fw,
        error: err.message,
      });
    }
  }

  // Persist evidence if requested
  let savedPath = null;
  if (save_evidence) {
    try {
      const evidenceDir = join(directory_path, '.scanner', 'evidence');
      if (!existsSync(evidenceDir)) {
        mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
      }
      const filename = `${formatTimestamp(new Date())}.json`;
      savedPath = join(evidenceDir, filename);
      const persistBundle = {
        ...bundle,
        compliance: frameworkResults,
      };
      writeFileSync(savedPath, JSON.stringify(persistBundle, null, 2), { encoding: 'utf-8', mode: 0o600 });
    } catch (err) {
      // Non-fatal — report but don't fail
      if (!bundle.errors) bundle.errors = [];
      bundle.errors.push({ source: 'evidence_persist', message: err.message });
    }
  }

  // Build response based on verbosity
  let response;
  switch (level) {
    case 'minimal':
      response = {
        directory: directory_path,
        tools_run: bundle.tools_run,
        compliance: frameworkResults.map(r => ({
          framework: r.framework,
          summary: r.summary || null,
          error: r.error || undefined,
        })),
        ...(savedPath && { evidence_saved: savedPath }),
      };
      break;

    case 'full':
      response = {
        evidence: bundle,
        compliance: frameworkResults,
        ...(savedPath && { evidence_saved: savedPath }),
      };
      break;

    case 'compact':
    default:
      response = {
        directory: directory_path,
        tools_run: bundle.tools_run,
        errors: bundle.errors || undefined,
        scan_summary: bundle.scan ? {
          grade: bundle.scan.grade,
          by_severity: bundle.scan.by_severity,
        } : null,
        sbom_summary: bundle.sbom ? {
          component_count: bundle.sbom.component_count,
          ecosystems: bundle.sbom.ecosystems,
        } : null,
        supply_chain: bundle.supply_chain.vulnerabilities || bundle.supply_chain.hallucinations ? {
          vulnerabilities: bundle.supply_chain.vulnerabilities ? {
            total: bundle.supply_chain.vulnerabilities.total,
            by_severity: bundle.supply_chain.vulnerabilities.by_severity,
          } : null,
          hallucinations: bundle.supply_chain.hallucinations ? {
            hallucinated_count: bundle.supply_chain.hallucinations.hallucinated_count,
          } : null,
          drift: bundle.supply_chain.drift,
        } : null,
        compliance: frameworkResults,
        ...(savedPath && { evidence_saved: savedPath }),
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
