// src/lib/compliance-controls.js — Multi-framework controls registry loader + schema validator.

import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

const KNOWN_TOOLS = new Set([
  'scan_security', 'scan_agent_prompt', 'scan_project', 'scan_skill',
  'scan_mcp_server', 'scan_agent_action', 'scan_git_diff',
  'sbom_generate', 'sbom_scan_vulnerabilities', 'sbom_check_hallucinations', 'sbom_diff',
]);
const OWASP_TAG_RE = /^LLM\d{2}$/;
const VALID_CHECK_OPS = new Set(['exists', 'eq', 'lte', 'gte']);

const _cache = new Map();

/**
 * Validate the controls registry schema. Returns array of error strings (empty = valid).
 */
export function validateRegistry(data) {
  const errors = [];

  if (!data || typeof data !== 'object') {
    errors.push('Registry must be a non-null object');
    return errors;
  }

  if (!Array.isArray(data.controls)) {
    errors.push('Registry must have a "controls" array');
    return errors;
  }

  // Validate registry-level domains array
  if (!Array.isArray(data.domains) || data.domains.length === 0) {
    errors.push('Registry must have a non-empty "domains" array');
    return errors;
  }
  const registryDomains = new Set(data.domains);

  const ids = new Set();
  for (const ctrl of data.controls) {
    // Required fields
    if (!ctrl.id) errors.push(`Control missing "id"`);
    if (!ctrl.title) errors.push(`Control ${ctrl.id || '?'} missing "title"`);
    if (!ctrl.domain) errors.push(`Control ${ctrl.id || '?'} missing "domain"`);
    if (!ctrl.evaluation) errors.push(`Control ${ctrl.id || '?'} missing "evaluation"`);

    // Duplicate ID check
    if (ctrl.id && ids.has(ctrl.id)) {
      errors.push(`Duplicate control ID: ${ctrl.id}`);
    }
    ids.add(ctrl.id);

    // Domain validation — check against this registry's own domains
    if (ctrl.domain && !registryDomains.has(ctrl.domain)) {
      errors.push(`Control ${ctrl.id}: unknown domain "${ctrl.domain}" (registry allows: ${data.domains.join(', ')})`);
    }

    // Scanner tools validation
    if (Array.isArray(ctrl.scanner_tools)) {
      for (const tool of ctrl.scanner_tools) {
        if (!KNOWN_TOOLS.has(tool)) {
          errors.push(`Control ${ctrl.id}: unknown scanner tool "${tool}"`);
        }
      }
    }

    // OWASP tags validation (optional — only validated when present)
    if (Array.isArray(ctrl.owasp_llm)) {
      for (const tag of ctrl.owasp_llm) {
        if (!OWASP_TAG_RE.test(tag)) {
          errors.push(`Control ${ctrl.id}: invalid OWASP tag "${tag}" (expected LLM\\d{2})`);
        }
      }
    }

    // References validation (optional — array of strings)
    if (ctrl.references !== undefined) {
      if (!Array.isArray(ctrl.references)) {
        errors.push(`Control ${ctrl.id}: references must be an array`);
      } else {
        for (const ref of ctrl.references) {
          if (typeof ref !== 'string') {
            errors.push(`Control ${ctrl.id}: each reference must be a string`);
          }
        }
      }
    }

    // Evaluation field types
    if (ctrl.evaluation) {
      const ev = ctrl.evaluation;
      if (ev.max_aivss_posture !== undefined && typeof ev.max_aivss_posture !== 'number') {
        errors.push(`Control ${ctrl.id}: evaluation.max_aivss_posture must be a number`);
      }
      if (ev.max_critical_findings !== undefined && typeof ev.max_critical_findings !== 'number') {
        errors.push(`Control ${ctrl.id}: evaluation.max_critical_findings must be a number`);
      }
      if (ev.required_tools !== undefined) {
        if (!Array.isArray(ev.required_tools)) {
          errors.push(`Control ${ctrl.id}: evaluation.required_tools must be an array`);
        } else {
          for (const tool of ev.required_tools) {
            if (!KNOWN_TOOLS.has(tool)) {
              errors.push(`Control ${ctrl.id}: evaluation.required_tools references unknown tool "${tool}"`);
            }
          }
        }
      }
      if (ev.fail_on_severities !== undefined && !Array.isArray(ev.fail_on_severities)) {
        errors.push(`Control ${ctrl.id}: evaluation.fail_on_severities must be an array`);
      }
      if (ev.fail_on_actions !== undefined && !Array.isArray(ev.fail_on_actions)) {
        errors.push(`Control ${ctrl.id}: evaluation.fail_on_actions must be an array`);
      }
      if (ev.min_grade !== undefined && typeof ev.min_grade !== 'string') {
        errors.push(`Control ${ctrl.id}: evaluation.min_grade must be a string`);
      }

      // evidence_checks validation (generic path-based checks for SOC2/GDPR controls)
      if (ev.evidence_checks !== undefined) {
        if (!Array.isArray(ev.evidence_checks)) {
          errors.push(`Control ${ctrl.id}: evaluation.evidence_checks must be an array`);
        } else {
          for (let i = 0; i < ev.evidence_checks.length; i++) {
            const check = ev.evidence_checks[i];
            const prefix = `Control ${ctrl.id}: evidence_checks[${i}]`;
            if (!check.path || typeof check.path !== 'string') {
              errors.push(`${prefix}: must have a string "path"`);
            }
            if (!check.operator || !VALID_CHECK_OPS.has(check.operator)) {
              errors.push(`${prefix}: operator must be one of: ${[...VALID_CHECK_OPS].join(', ')}`);
            }
            if (check.operator !== 'exists' && check.value === undefined) {
              errors.push(`${prefix}: non-exists operators require a "value"`);
            }
            if (!check.on_fail || !['fail', 'partial', 'not_evaluated'].includes(check.on_fail)) {
              errors.push(`${prefix}: on_fail must be "fail", "partial", or "not_evaluated"`);
            }
            if (check.not_evaluated_reason !== undefined && typeof check.not_evaluated_reason !== 'string') {
              errors.push(`${prefix}: not_evaluated_reason must be a string`);
            }
            if (check.reason !== undefined && typeof check.reason !== 'string') {
              errors.push(`${prefix}: reason must be a string`);
            }
            if (check.default !== undefined && typeof check.default !== 'number' && typeof check.default !== 'boolean') {
              errors.push(`${prefix}: default must be a number or boolean`);
            }
          }
        }
      }
    }
  }

  return errors;
}

/**
 * Load a controls registry by framework name. Validates on first load per framework.
 * @param {string} [framework='aiuc-1'] - Framework identifier (maps to compliance/<framework>-controls.json)
 * @returns {object} The full registry object
 */
export function loadControls(framework = 'aiuc-1') {
  if (_cache.has(framework)) return _cache.get(framework);

  const controlsPath = join(__dirname, '..', '..', 'compliance', `${framework}-controls.json`);
  let raw;
  try {
    raw = readFileSync(controlsPath, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot load controls registry for framework "${framework}": ${err.message}`);
  }
  const data = JSON.parse(raw);

  const errors = validateRegistry(data);
  if (errors.length > 0) {
    throw new Error(`${framework} controls registry validation failed:\n${errors.join('\n')}`);
  }

  _cache.set(framework, data);
  return data;
}

/**
 * Filter controls by framework, domain, control IDs, or OWASP tags.
 * @param {object} [filters]
 * @param {string} [filters.framework] - Framework to load (default: 'aiuc-1')
 * @param {string} [filters.domain] - Domain name or 'all'
 * @param {string[]} [filters.controlIds] - Specific control IDs
 * @param {string[]} [filters.owaspFilter] - OWASP LLM tags to match
 * @returns {object[]} Filtered controls
 */
export function filterControls({ framework = 'aiuc-1', domain, controlIds, owaspFilter } = {}) {
  const registry = loadControls(framework);
  let controls = registry.controls;

  if (domain && domain !== 'all') {
    controls = controls.filter(c => c.domain === domain);
  }

  if (controlIds && controlIds.length > 0) {
    const idSet = new Set(controlIds);
    controls = controls.filter(c => idSet.has(c.id));
  }

  if (owaspFilter && owaspFilter.length > 0) {
    const owaspSet = new Set(owaspFilter);
    controls = controls.filter(c =>
      Array.isArray(c.owasp_llm) && c.owasp_llm.some(tag => owaspSet.has(tag))
    );
  }

  return controls;
}

/**
 * List available framework names by scanning the compliance directory.
 * @returns {string[]} Available framework identifiers
 */
export function listFrameworks() {
  const dir = join(__dirname, '..', '..', 'compliance');
  try {
    return readdirSync(dir)
      .filter(f => f.endsWith('-controls.json'))
      .map(f => f.replace('-controls.json', ''));
  } catch {
    return [];
  }
}

export { KNOWN_TOOLS };

// Reset cache (for testing)
export function _resetCache() {
  _cache.clear();
}
