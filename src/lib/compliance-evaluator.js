// src/lib/compliance-evaluator.js — Deterministic pass/partial/fail evaluation logic.

import { scoreBatch } from './aivss.js';

const GRADE_ORDER = { A: 4, B: 3, C: 2, D: 1, F: 0 };

/**
 * Resolve a dot-path like "supply_chain.vulnerabilities.by_severity.critical" against an object.
 * Returns undefined for any missing intermediate key (never throws).
 */
export function resolvePath(obj, path) {
  if (obj == null || typeof path !== 'string') return undefined;
  const segments = path.split('.');
  let current = obj;
  for (const seg of segments) {
    if (current == null || typeof current !== 'object') return undefined;
    current = current[seg];
  }
  return current;
}

/**
 * Run a single evidence_check against the evidence bundle.
 * Returns { passed: boolean, status: string|null, reason: string } where:
 * - passed=true means check succeeded (no status change needed)
 * - passed=false means on_fail status should be applied, with reason
 */
function runEvidenceCheck(check, evidenceBundle) {
  const value = resolvePath(evidenceBundle, check.path);

  // Missing evidence handling — three tiers:
  //
  // 1. Any node along the path is explicitly `null` → source failure → not_evaluated.
  //    The evidence collector sets sections to null when a data source fails (e.g., OSV down).
  //
  // 2. A top-level section key is missing entirely (e.g., bundle has no "supply_chain") →
  //    evidence was never collected → not_evaluated. Defaults must not mask this.
  //
  // 3. A deeper leaf is missing but its parent exists (e.g., scan.by_category_severity.crypto
  //    is absent because no crypto findings) → safe to apply check.default.
  //
  if (value === undefined || value === null) {
    const segments = check.path.split('.');

    // Walk the path to find where it breaks
    let current = evidenceBundle;
    let depth = 0;
    for (depth = 0; depth < segments.length; depth++) {
      if (current === null) {
        // Explicit null — source failure
        const failedAt = segments.slice(0, depth).join('.') || segments[0];
        return {
          passed: false,
          status: 'not_evaluated',
          reason: `Evidence source unavailable: ${failedAt} is null (full path: ${check.path})`,
        };
      }
      if (current === undefined || typeof current !== 'object') break;
      const next = current[segments[depth]];
      if (next === null) {
        // Explicit null at this level
        const failedAt = segments.slice(0, depth + 1).join('.');
        return {
          passed: false,
          status: 'not_evaluated',
          reason: `Evidence source unavailable: ${failedAt} is null (full path: ${check.path})`,
        };
      }
      if (next === undefined) break; // missing key — check depth below
      current = next;
    }

    // If the break happened at depth 0 or 1, the top-level section is missing.
    // This means evidence was never collected — not_evaluated, no defaults.
    if (depth <= 1) {
      return {
        passed: false,
        status: 'not_evaluated',
        reason: `Evidence source unavailable: ${segments[0]} is missing (full path: ${check.path})`,
      };
    }

    // Break happened deeper — parent section exists, leaf key absent.
    // Safe to apply default (e.g., scan ran but no "crypto" category).
    if (check.default !== undefined) {
      return evaluateOp(check.operator, check.default, check.value, check);
    }

    return {
      passed: false,
      status: 'not_evaluated',
      reason: `Missing evidence at path: ${check.path}`,
    };
  }

  return evaluateOp(check.operator, value, check.value, check);
}

function evaluateOp(operator, actual, expected, check) {
  let passed;
  switch (operator) {
    case 'exists':
      passed = actual !== undefined && actual !== null;
      break;
    case 'eq':
      passed = actual === expected;
      break;
    case 'lte':
      passed = typeof actual === 'number' && actual <= expected;
      break;
    case 'gte':
      passed = typeof actual === 'number' && actual >= expected;
      break;
    default:
      return { passed: false, status: 'not_evaluated', reason: `Unknown operator: ${operator}` };
  }

  if (passed) {
    return { passed: true, status: null, reason: '' };
  }

  const status = check.on_fail || 'fail';
  // Use distinct reason for not_evaluated vs failure to avoid confusing audit consumers.
  // "reason" is the failure message; "not_evaluated_reason" explains why evidence was insufficient.
  const reason = status === 'not_evaluated'
    ? (check.not_evaluated_reason || `Evidence insufficient: ${check.path} ${operator} ${expected} (actual: ${actual})`)
    : (check.reason || `Check failed: ${check.path} ${operator} ${expected} (actual: ${actual})`);

  return { passed: false, status, reason };
}

/**
 * Check if actual grade is worse than threshold.
 * Missing/null grade → treated as F (worst case).
 */
function gradeIsWorse(actual, threshold) {
  const actualVal = GRADE_ORDER[actual] ?? 0; // null/missing → F → 0
  const thresholdVal = GRADE_ORDER[threshold] ?? 0;
  return actualVal < thresholdVal;
}

/**
 * Evaluate a single control against evidence.
 *
 * @param {object} control - A control from the registry
 * @param {object} evidence - Legacy evidence shape (aivssPosture, findings, grades, toolsRun)
 * @param {object} [evidenceBundle] - Full evidence bundle for evidence_checks evaluation
 * @returns {{ control_id: string, status: string, reasons: string[] }}
 */
export function evaluateControl(control, evidence, evidenceBundle) {
  if (!control || !control.id || !control.evaluation) {
    return {
      control_id: control?.id || 'unknown',
      status: 'not_evaluated',
      reasons: ['Malformed control: missing id or evaluation'],
    };
  }

  const ev = control.evaluation;
  const reasons = [];
  const toolsRun = evidence.toolsRun || [];

  // 1. Check required_tools
  if (Array.isArray(ev.required_tools)) {
    for (const tool of ev.required_tools) {
      if (!toolsRun.includes(tool)) {
        return {
          control_id: control.id,
          status: 'not_evaluated',
          reasons: [`Missing required tool: ${tool}`],
        };
      }
    }
  }

  let status = 'pass';

  // Scope findings to this control's relevant tools
  const relevantTools = Array.isArray(control.scanner_tools) ? new Set(control.scanner_tools) : null;
  const relevantFindings = (evidence.findings || []).filter(f => {
    if (!relevantTools) return true;
    return relevantTools.has(f.source_tool);
  });

  // 2. Check fail_on_severities
  if (Array.isArray(ev.fail_on_severities) && ev.fail_on_severities.length > 0) {
    const sevSet = new Set(ev.fail_on_severities);
    const matched = relevantFindings.filter(f => sevSet.has(f.severity));
    if (matched.length > 0) {
      status = 'fail';
      reasons.push(`${matched.length} finding(s) with severity in [${ev.fail_on_severities.join(', ')}]`);
    }
  }

  // 3. Check fail_on_actions
  if (Array.isArray(ev.fail_on_actions) && ev.fail_on_actions.length > 0) {
    const actSet = new Set(ev.fail_on_actions);
    const matched = relevantFindings.filter(f => f.action && actSet.has(f.action));
    if (matched.length > 0) {
      status = 'fail';
      reasons.push(`${matched.length} finding(s) with action in [${ev.fail_on_actions.join(', ')}]`);
    }
  }

  // 4. Check max_aivss_posture (scoped to this control's relevant findings)
  if (typeof ev.max_aivss_posture === 'number' && relevantFindings.length > 0) {
    const scopedPosture = scoreBatch(relevantFindings).posture;
    if (scopedPosture.posture_score > ev.max_aivss_posture) {
      status = 'fail';
      reasons.push(`AIVSS posture ${scopedPosture.posture_score} exceeds max ${ev.max_aivss_posture}`);
    }
  }

  // 5. Check max_critical_findings (scoped to this control's tools)
  if (typeof ev.max_critical_findings === 'number') {
    const critCount = relevantFindings.filter(f => f.severity === 'CRITICAL').length;
    if (critCount > ev.max_critical_findings) {
      status = 'fail';
      reasons.push(`${critCount} CRITICAL finding(s) exceeds max ${ev.max_critical_findings}`);
    }
  }

  // 6. Check min_grade (scoped to control's relevant grade keys)
  if (ev.min_grade) {
    const grades = evidence.grades || {};
    // Only consider grades for tools this control cares about
    const relevantGradeKeys = relevantTools
      ? Object.keys(grades).filter(k => relevantTools.has(k) || relevantTools.has(`scan_${k}`))
      : Object.keys(grades);
    const gradeValues = relevantGradeKeys.map(k => grades[k]);
    if (gradeValues.length > 0) {
      const worstGrade = gradeValues.reduce((worst, g) => {
        return gradeIsWorse(g, worst) ? g : worst;
      }, gradeValues[0]);
      if (gradeIsWorse(worstGrade, ev.min_grade)) {
        if (status !== 'fail') status = 'partial';
        reasons.push(`Grade ${worstGrade || 'F'} below minimum ${ev.min_grade}`);
      }
    } else if (status !== 'fail') {
      // No relevant grades available → treat as F
      if (gradeIsWorse(null, ev.min_grade)) {
        status = 'partial';
        reasons.push(`No relevant grade available (treated as F), below minimum ${ev.min_grade}`);
      }
    }
  }

  // 7. Run evidence_checks (generic path-based checks, used by SOC2/GDPR controls)
  if (Array.isArray(ev.evidence_checks) && evidenceBundle) {
    for (const check of ev.evidence_checks) {
      const result = runEvidenceCheck(check, evidenceBundle);
      if (!result.passed) {
        if (result.status === 'not_evaluated') {
          // If we haven't already failed/passed via legacy checks, mark not_evaluated
          if (status === 'pass') status = 'not_evaluated';
        } else if (result.status === 'fail') {
          status = 'fail';
        } else if (result.status === 'partial' && status !== 'fail') {
          status = 'partial';
        }
        if (result.reason) reasons.push(result.reason);
      }
    }
  }

  return { control_id: control.id, status, reasons };
}

/**
 * Evaluate all controls against evidence.
 *
 * @param {object[]} controls - Array of controls from registry
 * @param {object} evidence - Legacy evidence shape
 * @param {object} [evidenceBundle] - Full evidence bundle for evidence_checks
 * @returns {{ controls_evaluated: number, pass: number, partial: number, fail: number, not_evaluated: number, results: object[] }}
 */
export function evaluateAll(controls, evidence, evidenceBundle) {
  const results = controls.map(c => evaluateControl(c, evidence, evidenceBundle));

  const summary = { pass: 0, partial: 0, fail: 0, not_evaluated: 0 };
  for (const r of results) {
    summary[r.status] = (summary[r.status] || 0) + 1;
  }

  return {
    controls_evaluated: controls.length,
    ...summary,
    results,
  };
}
