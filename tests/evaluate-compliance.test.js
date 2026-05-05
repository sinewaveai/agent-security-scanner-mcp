import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdtempSync, rmSync, existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync, copyFileSync } from 'fs';
import { tmpdir } from 'os';
import { loadControls, filterControls, validateRegistry, _resetCache, listFrameworks } from '../src/lib/compliance-controls.js';
import { evaluateControl, evaluateAll, resolvePath } from '../src/lib/compliance-evaluator.js';
import { buildEvaluatorEvidence } from '../src/lib/compliance-evidence.js';
import { normalizeFindings } from '../src/lib/normalize-finding.js';
import { scoreBatch } from '../src/lib/aivss.js';
import scanProjectOutput from './fixtures/scan-project-output.json' with { type: 'json' };

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures', 'sbom');

function makeTmpWithLockfile() {
  const tmp = mkdtempSync(join(tmpdir(), 'eval-compliance-'));
  copyFileSync(join(fixturesDir, 'package-lock-v2.json'), join(tmp, 'package-lock.json'));
  writeFileSync(join(tmp, 'package.json'), JSON.stringify({ name: 'test-project', version: '1.0.0' }));
  return tmp;
}

// ============================================================
// Multi-framework registry loading
// ============================================================
describe('multi-framework loading', () => {
  beforeEach(() => _resetCache());

  it('loads AIUC-1 controls (default)', () => {
    const registry = loadControls();
    expect(registry.framework).toBe('AIUC-1');
    expect(registry.controls.length).toBe(16);
    expect(registry.domains).toEqual(['security', 'safety']);
  });

  it('loads SOC2-Technical controls', () => {
    const registry = loadControls('soc2-technical');
    expect(registry.framework).toBe('SOC2-Technical');
    expect(registry.controls.length).toBe(8);
    expect(registry.domains).toContain('supply-chain');
    expect(registry.domains).toContain('security');
    // Every control has evidence_checks
    for (const ctrl of registry.controls) {
      expect(ctrl.evaluation.evidence_checks).toBeDefined();
      expect(Array.isArray(ctrl.evaluation.evidence_checks)).toBe(true);
    }
  });

  it('loads GDPR-Technical controls', () => {
    const registry = loadControls('gdpr-technical');
    expect(registry.framework).toBe('GDPR-Technical');
    expect(registry.controls.length).toBe(6);
    expect(registry.domains).toContain('privacy');
    // All controls have references
    for (const ctrl of registry.controls) {
      expect(Array.isArray(ctrl.references)).toBe(true);
      expect(ctrl.references.length).toBeGreaterThan(0);
    }
  });

  it('throws for unknown framework', () => {
    expect(() => loadControls('nonexistent')).toThrow('Cannot load controls registry');
  });

  it('listFrameworks returns all available', () => {
    const frameworks = listFrameworks();
    expect(frameworks).toContain('aiuc-1');
    expect(frameworks).toContain('soc2-technical');
    expect(frameworks).toContain('gdpr-technical');
  });

  it('filterControls respects framework parameter', () => {
    const soc2 = filterControls({ framework: 'soc2-technical' });
    expect(soc2.length).toBe(8);
    expect(soc2[0].id).toMatch(/^SOC2-T/);

    const gdpr = filterControls({ framework: 'gdpr-technical' });
    expect(gdpr.length).toBe(6);
    expect(gdpr[0].id).toMatch(/^GDPR-T/);
  });

  it('filterControls domain filter works for non-AIUC frameworks', () => {
    const supplyChain = filterControls({ framework: 'soc2-technical', domain: 'supply-chain' });
    expect(supplyChain.length).toBeGreaterThan(0);
    expect(supplyChain.every(c => c.domain === 'supply-chain')).toBe(true);

    const privacy = filterControls({ framework: 'gdpr-technical', domain: 'privacy' });
    expect(privacy.length).toBeGreaterThan(0);
    expect(privacy.every(c => c.domain === 'privacy')).toBe(true);
  });

  it('AIUC-1 backward compat: default call returns same result', () => {
    const byDefault = loadControls();
    const byName = loadControls('aiuc-1');
    expect(byDefault).toBe(byName); // Same cached instance
    expect(byDefault.controls.length).toBe(16);
  });
});

// ============================================================
// Registry validation
// ============================================================
describe('validateRegistry with new features', () => {
  it('validates evidence_checks structure', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{
            path: 'scan.by_severity.CRITICAL',
            operator: 'lte',
            value: 0,
            on_fail: 'fail',
            reason: 'test reason',
          }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors).toHaveLength(0);
  });

  it('rejects invalid evidence_checks operator', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{
            path: 'scan.x', operator: 'invalid_op', value: 0, on_fail: 'fail',
          }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('operator must be one of'))).toBe(true);
  });

  it('rejects evidence_checks missing path', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ operator: 'eq', value: 0, on_fail: 'fail' }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('string "path"'))).toBe(true);
  });

  it('requires value for non-exists operators', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ path: 'a.b', operator: 'lte', on_fail: 'fail' }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('require a "value"'))).toBe(true);
  });

  it('allows exists without value', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ path: 'a.b', operator: 'exists', on_fail: 'not_evaluated' }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors).toHaveLength(0);
  });

  it('rejects non-string not_evaluated_reason', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ path: 'a.b', operator: 'eq', value: 0, on_fail: 'not_evaluated', not_evaluated_reason: 123 }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('not_evaluated_reason must be a string'))).toBe(true);
  });

  it('rejects non-string reason', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ path: 'a.b', operator: 'eq', value: 0, on_fail: 'fail', reason: true }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('reason must be a string'))).toBe(true);
  });

  it('rejects non-number/boolean default', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        evaluation: {
          evidence_checks: [{ path: 'a.b', operator: 'eq', value: 0, on_fail: 'fail', default: 'zero' }],
        },
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('default must be a number or boolean'))).toBe(true);
  });

  it('validates references as string array', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        references: ['CC6.1', 'Art. 32'],
        evaluation: {},
      }],
    };
    const errors = validateRegistry(data);
    expect(errors).toHaveLength(0);
  });

  it('rejects non-array references', () => {
    const data = {
      domains: ['security'],
      controls: [{
        id: 'T001', title: 'Test', domain: 'security',
        references: 'CC6.1',
        evaluation: {},
      }],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('references must be an array'))).toBe(true);
  });
});

// ============================================================
// Dot-path resolver
// ============================================================
describe('resolvePath', () => {
  it('resolves simple path', () => {
    expect(resolvePath({ a: 1 }, 'a')).toBe(1);
  });

  it('resolves nested path', () => {
    expect(resolvePath({ a: { b: { c: 42 } } }, 'a.b.c')).toBe(42);
  });

  it('returns undefined for missing intermediate', () => {
    expect(resolvePath({ a: {} }, 'a.b.c')).toBeUndefined();
  });

  it('returns undefined for null object', () => {
    expect(resolvePath(null, 'a')).toBeUndefined();
  });

  it('returns undefined for null path', () => {
    expect(resolvePath({ a: 1 }, null)).toBeUndefined();
  });

  it('handles zero values correctly', () => {
    expect(resolvePath({ a: { b: 0 } }, 'a.b')).toBe(0);
  });

  it('handles false values correctly', () => {
    expect(resolvePath({ a: { b: false } }, 'a.b')).toBe(false);
  });
});

// ============================================================
// Evidence_checks evaluator
// ============================================================
describe('evidence_checks evaluation', () => {
  const makeControl = (checks) => ({
    id: 'TEST-001',
    title: 'Test',
    domain: 'security',
    scanner_tools: [],
    evaluation: { evidence_checks: checks },
  });

  const baseEvidence = {
    findings: [],
    grades: {},
    toolsRun: [],
  };

  it('passes when all checks succeed', () => {
    const control = makeControl([
      { path: 'sbom.component_count', operator: 'gte', value: 1, on_fail: 'fail', reason: 'No components' },
    ]);
    const bundle = { sbom: { component_count: 10 } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('pass');
  });

  it('fails when lte check exceeded', () => {
    const control = makeControl([
      { path: 'supply_chain.vulnerabilities.by_severity.critical', operator: 'lte', value: 0, on_fail: 'fail', reason: 'Critical vulns' },
    ]);
    const bundle = { supply_chain: { vulnerabilities: { by_severity: { critical: 3 } } } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('fail');
    expect(result.reasons).toContain('Critical vulns');
  });

  it('partial when partial check fails', () => {
    const control = makeControl([
      { path: 'scan.by_severity.HIGH', operator: 'lte', value: 2, on_fail: 'partial', reason: 'Too many HIGH' },
    ]);
    const bundle = { scan: { by_severity: { HIGH: 5 } } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('partial');
  });

  it('not_evaluated when evidence path missing and no default', () => {
    const control = makeControl([
      { path: 'supply_chain.vulnerabilities.by_severity.critical', operator: 'lte', value: 0, on_fail: 'fail', reason: 'No vuln data' },
    ]);
    const bundle = {}; // no supply_chain data
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('not_evaluated');
  });

  it('not_evaluated when entire section is null even with default (source failure)', () => {
    const control = makeControl([
      { path: 'supply_chain.vulnerabilities.by_severity.critical', operator: 'lte', value: 0, on_fail: 'fail', reason: 'Critical vulns', default: 0 },
    ]);
    // Section entirely missing — source failed, default must NOT mask this
    const bundle = {};
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('not_evaluated');
    expect(result.reasons[0]).toContain('Evidence source unavailable');
  });

  it('uses default when section exists but leaf key is absent', () => {
    const control = makeControl([
      { path: 'scan.by_category_severity.crypto.CRITICAL', operator: 'lte', value: 0, on_fail: 'fail', reason: 'Critical crypto', default: 0 },
    ]);
    // scan section exists, but crypto category not present — safe to use default
    const bundle = { scan: { by_category_severity: {} } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('pass'); // default 0 <= 0
  });

  it('eq check with boolean works', () => {
    const control = makeControl([
      { path: 'supply_chain.drift.baseline_exists', operator: 'eq', value: true, on_fail: 'not_evaluated', not_evaluated_reason: 'No baseline' },
    ]);
    // Baseline exists
    const result1 = evaluateControl(control, baseEvidence, { supply_chain: { drift: { baseline_exists: true } } });
    expect(result1.status).toBe('pass');
    // Baseline does not exist — uses not_evaluated_reason, not failure reason
    const result2 = evaluateControl(control, baseEvidence, { supply_chain: { drift: { baseline_exists: false } } });
    expect(result2.status).toBe('not_evaluated');
    expect(result2.reasons[0]).toBe('No baseline');
  });

  it('exists check works', () => {
    const control = makeControl([
      { path: 'sbom.component_count', operator: 'exists', on_fail: 'fail', reason: 'No SBOM' },
    ]);
    const result1 = evaluateControl(control, baseEvidence, { sbom: { component_count: 5 } });
    expect(result1.status).toBe('pass');
    const result2 = evaluateControl(control, baseEvidence, {});
    expect(result2.status).toBe('not_evaluated'); // missing = not_evaluated (not fail)
  });

  it('multiple checks: first fail wins over subsequent partial', () => {
    const control = makeControl([
      { path: 'scan.by_severity.CRITICAL', operator: 'lte', value: 0, on_fail: 'fail', reason: 'Critical findings', default: 0 },
      { path: 'scan.by_severity.HIGH', operator: 'lte', value: 5, on_fail: 'partial', reason: 'Too many HIGH', default: 0 },
    ]);
    const bundle = { scan: { by_severity: { CRITICAL: 2, HIGH: 10 } } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('fail');
    expect(result.reasons.length).toBe(2);
  });

  it('evidence_checks not run when evidenceBundle is null', () => {
    const control = makeControl([
      { path: 'sbom.component_count', operator: 'gte', value: 1, on_fail: 'fail', reason: 'No SBOM' },
    ]);
    // No evidenceBundle passed → evidence_checks skipped
    const result = evaluateControl(control, baseEvidence);
    expect(result.status).toBe('pass');
  });
});

// ============================================================
// Regression tests for review findings
// ============================================================
describe('review finding fixes', () => {
  const baseEvidence = { findings: [], grades: {}, toolsRun: [] };

  it('F1: null scan section → not_evaluated, not pass (even with defaults)', () => {
    // Simulates OSV outage: supply_chain.vulnerabilities is null
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      scan: null, // scan source failed
      sbom: { component_count: 10 },
      supply_chain: {
        vulnerabilities: null, // OSV outage
        hallucinations: { hallucinated_count: 0, legitimate_count: 5 },
        drift: { baseline_exists: true },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);

    // SOC2-T002 (vulns) must NOT pass — source failed
    const t002 = result.results.find(r => r.control_id === 'SOC2-T002');
    expect(t002.status).toBe('not_evaluated');

    // SOC2-T004 (code findings) must NOT pass — scan is null
    const t004 = result.results.find(r => r.control_id === 'SOC2-T004');
    expect(t004.status).toBe('not_evaluated');

    // SOC2-T005 (exfiltration) must NOT pass — scan is null
    const t005 = result.results.find(r => r.control_id === 'SOC2-T005');
    expect(t005.status).toBe('not_evaluated');
  });

  it('F2: hallucination control is not_evaluated when all ecosystems unsupported', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      sbom: { component_count: 5 },
      supply_chain: {
        hallucinations: {
          hallucinated_count: 0,
          unsupported_count: 5,
          legitimate_count: 0, // no ecosystems could be verified
          hallucinated_packages: [],
          unsupported_packages: [],
        },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    const t003 = result.results.find(r => r.control_id === 'SOC2-T003');
    expect(t003.status).toBe('not_evaluated');
    expect(t003.reasons.some(r => r.includes('unsupported'))).toBe(true);
  });

  it('F4: not_evaluated uses distinct reason, not failure reason', () => {
    const makeControl = (checks) => ({
      id: 'TEST', title: 'Test', domain: 'security', scanner_tools: [],
      evaluation: { evidence_checks: checks },
    });
    const control = makeControl([{
      path: 'supply_chain.drift.baseline_exists',
      operator: 'eq',
      value: true,
      on_fail: 'not_evaluated',
      reason: 'Drift check failed — baseline diverged',
      not_evaluated_reason: 'No SBOM baseline available for comparison',
    }]);
    const bundle = { supply_chain: { drift: { baseline_exists: false } } };
    const result = evaluateControl(control, baseEvidence, bundle);
    expect(result.status).toBe('not_evaluated');
    // Should use not_evaluated_reason, NOT the failure reason
    expect(result.reasons[0]).toBe('No SBOM baseline available for comparison');
    expect(result.reasons[0]).not.toContain('diverged');
  });
});

// ============================================================
// SOC2/GDPR controls with real registry
// ============================================================
describe('SOC2-Technical evaluation', () => {
  beforeEach(() => _resetCache());

  it('SBOM-dependent controls become not_evaluated when SBOM evidence is missing', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: ['scan_project', 'scan_security'] };
    const bundle = { scan: { by_severity: {}, by_category_severity: {} } }; // no sbom data
    const result = evaluateAll(controls, legacyEvidence, bundle);

    // SOC2-T001 (dependency inventory exists) should be not_evaluated
    const t001 = result.results.find(r => r.control_id === 'SOC2-T001');
    expect(t001.status).toBe('not_evaluated');
  });

  it('critical dependency vulnerabilities fail SOC2-T002', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      sbom: { component_count: 10 },
      supply_chain: {
        vulnerabilities: { by_severity: { critical: 2, high: 0, medium: 0, low: 0 } },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    const t002 = result.results.find(r => r.control_id === 'SOC2-T002');
    expect(t002.status).toBe('fail');
    expect(t002.reasons.some(r => r.includes('Critical dependency vulnerabilities'))).toBe(true);
  });

  it('hallucinated packages fail SOC2-T003', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      sbom: { component_count: 10 },
      supply_chain: {
        hallucinations: { hallucinated_count: 1, hallucinated_packages: [{ name: 'fake-pkg' }] },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    const t003 = result.results.find(r => r.control_id === 'SOC2-T003');
    expect(t003.status).toBe('fail');
  });

  it('missing baseline makes drift control not_evaluated', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      sbom: { component_count: 10 },
      supply_chain: { drift: { baseline_exists: false } },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    const t008 = result.results.find(r => r.control_id === 'SOC2-T008');
    expect(t008.status).toBe('not_evaluated');
    expect(t008.reasons.some(r => r.includes('baseline'))).toBe(true);
  });

  it('clean project passes all SOC2 controls', () => {
    const controls = loadControls('soc2-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      scan: {
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        by_category_severity: {},
      },
      sbom: { component_count: 10 },
      supply_chain: {
        vulnerabilities: { by_severity: { critical: 0, high: 0, medium: 0, low: 0 } },
        hallucinations: { hallucinated_count: 0, legitimate_count: 5 },
        drift: { baseline_exists: true },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    // All should be pass (using defaults for missing category-severity)
    const failCount = result.results.filter(r => r.status === 'fail').length;
    expect(failCount).toBe(0);
  });
});

describe('GDPR-Technical evaluation', () => {
  beforeEach(() => _resetCache());

  it('loads and evaluates GDPR controls', () => {
    const controls = loadControls('gdpr-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      scan: { by_severity: {}, by_category_severity: {} },
      sbom: { component_count: 5 },
      supply_chain: {
        vulnerabilities: { by_severity: { critical: 0, high: 0 } },
        hallucinations: { hallucinated_count: 0, legitimate_count: 3 },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    expect(result.controls_evaluated).toBe(6);
    // No failures for clean project
    expect(result.fail).toBe(0);
  });

  it('critical info-exposure fails GDPR-T001', () => {
    const controls = loadControls('gdpr-technical').controls;
    const legacyEvidence = { findings: [], grades: {}, toolsRun: [] };
    const bundle = {
      scan: {
        by_severity: {},
        by_category_severity: {
          'info-exposure': { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        },
      },
    };
    const result = evaluateAll(controls, legacyEvidence, bundle);
    const t001 = result.results.find(r => r.control_id === 'GDPR-T001');
    expect(t001.status).toBe('fail');
  });
});

// ============================================================
// AIUC-1 backward compatibility
// ============================================================
describe('AIUC-1 backward compatibility', () => {
  beforeEach(() => _resetCache());

  it('evaluateAll without evidenceBundle works as before', () => {
    const controls = loadControls().controls;
    const evidence = {
      findings: [],
      grades: { project: 'A' },
      toolsRun: ['scan_project', 'scan_security'],
      aivssPosture: { posture_score: 2.0 },
    };
    const result = evaluateAll(controls, evidence);
    expect(result.controls_evaluated).toBe(16);
    expect(result.pass + result.partial + result.fail + result.not_evaluated).toBe(16);
  });

  it('integration with real scan fixture still works', () => {
    const normalized = normalizeFindings(scanProjectOutput.issues, 'scan_project');
    const { posture } = scoreBatch(normalized);
    const controls = loadControls().controls;
    const evidence = {
      findings: normalized,
      grades: { project: scanProjectOutput.grade },
      toolsRun: ['scan_project', 'scan_security'],
      aivssPosture: posture,
    };
    const result = evaluateAll(controls, evidence);
    expect(result.controls_evaluated).toBe(16);
    for (const r of result.results) {
      expect(['pass', 'partial', 'fail', 'not_evaluated']).toContain(r.status);
    }
  });
});

// ============================================================
// Evidence bundle persistence
// ============================================================
describe('evidence persistence', () => {
  let originalFetch;
  let tmp;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ results: Array(20).fill({ vulns: [] }) }),
    });
    _resetCache();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (tmp && existsSync(tmp)) rmSync(tmp, { recursive: true, force: true });
  });

  it('saves evidence bundle to disk when save_evidence=true', async () => {
    // This is an integration test — uses real scanProject + SBOM on a temp project
    const { evaluateCompliance } = await import('../src/tools/evaluate-compliance.js');

    tmp = makeTmpWithLockfile();
    // Create a simple JS file so scan_project has something to scan
    writeFileSync(join(tmp, 'index.js'), 'console.log("hello");');

    const result = await evaluateCompliance({
      directory_path: tmp,
      frameworks: ['soc2-technical'],
      save_evidence: true,
      verbosity: 'compact',
    });

    const output = JSON.parse(result.content[0].text);
    expect(output.evidence_saved).toBeDefined();
    expect(existsSync(output.evidence_saved)).toBe(true);

    // Verify the saved evidence structure
    const saved = JSON.parse(readFileSync(output.evidence_saved, 'utf-8'));
    expect(saved.metadata).toBeDefined();
    expect(saved.tools_run).toBeDefined();
    expect(saved.compliance).toBeDefined();
    expect(saved.compliance[0].framework).toBe('SOC2-Technical');
  }, 60000);
});
