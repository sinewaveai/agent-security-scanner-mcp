import { describe, it, expect, beforeEach } from 'vitest';
import { loadControls, filterControls, validateRegistry, _resetCache } from '../src/lib/compliance-controls.js';
import { evaluateControl, evaluateAll } from '../src/lib/compliance-evaluator.js';
import { normalizeFindings } from '../src/lib/normalize-finding.js';
import { scoreBatch } from '../src/lib/aivss.js';
import scanProjectOutput from './fixtures/scan-project-output.json' with { type: 'json' };

describe('compliance-controls loader', () => {
  beforeEach(() => _resetCache());

  it('loads all 16 controls successfully', () => {
    const registry = loadControls();
    expect(registry.controls).toHaveLength(16);
    expect(registry.framework).toBe('AIUC-1');
    expect(registry.schema_version).toBe('1.0');
  });

  it('domain filter returns only matching controls', () => {
    const security = filterControls({ domain: 'security' });
    expect(security.length).toBeGreaterThan(0);
    expect(security.every(c => c.domain === 'security')).toBe(true);

    const safety = filterControls({ domain: 'safety' });
    expect(safety.length).toBeGreaterThan(0);
    expect(safety.every(c => c.domain === 'safety')).toBe(true);

    expect(security.length + safety.length).toBe(16);
  });

  it('control ID filter works', () => {
    const result = filterControls({ controlIds: ['B001', 'C003'] });
    expect(result).toHaveLength(2);
    expect(result.map(c => c.id).sort()).toEqual(['B001', 'C003']);
  });

  it('OWASP filter works', () => {
    const result = filterControls({ owaspFilter: ['LLM01'] });
    expect(result.length).toBeGreaterThan(0);
    expect(result.every(c => c.owasp_llm.includes('LLM01'))).toBe(true);
  });
});

describe('validateRegistry', () => {
  it('catches duplicate IDs', () => {
    const data = {
      domains: ['security'],
      controls: [
        { id: 'B001', title: 'T', domain: 'security', evaluation: {} },
        { id: 'B001', title: 'T2', domain: 'security', evaluation: {} },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('Duplicate'))).toBe(true);
  });

  it('catches unknown domains', () => {
    const data = {
      domains: ['security'],
      controls: [
        { id: 'X001', title: 'T', domain: 'unknown_domain', evaluation: {} },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('unknown domain'))).toBe(true);
  });

  it('catches unknown tool names', () => {
    const data = {
      domains: ['security'],
      controls: [
        { id: 'X001', title: 'T', domain: 'security', scanner_tools: ['nonexistent_tool'], evaluation: {} },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('unknown scanner tool'))).toBe(true);
  });

  it('catches missing fields', () => {
    const data = {
      domains: ['security'],
      controls: [
        { title: 'T' }, // missing id, domain, evaluation
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('missing "id"'))).toBe(true);
    expect(errors.some(e => e.includes('missing "domain"'))).toBe(true);
    expect(errors.some(e => e.includes('missing "evaluation"'))).toBe(true);
  });

  it('catches unknown tool in evaluation.required_tools', () => {
    const data = {
      domains: ['security'],
      controls: [
        {
          id: 'X001', title: 'T', domain: 'security',
          evaluation: { required_tools: ['scan_security', 'scan_typo'] },
        },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('required_tools') && e.includes('scan_typo'))).toBe(true);
  });

  it('catches invalid OWASP tags', () => {
    const data = {
      domains: ['security'],
      controls: [
        { id: 'X001', title: 'T', domain: 'security', owasp_llm: ['BADTAG'], evaluation: {} },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('invalid OWASP tag'))).toBe(true);
  });

  it('rejects registry without domains array', () => {
    const data = {
      controls: [
        { id: 'X001', title: 'T', domain: 'security', evaluation: {} },
      ],
    };
    const errors = validateRegistry(data);
    expect(errors.some(e => e.includes('non-empty "domains"'))).toBe(true);
  });
});

describe('compliance-evaluator', () => {
  it('pass scenario: clean scan', () => {
    const control = {
      id: 'B003', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        max_aivss_posture: 6.0,
        fail_on_severities: ['CRITICAL'],
        required_tools: ['scan_security'],
        min_grade: 'C',
        max_critical_findings: 0,
      },
    };
    const evidence = {
      aivssPosture: { posture_score: 2.0 },
      findings: [],
      grades: { scan_security: 'A' },
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('pass');
    expect(result.reasons).toHaveLength(0);
  });

  it('fail on CRITICAL finding', () => {
    const control = {
      id: 'B001', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_agent_prompt'],
      evaluation: {
        fail_on_severities: ['CRITICAL'],
        required_tools: ['scan_agent_prompt'],
        max_critical_findings: 0,
      },
    };
    const evidence = {
      findings: [{ severity: 'CRITICAL', source_tool: 'scan_agent_prompt', rule_id: 'r1' }],
      grades: {},
      toolsRun: ['scan_agent_prompt'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('fail');
    expect(result.reasons.some(r => r.includes('CRITICAL'))).toBe(true);
  });

  it('fail on BLOCK action', () => {
    const control = {
      id: 'B002', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_agent_prompt'],
      evaluation: {
        fail_on_actions: ['BLOCK'],
        required_tools: ['scan_agent_prompt'],
      },
    };
    const evidence = {
      findings: [{ action: 'BLOCK', source_tool: 'scan_agent_prompt', severity: 'HIGH', rule_id: 'r1' }],
      grades: {},
      toolsRun: ['scan_agent_prompt'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('fail');
    expect(result.reasons.some(r => r.includes('BLOCK'))).toBe(true);
  });

  it('fail on high AIVSS posture from relevant findings', () => {
    const control = {
      id: 'B004', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        max_aivss_posture: 1.0,
        required_tools: ['scan_security'],
      },
    };
    const evidence = {
      findings: [
        { severity: 'HIGH', severity_rank: 3, confidence: 'HIGH', category: 'injection', source_tool: 'scan_security', rule_id: 'r1', message: 'test' },
      ],
      grades: {},
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('fail');
    expect(result.reasons.some(r => r.includes('AIVSS posture'))).toBe(true);
  });

  it('AIVSS posture from unrelated tool does not fail control', () => {
    const control = {
      id: 'B004', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        max_aivss_posture: 1.0,
        required_tools: ['scan_security'],
      },
    };
    const evidence = {
      findings: [
        { severity: 'HIGH', severity_rank: 3, confidence: 'HIGH', category: 'injection', source_tool: 'scan_skill', rule_id: 'unrelated', message: 'test' },
      ],
      grades: {},
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    // No relevant findings → posture not computed → should not fail
    expect(result.status).toBe('pass');
  });

  it('partial on bad grade (grade ordering: A > B > C > D > F)', () => {
    const control = {
      id: 'B007', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        required_tools: ['scan_security'],
        min_grade: 'C',
      },
    };
    const evidence = {
      findings: [],
      grades: { scan_security: 'D' },
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('partial');
    expect(result.reasons.some(r => r.includes('Grade D'))).toBe(true);
  });

  it('null/missing grade treated as F (worst case)', () => {
    const control = {
      id: 'B007', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        required_tools: ['scan_security'],
        min_grade: 'D',
      },
    };
    const evidence = {
      findings: [],
      grades: {},
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('partial');
    expect(result.reasons.some(r => r.includes('treated as F'))).toBe(true);
  });

  it('not_evaluated when required tool missing, reason includes tool name', () => {
    const control = {
      id: 'B001', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_agent_prompt'],
      evaluation: {
        required_tools: ['scan_agent_prompt'],
      },
    };
    const evidence = {
      findings: [],
      grades: {},
      toolsRun: ['scan_project'], // does NOT include scan_agent_prompt
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('not_evaluated');
    expect(result.reasons[0]).toContain('scan_agent_prompt');
  });

  it('malformed control handled gracefully', () => {
    const result = evaluateControl({}, { findings: [], grades: {}, toolsRun: [] });
    expect(result.status).toBe('not_evaluated');
    expect(result.reasons.some(r => r.includes('Malformed'))).toBe(true);
  });

  it('CRITICAL finding from unrelated tool does not fail control', () => {
    const control = {
      id: 'B001', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_agent_prompt'],
      evaluation: {
        fail_on_severities: ['CRITICAL'],
        required_tools: ['scan_agent_prompt'],
        max_critical_findings: 0,
      },
    };
    const evidence = {
      findings: [
        { severity: 'CRITICAL', source_tool: 'scan_skill', rule_id: 'unrelated' },
      ],
      grades: {},
      toolsRun: ['scan_agent_prompt'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('pass');
  });

  it('grade from unrelated scope does not trigger partial', () => {
    const control = {
      id: 'B007', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        required_tools: ['scan_security'],
        min_grade: 'C',
      },
    };
    const evidence = {
      findings: [],
      grades: { scan_security: 'A', scan_skill: 'F' },
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('pass');
  });

  it('unknown overrides in evaluation object ignored without crash', () => {
    const control = {
      id: 'B001', title: 'Test',
      domain: 'security',
      scanner_tools: ['scan_security'],
      evaluation: {
        required_tools: ['scan_security'],
        some_future_field: 'unknown',
        another_field: 42,
      },
    };
    const evidence = {
      findings: [],
      grades: { project: 'A' },
      toolsRun: ['scan_security'],
    };
    const result = evaluateControl(control, evidence);
    expect(result.status).toBe('pass');
  });
});

describe('evaluateAll', () => {
  it('evaluates all controls and returns summary', () => {
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
    // Many controls require tools not in toolsRun → not_evaluated
    expect(result.not_evaluated).toBeGreaterThan(0);
    expect(result.results).toHaveLength(16);
  });
});

describe('integration with fixtures', () => {
  it('evaluate with real scan_project output fixture', () => {
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
    // Some controls should be not_evaluated (missing scan_agent_prompt etc.)
    expect(result.not_evaluated).toBeGreaterThan(0);
    // Results array should have structured output
    for (const r of result.results) {
      expect(r).toHaveProperty('control_id');
      expect(r).toHaveProperty('status');
      expect(['pass', 'partial', 'fail', 'not_evaluated']).toContain(r.status);
      expect(r).toHaveProperty('reasons');
    }
  });
});
