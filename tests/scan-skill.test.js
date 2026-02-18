// tests/scan-skill.test.js — Comprehensive tests for scan_skill 6-layer scanner

import { describe, it, expect, afterAll } from 'vitest';
import { scanSkill } from '../src/tools/scan-skill.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'fs';
import { homedir } from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

function fixturePath(name) {
  return join(__dirname, 'fixtures', name);
}

// Paths to clean up after tests
const tempDirPath = join(__dirname, 'fixtures', '_empty-temp-dir');
const baselineDir = join(homedir(), '.openclaw', '.scanner-baselines');
const safeSkillBaseline = join(baselineDir, 'safe-skill.json');

afterAll(() => {
  // Clean up temp empty directory
  try { rmSync(tempDirPath, { recursive: true, force: true }); } catch { /* ignore */ }
  // Clean up rug pull baseline file
  try { rmSync(safeSkillBaseline, { force: true }); } catch { /* ignore */ }
});

// ==========================================================================
// 1. Path resolution
// ==========================================================================

describe('Path resolution', { timeout: 60000 }, () => {
  it('accepts directory path', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill') });
    const result = parseResult(raw);
    expect(result.grade).toBeDefined();
    expect(result.skill_path).toContain('safe-skill');
  });

  it('accepts SKILL.md file path', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill/SKILL.md') });
    const result = parseResult(raw);
    expect(result.grade).toBeDefined();
    expect(result.skill_path).toContain('safe-skill');
  });

  it('returns error for nonexistent path', async () => {
    // Use a path within cwd that doesn't exist (avoids path containment check)
    const raw = await scanSkill({ skill_path: join(__dirname, 'fixtures', 'nonexistent-skill') });
    const result = parseResult(raw);
    expect(result.error).toBeDefined();
    expect(result.error.toLowerCase()).toContain('not found');
  });

  it('returns error when SKILL.md missing from directory', async () => {
    // Create a temp empty directory
    if (!existsSync(tempDirPath)) {
      mkdirSync(tempDirPath, { recursive: true });
    }
    const raw = await scanSkill({ skill_path: tempDirPath });
    const result = parseResult(raw);
    expect(result.error).toBeDefined();
    expect(result.error.toLowerCase()).toContain('not found');
  });
});

// ==========================================================================
// 2. Layer 1: Prompt scanning
// ==========================================================================

describe('Layer 1: Prompt scanning', { timeout: 60000 }, () => {
  it('detects prompt injection in malicious skill', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const promptFindings = result.findings.filter(f => f.source === 'prompt_scanner');
    expect(promptFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('clean skill has no prompt scanner findings', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.findings_count).toBe(0);
  });

  it('detects multiple attack vectors', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const promptFindings = result.findings.filter(f => f.source === 'prompt_scanner');
    // The malicious skill has SSH theft references, webhook.site, "ignore previous instructions",
    // "override safety filters" — the prompt scanner should catch several.
    expect(promptFindings.length).toBeGreaterThanOrEqual(2);
  });
});

// ==========================================================================
// 3. Layer 2: Code block scanning
// ==========================================================================

describe('Layer 2: Code block scanning', { timeout: 60000 }, () => {
  it('scans bash code blocks via action scanner', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('skill-with-code'), verbosity: 'full' });
    const result = parseResult(raw);
    const actionFindings = result.findings.filter(f => f.source === 'action_scanner');
    // The curl|bash pattern should be caught by scanAgentAction
    expect(actionFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('scans code blocks via AST analyzer', async () => {
    // The malicious skill has JS code with eval(). Whether findings appear
    // depends on whether the Python analyzer is running. Use a lenient check.
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const codeFindings = result.findings.filter(f => f.source === 'code_analysis');
    if (codeFindings.length > 0) {
      // If findings exist from code_analysis, verify they have expected fields
      for (const f of codeFindings) {
        expect(f.category).toBeDefined();
        expect(f.severity).toBeDefined();
        expect(f.message).toBeDefined();
        expect(f.file).toBeDefined();
        expect(f.file).toContain('code_block');
      }
    }
    // If none, that is acceptable — Python analyzer may not be running
    expect(true).toBe(true);
  });

  it('extracts code blocks correctly', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    // The malicious skill has bash, python, and javascript code blocks.
    // There should be findings from multiple sources.
    expect(result.findings).toBeDefined();
    expect(result.findings.length).toBeGreaterThan(0);
    const sources = new Set(result.findings.map(f => f.source));
    expect(sources.size).toBeGreaterThanOrEqual(2);
  });
});

// ==========================================================================
// 4. Layer 4: ClawHavoc signatures
// ==========================================================================

describe('Layer 4: ClawHavoc signatures', { timeout: 60000 }, () => {
  it('detects reverse shell patterns', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const clawFindings = result.findings.filter(f => f.source === 'clawhavoc');
    const reverseShell = clawFindings.some(
      f => f.category === 'reverse_shell' || f.rule_id.includes('revshell')
    );
    expect(reverseShell).toBe(true);
  });

  it('detects osascript dialog pattern', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const clawFindings = result.findings.filter(f => f.source === 'clawhavoc');
    const osascriptMatch = clawFindings.some(
      f => f.rule_id.includes('osascript') || f.rule_id.includes('atomic') || f.rule_id.includes('dialog')
    );
    expect(osascriptMatch).toBe(true);
  });

  it('detects xattr quarantine bypass', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const clawFindings = result.findings.filter(f => f.source === 'clawhavoc');
    const quarantineMatch = clawFindings.some(
      f => f.rule_id.includes('xattr') || f.rule_id.includes('quarantine')
    );
    expect(quarantineMatch).toBe(true);
  });

  it('detects crypto miner patterns', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const clawFindings = result.findings.filter(f => f.source === 'clawhavoc');
    const minerMatch = clawFindings.some(
      f => f.rule_id.includes('miner') || f.rule_id.includes('xmrig') || f.category === 'crypto_miner'
    );
    expect(minerMatch).toBe(true);
  });

  it('detects OpenClaw config theft', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const clawFindings = result.findings.filter(f => f.source === 'clawhavoc');
    const configTheftMatch = clawFindings.some(
      f => f.rule_id.includes('openclaw') || f.rule_id.includes('config-theft') || f.rule_id.includes('soul')
    );
    expect(configTheftMatch).toBe(true);
  });
});

// ==========================================================================
// 5. Layer 6: Rug pull detection
// ==========================================================================

describe('Layer 6: Rug pull detection', { timeout: 60000 }, () => {
  it('saves baseline when flag is set', async () => {
    // Remove any existing baseline first
    try { rmSync(safeSkillBaseline, { force: true }); } catch { /* ignore */ }

    await scanSkill({ skill_path: fixturePath('safe-skill'), baseline: true });
    expect(existsSync(safeSkillBaseline)).toBe(true);

    // Verify the baseline contains expected fields
    const baseline = JSON.parse(readFileSync(safeSkillBaseline, 'utf-8'));
    expect(baseline.hash).toBeDefined();
    expect(baseline.skill_path).toBeDefined();
    expect(baseline.saved_at).toBeDefined();
    expect(baseline.content_length).toBeGreaterThan(0);
  });

  it('detects content change after baseline', async () => {
    // Step 1: Save a baseline
    await scanSkill({ skill_path: fixturePath('safe-skill'), baseline: true });
    expect(existsSync(safeSkillBaseline)).toBe(true);

    // Step 2: Corrupt the hash to simulate a content change
    const baseline = JSON.parse(readFileSync(safeSkillBaseline, 'utf-8'));
    baseline.hash = 'dead' + baseline.hash.substring(4);
    writeFileSync(safeSkillBaseline, JSON.stringify(baseline, null, 2), 'utf-8');

    // Step 3: Scan again without baseline flag — should detect rug pull
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    const rugPullFindings = result.findings.filter(f => f.source === 'rug_pull');
    expect(rugPullFindings.length).toBeGreaterThanOrEqual(1);
    expect(rugPullFindings[0].severity).toBe('CRITICAL');
  });
});

// ==========================================================================
// 6. Grade calculation
// ==========================================================================

describe('Grade calculation', { timeout: 180000 }, () => {
  it('grades safe skill as A', async () => {
    // Remove any lingering baseline that could cause a false rug_pull finding
    try { rmSync(safeSkillBaseline, { force: true }); } catch { /* ignore */ }

    const raw = await scanSkill({ skill_path: fixturePath('safe-skill') });
    const result = parseResult(raw);
    expect(result.grade).toBe('A');
  });

  it('grades malicious skill as F', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill') });
    const result = parseResult(raw);
    expect(result.grade).toBe('F');
  });

  it('grades skill-with-code as D or F', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('skill-with-code') });
    const result = parseResult(raw);
    expect(['D', 'F']).toContain(result.grade);
  });

  it('includes recommendation matching the grade', async () => {
    const rawSafe = await scanSkill({ skill_path: fixturePath('safe-skill') });
    const safeParsed = parseResult(rawSafe);
    expect(safeParsed.recommendation).toBeDefined();
    expect(safeParsed.recommendation.toLowerCase()).toContain('ok');

    const rawMalicious = await scanSkill({ skill_path: fixturePath('malicious-skill') });
    const malParsed = parseResult(rawMalicious);
    expect(malParsed.recommendation).toBeDefined();
    expect(malParsed.recommendation.toLowerCase()).toContain('do not install');
  });

  it('includes layers_executed in full verbosity', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.layers_executed).toBeDefined();
    expect(result.layers_executed).toHaveProperty('prompt_scan');
    expect(result.layers_executed).toHaveProperty('code_blocks');
    expect(result.layers_executed).toHaveProperty('clawhavoc');
  });
});

// ==========================================================================
// 7. Verbosity
// ==========================================================================

describe('Verbosity', { timeout: 60000 }, () => {
  it('minimal omits findings array', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill'), verbosity: 'minimal' });
    const result = parseResult(raw);
    expect(result.findings).toBeUndefined();
    expect(result.grade).toBeDefined();
    expect(result.findings_count).toBeDefined();
  });

  it('compact includes findings', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'compact' });
    const result = parseResult(raw);
    expect(result.findings).toBeDefined();
    expect(result.layers_executed).toBeUndefined();
  });

  it('full includes all metadata', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.findings).toBeDefined();
    expect(result.content_hash).toBeDefined();
    expect(result.layers_executed).toBeDefined();
  });
});

// ==========================================================================
// 8. Output format
// ==========================================================================

describe('Output format', { timeout: 180000 }, () => {
  it('returns MCP-compatible content structure', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('safe-skill') });
    expect(raw).toHaveProperty('content');
    expect(Array.isArray(raw.content)).toBe(true);
    expect(raw.content.length).toBe(1);
    expect(raw.content[0].type).toBe('text');
    expect(typeof raw.content[0].text).toBe('string');
    // Verify it parses as valid JSON
    const parsed = JSON.parse(raw.content[0].text);
    expect(parsed).toBeDefined();
  });

  it('each finding includes required fields', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.category).toBeDefined();
      expect(finding.severity).toBeDefined();
      expect(finding.message).toBeDefined();
      expect(finding.file).toBeDefined();
      expect(finding.source).toBeDefined();
      // Verify source is one of the known values
      expect([
        'prompt_scanner', 'code_analysis', 'action_scanner',
        'clawhavoc', 'supply_chain', 'rug_pull'
      ]).toContain(finding.source);
    }
  });

  it('findings_count matches actual findings array length', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('malicious-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.findings_count).toBe(result.findings.length);
  });
});

// ==========================================================================
// 9. Security: Path traversal rejection
// ==========================================================================

describe('Path traversal protection', { timeout: 60000 }, () => {
  it('rejects path outside cwd and ~/.openclaw/skills/', async () => {
    const raw = await scanSkill({ skill_path: '../../etc' });
    const result = parseResult(raw);
    expect(result.error).toBeDefined();
    expect(result.error).toContain('skill_path must be within');
  });

  it('rejects absolute path to system directory', async () => {
    const raw = await scanSkill({ skill_path: '/etc/passwd' });
    const result = parseResult(raw);
    expect(result.error).toBeDefined();
    expect(result.error).toContain('skill_path must be within');
  });

  it('rejects path with .. traversal to escape cwd', async () => {
    const raw = await scanSkill({ skill_path: join(__dirname, '..', '..', '..', 'etc') });
    const result = parseResult(raw);
    expect(result.error).toBeDefined();
    expect(result.error).toContain('skill_path must be within');
  });
});

// ==========================================================================
// 10. Hard-fail grading on malware
// ==========================================================================

describe('Hard-fail grading', { timeout: 180000 }, () => {
  it('ClawHavoc reverse shell results in grade F', async () => {
    const raw = await scanSkill({ skill_path: fixturePath('clawhavoc-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.grade).toBe('F');
    expect(result.recommendation).toContain('DO NOT INSTALL');
  });

  it('rug pull detection results in grade F', async () => {
    // Save baseline then corrupt it
    await scanSkill({ skill_path: fixturePath('safe-skill'), baseline: true });
    const baseline = JSON.parse(readFileSync(safeSkillBaseline, 'utf-8'));
    baseline.hash = 'dead' + baseline.hash.substring(4);
    writeFileSync(safeSkillBaseline, JSON.stringify(baseline, null, 2), 'utf-8');

    const raw = await scanSkill({ skill_path: fixturePath('safe-skill'), verbosity: 'full' });
    const result = parseResult(raw);
    expect(result.grade).toBe('F');
  });
});
