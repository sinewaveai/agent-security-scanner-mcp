import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';
import { execFileSync } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'index.js');

// ============= CLI tests (no MCP server needed) =============
describe('CLI commands', () => {
  it('--help includes scan-skill command', () => {
    const output = execFileSync('node', [CLI, '--help'], { encoding: 'utf-8' });
    expect(output).toContain('scan-skill');
  });

  it('--help includes audit command', () => {
    const output = execFileSync('node', [CLI, '--help'], { encoding: 'utf-8' });
    expect(output).toContain('audit');
  });

  it('--help includes harden command', () => {
    const output = execFileSync('node', [CLI, '--help'], { encoding: 'utf-8' });
    expect(output).toContain('harden');
  });

  it('audit command runs without error', () => {
    const output = execFileSync('node', [CLI, 'audit', '--allow-stub'], { encoding: 'utf-8' });
    expect(output).toContain('Security Audit');
  });

  it('harden command runs without error', () => {
    const output = execFileSync('node', [CLI, 'harden', '--allow-stub'], { encoding: 'utf-8' });
    expect(output).toContain('Auto-Hardening');
  });

  it('scan-skill shows error for missing path', () => {
    try {
      execFileSync('node', [CLI, 'scan-skill'], { encoding: 'utf-8', stdio: 'pipe' });
    } catch (err) {
      expect(err.stderr).toContain('Usage');
    }
  });
});

// ============= scan-skill tests =============
describe('scan-skill CLI', () => {
  const safeSkillDir = join(__dirname, 'fixtures', 'safe-skill');
  const maliciousSkillDir = join(__dirname, 'fixtures', 'malicious-skill');

  it('should grade safe skill as A', () => {
    const output = execFileSync('node', [CLI, 'scan-skill', safeSkillDir], {
      encoding: 'utf-8',
      timeout: 60000,
    });
    const result = JSON.parse(output);
    expect(result.grade).toBe('A');
    expect(result.findings_count).toBe(0);
    expect(result.recommendation).toContain('OK');
  });

  it('should detect threats in malicious skill', () => {
    try {
      execFileSync('node', [CLI, 'scan-skill', maliciousSkillDir], {
        encoding: 'utf-8',
        timeout: 60000,
      });
      // Should exit with code 1 for grade F
      expect.fail('Should have exited with code 1');
    } catch (err) {
      const result = JSON.parse(err.stdout);
      expect(result.grade).toBe('F');
      expect(result.findings_count).toBeGreaterThan(0);
      expect(result.recommendation).toContain('DO NOT INSTALL');
      // Verify findings have source field (multi-layer scanner)
      expect(result.findings.some(f => f.source)).toBe(true);
    }
  });

  it('should report error for nonexistent path', () => {
    const nonexistentPath = join(__dirname, 'fixtures', 'nonexistent-skill');
    const projectRoot = join(__dirname, '..');
    const output = execFileSync('node', [CLI, 'scan-skill', nonexistentPath], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: projectRoot,
    });
    const result = JSON.parse(output);
    expect(result.error).toContain('not found');
  });

  it('should reject path traversal outside cwd', () => {
    const output = execFileSync('node', [CLI, 'scan-skill', '/etc/passwd'], {
      encoding: 'utf-8',
      timeout: 60000,
    });
    const result = JSON.parse(output);
    expect(result.error).toContain('skill_path must be within');
  });

  it('should support minimal verbosity', () => {
    const output = execFileSync('node', [CLI, 'scan-skill', safeSkillDir, '--verbosity', 'minimal'], {
      encoding: 'utf-8',
      timeout: 60000,
    });
    const result = JSON.parse(output);
    expect(result.grade).toBe('A');
    expect(result.findings).toBeUndefined(); // minimal doesn't include findings array
  });
});

// ============= MCP tool tests =============
describe('clawproof_health MCP tool', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should return health status', async () => {
    const result = await client.callTool('clawproof_health', {});
    expect(result.name).toBe('agent-security-scanner-mcp');
    expect(result.version).toBeDefined();
    expect(result.daemon).toBeDefined();
    expect(result.timestamp).toBeDefined();
  });

  it('should include daemon status', async () => {
    const result = await client.callTool('clawproof_health', {});
    expect(result.daemon.status).toBeDefined();
    expect(['running', 'not running']).toContain(result.daemon.status);
  });
});

// ============= Plugin config tests =============
describe('plugin-config', () => {
  it('should return default config when no file exists', async () => {
    const { loadPluginConfig } = await import('../src/plugin-config.js');
    const config = loadPluginConfig();
    expect(config.version).toBe(1);
    expect(config.features.prompt_firewall).toBe(true);
    expect(config.severity_threshold).toBe('warning');
    expect(config.auto_block).toBe(true);
  });
});
