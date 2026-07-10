import { describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { buildQuickstartPlan, runQuickstart } from '../src/cli/quickstart.js';

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'scanner-quickstart-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('quickstart CLI planner', () => {
  it('recommends MCP, package, SBOM, client, and CI commands for an MCP npm repo', async () => {
    await withTempDir(async (dir) => {
      mkdirSync(join(dir, '.git'));
      mkdirSync(join(dir, 'src'));
      writeFileSync(join(dir, 'src', 'server.ts'), 'export const server = true;\n');
      writeFileSync(join(dir, 'package-lock.json'), '{"lockfileVersion":3}\n');
      writeFileSync(join(dir, 'package.json'), JSON.stringify({
        name: 'demo-mcp',
        dependencies: {
          '@modelcontextprotocol/sdk': '^1.0.0',
        },
      }));

      const plan = buildQuickstartPlan(dir, { client: 'cursor' });
      const commandIds = plan.commands.map((command) => command.id);

      expect(plan.project).toBe('demo-mcp');
      expect(plan.detected.mcp_server).toBe(true);
      expect(plan.detected.lockfile).toBe(true);
      expect(commandIds).toEqual(expect.arrayContaining([
        'scan-project',
        'scan-mcp',
        'scan-packages',
        'sbom-report',
        'init-client',
        'init-ci',
      ]));
      expect(plan.commands.find((command) => command.id === 'init-client').command).toContain('init cursor');
    });
  });

  it('recommends scan-skill when SKILL.md is present', async () => {
    await withTempDir(async (dir) => {
      writeFileSync(join(dir, 'SKILL.md'), '# Demo Skill\n');

      const plan = buildQuickstartPlan(dir);

      expect(plan.detected.skill).toBe(true);
      expect(plan.commands.map((command) => command.id)).toContain('scan-skill');
    });
  });

  it('prints JSON output without creating files', async () => {
    await withTempDir(async (dir) => {
      const log = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const plan = await runQuickstart(['--json', '--client', 'windsurf'], { cwd: dir });
        const output = log.mock.calls.map(([line]) => line).join('\n');
        const parsed = JSON.parse(output);

        expect(parsed.recommended_first_command).toBe('npx agent-security-scanner-mcp scan-project . --verbosity compact');
        expect(plan.commands.find((command) => command.id === 'init-client').command).toContain('init windsurf');
        expect(existsSync(join(dir, '.github'))).toBe(false);
      } finally {
        log.mockRestore();
      }
    });
  });
});
