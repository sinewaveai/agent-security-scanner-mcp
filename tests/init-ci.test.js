import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { runInitCi } from '../src/cli/init-ci.js';

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'init-ci-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('init-ci CLI', () => {
  it('writes the GitHub Actions workflow to the default path', async () => {
    await withTempDir(async (dir) => {
      const result = await runInitCi(['github'], { cwd: dir });
      const workflow = join(dir, '.github', 'workflows', 'agent-security.yml');

      expect(result.written).toBe(true);
      expect(result.outputPath).toBe(workflow);
      expect(readFileSync(workflow, 'utf8')).toContain('Agent Security Scan');
      expect(readFileSync(workflow, 'utf8')).toContain('sinewaveai/agent-security-scanner-mcp/.github/actions/security-scan@main');
    });
  });

  it('supports dry-run without writing files', async () => {
    await withTempDir(async (dir) => {
      const result = await runInitCi(['github', '--dry-run'], { cwd: dir });

      expect(result.written).toBe(false);
      expect(result.dryRun).toBe(true);
      expect(() => readFileSync(join(dir, '.github', 'workflows', 'agent-security.yml'), 'utf8')).toThrow();
    });
  });

  it('does not overwrite an existing workflow without --force', async () => {
    await withTempDir(async (dir) => {
      const workflow = join(dir, 'agent-security.yml');
      writeFileSync(workflow, 'existing', 'utf8');

      const result = await runInitCi(['github', '--path', workflow], { cwd: dir });

      expect(result.written).toBe(false);
      expect(result.reason).toBe('exists');
      expect(readFileSync(workflow, 'utf8')).toBe('existing');
    });
  });

  it('overwrites an existing workflow with --force', async () => {
    await withTempDir(async (dir) => {
      const workflow = join(dir, 'agent-security.yml');
      writeFileSync(workflow, 'existing', 'utf8');

      const result = await runInitCi(['github', '--path', workflow, '--force'], { cwd: dir });

      expect(result.written).toBe(true);
      expect(readFileSync(workflow, 'utf8')).toContain('Agent Security Scan');
    });
  });

  it('rejects unsupported CI providers', async () => {
    await expect(runInitCi(['circleci'])).rejects.toThrow('unsupported CI provider');
  });
});
