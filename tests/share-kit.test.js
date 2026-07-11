import { describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { buildShareKit, renderShareKitMarkdown, runShareKit } from '../src/cli/share-kit.js';

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'scanner-share-kit-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('share-kit CLI', () => {
  it('builds public-safe launch copy from repo detection', async () => {
    await withTempDir(async (dir) => {
      mkdirSync(join(dir, '.git'));
      writeFileSync(join(dir, 'server.json'), '{}\n');
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo-agent' }));

      const kit = buildShareKit(dir, { client: 'cursor' });

      expect(kit.project).toBe('demo-agent');
      expect(kit.client).toBe('cursor');
      expect(kit.commands).toContain('npx agent-security-scanner-mcp scan-project . --verbosity compact');
      expect(kit.commands).toContain('npx agent-security-scanner-mcp scan-mcp . --verbosity compact');
      expect(kit.commands).toContain('npx agent-security-scanner-mcp sbom-report . --format html');
      expect(kit.commands).toContain('npx agent-security-scanner-mcp init cursor');
      expect(kit.short_post).toContain('A-F security grade');
      expect(kit.issue_template).toContain('Post the grade');
      expect(kit.directory_listing).toContain('Claude Code');
    });
  });

  it('renders markdown with commands and copy blocks', async () => {
    await withTempDir(async (dir) => {
      writeFileSync(join(dir, 'SKILL.md'), '# Demo\n');

      const kit = buildShareKit(dir);
      const markdown = renderShareKitMarkdown(kit);

      expect(markdown).toContain('# agent-security-scanner-mcp Share Kit');
      expect(markdown).toContain('scan-skill');
      expect(markdown).toContain('## GitHub Issue');
      expect(markdown).toContain('## Directory Listing');
    });
  });

  it('writes markdown to --output without creating extra files', async () => {
    await withTempDir(async (dir) => {
      const outputPath = join(dir, 'share-kit.md');
      const log = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        await runShareKit(['--client', 'windsurf', '--output', outputPath], { cwd: dir });

        expect(existsSync(outputPath)).toBe(true);
        expect(readFileSync(outputPath, 'utf-8')).toContain('init windsurf');
        expect(log.mock.calls.flat().join('\n')).toContain('Wrote share kit');
      } finally {
        log.mockRestore();
      }
    });
  });

  it('prints JSON when --json is passed', async () => {
    await withTempDir(async (dir) => {
      const log = vi.spyOn(console, 'log').mockImplementation(() => {});

      try {
        const kit = await runShareKit(['--json', '--client', 'opencode'], { cwd: dir });
        const output = log.mock.calls.map(([line]) => line).join('\n');
        const parsed = JSON.parse(output);

        expect(parsed.client).toBe('opencode');
        expect(parsed.commands).toEqual(expect.arrayContaining(['npx agent-security-scanner-mcp init opencode']));
        expect(kit.client).toBe('opencode');
      } finally {
        log.mockRestore();
      }
    });
  });
});
