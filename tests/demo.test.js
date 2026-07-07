import { describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { runDemo } from '../src/cli/demo.js';

async function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'scanner-demo-'));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('demo CLI', () => {
  it('runs the package hallucination demo and removes the fixture by default', async () => {
    await withTempDir(async (dir) => {
      const result = await runDemo(['--type', 'packages', '--no-prompt'], { cwd: dir });

      expect(result.ecosystem).toBe('npm');
      expect(result.total_packages_found).toBe(4);
      expect(result.legitimate_count).toBe(2);
      expect(result.hallucinated_count).toBe(2);
      expect(result.hallucinated_packages).toEqual(
        expect.arrayContaining(['agent-memory-graph-cache', 'secure-mcp-session-bridge'])
      );
      expect(existsSync(join(dir, 'hallucination-demo.js'))).toBe(false);
    });
  });

  it('keeps the package hallucination fixture when requested', async () => {
    await withTempDir(async (dir) => {
      await runDemo(['--type', 'packages', '--keep'], { cwd: dir });

      expect(existsSync(join(dir, 'hallucination-demo.js'))).toBe(true);
    });
  });
});
