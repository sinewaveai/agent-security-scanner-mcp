import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';

describe('fix_security tool', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should suggest fixes for vulnerable Python file', async () => {
    const result = await client.callTool('fix_security', {
      file_path: fixturePath('vuln-python.py')
    });
    // Should have fix suggestions
    const fixes = result.fixes || result.suggestions || result.issues || [];
    expect(fixes.length).toBeGreaterThan(0);
  });

  it('should report no fixes needed for clean file', async () => {
    const result = await client.callTool('fix_security', {
      file_path: fixturePath('clean-python.py')
    });
    const fixes = result.fixes || result.suggestions || result.issues || [];
    expect(fixes.length).toBe(0);
  });

  it('should handle non-existent file gracefully', async () => {
    const result = await client.callTool('fix_security', {
      file_path: '/tmp/nonexistent-file-12345.py'
    });
    expect(result.error || result.fixes !== undefined || result.issues !== undefined).toBeTruthy();
  });
});
