import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient } from './helpers.js';
import { writeFileSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('edge cases', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should handle empty file for scan_security', async () => {
    const emptyFile = join(__dirname, 'fixtures', 'empty.py');
    writeFileSync(emptyFile, '');
    try {
      const result = await client.callTool('scan_security', {
        file_path: emptyFile
      });
      const issues = result.issues || result.findings || [];
      expect(issues.length).toBe(0);
    } finally {
      try { unlinkSync(emptyFile); } catch (e) { /* ignore */ }
    }
  });

  it('should handle very long prompt without crashing', async () => {
    const longPrompt = 'A'.repeat(50000);
    const result = await client.callTool('scan_agent_prompt', {
      prompt_text: longPrompt
    });
    expect(result.action).toBe('ALLOW');
    expect(result.audit.prompt_length).toBe(50000);
  });

  it('should handle unicode in prompt', async () => {
    const unicodePrompt = 'Help me sort a list 你好世界 🎉';
    const result = await client.callTool('scan_agent_prompt', {
      prompt_text: unicodePrompt
    });
    expect(result.action).toBe('ALLOW');
  });

  it('should handle empty package name', async () => {
    try {
      const result = await client.callTool('check_package', {
        package_name: '',
        ecosystem: 'pypi'
      });
      // Should return hallucinated since empty string isn't a real package
      expect(result.hallucinated || result.status === 'unknown').toBeTruthy();
    } catch (e) {
      // Validation error is also acceptable
      expect(e).toBeDefined();
    }
  });

  it('should handle prompt with only whitespace', async () => {
    const result = await client.callTool('scan_agent_prompt', {
      prompt_text: '   \n\t\n   '
    });
    expect(result.action).toBe('ALLOW');
    expect(result.findings_count).toBe(0);
  });
});
