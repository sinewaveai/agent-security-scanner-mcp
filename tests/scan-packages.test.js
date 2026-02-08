import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';

describe('scan_packages tool', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should scan Python imports and detect hallucinated packages', async () => {
    const result = await client.callTool('scan_packages', {
      file_path: fixturePath('test-packages.py'),
      ecosystem: 'pypi'
    });
    expect(result.total_packages_found).toBeGreaterThan(0);
    // requests, flask, numpy, pandas should be legitimate
    expect(result.legitimate_count).toBeGreaterThan(0);
    // fake_ai_helper_pkg, nonexistent_ml_toolkit should be hallucinated
    expect(result.hallucinated_count).toBeGreaterThan(0);
    expect(result.hallucinated_packages).toBeDefined();
  });

  it('should handle non-existent file', async () => {
    const result = await client.callTool('scan_packages', {
      file_path: '/tmp/nonexistent-file-12345.py',
      ecosystem: 'pypi'
    });
    expect(result.error).toBeDefined();
  });

  it('should include unknown_count in results', async () => {
    const result = await client.callTool('scan_packages', {
      file_path: fixturePath('test-packages.py'),
      ecosystem: 'pypi'
    });
    expect(result.unknown_count).toBeDefined();
  });
});
