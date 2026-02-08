import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient } from './helpers.js';

describe('MCP server tools', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should list all available tools', async () => {
    const tools = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);
    const toolNames = tools.map(t => t.name);
    expect(toolNames).toContain('scan_security');
    expect(toolNames).toContain('check_package');
    expect(toolNames).toContain('scan_packages');
    expect(toolNames).toContain('scan_agent_prompt');
  });

  it('should have fix_security tool', async () => {
    const tools = await client.listTools();
    const toolNames = tools.map(t => t.name);
    expect(toolNames).toContain('fix_security');
  });

  it('should have list_security_rules tool', async () => {
    const tools = await client.listTools();
    const toolNames = tools.map(t => t.name);
    expect(toolNames).toContain('list_security_rules');
  });

  it('should have list_package_stats tool', async () => {
    const tools = await client.listTools();
    const toolNames = tools.map(t => t.name);
    expect(toolNames).toContain('list_package_stats');
  });
});
