/**
 * MCP test client using official SDK
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_PATH = join(__dirname, '..', 'index.js');

export class MCPTestClient {
  constructor() {
    this.client = null;
    this.transport = null;
  }

  async start() {
    this.transport = new StdioClientTransport({
      command: 'node',
      args: [SERVER_PATH]
    });

    this.client = new Client({
      name: 'test-client',
      version: '1.0.0'
    });

    await this.client.connect(this.transport);
  }

  async callTool(name, args = {}) {
    const result = await this.client.callTool({ name, arguments: args });
    if (result?.content?.[0]?.text) {
      return JSON.parse(result.content[0].text);
    }
    return result;
  }

  async listTools() {
    const result = await this.client.listTools();
    return result.tools || [];
  }

  async stop() {
    try {
      await this.client?.close();
    } catch (e) {
      // Ignore close errors
    }
  }
}

export function fixturePath(name) {
  return join(__dirname, 'fixtures', name);
}
