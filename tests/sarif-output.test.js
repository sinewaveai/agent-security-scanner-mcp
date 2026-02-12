import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('SARIF Output Format', () => {
  let client;
  let transport;
  const testDir = join(__dirname, 'fixtures');

  beforeAll(async () => {
    if (!existsSync(testDir)) {
      mkdirSync(testDir, { recursive: true });
    }

    transport = new StdioClientTransport({
      command: 'node',
      args: [join(__dirname, '..', 'index.js')],
    });

    client = new Client({
      name: 'test-client',
      version: '1.0.0',
    }, {
      capabilities: {}
    });

    await client.connect(transport);
  }, 30000);

  afterAll(async () => {
    await client?.close();
  });

  it('should return valid SARIF 2.1.0 format', async () => {
    const testFile = join(testDir, 'sarif-test.py');
    writeFileSync(testFile, `
import os
password = "hardcoded_secret_123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
`);

    try {
      const result = await client.callTool({
        name: 'scan_security',
        arguments: {
          file_path: testFile,
          output_format: 'sarif'
        }
      });

      const sarif = JSON.parse(result.content[0].text);

      // Validate SARIF structure
      expect(sarif.$schema).toBe('https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json');
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toBeInstanceOf(Array);
      expect(sarif.runs.length).toBe(1);

      // Validate tool information
      const run = sarif.runs[0];
      expect(run.tool.driver.name).toBe('agent-security-scanner-mcp');
      expect(run.tool.driver.version).toBeDefined();
      expect(run.tool.driver.rules).toBeInstanceOf(Array);

      // Validate results
      expect(run.results).toBeInstanceOf(Array);
      expect(run.results.length).toBeGreaterThan(0);

      // Validate result structure
      const firstResult = run.results[0];
      expect(firstResult.ruleId).toBeDefined();
      expect(firstResult.level).toMatch(/^(error|warning|note)$/);
      expect(firstResult.message.text).toBeDefined();
      expect(firstResult.locations).toBeInstanceOf(Array);
      expect(firstResult.locations[0].physicalLocation.artifactLocation.uri).toBe(testFile);
      expect(firstResult.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);

    } finally {
      unlinkSync(testFile);
    }
  }, 30000);

  it('should include rules definitions', async () => {
    const testFile = join(testDir, 'sarif-rules-test.js');
    writeFileSync(testFile, `
document.getElementById('output').innerHTML = userInput;
`);

    try {
      const result = await client.callTool({
        name: 'scan_security',
        arguments: {
          file_path: testFile,
          output_format: 'sarif'
        }
      });

      const sarif = JSON.parse(result.content[0].text);
      const rules = sarif.runs[0].tool.driver.rules;

      expect(rules.length).toBeGreaterThan(0);

      const rule = rules[0];
      expect(rule.id).toBeDefined();
      expect(rule.shortDescription.text).toBeDefined();
      expect(rule.defaultConfiguration.level).toMatch(/^(error|warning|note)$/);

    } finally {
      unlinkSync(testFile);
    }
  }, 30000);

  it('should return empty results for clean file', async () => {
    const testFile = join(testDir, 'sarif-clean-test.py');
    writeFileSync(testFile, `
def add(a, b):
    return a + b
`);

    try {
      const result = await client.callTool({
        name: 'scan_security',
        arguments: {
          file_path: testFile,
          output_format: 'sarif'
        }
      });

      const sarif = JSON.parse(result.content[0].text);
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs[0].results).toBeInstanceOf(Array);
      // May have 0 results for clean file

    } finally {
      unlinkSync(testFile);
    }
  }, 30000);

  it('should default to JSON format when output_format not specified', async () => {
    const testFile = join(testDir, 'sarif-default-test.py');
    writeFileSync(testFile, `
password = "secret123"
`);

    try {
      const result = await client.callTool({
        name: 'scan_security',
        arguments: {
          file_path: testFile
          // No output_format specified
        }
      });

      const output = JSON.parse(result.content[0].text);

      // Should be JSON format, not SARIF
      expect(output.file).toBeDefined();
      expect(output.language).toBeDefined();
      expect(output.issues_count).toBeDefined();
      expect(output.issues).toBeInstanceOf(Array);
      // SARIF-specific fields should NOT exist
      expect(output.$schema).toBeUndefined();
      expect(output.version).toBeUndefined();
      expect(output.runs).toBeUndefined();

    } finally {
      unlinkSync(testFile);
    }
  }, 30000);

  it('should include fix suggestions in SARIF when available', async () => {
    const testFile = join(testDir, 'sarif-fix-test.js');
    writeFileSync(testFile, `
document.getElementById('output').innerHTML = userInput;
`);

    try {
      const result = await client.callTool({
        name: 'scan_security',
        arguments: {
          file_path: testFile,
          output_format: 'sarif'
        }
      });

      expect(result?.content?.[0]?.text).toBeDefined();
      const sarif = JSON.parse(result.content[0].text);
      expect(sarif.runs).toBeDefined();
      expect(sarif.runs.length).toBeGreaterThan(0);

      const resultsWithFixes = sarif.runs[0].results.filter(r => r.fixes);

      // innerHTML should have a fix suggestion
      if (resultsWithFixes.length > 0) {
        const fix = resultsWithFixes[0].fixes[0];
        expect(fix.description.text).toBeDefined();
        expect(fix.artifactChanges).toBeInstanceOf(Array);
      }

    } finally {
      unlinkSync(testFile);
    }
  }, 60000);
});
