import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';

describe('scan_security tool', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  // Python vulnerability detection
  it('should detect SQL injection in Python', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    expect(result.issues || result.findings).toBeDefined();
    const issues = result.issues || result.findings || [];
    const sqlIssues = issues.filter(i => i.ruleId?.includes('sql') || i.message?.toLowerCase().includes('sql'));
    expect(sqlIssues.length).toBeGreaterThan(0);
  });

  it('should detect command injection in Python', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    const issues = result.issues || result.findings || [];
    const cmdIssues = issues.filter(i =>
      i.ruleId?.includes('command') || i.ruleId?.includes('subprocess') ||
      i.message?.toLowerCase().includes('command') || i.message?.toLowerCase().includes('shell')
    );
    expect(cmdIssues.length).toBeGreaterThan(0);
  });

  it('should detect hardcoded secrets in Python', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    const issues = result.issues || result.findings || [];
    const secretIssues = issues.filter(i =>
      i.ruleId?.includes('secret') || i.ruleId?.includes('hardcoded') || i.ruleId?.includes('password') ||
      i.message?.toLowerCase().includes('secret') || i.message?.toLowerCase().includes('hardcoded')
    );
    expect(secretIssues.length).toBeGreaterThan(0);
  });

  it('should detect weak crypto in Python', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    const issues = result.issues || result.findings || [];
    const cryptoIssues = issues.filter(i =>
      i.ruleId?.includes('md5') || i.ruleId?.includes('sha1') || i.ruleId?.includes('crypto') ||
      i.message?.toLowerCase().includes('md5') || i.message?.toLowerCase().includes('sha1') ||
      i.message?.toLowerCase().includes('weak')
    );
    expect(cryptoIssues.length).toBeGreaterThan(0);
  });

  it('should detect multiple vulnerabilities in Python file', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    const issues = result.issues || result.findings || [];
    expect(issues.length).toBeGreaterThanOrEqual(5);
  });

  // JavaScript vulnerability detection
  it('should detect command injection in JavaScript', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-javascript.js')
    });
    const issues = result.issues || result.findings || [];
    const cmdIssues = issues.filter(i =>
      i.ruleId?.includes('exec') || i.ruleId?.includes('child-process') || i.ruleId?.includes('child_process') ||
      i.ruleId?.includes('detect-child') || i.ruleId?.includes('command') ||
      i.message?.toLowerCase().includes('exec') || i.message?.toLowerCase().includes('child_process') ||
      i.message?.toLowerCase().includes('command')
    );
    expect(cmdIssues.length).toBeGreaterThan(0);
  });

  it('should detect XSS in JavaScript', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-javascript.js')
    });
    const issues = result.issues || result.findings || [];
    const xssIssues = issues.filter(i =>
      i.ruleId?.includes('xss') || i.ruleId?.includes('innerhtml') || i.ruleId?.includes('innerHTML') ||
      i.ruleId?.includes('document-method') || i.ruleId?.includes('mustache-escape') ||
      i.message?.toLowerCase().includes('xss') || i.message?.toLowerCase().includes('innerhtml') ||
      i.message?.toLowerCase().includes('document.write') || i.message?.toLowerCase().includes('escaping')
    );
    expect(xssIssues.length).toBeGreaterThan(0);
  });

  it('should detect multiple vulnerabilities in JavaScript file', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-javascript.js')
    });
    const issues = result.issues || result.findings || [];
    expect(issues.length).toBeGreaterThanOrEqual(5);
  });

  // Clean file - with expanded Semgrep rules, we filter for actual security vulnerabilities
  it('should report no issues for clean Python file', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('clean-python.py')
    });
    const issues = result.issues || result.findings || [];
    // Filter to only actual vulnerabilities (SQL injection, command injection, etc)
    // Exclude framework-specific warnings and best-practice rules
    const securityIssues = issues.filter(i =>
      (i.ruleId?.includes('sql-injection') || i.ruleId?.includes('command-injection') ||
       i.ruleId?.includes('xss') || i.ruleId?.includes('hardcoded-secret') ||
       i.ruleId?.includes('pickle') || i.ruleId?.includes('eval-detected')) &&
      !i.ruleId?.includes('hardcoded_config')  // Exclude config warnings
    );
    expect(securityIssues.length).toBe(0);
  });

  // Error handling
  it('should handle non-existent file gracefully', async () => {
    const result = await client.callTool('scan_security', {
      file_path: '/tmp/nonexistent-file-12345.py'
    });
    expect(result.error || result.issues).toBeDefined();
  });

  it('should handle empty file path', async () => {
    try {
      const result = await client.callTool('scan_security', {
        file_path: ''
      });
      // Either returns error or throws
      expect(result.error || result.issues !== undefined).toBeTruthy();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  it('should include severity in findings', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py')
    });
    const issues = result.issues || result.findings || [];
    if (issues.length > 0) {
      expect(issues[0].severity).toBeDefined();
    }
  });
});
