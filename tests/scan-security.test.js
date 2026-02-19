import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
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
      i.ruleId?.includes('exec') || i.ruleId?.includes('child-process') ||
      i.message?.toLowerCase().includes('exec') || i.message?.toLowerCase().includes('child_process')
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
      i.message?.toLowerCase().includes('xss') || i.message?.toLowerCase().includes('innerhtml')
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

  // Clean file
  it('should report no issues for clean Python file', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('clean-python.py')
    });
    const issues = result.issues || result.findings || [];
    expect(issues.length).toBe(0);
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

describe('scan_security by_severity normalization', () => {
  it('by_severity keys match Python analyzer output case (all lowercase)', async () => {
    // Test the formatMinimal path which exposes by_severity in the response
    const client = new MCPTestClient();
    await client.start();
    try {
      const result = await client.callTool('scan_security', {
        file_path: fixturePath('vuln-python.py'),
        verbosity: 'minimal'
      });

      // Minimal format exposes critical (error), warning, info counts directly
      expect(result.total).toBeGreaterThan(0);
      expect(typeof result.critical).toBe('number');
      expect(typeof result.warning).toBe('number');
      expect(typeof result.info).toBe('number');

      // Sum of severity buckets must equal total
      const bucketSum = result.critical + result.warning + result.info;
      expect(bucketSum).toBe(result.total);

      // At least one bucket should be non-zero since we have issues
      expect(bucketSum).toBeGreaterThan(0);
    } finally {
      await client.stop();
    }
  });

  it('by_severity does not produce NaN or undefined counts from uppercase severities', async () => {
    const client = new MCPTestClient();
    await client.start();
    try {
      const result = await client.callTool('scan_security', {
        file_path: fixturePath('vuln-python.py'),
        verbosity: 'minimal'
      });

      // Before the fix, uppercase severity caused NaN/undefined counts
      // and the standard keys stayed at 0
      expect(result.critical).not.toBeNaN();
      expect(result.warning).not.toBeNaN();
      expect(result.info).not.toBeNaN();
      expect(result.critical).toBeDefined();
      expect(result.warning).toBeDefined();
      expect(result.info).toBeDefined();
    } finally {
      await client.stop();
    }
  });

  it('severity normalization handles uppercase from Python analyzer', () => {
    // Simulate the counter logic used in scan-security.js
    // Python analyzer returns uppercase: ERROR, WARNING, INFO
    const mockIssues = [
      { severity: 'ERROR' },
      { severity: 'ERROR' },
      { severity: 'WARNING' },
      { severity: 'INFO' },
      { severity: 'error' },  // already lowercase
    ];

    const bySev = { error: 0, warning: 0, info: 0 };
    mockIssues.forEach(i => {
      const key = (i.severity || '').toLowerCase();
      bySev[key] = (bySev[key] || 0) + 1;
    });

    // Verify lowercase keys with correct counts
    expect(bySev).toEqual({ error: 3, warning: 1, info: 1 });

    // Verify no extra keys were created (e.g., 'ERROR', 'WARNING')
    expect(Object.keys(bySev)).toEqual(['error', 'warning', 'info']);
  });
});
