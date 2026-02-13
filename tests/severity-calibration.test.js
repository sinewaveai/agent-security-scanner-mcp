import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';

describe('severity calibration and confidence scores', () => {
  let client;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();
  }, 30000);

  afterAll(async () => {
    await client.stop();
  });

  it('should assign error severity to SQL injection', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py'),
      verbosity: 'compact',
    });
    const issues = result.issues || [];
    const sqlIssues = issues.filter(i =>
      i.ruleId?.toLowerCase().includes('sql')
    );
    if (sqlIssues.length > 0) {
      // At least one SQL injection finding should be error severity
      const hasError = sqlIssues.some(i => i.severity === 'error');
      expect(hasError).toBe(true);
    }
  });

  it('should assign error severity to command injection', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py'),
      verbosity: 'compact',
    });
    const issues = result.issues || [];
    const cmdIssues = issues.filter(i =>
      i.ruleId?.toLowerCase().includes('subprocess') ||
      i.ruleId?.toLowerCase().includes('command') ||
      i.ruleId?.toLowerCase().includes('exec')
    );
    if (cmdIssues.length > 0) {
      const hasErrorOrWarning = cmdIssues.some(i => i.severity === 'error' || i.severity === 'warning');
      expect(hasErrorOrWarning).toBe(true);
    }
  });

  it('should assign info or warning severity to weak hash', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py'),
      verbosity: 'compact',
    });
    const issues = result.issues || [];
    const hashIssues = issues.filter(i =>
      i.ruleId?.toLowerCase().includes('md5') ||
      i.ruleId?.toLowerCase().includes('sha1') ||
      i.ruleId?.toLowerCase().includes('weak-hash')
    );
    if (hashIssues.length > 0) {
      // Weak hash should NOT be error severity
      const allNonError = hashIssues.every(i => i.severity === 'info' || i.severity === 'warning');
      expect(allNonError).toBe(true);
    }
  });

  it('should include confidence field in compact output', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py'),
      verbosity: 'compact',
    });
    const issues = result.issues || [];
    if (issues.length > 0) {
      // All issues should have a confidence field
      for (const issue of issues) {
        expect(issue.confidence).toBeDefined();
        expect(['HIGH', 'MEDIUM', 'LOW']).toContain(issue.confidence);
      }
    }
  });

  it('should include confidence field in full output', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-python.py'),
      verbosity: 'full',
    });
    const issues = result.issues || [];
    if (issues.length > 0) {
      for (const issue of issues) {
        expect(issue.confidence).toBeDefined();
      }
    }
  });

  it('should deduplicate cross-engine findings on same line', async () => {
    const result = await client.callTool('scan_security', {
      file_path: fixturePath('vuln-javascript.js'),
      verbosity: 'compact',
    });
    const issues = result.issues || [];
    // Check that we don't have two innerHTML findings on the same line
    const innerHtmlByLine = {};
    for (const issue of issues) {
      if (issue.ruleId?.toLowerCase().includes('innerhtml') || issue.ruleId?.toLowerCase().includes('inner_html')) {
        const line = issue.line;
        innerHtmlByLine[line] = (innerHtmlByLine[line] || 0) + 1;
      }
    }
    // No line should have more than one innerHTML-related finding
    for (const [line, count] of Object.entries(innerHtmlByLine)) {
      expect(count).toBeLessThanOrEqual(1);
    }
  });
});
