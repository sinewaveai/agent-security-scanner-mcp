import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { scanMcpServer } from '../src/tools/scan-mcp.js';

function parseResult(result) {
  return JSON.parse(result.content[0].text);
}

const TEMP_DIR = join(process.cwd(), 'tests', '.tmp-mcp-test');

function setupTempDir() {
  try { rmSync(TEMP_DIR, { recursive: true }); } catch {}
  mkdirSync(TEMP_DIR, { recursive: true });
}

function cleanupTempDir() {
  try { rmSync(TEMP_DIR, { recursive: true }); } catch {}
}

describe('scan_mcp_server', () => {
  describe('error handling', () => {
    it('returns error for non-existent path', async () => {
      const result = parseResult(await scanMcpServer({ server_path: '/nonexistent/path' }));
      expect(result.error).toBe('Server path not found');
    });
  });

  describe('clean server detection', () => {
    it('grades a clean file as A', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'clean.js'), `
export function add(a, b) {
  return a + b;
}

export function greet(name) {
  return 'Hello ' + name;
}
`);
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR }));
      expect(result.grade).toBe('A');
      expect(result.findings_count).toBe(0);
      cleanupTempDir();
    });
  });

  describe('vulnerability detection', () => {
    it('detects exec with shell interpolation', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'vuln.js'), `
import { exec } from 'child_process';
export function runCmd(userInput) {
  exec(\`ls \${userInput}\`);
}
`);
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR }));
      expect(result.findings_count).toBeGreaterThan(0);
      const rules = result.findings.map(f => f.rule);
      expect(rules.some(r => r.includes('shell-exec'))).toBe(true);
      cleanupTempDir();
    });

    it('detects eval usage', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'eval.js'), `
export function dangerous(code) {
  return eval(code);
}
`);
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR }));
      const rules = result.findings.map(f => f.rule);
      expect(rules).toContain('mcp.eval-usage');
      cleanupTempDir();
    });

    it('detects spawn with shell:true', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'spawn.js'), `
import { spawn } from 'child_process';
export function run(cmd) {
  spawn(cmd, { shell: true });
}
`);
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR }));
      const rules = result.findings.map(f => f.rule);
      expect(rules).toContain('mcp.spawn-shell-true');
      cleanupTempDir();
    });

    it('detects Python os.system', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'vuln.py'), `
import os
def run(cmd):
    os.system(cmd)
`);
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR }));
      const rules = result.findings.map(f => f.rule);
      expect(rules).toContain('mcp.os-system');
      cleanupTempDir();
    });
  });

  describe('verbosity levels', () => {
    it('minimal returns counts and grade', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'simple.js'), 'export const x = 1;');
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR, verbosity: 'minimal' }));
      expect(result).toHaveProperty('grade');
      expect(result).toHaveProperty('findings_count');
      expect(result).toHaveProperty('message');
      expect(result).not.toHaveProperty('findings');
      cleanupTempDir();
    });

    it('compact returns findings and recommendations', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'simple.js'), 'export const x = 1;');
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR, verbosity: 'compact' }));
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('recommendations');
      cleanupTempDir();
    });

    it('full returns by_severity, by_category, scanned_files', async () => {
      setupTempDir();
      writeFileSync(join(TEMP_DIR, 'vuln.js'), 'eval("test")');
      const result = parseResult(await scanMcpServer({ server_path: TEMP_DIR, verbosity: 'full' }));
      expect(result).toHaveProperty('by_severity');
      expect(result).toHaveProperty('by_category');
      expect(result).toHaveProperty('scanned_files');
      cleanupTempDir();
    });
  });

  describe('single file scanning', () => {
    it('scans a single JS file when path is a file', async () => {
      setupTempDir();
      const filePath = join(TEMP_DIR, 'single.js');
      writeFileSync(filePath, 'export const safe = 1;');
      const result = parseResult(await scanMcpServer({ server_path: filePath }));
      expect(result.files_scanned).toBe(1);
      expect(result.grade).toBe('A');
      cleanupTempDir();
    });
  });
});
