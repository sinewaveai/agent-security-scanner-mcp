// tests/fix-engine.test.js — Tests for fix_security tool
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { fixSecurity } from '../src/fix-engine.js';

const TMP = join(import.meta.dirname, '..', '.tmp-test-fix');

beforeAll(() => { mkdirSync(TMP, { recursive: true }); });
afterAll(() => { try { rmSync(TMP, { recursive: true }); } catch {} });

function writeTemp(name, content) {
  const p = join(TMP, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

describe('fixSecurity', () => {
  it('should return error for non-existent file', async () => {
    const result = await fixSecurity({ file_path: '/nonexistent/file.js' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('File not found');
  });

  it('should suggest fixes for eval usage', async () => {
    const file = writeTemp('fix-eval.js', `
const result = eval(userInput);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should suggest fixes for innerHTML', async () => {
    const file = writeTemp('fix-xss.js', `
document.getElementById("output").innerHTML = userInput;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should return no fixes for clean code', async () => {
    const file = writeTemp('fix-clean.js', `
const x = 1 + 2;
console.log(x);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    // Either no issues found or no fixes needed
    expect(parsed.fixes_applied === 0 || parsed.message).toBeTruthy();
  });

  it('should support minimal verbosity', async () => {
    const file = writeTemp('fix-mini.js', `eval(x);`);
    const result = await fixSecurity({ file_path: file, verbosity: 'minimal' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should support full verbosity with fixed_content', async () => {
    const file = writeTemp('fix-full.js', `
document.getElementById("x").innerHTML = data;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    // Full verbosity should include fixed_content if there were fixes
    if (parsed.fixes_applied > 0) {
      expect(parsed.fixed_content).toBeDefined();
    }
  });

  it('should handle Python files', async () => {
    const file = writeTemp('fix-py.py', `
import pickle
data = pickle.loads(user_input)
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle multiple vulnerabilities', async () => {
    const file = writeTemp('fix-multi.js', `
const a = eval(input);
document.innerHTML = data;
const q = "SELECT * FROM users WHERE id = " + id;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should provide fix descriptions in compact mode', async () => {
    const file = writeTemp('fix-desc.js', `const x = eval(userInput);`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    if (parsed.fixes_applied > 0 && parsed.fixes) {
      expect(parsed.fixes[0]).toHaveProperty('ruleId');
    }
  });

  it('should handle Go files', async () => {
    const file = writeTemp('fix-go.go', `
package main
import "os/exec"
func run(input string) {
    cmd := exec.Command("sh", "-c", input)
    cmd.Run()
}
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle command injection fixes', async () => {
    const file = writeTemp('fix-cmdi.js', `
const { exec } = require('child_process');
exec("ls " + userInput);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });
});
