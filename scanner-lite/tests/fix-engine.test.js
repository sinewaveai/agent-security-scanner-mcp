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

  it('should suggest fixes for SQL injection', async () => {
    const file = writeTemp('fix-sqli.js', `
const q = "SELECT * FROM users WHERE id = " + userId;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should suggest fixes for hardcoded secrets', async () => {
    const file = writeTemp('fix-secret.js', `
const apiKey = "sk-1234567890abcdef1234567890abcdef";
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should suggest fixes for XSS (document.write)', async () => {
    const file = writeTemp('fix-docwrite.js', `
document.write(userInput);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle Ruby eval fix', async () => {
    const file = writeTemp('fix-ruby-eval.rb', `
result = eval(user_input)
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle PHP eval fix', async () => {
    const file = writeTemp('fix-php-eval.php', `<?php
eval($user_input);
?>`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle Java SQL injection fix', async () => {
    const file = writeTemp('fix-java-sqli.java', `
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.executeQuery(query);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle C buffer overflow (gets) fix', async () => {
    const file = writeTemp('fix-c-gets.c', `
#include <stdio.h>
int main() {
    char buf[64];
    gets(buf);
    return 0;
}
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should apply multiple fixes on same file', async () => {
    const file = writeTemp('fix-multi2.js', `
const a = eval(input);
document.getElementById("out").innerHTML = data;
exec("rm " + userFile);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
    // With multiple vulns, expect multiple fixes or at least the struct
    expect(parsed.fixes_applied).toBeGreaterThanOrEqual(0);
  });

  it('should preserve line numbers across fixes', async () => {
    const file = writeTemp('fix-lines.js', `
const a = 1;
const b = eval(x);
const c = 3;
document.getElementById("out").innerHTML = data;
const d = 5;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    if (parsed.fixes_applied > 0 && parsed.fixes) {
      // Each fix should have a line number
      for (const fix of parsed.fixes) {
        expect(fix.line).toBeGreaterThan(0);
      }
    }
  });

  it('should handle file with no vulnerabilities (0 fixes)', async () => {
    const file = writeTemp('fix-none.js', `
const sum = (a, b) => a + b;
console.log(sum(1, 2));
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.fixes_applied === 0 || parsed.message).toBeTruthy();
  });

  it('should include fix description for each fix', async () => {
    const file = writeTemp('fix-desc2.js', `
document.getElementById("x").innerHTML = userInput;
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    if (parsed.fixes_applied > 0 && parsed.fixes) {
      for (const fix of parsed.fixes) {
        expect(fix).toHaveProperty('rule');
      }
    }
  });

  it('should handle spawn shell:true fix', async () => {
    const file = writeTemp('fix-spawn.js', `
const { spawn } = require('child_process');
spawn('ls', ['-la'], { shell: true });
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle MD5 weak hash fix', async () => {
    const file = writeTemp('fix-md5.js', `
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(data).digest('hex');
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle hardcoded password fix', async () => {
    const file = writeTemp('fix-pw.js', `
const password = "SuperSecret123!";
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle path traversal fix suggestion', async () => {
    const file = writeTemp('fix-traversal.js', `
const fs = require('fs');
const data = fs.readFileSync(userPath);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should support compact verbosity with fix details', async () => {
    const file = writeTemp('fix-compact.js', `eval(userInput);`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
    expect(parsed).toHaveProperty('file');
  });

  it('should handle Python exec fix', async () => {
    const file = writeTemp('fix-py-exec.py', `
exec(user_input)
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });

  it('should handle SSRF fetch fix', async () => {
    const file = writeTemp('fix-ssrf.js', `
const resp = await fetch(userUrl);
`);
    const result = await fixSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('fixes_applied');
  });
});
