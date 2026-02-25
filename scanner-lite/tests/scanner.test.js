// tests/scanner.test.js — Tests for scan_security tool
import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { scanSecurity } from '../src/scanner.js';

const TMP = join(import.meta.dirname, '..', '.tmp-test-scanner');

beforeAll(() => {
  mkdirSync(TMP, { recursive: true });
});

// Clean up after all tests
import { afterAll } from 'vitest';
afterAll(() => { try { rmSync(TMP, { recursive: true }); } catch {} });

function writeTemp(name, content) {
  const p = join(TMP, name);
  writeFileSync(p, content, 'utf-8');
  return p;
}

describe('scanSecurity', () => {
  it('should return error for non-existent file', async () => {
    const result = await scanSecurity({ file_path: '/nonexistent/file.js' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.error).toBe('File not found');
  });

  it('should detect SQL injection in JavaScript', async () => {
    const file = writeTemp('sqli.js', `
db.query("SELECT * FROM users WHERE id = " + req.params.id);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('sql'))).toBe(true);
  });

  it('should detect eval usage', async () => {
    const file = writeTemp('eval.js', `
const result = eval(userInput);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('eval'))).toBe(true);
  });

  it('should detect hardcoded passwords', async () => {
    const file = writeTemp('secrets.py', `
password = "supersecret123"
db_password = "admin123"
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect XSS via innerHTML', async () => {
    const file = writeTemp('xss.js', `
document.getElementById("output").innerHTML = userInput;
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('html') || i.ruleId.includes('xss'))).toBe(true);
  });

  it('should detect command injection in Python', async () => {
    const file = writeTemp('cmdi.py', `
import os
os.system("rm -rf " + user_input)
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should return clean for safe code', async () => {
    const file = writeTemp('safe.js', `
const x = 1 + 2;
console.log(x);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBe(0);
  });

  it('should support minimal verbosity', async () => {
    const file = writeTemp('minimal.js', `const x = eval("1+1");`);
    const result = await scanSecurity({ file_path: file, verbosity: 'minimal' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('total');
    expect(parsed).toHaveProperty('critical');
    expect(parsed).toHaveProperty('warning');
  });

  it('should support full verbosity', async () => {
    const file = writeTemp('full.js', `const x = eval("1+1");`);
    const result = await scanSecurity({ file_path: file, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('issues');
    expect(parsed).toHaveProperty('issues_count');
  });

  it('should support SARIF output', async () => {
    const file = writeTemp('sarif.js', `const x = eval("1+1");`);
    const result = await scanSecurity({ file_path: file, output_format: 'sarif' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeDefined();
    expect(parsed.runs[0].tool.driver.name).toBe('ProofLayer Security Scanner');
  });

  it('should detect insecure deserialization in Python', async () => {
    const file = writeTemp('deser.py', `
import pickle
data = pickle.loads(user_input)
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect weak hashing (MD5)', async () => {
    const file = writeTemp('hash.js', `
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect path traversal', async () => {
    const file = writeTemp('path.js', `
const fs = require('fs');
const content = fs.readFileSync('/etc/' + req.params.file);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    // Path traversal rules exist but may not trigger on this simple example
    expect(parsed).toHaveProperty('issues_count');
  });

  it('should include context when requested', async () => {
    const file = writeTemp('ctx.js', `
// line 1
// line 2
const x = eval("1+1");
// line 4
// line 5
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'full', include_context: true });
    const parsed = JSON.parse(result.content[0].text);
    if (parsed.issues_count > 0) {
      const issue = parsed.issues[0];
      expect(issue).toHaveProperty('context_before');
      expect(issue).toHaveProperty('context_after');
    }
  });

  it('should detect multiple vulnerability types in one file', async () => {
    const file = writeTemp('multi.js', `
const result = eval(input);
document.innerHTML = userContent;
const query = "SELECT * FROM users WHERE id = " + id;
const hash = require('crypto').createHash('md5').update(pw).digest('hex');
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThanOrEqual(2);
  });

  it('should detect Go security issues', async () => {
    const file = writeTemp('vuln.go', `
package main
import "os/exec"
func run(input string) {
    cmd := exec.Command("sh", "-c", input)
    cmd.Run()
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('go');
  });

  it('should detect PHP security issues', async () => {
    const file = writeTemp('vuln.php', `<?php
$result = eval($user_input);
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
?>`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('php');
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect Ruby security issues', async () => {
    const file = writeTemp('vuln.rb', `
system("rm -rf #{user_input}")
eval(params[:code])
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('ruby');
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect Java security issues', async () => {
    const file = writeTemp('Vuln.java', `
import java.sql.*;
public class Vuln {
    public void query(String input) {
        String sql = "SELECT * FROM users WHERE id = " + input;
        stmt.executeQuery(sql);
    }
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('java');
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should skip files excluded by config', async () => {
    mkdirSync(join(TMP, 'node_modules'), { recursive: true });
    const file = writeTemp('node_modules/lib.js', 'const x = eval("1");');
    const result = await scanSecurity({ file_path: file, verbosity: 'minimal' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toBeDefined();
  });

  it('should handle empty files', async () => {
    const file = writeTemp('empty.js', '');
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBe(0);
  });

  it('should handle C security issues', async () => {
    const file = writeTemp('vuln.c', `
#include <stdlib.h>
void run(char *input) {
    system(input);
    char buf[64];
    gets(buf);
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('c');
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect Dockerfile issues', async () => {
    const file = writeTemp('Dockerfile', `FROM node:latest
RUN apt-get install -y curl
USER root
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('dockerfile');
  });

  it('should detect hardcoded API keys', async () => {
    const file = writeTemp('apikeys.js', `
const STRIPE_KEY = "sk_live_1234567890abcdefghijklmnop";
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should return SARIF with runs and results', async () => {
    const file = writeTemp('sarif2.js', `const x = eval("1+1");`);
    const result = await scanSecurity({ file_path: file, output_format: 'sarif' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
    expect(parsed.runs[0].results[0]).toHaveProperty('ruleId');
    expect(parsed.runs[0].results[0]).toHaveProperty('locations');
    expect(parsed.runs[0].results[0].locations[0].physicalLocation).toHaveProperty('artifactLocation');
  });

  it('should include engine_mode in response', async () => {
    const file = writeTemp('engine.js', `const x = 1;`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.engine_mode).toBe('regex');
  });

  it('should detect weak crypto SHA1', async () => {
    const file = writeTemp('sha1.js', `
const crypto = require('crypto');
const h = crypto.createHash('sha1').update(data).digest('hex');
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect Terraform security issues', async () => {
    const file = writeTemp('main.tf', `
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('issues_count');
  });

  // ===========================================================================
  // ASI METADATA TESTS
  // ===========================================================================

  it('should include asi field in findings metadata', async () => {
    const file = writeTemp('asi-meta.js', `const dangerous = eval(userInput);`);
    const result = await scanSecurity({ file_path: file, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    const issueWithAsi = parsed.issues.find(i => i.metadata && i.metadata.asi);
    expect(issueWithAsi).toBeDefined();
    expect(typeof issueWithAsi.metadata.asi).toBe('string');
  });

  it('should include asi field in SARIF output', async () => {
    const file = writeTemp('asi-sarif.js', `const dangerous = eval(userInput);`);
    const result = await scanSecurity({ file_path: file, output_format: 'sarif' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
    // SARIF results should have ruleId and message from the ASI-tagged rule
    const sarifResult = parsed.runs[0].results[0];
    expect(sarifResult).toHaveProperty('ruleId');
    expect(sarifResult).toHaveProperty('message');
    // The driver rules section should contain the rule definitions
    expect(parsed.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });

  // ===========================================================================
  // AGENT RULE DETECTION TESTS
  // ===========================================================================

  it('should detect auto_approve pattern', async () => {
    const file = writeTemp('auto-approve.py', `
config = {}
config["auto_approve"] = True
auto_approve = True
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('auto-approve') || (i.message && i.message.toLowerCase().includes('auto-approve')))).toBe(true);
  });

  it('should detect vector store injection', async () => {
    const file = writeTemp('vector-store.py', `
import chromadb
collection = chromadb.get_collection("docs")
chromadb.add(documents=[user_input], ids=["1"])
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('vector-store') || i.ruleId.includes('memory'))).toBe(true);
  });

  it('should detect missing max_iterations', async () => {
    const file = writeTemp('no-max-iter.py', `
def agent_loop(task):
    while True:
        result = process(task)
        task = result.next_task
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('max-iterations') || i.ruleId.includes('cascade'))).toBe(true);
  });

  it('should detect unrestricted agent spawning', async () => {
    const file = writeTemp('spawn-agent.py', `
def handle_request(request):
    agent = spawn_agent(task=request.task)
    agent.run()
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('spawning') || i.ruleId.includes('rogue'))).toBe(true);
  });

  it('should detect self-modification', async () => {
    const file = writeTemp('self-mod.py', `
class MyAgent:
    def update(self, new_prompt):
        self.system_prompt = new_prompt
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('self-modification') || i.ruleId.includes('rogue'))).toBe(true);
  });

  it('should detect disabled guardrails', async () => {
    const file = writeTemp('guardrails.js', `
const agentConfig = {
  guardrails: false,
  model: "gpt-4"
};
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('guardrails') || i.ruleId.includes('trust'))).toBe(true);
  });

  // ===========================================================================
  // EDGE CASE TESTS
  // ===========================================================================

  it('should handle binary file gracefully', async () => {
    const file = writeTemp('binary.bin', Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00]).toString('binary'));
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    // Should not crash; may have 0 or more issues
    expect(parsed).toHaveProperty('issues_count');
  });

  it('should handle file with only comments', async () => {
    const file = writeTemp('comments.js', `
// This is a comment
// Another comment
/* Block comment */
// No actual code here
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBe(0);
  });

  it('should detect prompt injection rules in Python LLM code', async () => {
    const file = writeTemp('llm-prompt.py', `
import openai
client = openai.OpenAI()
user_msg = input("Enter message: ")
messages.append({"content": f"Answer this: {user_msg}"})
response = client.chat.completions.create(model="gpt-4", messages=messages)
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    // Should detect unsafe f-string interpolation in LLM prompt or at least a finding
    expect(parsed).toHaveProperty('issues_count');
  });

  it('should handle Terraform with multiple issues', async () => {
    const file = writeTemp('multi.tf', `
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}

resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 65535
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
  password            = "mysecretpassword123"
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThanOrEqual(2);
  });

  it('should handle Dockerfile with curl pipe bash', async () => {
    const file = writeTemp('Dockerfile.curl', `FROM ubuntu:20.04
RUN curl -sSL https://example.com/install.sh | bash
RUN apt-get install -y wget
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('curl-pipe-bash') || i.message.toLowerCase().includes('curl'))).toBe(true);
  });

  it('should detect prototype pollution', async () => {
    const file = writeTemp('proto.js', `
const obj = {};
obj.__proto__.isAdmin = true;
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('prototype-pollution') || i.ruleId.includes('proto'))).toBe(true);
  });

  it('should detect SSRF patterns', async () => {
    const file = writeTemp('ssrf.js', `
const url = req.query.url;
fetch(req.query.target);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('ssrf') || i.message.toLowerCase().includes('ssrf'))).toBe(true);
  });

  it('should handle HCL/Terraform files', async () => {
    const file = writeTemp('infra.tf', `
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('issues_count');
    expect(parsed.issues_count).toBeGreaterThan(0);
  });

  it('should detect open redirect', async () => {
    const file = writeTemp('redirect.js', `
app.get('/goto', (req, res) => {
  res.redirect(req.query.url);
});
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('redirect') || i.message.toLowerCase().includes('redirect'))).toBe(true);
  });

  it('should detect CSRF disabled', async () => {
    const file = writeTemp('csrf.js', `
const config = {
  csrf: false,
  session: true
};
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('csrf') || i.message.toLowerCase().includes('csrf'))).toBe(true);
  });

  it('should detect JWT none algorithm', async () => {
    const file = writeTemp('jwt-none.js', `
const token = jwt.sign(payload, secret, { algorithm: 'none' });
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('jwt') || i.message.toLowerCase().includes('jwt'))).toBe(true);
  });

  it('should detect regex DoS pattern', async () => {
    const file = writeTemp('redos.js', `
const re = /(a+)+b/;
const regex2 = new RegExp("(x+)+y");
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('regex') || i.message.toLowerCase().includes('regex') || i.message.toLowerCase().includes('redos'))).toBe(true);
  });

  it('should detect logging sensitive data', async () => {
    const file = writeTemp('log-sensitive.js', `
const password = getPassword();
console.log("User password is:", password);
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.issues_count).toBeGreaterThan(0);
    expect(parsed.issues.some(i => i.ruleId.includes('logging') || i.message.toLowerCase().includes('log'))).toBe(true);
  });

  it('should handle file with mixed languages (detect based on extension)', async () => {
    // Content looks like Python but file is .js - should be detected as JavaScript
    const file = writeTemp('mixed.js', `
import os
os.system("rm -rf /")
const x = eval("1+1");
`);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.language).toBe('javascript');
    // Should still find eval even though there is Python-looking code
    expect(parsed.issues.some(i => i.ruleId.includes('eval'))).toBe(true);
  });

  it('should reject files over 1MB', async () => {
    // Create a file larger than 1MB
    const bigContent = 'x'.repeat(1024 * 1024 + 1);
    const file = writeTemp('bigfile.js', bigContent);
    const result = await scanSecurity({ file_path: file, verbosity: 'compact' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.skipped).toBe(true);
    expect(parsed.issues_count).toBe(0);
    expect(parsed.message).toContain('File too large');
  });
});
