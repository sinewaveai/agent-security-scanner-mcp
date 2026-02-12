import { execFileSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { createInterface } from "readline";
import { dirname } from "path";
import { fileURLToPath } from "url";

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

const DEMO_TEMPLATES = {
  js: {
    ext: 'js',
    name: 'JavaScript',
    code: `const express = require("express");
const child_process = require("child_process");
const app = express();

// SQL Injection vulnerability
app.get("/user", (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + userId, (err, result) => {
    res.send(result);
  });
});

// XSS vulnerability
app.get("/profile", (req, res) => {
  const name = req.query.name;
  document.getElementById("welcome").innerHTML = name;
});

// Command Injection vulnerability
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  child_process.exec("ls " + cmd, (err, stdout) => {
    res.send(stdout);
  });
});
`
  },
  py: {
    ext: 'py',
    name: 'Python',
    code: `import pickle
import subprocess
import hashlib

API_SECRET = "stripe_test_FAKEFAKEFAKEFAKE1234"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def load_data(data):
    return pickle.loads(data)

def run_command(cmd):
    return subprocess.call(cmd, shell=True)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
`
  },
  go: {
    ext: 'go',
    name: 'Go',
    code: `package main

import (
\t"crypto/md5"
\t"database/sql"
\t"fmt"
\t"net/http"
\t"os/exec"
)

var dbPassword = "super_secret_password_123"

func getUser(w http.ResponseWriter, r *http.Request) {
\tid := r.URL.Query().Get("id")
\tquery := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
\tdb.Query(query)
}

func runCmd(w http.ResponseWriter, r *http.Request) {
\tcmd := r.URL.Query().Get("cmd")
\tout, _ := exec.Command("sh", "-c", cmd).Output()
\tw.Write(out)
}

func hashData(data string) string {
\th := md5.Sum([]byte(data))
\treturn fmt.Sprintf("%x", h)
}
`
  },
  java: {
    ext: 'java',
    name: 'Java',
    code: `import java.sql.*;
import java.io.*;
import java.security.MessageDigest;

public class VulnDemo {
    private static final String DB_PASSWORD = "admin123";

    public ResultSet getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    public String runCommand(String cmd) throws IOException {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec(cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        return reader.readLine();
    }

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
}
`
  }
};

function parseDemoFlags(args) {
  const flags = { lang: 'js' };
  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if ((arg === '--lang' || arg === '-l') && i + 1 < args.length) {
      flags.lang = args[++i].toLowerCase();
    } else if (!arg.startsWith('-')) {
      flags.lang = arg.toLowerCase();
    }
    i++;
  }
  return flags;
}

function checkCommand(cmd, args) {
  try {
    const out = execFileSync(cmd, args, { timeout: 10000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    return { ok: true, output: out.trim() };
  } catch {
    return { ok: false, output: null };
  }
}

export async function runDemo(args) {
  const flags = parseDemoFlags(args);
  const template = DEMO_TEMPLATES[flags.lang];
  if (!template) {
    console.log(`\n  Unknown language: "${flags.lang}"`);
    console.log(`  Available: ${Object.keys(DEMO_TEMPLATES).join(', ')}\n`);
    process.exit(1);
  }

  const filename = `vuln-demo.${template.ext}`;
  const filepath = join(process.cwd(), filename);

  console.log(`\n  agent-security-scanner-mcp demo\n`);
  console.log(`  Creating ${filename} with 3 intentional vulnerabilities...\n`);

  // Write the vulnerable file
  writeFileSync(filepath, template.code);

  // Run the analyzer
  const analyzerPath = join(__dirname, '..', '..', 'analyzer.py');
  let pythonCmd = 'python3';
  const py3 = checkCommand('python3', ['--version']);
  if (!py3.ok) {
    const py = checkCommand('python', ['--version']);
    if (py.ok && py.output.includes('3.')) {
      pythonCmd = 'python';
    } else {
      console.log(`  Error: Python 3 not found. Run "npx agent-security-scanner-mcp doctor" to diagnose.\n`);
      unlinkSync(filepath);
      process.exit(1);
    }
  }

  let results;
  try {
    const output = execFileSync(pythonCmd, [analyzerPath, filepath], { timeout: 30000, encoding: 'utf-8' });
    results = JSON.parse(output);
  } catch (e) {
    console.log(`  Error running analyzer: ${e.message}\n`);
    unlinkSync(filepath);
    process.exit(1);
  }

  // Display results
  console.log(`  Scanning...\n`);

  if (results.length === 0) {
    console.log(`  No issues found (unexpected for demo file).\n`);
  } else {
    console.log(`  Found ${results.length} issue(s):\n`);
    for (const issue of results) {
      const severity = (issue.severity || 'error').toUpperCase();
      const icon = severity === 'ERROR' ? '\u2717' : severity === 'WARNING' ? '\u2717' : '\u2022';
      console.log(`    ${icon} ${severity.padEnd(8)} Line ${String(issue.line).padEnd(4)} ${issue.message}`);
      if (issue.metadata) {
        const refs = [issue.metadata.cwe, issue.metadata.owasp].filter(Boolean).join(' | ');
        if (refs) console.log(`      ${refs}`);
      }
    }
    console.log(`\n  ${results.length} vulnerabilities detected.\n`);
  }

  // Ask to keep or delete
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => {
    rl.question(`  Keep ${filename} for testing? (y/N): `, (a) => { rl.close(); resolve(a); });
  });

  if (answer.toLowerCase() === 'y') {
    console.log(`\n  Kept: ${filepath}`);
  } else {
    unlinkSync(filepath);
    console.log(`\n  Deleted: ${filename}`);
  }

  console.log(`\n  Next: Connect to your AI coding tool and ask it to`);
  console.log(`  "scan ${filename} for security issues"\n`);
}
