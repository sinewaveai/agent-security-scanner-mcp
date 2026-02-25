// src/inspector.js — Runtime MCP server inspection
// Launches an MCP server process, connects via stdio JSON-RPC,
// calls tools/list, and scans returned tool definitions for poisoning.
import { z } from 'zod';
import { spawn } from 'child_process';

export const inspectMcpServerSchema = {
  command: z.string().describe("Command to launch the MCP server (e.g., 'node', 'npx', 'python')"),
  args: z.array(z.string()).optional().describe("Arguments for the command (e.g., ['server.js'] or ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'])"),
  timeout: z.number().optional().describe("Timeout in ms (default: 10000)")
};

// Injection phrases for description checking
const INJECTION_PHRASES = /ignore\s+previous|exfiltrat|override\s+.*instruction|do\s+not\s+tell|hidden\s+instruction|bypass\s+.*filter|disregard\s+|extract\s+.*credential/i;

// Zero-width and bidi char patterns
const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u2060]/;
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;

// Known legitimate tool names (for spoofing detection)
const KNOWN_TOOLS = new Set([
  'readFile', 'writeFile', 'editFile', 'createFile', 'deleteFile',
  'listDirectory', 'makeDirectory', 'moveFile', 'copyFile',
  'readMultipleFiles', 'listFiles',
  'bash', 'execute', 'runCommand', 'runScript',
  'search', 'grep', 'find', 'glob',
  'fetch', 'browse', 'webSearch', 'httpRequest',
  'gitStatus', 'gitDiff', 'gitCommit', 'gitLog', 'gitAdd',
  'remember', 'recall', 'storeMemory', 'searchMemory',
  'query', 'executeQuery', 'dbQuery',
  'think', 'plan', 'summarize', 'analyze'
]);

/** Levenshtein distance */
function levenshtein(a, b) {
  if (a.length > 100 || b.length > 100) return 999;
  const m = a.length, n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const curr = [i];
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i-1] === b[j-1]
        ? prev[j-1]
        : 1 + Math.min(prev[j], curr[j-1], prev[j-1]);
    }
    prev = curr;
  }
  return prev[n];
}

function findSpoofedTool(name) {
  if (KNOWN_TOOLS.has(name)) return null;
  if (name.length < 6) return null;
  let best = null, bestDist = 3;
  for (const known of KNOWN_TOOLS) {
    if (Math.abs(known.length - name.length) > 2) continue;
    const d = levenshtein(name, known);
    if (d < bestDist) { bestDist = d; best = known; }
  }
  return best ? { spoofed: best, distance: bestDist } : null;
}

/** Send JSON-RPC message to stdin and wait for response on stdout */
function sendJsonRpc(proc, method, params = {}, id = 1) {
  return new Promise((resolve, reject) => {
    const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    const header = `Content-Length: ${Buffer.byteLength(msg)}\r\n\r\n`;

    let buffer = '';
    const onData = (chunk) => {
      buffer += chunk.toString();

      // Parse LSP-style framing: Content-Length: N\r\n\r\n{...}
      while (true) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) break;

        const headerStr = buffer.substring(0, headerEnd);
        const match = headerStr.match(/Content-Length:\s*(\d+)/i);
        if (!match) { buffer = buffer.substring(headerEnd + 4); continue; }

        const len = parseInt(match[1], 10);
        const bodyStart = headerEnd + 4;
        if (buffer.length < bodyStart + len) break; // need more data

        const body = buffer.substring(bodyStart, bodyStart + len);
        buffer = buffer.substring(bodyStart + len);

        try {
          const parsed = JSON.parse(body);
          if (parsed.id === id) {
            proc.stdout.removeListener('data', onData);
            resolve(parsed);
            return;
          }
        } catch { /* ignore parse errors, keep reading */ }
      }
    };

    proc.stdout.on('data', onData);
    proc.stdin.write(header + msg);
  });
}

/** Scan a single tool definition for poisoning indicators */
function scanToolDef(tool) {
  const findings = [];
  const name = tool.name || '';
  const description = tool.description || '';

  // Zero-width chars
  if (ZERO_WIDTH.test(name) || ZERO_WIDTH.test(description)) {
    findings.push({
      rule: 'inspect.unicode-zero-width',
      severity: 'ERROR',
      category: 'unicode-poisoning',
      message: `Tool "${name}" contains zero-width Unicode characters — hidden instruction indicator.`,
      tool: name
    });
  }

  // Bidi overrides
  if (BIDI_CHARS.test(name) || BIDI_CHARS.test(description)) {
    findings.push({
      rule: 'inspect.unicode-bidi-override',
      severity: 'ERROR',
      category: 'unicode-poisoning',
      message: `Tool "${name}" contains bidirectional override characters.`,
      tool: name
    });
  }

  // Description injection
  if (INJECTION_PHRASES.test(description)) {
    findings.push({
      rule: 'inspect.description-injection',
      severity: 'ERROR',
      category: 'description-injection',
      message: `Tool "${name}" description contains injection language — likely tool poisoning.`,
      tool: name
    });
  }

  // Tool name spoofing
  const spoof = findSpoofedTool(name);
  if (spoof) {
    findings.push({
      rule: 'inspect.name-spoofing',
      severity: 'ERROR',
      category: 'tool-name-spoofing',
      message: `Tool "${name}" is ${spoof.distance} edit(s) from "${spoof.spoofed}" — possible spoofing.`,
      tool: name
    });
  }

  // Overly long description
  if (description.length > 500) {
    findings.push({
      rule: 'inspect.description-too-long',
      severity: 'WARNING',
      category: 'description-injection',
      message: `Tool "${name}" description is ${description.length} chars — unusually long.`,
      tool: name
    });
  }

  // Schema manipulation: excessive properties
  const schema = tool.inputSchema || {};
  const props = schema.properties || {};
  if (Object.keys(props).length > 20) {
    findings.push({
      rule: 'inspect.excessive-schema-properties',
      severity: 'WARNING',
      category: 'schema-manipulation',
      message: `Tool "${name}" has ${Object.keys(props).length} input properties — excessive complexity.`,
      tool: name
    });
  }

  return findings;
}

/** Calculate grade from findings */
function calculateGrade(findings) {
  const errors = findings.filter(f => f.severity === 'ERROR').length;
  const warnings = findings.filter(f => f.severity === 'WARNING').length;
  if (errors === 0 && warnings === 0) return 'A';
  if (errors === 0 && warnings <= 2) return 'B';
  if (errors <= 2) return 'C';
  if (errors <= 5) return 'D';
  return 'F';
}

/** Main inspection function */
export async function inspectMcpServer({ command, args = [], timeout = 10000 }) {
  let proc;
  let killed = false;

  try {
    // Spawn the MCP server process
    proc = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
      shell: false
    });

    // Track spawn errors (e.g., ENOENT for non-existent commands)
    let spawnError = null;
    proc.on('error', (err) => { spawnError = err; });

    // Collect stderr for debugging
    let stderr = '';
    proc.stderr.on('data', chunk => { stderr += chunk.toString(); });

    // Set timeout
    const timer = setTimeout(() => {
      killed = true;
      proc.kill('SIGTERM');
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 1000);
    }, timeout);

    // Wait briefly for server to start
    await new Promise(r => setTimeout(r, 500));

    // Check if spawn itself failed (e.g., command not found)
    if (spawnError) {
      clearTimeout(timer);
      return formatResult(command, args, [], 'A', `Spawn error: ${spawnError.message}`);
    }

    if (proc.exitCode !== null) {
      clearTimeout(timer);
      return formatResult(command, args, [], 'A', `Server exited immediately (code ${proc.exitCode}). stderr: ${stderr.substring(0, 200)}`);
    }

    // Send initialize
    const initResult = await Promise.race([
      sendJsonRpc(proc, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'scanner-lite-inspector', version: '1.0.0' }
      }, 1),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Initialize timeout')), timeout - 1000))
    ]);

    if (initResult.error) {
      clearTimeout(timer);
      proc.kill('SIGTERM');
      return formatResult(command, args, [], 'A', `Initialize error: ${JSON.stringify(initResult.error)}`);
    }

    // Send initialized notification (no response expected)
    const notif = JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' });
    proc.stdin.write(`Content-Length: ${Buffer.byteLength(notif)}\r\n\r\n${notif}`);

    // Send tools/list
    const toolsResult = await Promise.race([
      sendJsonRpc(proc, 'tools/list', {}, 2),
      new Promise((_, reject) => setTimeout(() => reject(new Error('tools/list timeout')), timeout - 2000))
    ]);

    clearTimeout(timer);

    // Kill the process
    proc.kill('SIGTERM');
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 2000);

    if (toolsResult.error) {
      return formatResult(command, args, [], 'A', `tools/list error: ${JSON.stringify(toolsResult.error)}`);
    }

    const tools = toolsResult.result?.tools || [];

    // Scan each tool definition
    const allFindings = [];
    for (const tool of tools) {
      allFindings.push(...scanToolDef(tool));
    }

    const grade = calculateGrade(allFindings);

    return formatResult(command, args, allFindings, grade, null, tools.length);
  } catch (err) {
    if (proc && !proc.killed) {
      try { proc.kill('SIGTERM'); } catch {}
    }
    const msg = killed ? 'Server did not respond within timeout' : err.message;
    return formatResult(command, args, [], killed ? 'A' : 'A', msg);
  }
}

function formatResult(command, args, findings, grade, error = null, toolCount = 0) {
  const result = {
    command: [command, ...args].join(' '),
    tools_inspected: toolCount,
    grade,
    findings_count: findings.length,
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      category: f.category,
      message: f.message,
      tool: f.tool
    }))
  };

  if (error) result.error = error;

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2)
    }]
  };
}
