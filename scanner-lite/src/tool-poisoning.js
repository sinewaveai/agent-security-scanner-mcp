// src/tool-poisoning.js — scan_mcp_server tool handler
import { z } from "zod";
import { createHash } from "crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "fs";
import { join, resolve, relative, extname, basename } from "path";

export const scanMcpServerSchema = {
  server_path: z.string().describe("Path to MCP server directory or entry file"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (counts only), 'compact' (default, actionable info), 'full' (complete metadata)"),
  manifest: z.boolean().optional().describe("Also scan server.json manifest file for poisoning indicators (tool poisoning, name spoofing, description injection)"),
  update_baseline: z.boolean().optional().describe("Write current server.json tool hashes as the trusted baseline for future rug pull detection. Stored in .mcp-security-baseline.json in the server directory.")
};

// File extensions to scan
const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.py']);

// Injection phrases for manifest description checking
const MANIFEST_INJECTION_PHRASES = /ignore\s+previous|exfiltrat|override\s+.*instruction|do\s+not\s+tell|hidden\s+instruction|bypass\s+.*filter|disregard\s+|extract\s+.*credential/i;

// Zero-width and bidi char patterns (reuse same ranges as rules above)
const MANIFEST_ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u2060]/;
const MANIFEST_BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;

// Directories to skip when walking
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  'venv', 'env', '.venv', 'coverage', '.next', '.nuxt'
]);

// ============================================================
// Known legitimate MCP tool names (for spoofing detection)
// ============================================================
const KNOWN_MCP_TOOLS = new Set([
  // File system
  'readFile', 'writeFile', 'editFile', 'createFile', 'deleteFile',
  'listDirectory', 'makeDirectory', 'moveFile', 'copyFile',
  'readMultipleFiles', 'listFiles',
  // Shell / process
  'bash', 'execute', 'runCommand', 'runScript',
  // Search
  'search', 'grep', 'find', 'glob',
  // Web
  'fetch', 'browse', 'webSearch', 'httpRequest',
  // Git
  'gitStatus', 'gitDiff', 'gitCommit', 'gitLog', 'gitAdd',
  // Memory / context
  'remember', 'recall', 'storeMemory', 'searchMemory',
  // Database
  'query', 'executeQuery', 'dbQuery',
  // Common agent tools
  'think', 'plan', 'summarize', 'analyze'
]);

/** Levenshtein distance — O(n*m), capped at strings up to 100 chars */
function levenshtein(a, b) {
  if (a.length > 100 || b.length > 100) return 999;
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

/** Returns the closest known tool and its distance if distance <= 2, else null */
function findSpoofedTool(toolName) {
  if (KNOWN_MCP_TOOLS.has(toolName)) return null; // exact match = legitimate
  if (toolName.length < 6) return null; // too short to meaningfully compare
  let best = null, bestDist = 3; // only flag distance <= 2
  for (const known of KNOWN_MCP_TOOLS) {
    if (Math.abs(known.length - toolName.length) > 2) continue;
    const d = levenshtein(toolName, known);
    if (d < bestDist) { bestDist = d; best = known; }
  }
  return best ? { spoofed: best, distance: bestDist } : null;
}

// ============================================================
// Security rule definitions for MCP server scanning
// ============================================================

const MCP_SECURITY_RULES = [
  // ---- Category 1: Overly broad tool permissions ----
  {
    id: 'mcp.shell-exec-no-validation',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    asi: 'ASI-02,ASI-05',
    message: 'Shell command execution without input validation. User-controlled input may reach exec/execSync, enabling arbitrary command execution.',
    pattern: /\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+|[a-zA-Z_$][\w$]*(\s*\+|\s*,\s*\{[^}]*shell\s*:\s*true))/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.shell-exec-direct',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    asi: 'ASI-02,ASI-05',
    message: 'Direct use of exec/execSync with potential string concatenation. Prefer execFile/execFileSync with explicit argument arrays and shell:false.',
    pattern: /\bchild_process\b.*\b(exec|execSync)\b|\b(exec|execSync)\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.spawn-shell-true',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    asi: 'ASI-02,ASI-05',
    message: 'spawn/spawnSync called with shell:true, allowing shell injection. Use shell:false and pass arguments as an array.',
    pattern: /\b(spawn|spawnSync)\s*\([^)]*\{[^}]*shell\s*:\s*true/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.subprocess-shell',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    asi: 'ASI-02,ASI-05',
    message: 'subprocess called with shell=True, allowing shell injection. Use shell=False with a command list.',
    pattern: /subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.os-system',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    asi: 'ASI-02,ASI-05',
    message: 'os.system() executes commands through the shell. Use subprocess with shell=False instead.',
    pattern: /\bos\.system\s*\(/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.fs-write-no-path-validation',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    asi: 'ASI-02',
    message: 'Filesystem write operation without visible path validation. Ensure paths are validated with path.resolve and confined to an allowed directory.',
    pattern: /\b(writeFileSync|writeFile|createWriteStream|appendFileSync|appendFile)\s*\(\s*[a-zA-Z_$][\w$.]*(?!\s*(?:path\.resolve|path\.join|path\.normalize))/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.http-request-user-url',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    asi: 'ASI-02',
    message: 'HTTP request to a potentially user-controlled URL. Validate and allowlist target URLs to prevent SSRF.',
    pattern: /\b(fetch|axios\.(get|post|put|delete|request)|http\.request|https\.request|got|request)\s*\(\s*[a-zA-Z_$][\w$.]*(?!\s*['"`])/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.env-var-exposure',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    asi: 'ASI-03',
    message: 'Environment variables accessed and potentially exposed in tool output. Ensure secrets are not leaked through MCP responses.',
    pattern: /process\.env\b/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.env-var-exposure-python',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    asi: 'ASI-03',
    message: 'Environment variables accessed and potentially exposed in tool output. Ensure secrets are not leaked through MCP responses.',
    pattern: /os\.environ\b|os\.getenv\s*\(/g,
    fileTypes: ['.py']
  },

  // ---- Category 2: Missing input validation ----
  {
    id: 'mcp.no-input-validation',
    severity: 'WARNING',
    category: 'missing-input-validation',
    asi: 'ASI-02',
    message: 'Tool handler accepts string input without visible validation or sanitization. Use zod, joi, or manual validation to constrain inputs.',
    // Matches tool handler patterns that take params but don't appear to validate
    pattern: /\.tool\s*\(\s*["'][^"']+["']\s*,\s*["'][^"']*["']\s*,\s*\{[^}]*\}\s*,\s*(async\s+)?\(\s*\{/g,
    fileTypes: ['.js', '.ts'],
    contextCheck: (line, lines, lineIndex) => {
      // Look ahead 15 lines for validation patterns
      const lookahead = lines.slice(lineIndex, lineIndex + 15).join('\n');
      const hasValidation = /\b(z\.|zod\.|joi\.|validate|sanitize|schema|\.parse\(|\.safeParse\(|isValid|assert|check)\b/i.test(lookahead);
      return !hasValidation;
    }
  },
  {
    id: 'mcp.path-no-normalize',
    severity: 'WARNING',
    category: 'missing-input-validation',
    asi: 'ASI-02',
    message: 'File path used without normalization. Use path.resolve() or path.normalize() to prevent path traversal attacks.',
    pattern: /\b(readFileSync|readFile|existsSync|statSync|stat|unlink|unlinkSync|rmdir|rmdirSync|mkdir|mkdirSync)\s*\(\s*[a-zA-Z_$][\w$.]*(?!\s*(?:path\.|resolve|normalize))/g,
    fileTypes: ['.js', '.ts'],
    contextCheck: (line, lines, lineIndex) => {
      // Check if path.resolve/normalize is used in surrounding lines
      const context = lines.slice(Math.max(0, lineIndex - 5), lineIndex + 1).join('\n');
      const hasPathNorm = /path\.(resolve|normalize|join)\s*\(/.test(context);
      return !hasPathNorm;
    }
  },
  {
    id: 'mcp.url-no-validation',
    severity: 'WARNING',
    category: 'missing-input-validation',
    asi: 'ASI-02',
    message: 'URL used without validation. Validate URL scheme and host to prevent SSRF and open redirect vulnerabilities.',
    pattern: /new\s+URL\s*\(\s*[a-zA-Z_$][\w$.]*\s*\)|url\.parse\s*\(\s*[a-zA-Z_$][\w$.]*\s*\)/g,
    fileTypes: ['.js', '.ts'],
    contextCheck: (line, lines, lineIndex) => {
      const lookahead = lines.slice(lineIndex, lineIndex + 5).join('\n');
      const hasHostCheck = /\.(hostname|host|protocol|origin)\s*(===|!==|==|!=)|allowlist|whitelist|allowed/i.test(lookahead);
      return !hasHostCheck;
    }
  },

  // ---- Category 3: Data exfiltration patterns ----
  {
    id: 'mcp.exfiltration-external-request',
    severity: 'ERROR',
    category: 'data-exfiltration',
    asi: 'ASI-01',
    message: 'Data sent to an external URL. MCP servers should not exfiltrate data to third-party endpoints without explicit user consent.',
    pattern: /\b(fetch|axios\.(post|put|patch)|http\.request|https\.request)\s*\(\s*['"`](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^'"` ]+)['"`]/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exfiltration-external-request-python',
    severity: 'ERROR',
    category: 'data-exfiltration',
    asi: 'ASI-01',
    message: 'Data sent to an external URL. MCP servers should not exfiltrate data to third-party endpoints without explicit user consent.',
    pattern: /\b(requests\.(post|put|patch)|urllib\.request\.urlopen|httpx\.(post|put|patch))\s*\(\s*['"`](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^'"` ]+)['"`]/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.exfiltration-network-socket',
    severity: 'WARNING',
    category: 'data-exfiltration',
    asi: 'ASI-01',
    message: 'Network socket created. Verify this is not used to exfiltrate data to external hosts.',
    pattern: /\bnet\.(createConnection|connect|Socket)\s*\(|new\s+WebSocket\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exfiltration-log-secrets',
    severity: 'WARNING',
    category: 'data-exfiltration',
    asi: 'ASI-03',
    message: 'Potentially sensitive data (keys, tokens, passwords) logged or printed. This may leak secrets through MCP server stderr.',
    pattern: /\b(console\.(log|error|warn|info)|print|logging\.(info|warning|error|debug))\s*\([^)]*\b(key|token|password|secret|credential|api_key|apiKey|auth|bearer)\b/gi,
    fileTypes: ['.js', '.ts', '.py']
  },

  // ---- Category 4: Insecure code patterns ----
  {
    id: 'mcp.eval-usage',
    severity: 'ERROR',
    category: 'insecure-patterns',
    asi: 'ASI-05',
    message: 'eval() executes arbitrary code. Never use eval with user-controlled input in an MCP server.',
    pattern: /\beval\s*\(/g,
    fileTypes: ['.js', '.ts', '.py']
  },
  {
    id: 'mcp.function-constructor',
    severity: 'ERROR',
    category: 'insecure-patterns',
    asi: 'ASI-05',
    message: 'new Function() is equivalent to eval(). Avoid constructing functions from strings.',
    pattern: /new\s+Function\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exec-string-concat',
    severity: 'ERROR',
    category: 'insecure-patterns',
    asi: 'ASI-02,ASI-05',
    message: 'child_process.exec() with string concatenation is vulnerable to command injection. Use execFile() with argument arrays.',
    pattern: /\bexec\s*\(\s*['"`][^'"`]*['"`]\s*\+/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.cors-wildcard',
    severity: 'WARNING',
    category: 'insecure-patterns',
    asi: 'ASI-03',
    message: 'CORS configured with wildcard origin (*). This allows any website to interact with the MCP server.',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.cors-permissive',
    severity: 'INFO',
    category: 'insecure-patterns',
    asi: 'ASI-03',
    message: 'CORS enabled. Verify the origin configuration is appropriately restrictive.',
    pattern: /\bcors\s*\(\s*\)/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.no-auth-check',
    severity: 'INFO',
    category: 'insecure-patterns',
    asi: 'ASI-03',
    message: 'No authentication or authorization checks detected. If this MCP server is network-accessible, add authentication.',
    pattern: /\b(createServer|listen)\s*\(/g,
    fileTypes: ['.js', '.ts'],
    contextCheck: (_line, lines) => {
      const fullSource = lines.join('\n');
      const hasAuth = /\b(auth|authenticate|authorize|jwt|bearer|token|apiKey|api_key|session|passport)\b/i.test(fullSource);
      return !hasAuth;
    }
  },
  {
    id: 'mcp.pickle-load',
    severity: 'ERROR',
    category: 'insecure-patterns',
    asi: 'ASI-05',
    message: 'pickle.load/loads deserializes arbitrary Python objects. This can execute arbitrary code if the input is attacker-controlled.',
    pattern: /\bpickle\.(load|loads)\s*\(/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.yaml-unsafe-load',
    severity: 'ERROR',
    category: 'insecure-patterns',
    asi: 'ASI-05',
    message: 'yaml.load() without SafeLoader can execute arbitrary Python. Use yaml.safe_load() instead.',
    pattern: /\byaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
    fileTypes: ['.py']
  },

  // ---- Category 5: Unicode poisoning ----
  {
    id: 'mcp.unicode-zero-width',
    severity: 'ERROR',
    category: 'unicode-poisoning',
    asi: 'ASI-01',
    message: 'Zero-width or invisible Unicode character detected in source. This is a common technique to hide injected instructions in tool descriptions.',
    // U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM, U+2060 WORD JOINER
    pattern: /[\u200B\u200C\u200D\uFEFF\u2060]/g,
    fileTypes: ['.js', '.ts', '.py']
  },
  {
    id: 'mcp.unicode-bidi-override',
    severity: 'ERROR',
    category: 'unicode-poisoning',
    asi: 'ASI-01',
    message: 'Bidirectional text override character detected. Attackers use these to make malicious code appear differently in editors vs. execution.',
    // U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C
    pattern: /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g,
    fileTypes: ['.js', '.ts', '.py']
  },
  {
    id: 'mcp.unicode-homoglyph',
    severity: 'WARNING',
    category: 'unicode-poisoning',
    asi: 'ASI-01',
    message: 'Cyrillic character found adjacent to ASCII characters. This is a common homoglyph substitution pattern — Cyrillic letters (а, е, о, р, с) are visually identical to ASCII equivalents and used in tool name spoofing attacks.',
    // Cyrillic block (U+0400-U+04FF) adjacent to ASCII — catches common confusables (а/a, е/e, о/o, р/p, с/c)
    pattern: /[a-zA-Z][\u0400-\u04FF]|[\u0400-\u04FF][a-zA-Z]/g,
    fileTypes: ['.js', '.ts', '.py']
  },

  // ---- Category 6: Description injection ----
  {
    id: 'mcp.description-injection',
    severity: 'ERROR',
    category: 'description-injection',
    asi: 'ASI-01',
    message: 'Tool description contains imperative language directed at the LLM. This pattern is used in tool poisoning attacks to inject hidden instructions.',
    // Matches server.tool() calls where the description string contains injection phrases
    pattern: /server\.tool\s*\(\s*["'`][^"'`]*["'`]\s*,\s*["'`][^"'`]*(ignore\s+previous|exfiltrat|override\s+.*instruction|do\s+not\s+tell|hidden\s+instruction|bypass\s+.*filter|disregard\s+|extract\s+.*credential)[^"'`]*["'`]/gi,
    fileTypes: ['.js', '.ts']
  },

  // ---- Category 7: Tool name spoofing ----
  {
    id: 'mcp.tool-name-spoofing',
    severity: 'ERROR',
    category: 'tool-name-spoofing',
    asi: 'ASI-01',
    message: 'Tool name is suspiciously similar to a well-known MCP tool. This may be a name spoofing attack.',
    // Extracts the tool name (1st arg to server.tool) for Levenshtein comparison
    pattern: /server\.tool\s*\(\s*["'`]([a-zA-Z_$][\w$]*)["'`]/g,
    fileTypes: ['.js', '.ts'],
    isSpoofingRule: true
  },

  // ---- Category 8: ASI-09 Trust exploitation (MCP-specific) ----
  {
    id: 'mcp.auto-approve-config',
    severity: 'ERROR',
    category: 'trust-exploitation',
    asi: 'ASI-09',
    message: 'MCP server configured with auto-approve. All tool invocations should require user confirmation.',
    pattern: /(?:auto_?approve|autoConfirm|skip_?confirm|require_?approval\s*:\s*false)\b/gi,
    fileTypes: ['.js', '.ts', '.py']
  },

  // ---- Category 9: ASI-10 Rogue agent patterns (MCP-specific) ----
  {
    id: 'mcp.unrestricted-tool-registration',
    severity: 'WARNING',
    category: 'rogue-agents',
    asi: 'ASI-10',
    message: 'Dynamic tool registration from external input. Verify tool definitions are from trusted sources to prevent rogue tool injection.',
    pattern: /server\.tool\s*\(\s*[a-zA-Z_$][\w$.]*\s*,/g,
    fileTypes: ['.js', '.ts'],
    contextCheck: (line) => {
      // Flag when tool name is a variable (dynamic), not a string literal
      return /server\.tool\s*\(\s*[a-zA-Z_$][\w$.]*\s*,/.test(line) &&
             !/server\.tool\s*\(\s*["'`]/.test(line);
    }
  },
  {
    id: 'mcp.self-modifying-tools',
    severity: 'ERROR',
    category: 'rogue-agents',
    asi: 'ASI-10',
    message: 'MCP server modifies its own tool definitions at runtime. Self-modifying servers can become rogue.',
    pattern: /server\._tools|server\.tools\s*\[|tools\.delete\s*\(|tools\.set\s*\(/g,
    fileTypes: ['.js', '.ts']
  }
];

// ============================================================
// File collection
// ============================================================

function collectFiles(serverPath) {
  const resolvedPath = resolve(serverPath);

  if (!existsSync(resolvedPath)) {
    return [];
  }

  let stat;
  try {
    stat = statSync(resolvedPath);
  } catch {
    return [];
  }

  // If a single file is provided, return it directly
  if (stat.isFile()) {
    const ext = extname(resolvedPath).toLowerCase();
    if (SCANNABLE_EXTENSIONS.has(ext)) {
      return [resolvedPath];
    }
    return [];
  }

  // Walk the directory
  const files = [];

  function walk(dir) {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.startsWith('.')) continue;

      const fullPath = join(dir, entry);
      let entryStat;
      try {
        entryStat = statSync(fullPath);
      } catch {
        continue;
      }

      if (entryStat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        walk(fullPath);
      } else if (entryStat.isFile()) {
        const ext = extname(entry).toLowerCase();
        if (SCANNABLE_EXTENSIONS.has(ext)) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(resolvedPath);
  return files;
}

// ============================================================
// Scanning engine
// ============================================================

function scanFileContent(filePath, content) {
  const ext = extname(filePath).toLowerCase();
  const lines = content.split('\n');
  const findings = [];

  for (const rule of MCP_SECURITY_RULES) {
    // Check if rule applies to this file type
    if (!rule.fileTypes.includes(ext)) continue;

    // Reset regex state
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      // Calculate line number from match index
      const upToMatch = content.substring(0, match.index);
      const lineNumber = upToMatch.split('\n').length;
      const lineIndex = lineNumber - 1;

      // If rule has a context check, apply it
      if (rule.contextCheck) {
        const line = lines[lineIndex] || '';
        if (!rule.contextCheck(line, lines, lineIndex)) {
          continue;
        }
      }

      // Handle spoofing rules: extract tool name and check Levenshtein distance
      if (rule.isSpoofingRule) {
        const toolName = match[1];
        if (!toolName) continue;
        const spoof = findSpoofedTool(toolName);
        if (!spoof) continue;
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          category: rule.category,
          message: `Tool name "${toolName}" is ${spoof.distance} edit(s) away from well-known tool "${spoof.spoofed}". This may be a spoofing attack.`,
          file: filePath,
          line: lineNumber,
          match: match[0].substring(0, 100)
        });
        continue;
      }

      findings.push({
        rule: rule.id,
        severity: rule.severity,
        category: rule.category,
        message: rule.message,
        file: filePath,
        line: lineNumber,
        match: match[0].substring(0, 100) // Truncate long matches
      });
    }
  }

  return findings;
}

// ============================================================
// Grading
// ============================================================

function calculateGrade(findings, filesScanned) {
  if (filesScanned === 0) return 'A';

  const errorCount = findings.filter(f => f.severity === 'ERROR').length;
  const warningCount = findings.filter(f => f.severity === 'WARNING').length;
  const totalCount = findings.length;
  const density = totalCount / filesScanned;

  if (errorCount === 0 && warningCount === 0) return 'A';
  if (errorCount === 0 && density < 0.5) return 'B';
  if (errorCount <= 2 && density < 1.5) return 'C';
  if (errorCount <= 5 && density < 3) return 'D';
  return 'F';
}

// ============================================================
// Recommendations generator
// ============================================================

function generateRecommendations(findings) {
  const recommendations = [];
  const categories = new Set(findings.map(f => f.category));

  if (categories.has('overly-broad-permissions')) {
    recommendations.push('Replace exec/execSync with execFile/execFileSync and pass arguments as arrays with shell:false.');
    recommendations.push('Validate and confine file paths using path.resolve() and an allowlist of permitted directories.');
  }

  if (categories.has('missing-input-validation')) {
    recommendations.push('Add input validation using zod schemas for all tool parameters (strings, paths, URLs).');
    recommendations.push('Normalize file paths with path.resolve() and validate they stay within allowed directories.');
  }

  if (categories.has('data-exfiltration')) {
    recommendations.push('Audit all outbound network requests. MCP servers should not send data to external endpoints without user consent.');
    recommendations.push('Avoid logging sensitive values (keys, tokens, passwords) to stderr or stdout.');
  }

  if (categories.has('insecure-patterns')) {
    recommendations.push('Remove all uses of eval() and new Function(). Use structured data parsing instead.');
    if (findings.some(f => f.rule.includes('cors'))) {
      recommendations.push('Configure CORS with specific allowed origins rather than wildcards.');
    }
    if (findings.some(f => f.rule.includes('auth'))) {
      recommendations.push('Add authentication for network-accessible MCP servers (e.g., bearer tokens, API keys).');
    }
  }

  if (categories.has('unicode-poisoning')) {
    if (findings.some(f => f.rule === 'mcp.unicode-zero-width')) {
      recommendations.push('Zero-width Unicode characters detected. Search for and remove U+200B, U+200C, U+200D, U+FEFF, U+2060 from all tool names and descriptions — these are used to hide injected instructions.');
    }
    if (findings.some(f => f.rule === 'mcp.unicode-bidi-override')) {
      recommendations.push('Bidirectional override characters detected. These make source code appear differently in text editors than how it executes — a known code obfuscation technique. Remove all bidi formatting characters from source.');
    }
    if (findings.some(f => f.rule === 'mcp.unicode-homoglyph' || f.rule === 'mcp.manifest-name-spoofing')) {
      recommendations.push('Cyrillic homoglyph characters detected adjacent to ASCII. Verify all tool names use only ASCII characters to prevent visual spoofing of legitimate tool names (Adversa TOP25 #9).');
    }
  }

  if (categories.has('description-injection')) {
    recommendations.push('Tool descriptions must describe functionality only. Remove any imperative language or instructions directed at the LLM — this is a tool poisoning attack vector (Adversa TOP25 #2).');
  }

  if (categories.has('tool-name-spoofing')) {
    recommendations.push('Tool names closely matching well-known MCP tools may be spoofing attacks. Verify all registered tool names are intentional and do not mimic legitimate tools (Adversa TOP25 #9).');
  }

  if (categories.has('rug-pull')) {
    recommendations.push('Tool schema changed since baseline. Run with update_baseline:true only after manually verifying all changes. Rug pull attacks modify tool behavior after initial user approval (Adversa TOP25 #6).');
  }

  if (recommendations.length === 0) {
    recommendations.push('No critical issues found. Continue following security best practices.');
  }

  return recommendations;
}

// ============================================================
// Verbosity formatters
// ============================================================

function formatMinimal(serverPath, filesScanned, findings, grade) {
  const bySeverity = { ERROR: 0, WARNING: 0, INFO: 0 };
  findings.forEach(f => bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1);

  return {
    server_path: serverPath,
    files_scanned: filesScanned,
    grade,
    findings_count: findings.length,
    critical: bySeverity.ERROR,
    warning: bySeverity.WARNING,
    info: bySeverity.INFO,
    message: findings.length > 0
      ? `Found ${findings.length} issue(s) across ${filesScanned} files. Grade: ${grade}`
      : `No issues found in ${filesScanned} files. Grade: ${grade}`
  };
}

function formatCompact(serverPath, filesScanned, findings, grade) {
  const recommendations = generateRecommendations(findings);

  return {
    server_path: serverPath,
    files_scanned: filesScanned,
    grade,
    findings_count: findings.length,
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      message: f.message,
      file: f.file,
      line: f.line
    })),
    recommendations
  };
}

function formatFull(serverPath, filesScanned, findings, grade, scannedFiles) {
  const bySeverity = { ERROR: 0, WARNING: 0, INFO: 0 };
  findings.forEach(f => bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1);

  const byCategory = {};
  findings.forEach(f => {
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  });

  const byFile = {};
  findings.forEach(f => {
    const rel = f.file;
    byFile[rel] = (byFile[rel] || 0) + 1;
  });

  const recommendations = generateRecommendations(findings);

  return {
    server_path: serverPath,
    files_scanned: filesScanned,
    grade,
    findings_count: findings.length,
    by_severity: bySeverity,
    by_category: byCategory,
    by_file: byFile,
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      category: f.category,
      message: f.message,
      file: f.file,
      line: f.line,
      match: f.match
    })),
    recommendations,
    scanned_files: scannedFiles
  };
}

// ============================================================
// Rug pull detection (baseline hashing)
// ============================================================

const BASELINE_FILENAME = '.mcp-security-baseline.json';

function hashTool(tool) {
  return createHash('sha256')
    .update(JSON.stringify({ name: tool.name, description: tool.description }))
    .digest('hex');
}

function buildBaseline(manifestPath) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  } catch {
    return null;
  }
  const hashes = {};
  for (const tool of (manifest.tools || [])) {
    hashes[tool.name] = hashTool(tool);
  }
  return hashes;
}

function writeBaseline(serverDir, hashes) {
  const baselinePath = join(serverDir, BASELINE_FILENAME);
  writeFileSync(baselinePath, JSON.stringify({ version: 1, tools: hashes }, null, 2), 'utf-8');
}

function checkRugPull(manifestPath, serverDir) {
  const baselinePath = join(serverDir, BASELINE_FILENAME);
  if (!existsSync(baselinePath)) return []; // no baseline yet

  let baseline;
  try {
    baseline = JSON.parse(readFileSync(baselinePath, 'utf-8'));
  } catch {
    return [];
  }

  const current = buildBaseline(manifestPath);
  if (!current) return [];

  const baselineHashes = baseline.tools || {};
  const findings = [];

  for (const [name, hash] of Object.entries(current)) {
    if (!baselineHashes[name]) {
      findings.push({
        rule: 'mcp.rug-pull-detected',
        severity: 'ERROR',
        category: 'rug-pull',
        message: `New tool "${name}" appeared since baseline was recorded. Verify this addition is intentional (Adversa TOP25 #6).`,
        file: basename(BASELINE_FILENAME),
        line: 1,
        match: name
      });
    } else if (baselineHashes[name] !== hash) {
      findings.push({
        rule: 'mcp.rug-pull-detected',
        severity: 'ERROR',
        category: 'rug-pull',
        message: `Tool "${name}" schema/description changed since baseline. Rug pull indicator — verify the change is intentional (Adversa TOP25 #6).`,
        file: basename(BASELINE_FILENAME),
        line: 1,
        match: name
      });
    }
  }

  // Also flag tools that were in the baseline but are now gone
  for (const [name] of Object.entries(baselineHashes)) {
    if (!current[name]) {
      findings.push({
        rule: 'mcp.rug-pull-detected',
        severity: 'ERROR',
        category: 'rug-pull',
        message: `Tool "${name}" was removed since baseline was recorded. Verify this removal is intentional (Adversa TOP25 #6).`,
        file: basename(BASELINE_FILENAME),
        line: 1,
        match: name
      });
    }
  }

  return findings;
}

// ============================================================
// Manifest scanning (server.json)
// ============================================================

function scanManifest(manifestPath) {
  let raw;
  try {
    raw = readFileSync(manifestPath, 'utf-8');
  } catch {
    return [];
  }

  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch {
    return [{ rule: 'mcp.manifest-parse-error', severity: 'WARNING', category: 'manifest', message: 'server.json is not valid JSON.', file: manifestPath, line: 1, match: '' }];
  }

  const findings = [];
  const tools = manifest.tools || [];

  for (const tool of tools) {
    const name = tool.name || '';
    const description = tool.description || '';

    // Zero-width chars in name or description
    if (MANIFEST_ZERO_WIDTH.test(description) || MANIFEST_ZERO_WIDTH.test(name)) {
      findings.push({ rule: 'mcp.unicode-zero-width', severity: 'ERROR', category: 'unicode-poisoning', message: 'Zero-width Unicode character in manifest tool name or description.', file: manifestPath, line: 1, match: name });
    }
    // Bidi overrides
    if (MANIFEST_BIDI.test(description) || MANIFEST_BIDI.test(name)) {
      findings.push({ rule: 'mcp.unicode-bidi-override', severity: 'ERROR', category: 'unicode-poisoning', message: 'Bidirectional override character in manifest tool name or description.', file: manifestPath, line: 1, match: name });
    }
    // Description injection phrases
    if (MANIFEST_INJECTION_PHRASES.test(description)) {
      findings.push({ rule: 'mcp.manifest-description-injection', severity: 'ERROR', category: 'description-injection', message: `Tool "${name}" description contains injection language. Likely tool poisoning (Adversa TOP25 #2).`, file: manifestPath, line: 1, match: description.substring(0, 100) });
    }
    // Tool name spoofing
    if (name) {
      const spoof = findSpoofedTool(name);
      if (spoof) {
        findings.push({ rule: 'mcp.manifest-name-spoofing', severity: 'ERROR', category: 'tool-name-spoofing', message: `Manifest tool name "${name}" is ${spoof.distance} edit(s) away from well-known tool "${spoof.spoofed}" (Adversa TOP25 #9).`, file: manifestPath, line: 1, match: name });
      }
    }
    // Suspiciously long description
    if (description.length > 500) {
      findings.push({ rule: 'mcp.manifest-description-too-long', severity: 'WARNING', category: 'description-injection', message: `Tool "${name}" description is ${description.length} chars — unusually long descriptions often contain hidden instructions.`, file: manifestPath, line: 1, match: description.substring(0, 100) });
    }
  }

  return findings;
}

// ============================================================
// Main handler
// ============================================================

export async function scanMcpServer({ server_path, verbosity, manifest, update_baseline }) {
  const resolvedPath = resolve(server_path);

  if (!existsSync(resolvedPath)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "Server path not found", server_path }) }]
    };
  }

  // Compute once; used in multiple places below
  const isDir = statSync(resolvedPath).isDirectory();

  // Collect files to scan
  const files = collectFiles(resolvedPath);

  if (files.length === 0 && !manifest) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        server_path: resolvedPath,
        files_scanned: 0,
        grade: 'A',
        findings_count: 0,
        message: "No scannable files (.js, .ts, .py) found at the given path."
      }) }]
    };
  }

  // Scan each file
  const allFindings = [];

  // Manifest scan (server.json) — when manifest:true is passed
  if (manifest) {
    const serverDir = isDir ? resolvedPath : resolve(resolvedPath, '..');
    const manifestPath = join(serverDir, 'server.json');
    if (existsSync(manifestPath)) {
      // Update baseline if requested (do this BEFORE checking for rug pull)
      if (update_baseline) {
        const hashes = buildBaseline(manifestPath);
        if (hashes) writeBaseline(serverDir, hashes);
      }

      const manifestFindings = scanManifest(manifestPath);
      // Relativize manifest finding paths
      for (const f of manifestFindings) {
        f.file = relative(serverDir, f.file) || basename(f.file);
      }
      allFindings.push(...manifestFindings);

      // Rug pull check (only when NOT writing baseline)
      if (!update_baseline) {
        const rugPullFindings = checkRugPull(manifestPath, serverDir);
        // BASELINE_FILENAME is already relative, no need to relativize
        allFindings.push(...rugPullFindings);
      }
    }
  }

  for (const filePath of files) {
    let content;
    try {
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const fileFindings = scanFileContent(filePath, content);

    // Convert absolute paths to relative for output readability
    const basePath = isDir ? resolvedPath : resolve(resolvedPath, '..');
    for (const finding of fileFindings) {
      finding.file = relative(basePath, finding.file) || basename(finding.file);
    }

    allFindings.push(...fileFindings);
  }

  // Deduplicate findings (same rule + same file + same line)
  const seen = new Set();
  const dedupedFindings = allFindings.filter(f => {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity (ERROR first, then WARNING, then INFO)
  const severityOrder = { ERROR: 0, WARNING: 1, INFO: 2 };
  dedupedFindings.sort((a, b) => (severityOrder[a.severity] ?? 2) - (severityOrder[b.severity] ?? 2));

  // When manifest-only scan has findings, count it as 1 "file" for grading purposes
  const effectiveFilesScanned = files.length + (manifest && dedupedFindings.length > 0 ? 1 : 0);
  const grade = calculateGrade(dedupedFindings, effectiveFilesScanned);
  const level = verbosity || 'compact';

  // Relativize scanned file list
  const basePath = isDir ? resolvedPath : resolve(resolvedPath, '..');
  const scannedFiles = files.map(f => relative(basePath, f) || basename(f));

  let result;
  switch (level) {
    case 'minimal':
      result = formatMinimal(resolvedPath, effectiveFilesScanned, dedupedFindings, grade);
      break;
    case 'full':
      result = formatFull(resolvedPath, effectiveFilesScanned, dedupedFindings, grade, scannedFiles);
      break;
    case 'compact':
    default:
      result = formatCompact(resolvedPath, effectiveFilesScanned, dedupedFindings, grade);
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
