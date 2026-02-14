// src/tools/scan-mcp.js
import { z } from "zod";
import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, resolve, relative, extname, basename } from "path";

export const scanMcpServerSchema = {
  server_path: z.string().describe("Path to MCP server directory or entry file"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (counts only), 'compact' (default, actionable info), 'full' (complete metadata)")
};

// File extensions to scan
const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.py']);

// Directories to skip when walking
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__',
  'venv', 'env', '.venv', 'coverage', '.next', '.nuxt'
]);

// ============================================================
// Security rule definitions for MCP server scanning
// ============================================================

const MCP_SECURITY_RULES = [
  // ---- Category 1: Overly broad tool permissions ----
  {
    id: 'mcp.shell-exec-no-validation',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    message: 'Shell command execution without input validation. User-controlled input may reach exec/execSync, enabling arbitrary command execution.',
    pattern: /\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|['"][^'"]*['"]\s*\+|[a-zA-Z_$][\w$]*(\s*\+|\s*,\s*\{[^}]*shell\s*:\s*true))/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.shell-exec-direct',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    message: 'Direct use of exec/execSync with potential string concatenation. Prefer execFile/execFileSync with explicit argument arrays and shell:false.',
    pattern: /\bchild_process\b.*\b(exec|execSync)\b|\b(exec|execSync)\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.spawn-shell-true',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    message: 'spawn/spawnSync called with shell:true, allowing shell injection. Use shell:false and pass arguments as an array.',
    pattern: /\b(spawn|spawnSync)\s*\([^)]*\{[^}]*shell\s*:\s*true/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.subprocess-shell',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    message: 'subprocess called with shell=True, allowing shell injection. Use shell=False with a command list.',
    pattern: /subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.os-system',
    severity: 'ERROR',
    category: 'overly-broad-permissions',
    message: 'os.system() executes commands through the shell. Use subprocess with shell=False instead.',
    pattern: /\bos\.system\s*\(/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.fs-write-no-path-validation',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    message: 'Filesystem write operation without visible path validation. Ensure paths are validated with path.resolve and confined to an allowed directory.',
    pattern: /\b(writeFileSync|writeFile|createWriteStream|appendFileSync|appendFile)\s*\(\s*[a-zA-Z_$][\w$.]*(?!\s*(?:path\.resolve|path\.join|path\.normalize))/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.http-request-user-url',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    message: 'HTTP request to a potentially user-controlled URL. Validate and allowlist target URLs to prevent SSRF.',
    pattern: /\b(fetch|axios\.(get|post|put|delete|request)|http\.request|https\.request|got|request)\s*\(\s*[a-zA-Z_$][\w$.]*(?!\s*['"`])/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.env-var-exposure',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    message: 'Environment variables accessed and potentially exposed in tool output. Ensure secrets are not leaked through MCP responses.',
    pattern: /process\.env\b/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.env-var-exposure-python',
    severity: 'WARNING',
    category: 'overly-broad-permissions',
    message: 'Environment variables accessed and potentially exposed in tool output. Ensure secrets are not leaked through MCP responses.',
    pattern: /os\.environ\b|os\.getenv\s*\(/g,
    fileTypes: ['.py']
  },

  // ---- Category 2: Missing input validation ----
  {
    id: 'mcp.no-input-validation',
    severity: 'WARNING',
    category: 'missing-input-validation',
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
    message: 'Data sent to an external URL. MCP servers should not exfiltrate data to third-party endpoints without explicit user consent.',
    pattern: /\b(fetch|axios\.(post|put|patch)|http\.request|https\.request)\s*\(\s*['"`](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^'"` ]+)['"`]/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exfiltration-external-request-python',
    severity: 'ERROR',
    category: 'data-exfiltration',
    message: 'Data sent to an external URL. MCP servers should not exfiltrate data to third-party endpoints without explicit user consent.',
    pattern: /\b(requests\.(post|put|patch)|urllib\.request\.urlopen|httpx\.(post|put|patch))\s*\(\s*['"`](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^'"` ]+)['"`]/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.exfiltration-network-socket',
    severity: 'WARNING',
    category: 'data-exfiltration',
    message: 'Network socket created. Verify this is not used to exfiltrate data to external hosts.',
    pattern: /\bnet\.(createConnection|connect|Socket)\s*\(|new\s+WebSocket\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exfiltration-log-secrets',
    severity: 'WARNING',
    category: 'data-exfiltration',
    message: 'Potentially sensitive data (keys, tokens, passwords) logged or printed. This may leak secrets through MCP server stderr.',
    pattern: /\b(console\.(log|error|warn|info)|print|logging\.(info|warning|error|debug))\s*\([^)]*\b(key|token|password|secret|credential|api_key|apiKey|auth|bearer)\b/gi,
    fileTypes: ['.js', '.ts', '.py']
  },

  // ---- Category 4: Insecure code patterns ----
  {
    id: 'mcp.eval-usage',
    severity: 'ERROR',
    category: 'insecure-patterns',
    message: 'eval() executes arbitrary code. Never use eval with user-controlled input in an MCP server.',
    pattern: /\beval\s*\(/g,
    fileTypes: ['.js', '.ts', '.py']
  },
  {
    id: 'mcp.function-constructor',
    severity: 'ERROR',
    category: 'insecure-patterns',
    message: 'new Function() is equivalent to eval(). Avoid constructing functions from strings.',
    pattern: /new\s+Function\s*\(/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.exec-string-concat',
    severity: 'ERROR',
    category: 'insecure-patterns',
    message: 'child_process.exec() with string concatenation is vulnerable to command injection. Use execFile() with argument arrays.',
    pattern: /\bexec\s*\(\s*['"`][^'"`]*['"`]\s*\+/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.cors-wildcard',
    severity: 'WARNING',
    category: 'insecure-patterns',
    message: 'CORS configured with wildcard origin (*). This allows any website to interact with the MCP server.',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.cors-permissive',
    severity: 'INFO',
    category: 'insecure-patterns',
    message: 'CORS enabled. Verify the origin configuration is appropriately restrictive.',
    pattern: /\bcors\s*\(\s*\)/g,
    fileTypes: ['.js', '.ts']
  },
  {
    id: 'mcp.no-auth-check',
    severity: 'INFO',
    category: 'insecure-patterns',
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
    message: 'pickle.load/loads deserializes arbitrary Python objects. This can execute arbitrary code if the input is attacker-controlled.',
    pattern: /\bpickle\.(load|loads)\s*\(/g,
    fileTypes: ['.py']
  },
  {
    id: 'mcp.yaml-unsafe-load',
    severity: 'ERROR',
    category: 'insecure-patterns',
    message: 'yaml.load() without SafeLoader can execute arbitrary Python. Use yaml.safe_load() instead.',
    pattern: /\byaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
    fileTypes: ['.py']
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
// Main handler
// ============================================================

export async function scanMcpServer({ server_path, verbosity }) {
  const resolvedPath = resolve(server_path);

  if (!existsSync(resolvedPath)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "Server path not found", server_path }) }]
    };
  }

  // Collect files to scan
  const files = collectFiles(resolvedPath);

  if (files.length === 0) {
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

  for (const filePath of files) {
    let content;
    try {
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const fileFindings = scanFileContent(filePath, content);

    // Convert absolute paths to relative for output readability
    const basePath = statSync(resolvedPath).isDirectory() ? resolvedPath : resolve(resolvedPath, '..');
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

  const grade = calculateGrade(dedupedFindings, files.length);
  const level = verbosity || 'compact';

  // Relativize scanned file list
  const basePath = statSync(resolvedPath).isDirectory() ? resolvedPath : resolve(resolvedPath, '..');
  const scannedFiles = files.map(f => relative(basePath, f) || basename(f));

  let result;
  switch (level) {
    case 'minimal':
      result = formatMinimal(resolvedPath, files.length, dedupedFindings, grade);
      break;
    case 'full':
      result = formatFull(resolvedPath, files.length, dedupedFindings, grade, scannedFiles);
      break;
    case 'compact':
    default:
      result = formatCompact(resolvedPath, files.length, dedupedFindings, grade);
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
