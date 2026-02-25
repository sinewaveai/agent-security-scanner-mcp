// Cross-engine deduplication for security findings.
// When AST and regex engines flag the same vulnerability on the same line
// with different ruleIds, this module merges them into a single finding.

// Maps ruleId substrings to vulnerability classes for cross-engine dedup.
// Order matters: more specific patterns must come before generic ones.
const VULN_CLASS_PATTERNS = [
  // XSS variants
  ['innerhtml', 'xss-innerhtml'],
  ['outerhtml', 'xss-outerhtml'],
  ['document-write', 'xss-document-write'],
  ['document.write', 'xss-document-write'],
  ['insertadjacenthtml', 'xss-insertadjacenthtml'],
  ['dangerouslysetinnerhtml', 'xss-dangerouslysetinnerhtml'],
  ['mustache-escape', 'xss-innerhtml'],
  ['insecure-document-method', 'xss-document-write'],
  ['dom-based-xss', 'xss-dom'],
  ['xss-echo', 'xss-echo'],
  ['xss-raw', 'xss-raw'],
  ['xss-response-write', 'xss-response-write'],

  // SQL Injection
  ['sql-injection', 'sqli'],
  ['nosql-injection', 'nosqli'],

  // Command Injection
  ['child-process-exec', 'cmdi-exec'],
  ['spawn-shell', 'cmdi-spawn'],
  ['dangerous-subprocess', 'cmdi-subprocess'],
  ['dangerous-system-call', 'cmdi-system'],
  ['command-injection', 'cmdi'],
  ['backticks-exec', 'cmdi-backticks'],
  ['libc-system-call', 'cmdi-libc'],

  // Code Injection
  ['eval-detected', 'code-eval'],
  ['eval-usage', 'code-eval'],
  ['exec-detected', 'code-exec'],
  ['function-constructor', 'code-function-constructor'],

  // Deserialization
  ['pickle-load', 'deser-pickle'],
  ['unsafe-unserialize', 'deser-unserialize'],
  ['unsafe-yaml-load', 'deser-yaml'],
  ['yaml-load', 'deser-yaml'],
  ['unsafe-marshal', 'deser-marshal'],
  ['insecure-deserialization', 'deser'],

  // Crypto
  ['md5', 'weak-hash-md5'],
  ['sha1', 'weak-hash-sha1'],
  ['insecure-hash', 'weak-hash'],
  ['weak-hash', 'weak-hash'],
  ['weak-cipher', 'weak-cipher'],

  // Secrets
  ['hardcoded-password', 'hardcoded-password'],
  ['hardcoded-secret', 'hardcoded-secret'],
  ['hardcoded-api-key', 'hardcoded-api-key'],
  ['hardcoded-connection-string', 'hardcoded-connection-string'],

  // Path traversal
  ['path-traversal', 'path-traversal'],

  // SSL
  ['ssl-verify-disabled', 'ssl-verify-disabled'],

  // Random
  ['insecure-random', 'insecure-random'],
  ['weak-random', 'weak-random'],
];

// Engine priority (higher = more trusted analysis)
const ENGINE_PRIORITY = {
  'taint': 3,
  'ast': 2,
  'regex': 1,
  'regex-fallback': 0,
};

const SEVERITY_ORDER = { error: 3, warning: 2, info: 1 };

export function classifyFinding(ruleId) {
  const lower = ruleId.toLowerCase();
  for (const [pattern, vulnClass] of VULN_CLASS_PATTERNS) {
    if (lower.includes(pattern)) return vulnClass;
  }
  return lower;
}

export function deduplicateFindings(findings) {
  if (!Array.isArray(findings)) return findings;

  // Group by (vulnClass, line)
  const groups = new Map();
  for (const finding of findings) {
    const vulnClass = classifyFinding(finding.ruleId);
    const key = `${vulnClass}:${finding.line}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }

  const deduped = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      deduped.push(group[0]);
      continue;
    }

    // Sort by engine priority (highest first)
    group.sort((a, b) =>
      (ENGINE_PRIORITY[b.engine] || 0) - (ENGINE_PRIORITY[a.engine] || 0)
    );

    const best = { ...group[0] };

    // Preserve highest severity across group
    for (const f of group) {
      if ((SEVERITY_ORDER[f.severity] || 0) > (SEVERITY_ORDER[best.severity] || 0)) {
        best.severity = f.severity;
      }
    }

    best.engines_matched = [...new Set(group.map(f => f.engine))];
    deduped.push(best);
  }

  return deduped;
}
