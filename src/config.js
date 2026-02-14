// .scannerrc configuration loading and filtering.
// Supports YAML (.scannerrc.yaml/.yml) and JSON (.scannerrc.json) project configs.

import { existsSync, readFileSync } from 'fs';
import { dirname, join, resolve, sep } from 'path';
import { execFileSync } from 'child_process';

const DEFAULT_CONFIG = {
  version: 1,
  suppress: [],
  exclude: ['node_modules/**', 'vendor/**', 'dist/**', '**/*.min.js'],
  severity_threshold: 'info',
  confidence_threshold: 'LOW',
  policy: {
    block_on: 'error',       // severity that causes a policy failure: 'error', 'warning', 'info'
    max_critical: null,       // max allowed critical issues (null = no limit)
    max_warning: null,        // max allowed warnings (null = no limit)
    required_grade: null,     // minimum required grade: 'A', 'B', 'C', 'D', 'F' (null = no requirement)
  },
};

const SEVERITY_ORDER = { info: 0, warning: 1, error: 2 };
const CONFIDENCE_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2 };

// Simple glob-to-regex converter (no external dependency)
function globToRegex(pattern) {
  let regex = '';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        if (pattern[i + 2] === '/') {
          regex += '(?:.+/)?';
          i += 3;
          continue;
        }
        regex += '.*';
        i += 2;
        continue;
      }
      regex += '[^/]*';
    } else if (c === '?') {
      regex += '[^/]';
    } else if (c === '{') {
      regex += '(?:';
    } else if (c === '}') {
      regex += ')';
    } else if (c === ',') {
      regex += '|';
    } else if ('.+^$|()[]\\'.includes(c)) {
      regex += '\\' + c;
    } else {
      regex += c;
    }
    i++;
  }
  return new RegExp('^' + regex + '$');
}

export function matchGlob(filePath, pattern) {
  // Normalize path separators
  const normalized = filePath.replace(/\\/g, '/');
  const re = globToRegex(pattern);
  // Test against both full path and basename
  return re.test(normalized) || re.test(normalized.split('/').pop());
}

// Walk up from filePath to find config file
function findConfigFile(startPath) {
  const names = ['.scannerrc.yaml', '.scannerrc.yml', '.scannerrc.json'];
  let dir = resolve(dirname(startPath));
  const root = resolve('/');

  for (let i = 0; i < 50; i++) {
    for (const name of names) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir || dir === root) break;
    dir = parent;
  }
  return null;
}

function parseYaml(filePath) {
  try {
    const result = execFileSync('python3', [
      '-c',
      'import yaml,json,sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))',
      filePath,
    ], { encoding: 'utf-8', timeout: 5000 });
    return JSON.parse(result.trim());
  } catch {
    // Fallback: try simple key-value parsing for basic configs
    return null;
  }
}

export function loadConfig(filePath) {
  const configFile = findConfigFile(filePath);
  if (!configFile) return { ...DEFAULT_CONFIG };

  try {
    let parsed;
    if (configFile.endsWith('.json')) {
      parsed = JSON.parse(readFileSync(configFile, 'utf-8'));
    } else {
      parsed = parseYaml(configFile);
    }

    if (!parsed || typeof parsed !== 'object') return { ...DEFAULT_CONFIG };

    const parsedPolicy = parsed.policy && typeof parsed.policy === 'object' ? parsed.policy : {};
    return {
      version: parsed.version || DEFAULT_CONFIG.version,
      suppress: Array.isArray(parsed.suppress) ? parsed.suppress : DEFAULT_CONFIG.suppress,
      exclude: Array.isArray(parsed.exclude) ? parsed.exclude : DEFAULT_CONFIG.exclude,
      severity_threshold: parsed.severity_threshold || DEFAULT_CONFIG.severity_threshold,
      confidence_threshold: parsed.confidence_threshold || DEFAULT_CONFIG.confidence_threshold,
      policy: {
        block_on: parsedPolicy.block_on || DEFAULT_CONFIG.policy.block_on,
        max_critical: parsedPolicy.max_critical ?? DEFAULT_CONFIG.policy.max_critical,
        max_warning: parsedPolicy.max_warning ?? DEFAULT_CONFIG.policy.max_warning,
        required_grade: parsedPolicy.required_grade ?? DEFAULT_CONFIG.policy.required_grade,
      },
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function shouldExcludeFile(filePath, config) {
  if (!config.exclude || config.exclude.length === 0) return false;
  const normalized = filePath.replace(/\\/g, '/');
  return config.exclude.some(pattern => matchGlob(normalized, pattern));
}

export function shouldSuppressRule(ruleId, filePath, config) {
  if (!config.suppress || config.suppress.length === 0) return false;

  for (const entry of config.suppress) {
    const rule = typeof entry === 'string' ? entry : entry.rule;
    if (!rule) continue;

    // Check if rule pattern matches
    const ruleMatches = matchGlob(ruleId, rule);
    if (!ruleMatches) continue;

    // Check path restriction if present
    if (entry.paths && Array.isArray(entry.paths)) {
      const normalized = filePath.replace(/\\/g, '/');
      const pathMatches = entry.paths.some(p => matchGlob(normalized, p));
      if (!pathMatches) continue;
    }

    return true;
  }

  return false;
}

export function meetsSeverityThreshold(severity, config) {
  const threshold = config.severity_threshold || 'info';
  const severityLevel = SEVERITY_ORDER[severity] ?? 0;
  const thresholdLevel = SEVERITY_ORDER[threshold] ?? 0;
  return severityLevel >= thresholdLevel;
}

export function meetsConfidenceThreshold(confidence, config) {
  const threshold = config.confidence_threshold || 'LOW';
  const confidenceLevel = CONFIDENCE_ORDER[confidence] ?? 0;
  const thresholdLevel = CONFIDENCE_ORDER[threshold] ?? 0;
  return confidenceLevel >= thresholdLevel;
}

const GRADE_ORDER = { A: 4, B: 3, C: 2, D: 1, F: 0 };

export function evaluatePolicy(scanResult, config) {
  const violations = [];
  const policy = config && config.policy ? config.policy : DEFAULT_CONFIG.policy;

  // Check block_on severity
  const blockOn = policy.block_on || 'error';
  const severityKeys = [];
  if (blockOn === 'info') severityKeys.push('info', 'warning', 'error');
  else if (blockOn === 'warning') severityKeys.push('warning', 'error');
  else severityKeys.push('error');

  const bySeverity = scanResult.by_severity || {};
  for (const key of severityKeys) {
    if ((bySeverity[key] || 0) > 0) {
      violations.push(`Policy violation: found ${bySeverity[key]} ${key} issue(s) (block_on: ${blockOn})`);
      break;
    }
  }

  // Check max_critical
  if (policy.max_critical !== null && policy.max_critical !== undefined) {
    const criticalCount = bySeverity.error || 0;
    if (criticalCount > policy.max_critical) {
      violations.push(`Policy violation: ${criticalCount} critical issue(s) exceeds max_critical (${policy.max_critical})`);
    }
  }

  // Check max_warning
  if (policy.max_warning !== null && policy.max_warning !== undefined) {
    const warningCount = bySeverity.warning || 0;
    if (warningCount > policy.max_warning) {
      violations.push(`Policy violation: ${warningCount} warning(s) exceeds max_warning (${policy.max_warning})`);
    }
  }

  // Check required_grade
  if (policy.required_grade) {
    const actualGrade = scanResult.grade || 'A';
    const requiredLevel = GRADE_ORDER[policy.required_grade] ?? 0;
    const actualLevel = GRADE_ORDER[actualGrade] ?? 0;
    if (actualLevel < requiredLevel) {
      violations.push(`Policy violation: grade ${actualGrade} does not meet required_grade (${policy.required_grade})`);
    }
  }

  return {
    passed: violations.length === 0,
    violations,
  };
}

export function applyConfig(findings, filePath, config) {
  if (!Array.isArray(findings)) return findings;
  if (!config) return findings;

  return findings.filter(finding => {
    // Check rule suppression
    if (shouldSuppressRule(finding.ruleId, filePath, config)) return false;

    // Check severity threshold
    if (!meetsSeverityThreshold(finding.severity, config)) return false;

    // Check confidence threshold
    if (!meetsConfidenceThreshold(finding.confidence || 'MEDIUM', config)) return false;

    return true;
  });
}
