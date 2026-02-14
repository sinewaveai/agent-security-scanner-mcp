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

    return {
      version: parsed.version || DEFAULT_CONFIG.version,
      suppress: Array.isArray(parsed.suppress) ? parsed.suppress : DEFAULT_CONFIG.suppress,
      exclude: Array.isArray(parsed.exclude) ? parsed.exclude : DEFAULT_CONFIG.exclude,
      severity_threshold: parsed.severity_threshold || DEFAULT_CONFIG.severity_threshold,
      confidence_threshold: parsed.confidence_threshold || DEFAULT_CONFIG.confidence_threshold,
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
