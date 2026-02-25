// src/regex-engine.js
// Pure JavaScript regex-based security scanner
// Replaces analyzer.py + regex_fallback.py for lightweight, zero-Python operation

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// Handle both ESM and CJS bundling
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

const RULES_DIR = join(__dirname, '..', 'rules');

// In-memory cache for parsed rules
const _rulesCache = new Map();
const _rulesByLanguage = new Map();

/**
 * Parse a single YAML rule file into JavaScript objects
 * Minimal YAML parser - handles the subset used in our security rules
 */
export function parseRulesYaml(yamlContent) {
  const rules = [];
  const lines = yamlContent.split('\n');
  let currentRule = null;
  let currentKey = null;
  let inPatterns = false;
  let inMetadata = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (trimmed.startsWith('#') || trimmed === '') continue;

    // Start of new rule (- id: ...)
    if (trimmed.startsWith('- id:')) {
      if (currentRule) {
        rules.push(currentRule);
      }
      currentRule = {
        id: trimmed.substring(5).trim(),
        languages: [],
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };
      inPatterns = false;
      inMetadata = false;
      continue;
    }

    if (!currentRule) continue;

    // Languages array: languages: [python, javascript]
    if (trimmed.startsWith('languages:')) {
      const langMatch = trimmed.match(/languages:\s*\[(.*?)\]/);
      if (langMatch) {
        currentRule.languages = langMatch[1].split(',').map(l => l.trim());
      }
      continue;
    }

    // Severity: ERROR|WARNING|INFO
    if (trimmed.startsWith('severity:')) {
      currentRule.severity = trimmed.substring(9).trim();
      continue;
    }

    // Message (handle multi-line messages with >- YAML syntax)
    if (trimmed.startsWith('message:')) {
      let messageValue = trimmed.substring(8).trim();

      // Handle YAML folded scalar (>- means strip trailing newlines)
      if (messageValue === '>-' || messageValue === '>' || messageValue === '|-' || messageValue === '|') {
        // Multi-line message - collect following indented lines
        let messageLines = [];
        for (let j = i + 1; j < lines.length; j++) {
          const nextLine = lines[j];
          if (nextLine.trim() && !nextLine.startsWith(' ')) {
            break; // End of message
          }
          if (nextLine.trim()) {
            messageLines.push(nextLine.trim());
          }
        }
        currentRule.message = messageLines.join(' ');
      } else {
        currentRule.message = messageValue.replace(/^["']|["']$/g, '');
      }
      continue;
    }

    // Patterns section start
    if (trimmed === 'patterns:') {
      inPatterns = true;
      inMetadata = false;
      continue;
    }

    // Metadata section start
    if (trimmed === 'metadata:') {
      inMetadata = true;
      inPatterns = false;
      continue;
    }

    // Pattern entries (- "pattern" or - 'pattern')
    if (inPatterns && trimmed.startsWith('-')) {
      let pattern = trimmed.substring(1).trim().replace(/^["']|["']$/g, '');
      // Unescape YAML double-backslashes: \\b -> \b, \\s -> \s, etc.
      pattern = pattern.replace(/\\\\/g, '\\');
      if (pattern) {
        currentRule.patterns.push(pattern);
      }
      continue;
    }

    // Metadata entries (cwe: "CWE-123", risk_score: 90)
    if (inMetadata) {
      const metaMatch = trimmed.match(/^(\w+):\s*(.+)$/);
      if (metaMatch) {
        let value = metaMatch[2].trim().replace(/^["']|["']$/g, '');
        // Parse numbers
        if (/^\d+$/.test(value)) {
          value = parseInt(value, 10);
        }
        currentRule.metadata[metaMatch[1]] = value;
      }
      continue;
    }
  }

  // Push last rule
  if (currentRule) {
    rules.push(currentRule);
  }

  return { rules };
}

/**
 * Load YAML files for a specific language (lazy loading)
 * Only loads rules for the requested language + generic rules
 */
function loadYamlFilesForLanguage(dir, language) {
  const allRules = [];

  // Language-specific files to load
  const filesToLoad = [
    `${language}.security.yaml`,
    `${language}.secrets.yaml`,
    'generic.secrets.yaml',
    'agent-attacks.security.yaml'
  ];

  // Load language-specific files
  for (const filename of filesToLoad) {
    const fullPath = join(dir, filename);
    try {
      if (existsSync(fullPath)) {
        const content = readFileSync(fullPath, 'utf-8');
        const parsed = parseRulesYaml(content);
        allRules.push(...parsed.rules);
      }
    } catch (err) {
      // Silently skip missing files
    }
  }

  // Load language-specific subdirectories (e.g., javascript/, python/)
  const langDir = join(dir, language);
  if (existsSync(langDir)) {
    try {
      const entries = readdirSync(langDir);
      for (const entry of entries) {
        const fullPath = join(langDir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          // Recursively load subdirectories
          walkDirectory(fullPath, allRules);
        } else if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
          try {
            const content = readFileSync(fullPath, 'utf-8');
            const parsed = parseRulesYaml(content);
            allRules.push(...parsed.rules);
          } catch (err) {
            // Skip invalid files
          }
        }
      }
    } catch (err) {
      // Skip if directory doesn't exist
    }
  }

  return allRules;
}

/**
 * Recursively walk a directory and load all YAML files
 */
function walkDirectory(dir, allRules) {
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        walkDirectory(fullPath, allRules);
      } else if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
        try {
          const content = readFileSync(fullPath, 'utf-8');
          const parsed = parseRulesYaml(content);
          allRules.push(...parsed.rules);
        } catch (err) {
          // Skip invalid files
        }
      }
    }
  } catch (err) {
    // Skip if directory doesn't exist
  }
}

/**
 * Get rules for a specific language (with lazy loading and caching)
 * @param {string} language - Language name (javascript, python, generic, etc.)
 * @returns {Array} Array of rule objects
 */
export function getRulesForLanguage(language) {
  // Check cache first
  if (_rulesByLanguage.has(language)) {
    return _rulesByLanguage.get(language);
  }

  // Lazy load only rules for this language (not all 1,700+ rules)
  const rules = loadYamlFilesForLanguage(RULES_DIR, language);

  // Cache the result
  _rulesByLanguage.set(language, rules);

  return rules;
}

/**
 * Scan file content against regex rules
 * @param {string} fileContent - File content to scan
 * @param {string} language - Language name
 * @returns {Array} Array of findings
 */
export function scanWithRegex(fileContent, language) {
  const rules = getRulesForLanguage(language);
  const findings = [];
  const lines = fileContent.split('\n');

  for (const rule of rules) {
    for (const patternStr of rule.patterns) {
      try {
        // Skip overly complex patterns that cause catastrophic backtracking
        // Patterns with multiple .* and \s+ are problematic
        const hasMultipleDotStar = (patternStr.match(/\.\*/g) || []).length > 2;
        const hasMultipleWhitespace = (patternStr.match(/\\s\+/g) || []).length > 3;

        if (hasMultipleDotStar && hasMultipleWhitespace) {
          // Use simple line-by-line substring matching for complex patterns
          for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];

            // Extract key terms from pattern (simple heuristic)
            const keyTerms = patternStr
              .replace(/\(\?i\)/g, '')
              .replace(/[\\().*+?[\]{}|^$]/g, ' ')
              .split(/\s+/)
              .filter(term => term.length > 3)
              .slice(0, 3)  // Take first 3 meaningful terms
              .map(t => t.toLowerCase());

            // Check if line contains all key terms
            const lineLower = line.toLowerCase();
            if (keyTerms.length > 0 && keyTerms.every(term => lineLower.includes(term))) {
              findings.push({
                ruleId: rule.id,
                severity: rule.severity.toLowerCase(),
                message: rule.message,
                line: lineNum,
                column: 0,
                matched_text: line.substring(0, 100),
                engine: 'regex',
                confidence: 'LOW',  // Lower confidence for simplified matching
                metadata: rule.metadata
              });
            }
          }
          continue;
        }

        // Strip Python-style inline (?i) flag — JS doesn't support it
        let effectivePattern = patternStr;
        let flags = 'gm';
        if (effectivePattern.startsWith('(?i)')) {
          effectivePattern = effectivePattern.slice(4);
          flags = 'gmi';
        }

        // Standard regex matching for simpler patterns
        const regex = new RegExp(effectivePattern, flags);
        let match;
        let iterations = 0;
        const maxIterations = 100;  // Lower limit to prevent runaway matches

        while ((match = regex.exec(fileContent)) !== null && iterations < maxIterations) {
          iterations++;
          const matchText = match[0];

          // Skip empty matches (likely a bad pattern)
          if (matchText.length === 0) {
            break;
          }

          // Find line number and column
          const upToMatch = fileContent.substring(0, match.index);
          const lineNumber = upToMatch.split('\n').length - 1;
          const lineStart = upToMatch.lastIndexOf('\n') + 1;
          const column = match.index - lineStart;

          findings.push({
            ruleId: rule.id,
            severity: rule.severity.toLowerCase(),
            message: rule.message,
            line: lineNumber,
            column: column,
            matched_text: matchText.substring(0, 100), // Limit match text length
            engine: 'regex',
            confidence: rule.metadata.confidence || 'MEDIUM',
            metadata: rule.metadata
          });

          // Prevent infinite loops on zero-width matches
          if (match.index === regex.lastIndex) {
            regex.lastIndex++;
          }
        }
      } catch (err) {
        // Skip invalid patterns silently
      }
    }
  }

  return findings;
}

/**
 * Main entry point - analyze a file
 * Drop-in replacement for Python analyzer
 * @param {string} filePath - Path to file to analyze
 * @param {string} engine - Engine mode (always 'regex' for this implementation)
 * @returns {Object} Analysis result with findings
 */
export async function analyzeFile(filePath, engine = 'regex') {
  try {
    const content = readFileSync(filePath, 'utf-8');

    // Detect language from file extension
    const ext = filePath.split('.').pop().toLowerCase();
    const langMap = {
      'py': 'python', 'js': 'javascript', 'ts': 'typescript',
      'tsx': 'typescript', 'jsx': 'javascript', 'java': 'java',
      'go': 'go', 'rb': 'ruby', 'php': 'php',
      'cs': 'csharp', 'rs': 'rust', 'c': 'c', 'cpp': 'cpp',
      'cc': 'cpp', 'cxx': 'cpp', 'h': 'c', 'hpp': 'cpp',
      'yaml': 'generic', 'yml': 'generic', 'txt': 'generic',
      'md': 'generic', 'sql': 'sql',
      'tf': 'terraform', 'hcl': 'terraform'
    };

    // Check basename for Docker files
    const basename = filePath.split('/').pop().split('\\').pop();
    let language = langMap[ext] || 'generic';
    if (basename.toLowerCase().startsWith('dockerfile')) {
      language = 'dockerfile';
    }

    // Scan with regex engine
    const findings = scanWithRegex(content, language);

    return {
      findings,
      language,
      engine: 'regex',
      file: filePath
    };
  } catch (error) {
    return {
      error: error.message,
      findings: [],
      file: filePath
    };
  }
}

/**
 * Scan prompt text for injection attempts
 * Used by scan_agent_prompt tool
 */
export function scanPrompt(promptText) {
  const rules = getRulesForLanguage('generic');
  const findings = [];

  // Filter to only prompt injection rules
  const promptRules = rules.filter(r =>
    r.id.includes('prompt') ||
    r.id.includes('agent.') ||
    r.id.includes('jailbreak')
  );

  for (const rule of promptRules) {
    for (const patternStr of rule.patterns) {
      try {
        const regex = new RegExp(patternStr, 'gmi');
        const matches = promptText.matchAll(regex);

        for (const match of matches) {
          findings.push({
            ruleId: rule.id,
            severity: rule.severity.toLowerCase(),
            message: rule.message,
            matched_text: match[0],
            engine: 'regex',
            confidence: rule.metadata.confidence || 'MEDIUM',
            metadata: rule.metadata,
            category: rule.metadata.category || 'prompt-injection'
          });
        }
      } catch (err) {
        console.error(`[regex-engine] Invalid regex in ${rule.id}: ${patternStr}`);
      }
    }
  }

  return findings;
}

/**
 * Clear the rules cache (useful for testing)
 */
export function clearCache() {
  _rulesCache.clear();
  _rulesByLanguage.clear();
}
