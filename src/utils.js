import { execFileSync } from "child_process";
import { createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { dirname, join, extname, basename } from "path";
import { fileURLToPath } from "url";
import { FIX_TEMPLATES } from './fix-patterns.js';

// Handle both ESM and CJS bundling (Smithery bundles to CJS)
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Read version from package.json at module load time
const _packageVersion = (() => {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

// Detect language from file extension
export function detectLanguage(filePath) {
  // Check basename first for extensionless files like Dockerfile
  const base = filePath.split('/').pop().split('\\').pop().toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.')) return 'dockerfile';

  const ext = filePath.split('.').pop().toLowerCase();
  const langMap = {
    'py': 'python', 'js': 'javascript', 'ts': 'typescript',
    'tsx': 'typescript', 'jsx': 'javascript', 'java': 'java',
    'go': 'go', 'rb': 'ruby', 'php': 'php',
    'cs': 'csharp', 'rs': 'rust', 'c': 'c', 'cpp': 'cpp',
    'cc': 'cpp', 'cxx': 'cpp', 'h': 'c', 'hpp': 'cpp',
    'tf': 'terraform', 'hcl': 'terraform',
    'yaml': 'generic', 'yml': 'generic',
    'sql': 'sql',
    // Prompt/text file extensions for prompt injection scanning
    'txt': 'generic', 'md': 'generic', 'prompt': 'generic',
    'jinja': 'generic', 'jinja2': 'generic', 'j2': 'generic'
  };
  return langMap[ext] || 'generic';
}

// Detect which analysis engine is available
export function detectEngineMode() {
  try {
    execFileSync('python3', ['-c', 'import tree_sitter; print("ast")'], {
      encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe']
    });
    return 'ast';
  } catch {
    try {
      execFileSync('python3', ['--version'], {
        encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe']
      });
      return 'regex';
    } catch {
      return 'regex-only';
    }
  }
}

// Cached engine mode (detected once per process)
let _cachedEngineMode = null;
export function getEngineMode() {
  if (_cachedEngineMode === null) {
    _cachedEngineMode = detectEngineMode();
  }
  return _cachedEngineMode;
}

// Run the Python analyzer
export function runAnalyzer(filePath, engine = 'auto') {
  try {
    const analyzerPath = join(__dirname, '..', 'analyzer.py');
    const args = [analyzerPath, filePath];
    if (engine !== 'auto') {
      args.push('--engine', engine);
    }
    const result = execFileSync('python3', args, {
      encoding: 'utf-8',
      timeout: 30000
    });
    return JSON.parse(result);
  } catch (error) {
    return { error: error.message };
  }
}

// Patterns that indicate an unsafe fix (user input still concatenated into dangerous sinks)
const UNSAFE_FIX_PATTERNS = [
  // execFile/exec with string concatenation of user input
  /\bexecFile\s*\(\s*["'][^"']*["']\s*\+\s*\w+/,
  /\bexecFile\s*\(\s*`[^`]*\$\{/,
  // spawn/exec with shell: true still present alongside user input
  /\bspawn\s*\(.*shell\s*:\s*true/,
  // subprocess.run with shell=True still present
  /subprocess\.\w+\(.*shell\s*=\s*True/,
  // os.system still in a "fix"
  /\bos\.system\s*\(/,
];

// Validate that a fix produces syntactically reasonable and safe output
export function validateFix(original, fixed) {
  if (!fixed || fixed === original) return false;

  // Strip escaped quotes for bracket/quote counting
  const unescaped = fixed.replace(/\\["'`]/g, '');

  // Check balanced quotes (single pass)
  const singleQ = (unescaped.match(/'/g) || []).length;
  const doubleQ = (unescaped.match(/"/g) || []).length;
  const backtickQ = (unescaped.match(/`/g) || []).length;
  if (singleQ % 2 !== 0 || doubleQ % 2 !== 0 || backtickQ % 2 !== 0) return false;

  // Check balanced brackets
  const brackets = { '(': 0, '[': 0, '{': 0 };
  const closers = { ')': '(', ']': '[', '}': '{' };
  for (const char of unescaped) {
    if (brackets[char] !== undefined) brackets[char]++;
    if (closers[char]) {
      brackets[closers[char]]--;
      if (brackets[closers[char]] < 0) return false;
    }
  }
  if (Object.values(brackets).some(v => v !== 0)) return false;

  // Reject fixes that still contain unsafe patterns
  for (const pattern of UNSAFE_FIX_PATTERNS) {
    if (pattern.test(fixed)) return false;
  }

  return true;
}

// Generate fix suggestion for an issue
export function generateFix(issue, line, language) {
  const ruleId = issue.ruleId.toLowerCase();

  for (const [pattern, template] of Object.entries(FIX_TEMPLATES)) {
    if (ruleId.includes(pattern)) {
      try {
        const fixed = template.fix(line, language);
        // Validate the fix produces reasonable output
        if (fixed && !validateFix(line, fixed)) {
          return {
            description: template.description + " (manual fix required)",
            original: line,
            fixed: null
          };
        }
        return {
          description: template.description,
          original: line,
          fixed: fixed
        };
      } catch {
        return {
          description: template.description + " (manual fix required)",
          original: line,
          fixed: null
        };
      }
    }
  }

  return {
    description: "Review and fix manually based on the security rule",
    original: line,
    fixed: null
  };
}

// Run cross-file taint analysis
export function runCrossFileAnalyzer(filePaths) {
  try {
    const analyzerPath = join(__dirname, '..', 'cross_file_analyzer.py');
    if (!existsSync(analyzerPath)) return [];
    const result = execFileSync('python3', [analyzerPath, ...filePaths], {
      encoding: 'utf-8',
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    const parsed = JSON.parse(result);
    // Return only cross-file warnings (per-file findings are handled by scanSecurity)
    return Array.isArray(parsed)
      ? parsed.filter(f => f.ruleId === 'cross-file-taint-warning')
      : [];
  } catch {
    return [];
  }
}

// Convert issues to SARIF 2.1.0 format
export function toSarif(file_path, language, issues) {
  const severityToLevel = {
    'error': 'error',
    'ERROR': 'error',
    'warning': 'warning',
    'WARNING': 'warning',
    'info': 'note',
    'INFO': 'note'
  };

  // Build unique rules from issues
  const rulesMap = new Map();
  for (const issue of issues) {
    if (!rulesMap.has(issue.ruleId)) {
      rulesMap.set(issue.ruleId, {
        id: issue.ruleId,
        shortDescription: { text: issue.message },
        defaultConfiguration: {
          level: severityToLevel[issue.severity] || 'warning'
        },
        properties: issue.metadata || {}
      });
    }
  }

  // Build results
  const results = issues.map(issue => {
    const result = {
      ruleId: issue.ruleId,
      level: severityToLevel[issue.severity] || 'warning',
      message: { text: issue.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: file_path },
          region: {
            startLine: (issue.line || 0) + 1,
            startColumn: (issue.column || 0) + 1
          }
        }
      }]
    };

    // Add partial fingerprints for cross-run deduplication
    if (issue.line_content) {
      result.partialFingerprints = {
        primaryLocationLineHash: createHash('sha256')
          .update(issue.line_content)
          .digest('hex')
      };
    }

    // Add code flows for taint analysis findings
    if (issue.taint_source && issue.taint_sink) {
      result.codeFlows = [{
        threadFlows: [{
          locations: [
            {
              location: {
                physicalLocation: {
                  artifactLocation: { uri: file_path },
                  region: { startLine: issue.taint_source.line || 1 }
                },
                message: { text: issue.taint_source.label || 'Source' }
              }
            },
            {
              location: {
                physicalLocation: {
                  artifactLocation: { uri: file_path },
                  region: { startLine: issue.taint_sink.line || 1 }
                },
                message: { text: issue.taint_sink.label || 'Sink' }
              }
            }
          ]
        }]
      }];
    }

    // Add related locations if present
    if (issue.related_file) {
      result.relatedLocations = [{
        id: 0,
        physicalLocation: {
          artifactLocation: { uri: issue.related_file },
          region: { startLine: issue.related_line || 1 }
        },
        message: { text: issue.related_message || 'Related location' }
      }];
    }

    // Add fix if available
    if (issue.suggested_fix && issue.suggested_fix.fixed) {
      result.fixes = [{
        description: { text: issue.suggested_fix.description || 'Apply security fix' },
        artifactChanges: [{
          artifactLocation: { uri: file_path },
          replacements: [{
            deletedRegion: {
              startLine: (issue.line || 0) + 1,
              startColumn: 1,
              endLine: (issue.line || 0) + 1,
              endColumn: (issue.line_content?.length || 0) + 1
            },
            insertedContent: { text: issue.suggested_fix.fixed }
          }]
        }]
      }];
    }

    return result;
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'agent-security-scanner-mcp',
          version: _packageVersion,
          informationUri: 'https://github.com/sinewaveai/agent-security-scanner-mcp',
          rules: Array.from(rulesMap.values())
        }
      },
      results: results
    }]
  };
}
