/**
 * Semantic Analysis Integration
 *
 * Integrates semantic analyzer into existing scan pipeline
 */

import { SemanticAnalyzer } from './semantic-analyzer.js';
import { readFileSync } from 'fs';
import { execFileSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { resolvePythonCommand, pythonArgs } from './python.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Run semantic analysis on a file
 *
 * @param {string} filePath - Path to file to analyze
 * @param {object} options - Analysis options
 * @returns {Array} Semantic findings
 */
export async function runSemanticAnalysis(filePath, options = {}) {
  try {
    // Get AST from Python analyzer
    const ast = await getASTFromPython(filePath);

    if (!ast || ast.error) {
      console.error(`[SEMANTIC] Failed to get AST: ${ast?.error || 'unknown error'}`);
      return [];
    }

    // Determine language
    const language = detectLanguage(filePath);

    // Run semantic analyzer
    const analyzer = new SemanticAnalyzer(ast, language, filePath);
    const findings = analyzer.analyze();

    // Convert findings to standard format
    return findings.map(f => ({
      ruleId: f.ruleId,
      message: f.message,
      line: extractLineNumber(f, ast),
      column: 0,
      length: 0,
      severity: mapSeverity(f.severity),
      confidence: (f.confidence ? String(f.confidence) : 'MEDIUM').toUpperCase(),
      metadata: {
        category: f.category,
        engine: 'semantic',
        ...f
      },
      engine: 'semantic'
    }));

  } catch (error) {
    console.error(`[SEMANTIC] Analysis error: ${error.message}`);
    return [];
  }
}

/**
 * Get AST from Python analyzer
 */
async function getASTFromPython(filePath) {
  try {
    const pyCmd = resolvePythonCommand();
    const analyzerPath = path.join(__dirname, '..', 'ast_parser.py');

    // Call Python AST parser via the analyzer wrapper which outputs JSON
    const result = execFileSync(pyCmd, [
      ...pythonArgs(),
      analyzerPath,
      '--ast-only',
      filePath
    ], {
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      timeout: 30000 // 30s timeout
    });

    return JSON.parse(result);
  } catch (error) {
    console.error(`[SEMANTIC] AST extraction failed: ${error.message}`);
    return null;
  }
}

/**
 * Detect language from file extension
 */
function detectLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const extMap = {
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.cs': 'csharp',
    '.rs': 'rust',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp'
  };

  return extMap[ext] || 'generic';
}

/**
 * Extract line number from finding
 */
function extractLineNumber(finding, ast) {
  // Try to get line from node metadata
  if (finding.node && finding.node.ast) {
    const astNode = finding.node.ast;
    if (astNode.line) return astNode.line;
    if (astNode.start_point && astNode.start_point.row) return astNode.start_point.row + 1;
  }

  if (finding.nodeId && finding.nodeId.includes('_')) {
    // Extract from node ID if possible
    const parts = finding.nodeId.split('_');
    if (parts.length > 1 && !isNaN(parts[1])) {
      return parseInt(parts[1]);
    }
  }

  return 1; // Default to line 1 if we can't determine
}

/**
 * Map severity levels
 */
function mapSeverity(severity) {
  if (!severity) return 'warning';

  const s = severity.toLowerCase();
  if (s === 'error' || s === 'critical') return 'error';
  if (s === 'warning' || s === 'warn') return 'warning';
  if (s === 'info' || s === 'note') return 'info';

  return 'warning';
}

/**
 * Load semantic rules from YAML
 */
export async function loadSemanticRules() {
  try {
    const rulesPath = path.join(__dirname, '..', 'rules', 'semantic-security.yaml');
    const yamlContent = readFileSync(rulesPath, 'utf8');

    // Parse YAML (simplified - in production use a YAML library)
    const rules = parseSimpleYAML(yamlContent);

    return rules;
  } catch (error) {
    console.error(`[SEMANTIC] Failed to load rules: ${error.message}`);
    return [];
  }
}

/**
 * Simple YAML parser for rule files
 * (In production, use js-yaml library)
 */
function parseSimpleYAML(yamlContent) {
  const rules = [];
  const ruleBlocks = yamlContent.split(/^- id:/m).filter(b => b.trim());

  for (const block of ruleBlocks) {
    try {
      const rule = {};

      // Extract ID
      const idMatch = block.match(/^\s*(.+?)$/m);
      if (idMatch) {
        rule.id = idMatch[1].trim();
      }

      // Extract languages
      const langMatch = block.match(/languages:\s*\[([^\]]+)\]/);
      if (langMatch) {
        rule.languages = langMatch[1].split(',').map(l => l.trim());
      }

      // Extract severity
      const severityMatch = block.match(/severity:\s*(\w+)/);
      if (severityMatch) {
        rule.severity = severityMatch[1].trim();
      }

      // Extract message
      const messageMatch = block.match(/message:\s*["'](.+?)["']/);
      if (messageMatch) {
        rule.message = messageMatch[1];
      }

      // Extract metadata (simplified)
      rule.metadata = {};

      const categoryMatch = block.match(/category:\s*(\S+)/);
      if (categoryMatch) {
        rule.metadata.category = categoryMatch[1];
      }

      const cweMatch = block.match(/cwe:\s*["']([^"']+)["']/);
      if (cweMatch) {
        rule.metadata.cwe = cweMatch[1];
      }

      const owaspMatch = block.match(/owasp:\s*["']([^"']+)["']/);
      if (owaspMatch) {
        rule.metadata.owasp = owaspMatch[1];
      }

      const confidenceMatch = block.match(/confidence:\s*(\w+)/);
      if (confidenceMatch) {
        rule.metadata.confidence = confidenceMatch[1];
      }

      if (rule.id) {
        rules.push(rule);
      }
    } catch (error) {
      console.error(`[SEMANTIC] Failed to parse rule block: ${error.message}`);
    }
  }

  return rules;
}

/**
 * Check if semantic analysis is available
 */
let _semanticAvailable = null;

export function isSemanticAnalysisAvailable() {
  if (_semanticAvailable !== null) return _semanticAvailable;
  try {
    const pyCmd = resolvePythonCommand();
    // Verify that Python 3 exists AND tree-sitter can be imported, which is
    // the actual prerequisite for AST extraction.  A bare "python --version"
    // check was giving false positives on systems without tree-sitter.
    execFileSync(pyCmd, [
      ...pythonArgs(),
      '-c',
      'import tree_sitter; import ast_parser'
    ], {
      stdio: 'pipe',
      timeout: 10000,
      cwd: path.join(__dirname, '..')
    });
    _semanticAvailable = true;
  } catch {
    _semanticAvailable = false;
  }
  return _semanticAvailable;
}

/**
 * Get semantic analyzer statistics
 */
export async function getSemanticStats() {
  const rules = await loadSemanticRules();

  const stats = {
    total_rules: rules.length,
    by_severity: {},
    by_category: {},
    by_language: {}
  };

  for (const rule of rules) {
    // Count by severity
    const severity = rule.severity || 'UNKNOWN';
    stats.by_severity[severity] = (stats.by_severity[severity] || 0) + 1;

    // Count by category
    const category = rule.metadata?.category || 'unknown';
    stats.by_category[category] = (stats.by_category[category] || 0) + 1;

    // Count by language
    if (rule.languages) {
      for (const lang of rule.languages) {
        stats.by_language[lang] = (stats.by_language[lang] || 0) + 1;
      }
    }
  }

  return stats;
}
