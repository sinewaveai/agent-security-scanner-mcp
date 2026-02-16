import { execFileSync } from "child_process";
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

// Run the Python analyzer
export function runAnalyzer(filePath) {
  try {
    const analyzerPath = join(__dirname, '..', 'analyzer.py');
    const result = execFileSync('python3', [analyzerPath, filePath], {
      encoding: 'utf-8',
      timeout: 30000
    });
    return JSON.parse(result);
  } catch (error) {
    return { error: error.message };
  }
}

// Generate fix suggestion for an issue
export function generateFix(issue, line, language) {
  const ruleId = issue.ruleId.toLowerCase();

  for (const [pattern, template] of Object.entries(FIX_TEMPLATES)) {
    if (ruleId.includes(pattern)) {
      return {
        description: template.description,
        original: line,
        fixed: template.fix(line, language)
      };
    }
  }

  return {
    description: "Review and fix manually based on the security rule",
    original: line,
    fixed: null
  };
}

// Check if a file path looks like a test/fixture/mock file
export function isTestFile(filePath) {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const testPatterns = [
    '/test/', '/tests/', '/__tests__/', '/spec/', '/specs/',
    '/__mocks__/', '/__fixtures__/', '/fixtures/', '/mocks/',
    '/testing/', '/testdata/', '/test-data/',
  ];
  const suffixPatterns = [
    '.test.', '.spec.', '_test.', '_spec.',
    '.tests.', '.specs.',
  ];
  if (testPatterns.some(p => normalized.includes(p))) return true;
  const base = normalized.split('/').pop();
  if (suffixPatterns.some(p => base.includes(p))) return true;
  if (base.startsWith('test_') || base.startsWith('test-')) return true;
  return false;
}

// Extract import/require statements from source code
export function extractImports(content, language) {
  const imports = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    switch (language) {
      case 'javascript':
      case 'typescript': {
        // ES imports: import X from 'pkg', import { X } from 'pkg'
        const esMatch = trimmed.match(/import\s+.*?\s+from\s+['"]([^'"]+)['"]/);
        if (esMatch) { imports.push(esMatch[1]); break; }
        // Side-effect imports: import 'pkg'
        const sideMatch = trimmed.match(/import\s+['"]([^'"]+)['"]/);
        if (sideMatch) { imports.push(sideMatch[1]); break; }
        // Dynamic imports: import('pkg')
        const dynMatch = trimmed.match(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/);
        if (dynMatch) { imports.push(dynMatch[1]); break; }
        // CJS require: require('pkg')
        const reqMatch = trimmed.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
        if (reqMatch) { imports.push(reqMatch[1]); break; }
        break;
      }
      case 'python': {
        // import pkg / import pkg.sub
        const impMatch = trimmed.match(/^import\s+([a-zA-Z_][\w.]*)/);
        if (impMatch) { imports.push(impMatch[1].split('.')[0]); break; }
        // from pkg import X
        const fromMatch = trimmed.match(/^from\s+([a-zA-Z_][\w.]*)\s+import/);
        if (fromMatch) { imports.push(fromMatch[1].split('.')[0]); break; }
        break;
      }
      case 'go': {
        // "github.com/pkg/name"
        const goMatch = trimmed.match(/["']([^"']+)["']/);
        if (goMatch && (trimmed.startsWith('"') || trimmed.startsWith('_') || /^\w/.test(trimmed))) {
          imports.push(goMatch[1]);
        }
        break;
      }
      case 'ruby': {
        // require 'pkg' / require_relative 'pkg'
        const rbMatch = trimmed.match(/require(?:_relative)?\s+['"]([^'"]+)['"]/);
        if (rbMatch) { imports.push(rbMatch[1]); break; }
        // gem 'pkg'
        const gemMatch = trimmed.match(/gem\s+['"]([^'"]+)['"]/);
        if (gemMatch) { imports.push(gemMatch[1]); break; }
        break;
      }
      case 'java': {
        // import com.example.pkg;
        const javaMatch = trimmed.match(/^import\s+(?:static\s+)?([a-zA-Z][\w.]*)/);
        if (javaMatch) { imports.push(javaMatch[1]); break; }
        break;
      }
    }
  }

  return [...new Set(imports)];
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
          version: '3.1.0',
          informationUri: 'https://github.com/sinewaveai/agent-security-scanner-mcp',
          rules: Array.from(rulesMap.values())
        }
      },
      results: results
    }]
  };
}
