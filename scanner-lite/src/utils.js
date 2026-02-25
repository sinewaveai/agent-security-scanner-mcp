// src/utils.js - Lightweight version (zero Python dependencies)
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { FIX_TEMPLATES } from './fix-patterns.js';
import { analyzeFile } from './regex-engine.js';

// Handle both ESM and CJS bundling
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Read version from package.json
const _packageVersion = (() => {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version || '1.0.0';
  } catch {
    return '1.0.0';
  }
})();

export function getVersion() {
  return _packageVersion;
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
    'yaml': 'generic', 'yml': 'generic',
    'sql': 'sql',
    'txt': 'generic', 'md': 'generic', 'prompt': 'generic'
  };
  return langMap[ext] || 'generic';
}

// Engine mode is always 'regex' for lightweight version
export function getEngineMode() {
  return 'regex';
}

// Run analyzer (delegates to regex engine)
export async function runAnalyzerAsync(filePath, engine = 'regex') {
  return await analyzeFile(filePath, engine);
}

// Synchronous version (for backwards compatibility)
export function runAnalyzer(filePath, engine = 'regex') {
  // Import is done at top of file, use analyzeFile directly
  try {
    const content = readFileSync(filePath, 'utf-8');
    const language = detectLanguage(filePath);
    // Use the already imported analyzeFile function (though it's async, we handle it differently)
    // For CLI sync usage, we'll use the async version via runAnalyzerAsync
    throw new Error('Use runAnalyzerAsync instead - this is a lightweight package with async-only scanning');
  } catch (error) {
    return { error: error.message, findings: [], file: filePath };
  }
}

// Generate fix suggestion
export function generateFix(finding, fileContent) {
  const ruleId = finding.ruleId;
  const template = FIX_TEMPLATES[ruleId];

  if (!template) {
    return null;
  }

  // Extract matched text and provide generic fix
  const lines = fileContent.split('\n');
  const line = lines[finding.line] || '';

  return {
    fixed: template.fixed || line,
    explanation: template.explanation || 'See rule documentation for fix details',
    automated: false
  };
}

// Convert findings to SARIF format
export function toSarif(findings, filePath, language) {
  return {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "ProofLayer Security Scanner",
          version: _packageVersion,
          informationUri: "https://github.com/sinewaveai/agent-security-scanner-mcp",
          rules: findings.map(f => ({
            id: f.ruleId,
            shortDescription: { text: f.message },
            fullDescription: { text: f.message },
            defaultConfiguration: {
              level: f.severity === 'error' ? 'error' : 'warning'
            }
          }))
        }
      },
      results: findings.map(f => ({
        ruleId: f.ruleId,
        level: f.severity === 'error' ? 'error' : 'warning',
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: filePath },
            region: {
              startLine: f.line + 1,
              startColumn: f.column || 0
            }
          }
        }]
      }))
    }]
  };
}

// Extract imports from file content
export function extractImports(fileContent, language) {
  const imports = [];
  const lines = fileContent.split('\n');

  if (language === 'javascript' || language === 'typescript') {
    const importRegex = /import\s+.*\s+from\s+['"]([^'"]+)['"]/g;
    const requireRegex = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

    for (const line of lines) {
      let match;
      while ((match = importRegex.exec(line)) !== null) {
        imports.push(match[1]);
      }
      while ((match = requireRegex.exec(line)) !== null) {
        imports.push(match[1]);
      }
    }
  } else if (language === 'python') {
    const importRegex = /^(?:from\s+(\S+)\s+)?import\s+(\S+)/;

    for (const line of lines) {
      const match = line.trim().match(importRegex);
      if (match) {
        imports.push(match[1] || match[2]);
      }
    }
  }

  return imports;
}

// Check if file is a test file
export function isTestFile(filePath) {
  const lowerPath = filePath.toLowerCase();
  return lowerPath.includes('/test/') ||
         lowerPath.includes('/__tests__/') ||
         lowerPath.includes('.test.') ||
         lowerPath.includes('.spec.') ||
         lowerPath.endsWith('_test.py') ||
         lowerPath.endsWith('_test.js');
}
