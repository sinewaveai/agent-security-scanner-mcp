// src/tools/scan-project.js
import { z } from "zod";
import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, resolve, relative, extname, basename, dirname } from "path";
import { execFileSync } from "child_process";
import { fileURLToPath } from "url";
import { scanSecurity } from './scan-security.js';
import { matchGlob, loadConfig, shouldExcludeFile } from '../config.js';
import { detectLanguage } from '../utils.js';
import { resolveImportGraph } from './import-resolver.js';

// Resolve path to mcp-server root for Python analyzer scripts
let __scanProjectDir;
try {
  __scanProjectDir = dirname(fileURLToPath(import.meta.url));
} catch {
  __scanProjectDir = process.cwd();
}
const CROSS_FILE_ANALYZER_PATH = join(__scanProjectDir, '..', '..', 'cross_file_analyzer.py');

export const scanProjectSchema = {
  directory_path: z.string().describe("Path to the directory to scan"),
  recursive: z.boolean().optional().describe("Scan subdirectories recursively (default: true)"),
  include_patterns: z.array(z.string()).optional().describe("Glob patterns to include (e.g. ['**/*.py', '**/*.js'])"),
  exclude_patterns: z.array(z.string()).optional().describe("Glob patterns to exclude (e.g. ['*test*', 'vendor/**'])"),
  diff_only: z.boolean().optional().describe("Only scan git-changed files"),
  cross_file: z.boolean().optional().describe("Enable cross-file taint analysis (max 50 files)"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level")
};

// Scannable file extensions
const SCANNABLE_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.go', '.rb', '.php',
  '.rs', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.cs',
  '.tf', '.hcl', '.sql',
]);

// Parse .gitignore into patterns
function parseGitignore(dirPath) {
  const gitignorePath = join(dirPath, '.gitignore');
  if (!existsSync(gitignorePath)) return [];

  try {
    const content = readFileSync(gitignorePath, 'utf-8');
    return content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .map(line => {
        // Normalize: remove trailing slash for directories
        if (line.endsWith('/')) return line.slice(0, -1) + '/**';
        return line;
      });
  } catch {
    return [];
  }
}

// Check if a file path matches gitignore patterns
function isGitignored(filePath, patterns) {
  const normalized = filePath.replace(/\\/g, '/');
  return patterns.some(pattern => matchGlob(normalized, pattern));
}

// Recursively walk a directory, respecting exclusions
function walkDirectory(dirPath, options = {}) {
  const { recursive = true, includePatterns = [], excludePatterns = [], gitignorePatterns = [], config } = options;
  const files = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = readdirSync(currentDir);
    } catch {
      return;
    }

    for (const entry of entries) {
      // Skip hidden directories/files
      if (entry.startsWith('.')) continue;

      const fullPath = join(currentDir, entry);
      const relativePath = relative(dirPath, fullPath);

      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        // Skip common non-source directories
        if (['node_modules', 'vendor', 'dist', 'build', '__pycache__', '.git',
             'venv', 'env', '.venv', 'target', 'coverage'].includes(entry)) continue;

        // Skip gitignored directories
        if (isGitignored(relativePath, gitignorePatterns)) continue;

        if (recursive) walk(fullPath);
      } else if (stat.isFile()) {
        const ext = extname(entry).toLowerCase();
        const base = basename(entry).toLowerCase();

        // Check extension or special filenames
        if (!SCANNABLE_EXTENSIONS.has(ext) && base !== 'dockerfile') continue;

        // Check gitignore
        if (isGitignored(relativePath, gitignorePatterns)) continue;

        // Check config exclusions
        if (config && shouldExcludeFile(relativePath, config)) continue;

        // Check include patterns (if specified, only include matching files)
        if (includePatterns.length > 0) {
          const matches = includePatterns.some(p => matchGlob(relativePath, p));
          if (!matches) continue;
        }

        // Check exclude patterns (if specified, skip matching files)
        if (excludePatterns.length > 0) {
          const excluded = excludePatterns.some(p => matchGlob(relativePath, p) || relativePath.includes(p) || entry.includes(p));
          if (excluded) continue;
        }

        files.push(fullPath);
      }
    }
  }

  walk(dirPath);
  return files;
}

// Get git-changed files in a directory
function getGitChangedFiles(dirPath) {
  try {
    const output = execFileSync('git', ['diff', '--name-only', 'HEAD'], {
      cwd: dirPath, encoding: 'utf-8', timeout: 10000
    });
    const untrackedOutput = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
      cwd: dirPath, encoding: 'utf-8', timeout: 10000
    });
    const allFiles = [...output.trim().split('\n'), ...untrackedOutput.trim().split('\n')]
      .filter(f => f.trim())
      .map(f => resolve(dirPath, f))
      .filter(f => existsSync(f));
    return [...new Set(allFiles)];
  } catch {
    return [];
  }
}

// Calculate security grade based on findings
function calculateGrade(totalIssues, totalFiles, errorCount) {
  if (totalFiles === 0) return 'A';
  const density = totalIssues / totalFiles;

  if (errorCount === 0 && density === 0) return 'A';
  if (errorCount === 0 && density < 0.5) return 'B';
  if (errorCount <= 2 && density < 1.5) return 'C';
  if (errorCount <= 5 && density < 3) return 'D';
  return 'F';
}

export async function scanProject({ directory_path, recursive, include_patterns, exclude_patterns, diff_only, cross_file, verbosity }) {
  const dirPath = resolve(directory_path);

  if (!existsSync(dirPath)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "Directory not found" }) }]
    };
  }

  // Load config from directory
  const config = loadConfig(join(dirPath, 'dummy.js'));
  const gitignorePatterns = parseGitignore(dirPath);

  // Get files to scan
  let files;
  if (diff_only) {
    files = getGitChangedFiles(dirPath);
  } else {
    files = walkDirectory(dirPath, {
      recursive: recursive !== false,
      includePatterns: include_patterns || [],
      excludePatterns: exclude_patterns || [],
      gitignorePatterns,
      config
    });
  }

  // Filter to scannable extensions
  files = files.filter(f => {
    const ext = extname(f).toLowerCase();
    const base = basename(f).toLowerCase();
    return SCANNABLE_EXTENSIONS.has(ext) || base === 'dockerfile';
  });

  if (files.length === 0) {
    return {
      content: [{ type: "text", text: JSON.stringify({
        directory: dirPath,
        message: "No scannable files found",
        files_scanned: 0,
        grade: 'A'
      }) }]
    };
  }

  // Scan each file
  const allIssues = [];
  const byFile = {};
  const bySeverity = { error: 0, warning: 0, info: 0 };
  const byCategory = {};

  for (const filePath of files) {
    const result = await scanSecurity({ file_path: filePath, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);

    if (parsed.issues && Array.isArray(parsed.issues)) {
      const relativePath = relative(dirPath, filePath);
      byFile[relativePath] = parsed.issues.length;

      for (const issue of parsed.issues) {
        allIssues.push({ ...issue, file: relativePath });
        bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
        const category = issue.ruleId?.split('.')[0] || 'other';
        byCategory[category] = (byCategory[category] || 0) + 1;
      }
    }
  }

  // Cross-file taint analysis via import graph (opt-in, max 50 files)
  let crossFileIssues = [];
  if (cross_file && files.length <= 50) {
    let usedPythonAnalyzer = false;

    // Try Python cross-file analyzer first (deeper analysis with taint tracking)
    try {
      if (existsSync(CROSS_FILE_ANALYZER_PATH)) {
        const result = execFileSync('python3', [CROSS_FILE_ANALYZER_PATH, ...files], {
          encoding: 'utf-8',
          timeout: 60000,
          cwd: dirname(CROSS_FILE_ANALYZER_PATH)
        });
        // Strip any non-JSON prefix (e.g. PyYAML warnings on stdout)
        const jsonStart = result.indexOf('[');
        const jsonStr = jsonStart >= 0 ? result.slice(jsonStart) : result;
        const crossResults = JSON.parse(jsonStr);
        if (Array.isArray(crossResults)) {
          const deepFindings = crossResults.filter(f => f.ruleId === 'cross-file-taint');
          for (const finding of deepFindings) {
            // Normalize file path to relative
            finding.file = typeof finding.file === 'string' ? relative(dirPath, finding.file) : finding.file;
            crossFileIssues.push(finding);
          }
          usedPythonAnalyzer = deepFindings.length > 0;
        }
      }
    } catch {
      // Python cross-file analyzer failed — fall back to JS approach
    }

    // Fall back to JS import graph approach (shallow warnings)
    try {
      // Build a set of files with ERROR-severity findings
      const errorFiles = new Set();
      for (const issue of allIssues) {
        if (issue.severity === 'error' || issue.severity === 'ERROR') {
          const absPath = resolve(dirPath, issue.file);
          errorFiles.add(absPath);
        }
      }

      // For each scanned file, build import graph and propagate warnings
      for (const filePath of files) {
        const graph = resolveImportGraph(filePath, dirPath, { maxDepth: 2 });
        for (const edge of graph.edges) {
          if (errorFiles.has(edge.to)) {
            const fromRelative = relative(dirPath, edge.from);
            const toRelative = relative(dirPath, edge.to);
            // Find the error-severity issues in the imported file
            const importedErrors = allIssues.filter(i =>
              i.file === toRelative && (i.severity === 'error' || i.severity === 'ERROR')
            );
            for (const err of importedErrors) {
              const crossIssue = {
                ruleId: 'cross-file-taint-warning',
                severity: 'warning',
                message: `File imports ${toRelative} (via "${edge.importSpec}") which has ${err.severity}-severity issue: ${err.ruleId || err.message}`,
                file: fromRelative,
                line: 0,
                imported_file: toRelative,
                source_issue: err.ruleId,
              };
              crossFileIssues.push(crossIssue);
            }
          }
        }
      }

      // Deduplicate cross-file issues (same from+to+source_issue or ruleId+file+line)
      const seen = new Set();
      crossFileIssues = crossFileIssues.filter(issue => {
        const key = issue.ruleId === 'cross-file-taint'
          ? `${issue.ruleId}|${issue.file}|${issue.line}|${issue.message}`
          : `${issue.file}|${issue.imported_file}|${issue.source_issue}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    } catch {
      // JS cross-file analysis failed — skip silently
    }

    // Add cross-file issues to allIssues
    for (const issue of crossFileIssues) {
      allIssues.push(issue);
      bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
    }
  }

  const grade = calculateGrade(allIssues.length, files.length, bySeverity.error);
  const level = verbosity || 'compact';

  if (level === 'minimal') {
    return {
      content: [{ type: "text", text: JSON.stringify({
        directory: dirPath,
        files_scanned: files.length,
        total: allIssues.length,
        critical: bySeverity.error,
        warning: bySeverity.warning,
        info: bySeverity.info,
        grade,
        message: allIssues.length > 0
          ? `Found ${allIssues.length} issue(s) across ${files.length} files. Grade: ${grade}`
          : `No issues found in ${files.length} files. Grade: ${grade}`
      }) }]
    };
  }

  if (level === 'compact') {
    // Show top issues per file, sorted by severity
    const topIssues = allIssues
      .sort((a, b) => {
        const order = { error: 0, warning: 1, info: 2 };
        return (order[a.severity] || 2) - (order[b.severity] || 2);
      })
      .slice(0, 50)
      .map(i => ({
        file: i.file,
        line: (i.line || 0) + 1,
        ruleId: i.ruleId,
        severity: i.severity,
        message: i.message
      }));

    return {
      content: [{ type: "text", text: JSON.stringify({
        directory: dirPath,
        files_scanned: files.length,
        issues_count: allIssues.length,
        grade,
        by_severity: bySeverity,
        by_category: byCategory,
        cross_file_issues: crossFileIssues.length > 0 ? crossFileIssues.length : undefined,
        issues: topIssues
      }, null, 2) }]
    };
  }

  // full
  return {
    content: [{ type: "text", text: JSON.stringify({
      directory: dirPath,
      files_scanned: files.length,
      issues_count: allIssues.length,
      grade,
      by_severity: bySeverity,
      by_category: byCategory,
      by_file: byFile,
      cross_file_issues: crossFileIssues.length > 0 ? crossFileIssues : undefined,
      issues: allIssues,
      scanned_files: files.map(f => relative(dirPath, f))
    }, null, 2) }]
  };
}
