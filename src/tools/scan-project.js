// src/tools/scan-project.js
import { z } from "zod";
import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, resolve, relative, extname, basename } from "path";
import { execFileSync } from "child_process";
import { scanSecurity } from './scan-security.js';
import { matchGlob, loadConfig, shouldExcludeFile } from '../config.js';
import { detectLanguage } from '../utils.js';

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

  // Cross-file taint analysis (opt-in, max 50 files)
  let crossFileIssues = [];
  if (cross_file && files.length <= 50) {
    try {
      const { runCrossFileAnalyzer } = await import('../utils.js');
      if (typeof runCrossFileAnalyzer === 'function') {
        const crossResults = runCrossFileAnalyzer(files);
        if (Array.isArray(crossResults)) {
          crossFileIssues = crossResults;
          for (const issue of crossFileIssues) {
            const relativePath = relative(dirPath, issue.file || '');
            allIssues.push({ ...issue, file: relativePath });
            bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
          }
        }
      }
    } catch {
      // Cross-file analysis not available
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
