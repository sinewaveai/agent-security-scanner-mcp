// src/tools/scan-diff.js
import { z } from "zod";
import { execFileSync } from "child_process";
import { existsSync } from "fs";
import { scanSecurity } from './scan-security.js';

export const scanDiffSchema = {
  base_ref: z.string().optional().describe("Base git ref (default: HEAD~1)"),
  target_ref: z.string().optional().describe("Target git ref (default: HEAD)"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level")
};

// Parse unified diff output to extract changed files and line ranges
function parseDiffOutput(diffOutput) {
  const changes = new Map(); // filePath -> Set<lineNumber>
  let currentFile = null;

  for (const line of diffOutput.split('\n')) {
    // Match diff header: +++ b/path/to/file
    const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
    if (fileMatch) {
      currentFile = fileMatch[1];
      if (!changes.has(currentFile)) {
        changes.set(currentFile, new Set());
      }
      continue;
    }

    // Match hunk header: @@ -old,count +new,count @@
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (hunkMatch && currentFile) {
      const start = parseInt(hunkMatch[1], 10);
      const count = parseInt(hunkMatch[2] || '1', 10);
      const fileChanges = changes.get(currentFile);
      for (let i = start; i < start + count; i++) {
        fileChanges.add(i);
      }
    }
  }

  return changes;
}

export async function scanDiff({ base_ref, target_ref, verbosity }) {
  const base = base_ref || 'HEAD~1';
  const target = target_ref || 'HEAD';

  // Get diff output
  let diffOutput;
  try {
    diffOutput = execFileSync('git', ['diff', '--unified=0', `${base}...${target}`], {
      encoding: 'utf-8',
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024
    });
  } catch (err) {
    // Try without three-dot notation (for uncommitted changes)
    try {
      diffOutput = execFileSync('git', ['diff', '--unified=0', base, target], {
        encoding: 'utf-8',
        timeout: 30000,
        maxBuffer: 10 * 1024 * 1024
      });
    } catch (err2) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Git diff failed: ${err2.message}` }) }]
      };
    }
  }

  if (!diffOutput.trim()) {
    return {
      content: [{ type: "text", text: JSON.stringify({ message: "No changes found between refs", base, target, issues_count: 0 }) }]
    };
  }

  // Parse diff to get changed files and lines
  const changes = parseDiffOutput(diffOutput);
  const allIssues = [];
  const scannedFiles = [];

  // Scan each changed file
  for (const [filePath, changedLines] of changes) {
    if (!existsSync(filePath)) continue;

    const result = await scanSecurity({ file_path: filePath, verbosity: 'full' });
    const parsed = JSON.parse(result.content[0].text);

    if (parsed.issues && Array.isArray(parsed.issues)) {
      // Filter to only issues on changed lines
      const diffIssues = parsed.issues.filter(issue => {
        const issueLine = (issue.line || 0) + 1; // convert 0-indexed to 1-indexed
        return changedLines.has(issueLine);
      });

      for (const issue of diffIssues) {
        allIssues.push({ ...issue, file: filePath });
      }
    }
    scannedFiles.push(filePath);
  }

  // Format based on verbosity
  const level = verbosity || 'compact';

  if (level === 'minimal') {
    const bySeverity = { error: 0, warning: 0, info: 0 };
    allIssues.forEach(i => bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1);
    return {
      content: [{ type: "text", text: JSON.stringify({
        base, target,
        files_scanned: scannedFiles.length,
        total: allIssues.length,
        critical: bySeverity.error,
        warning: bySeverity.warning,
        info: bySeverity.info,
        message: allIssues.length > 0
          ? `Found ${allIssues.length} new issue(s) in changed code.`
          : "No new security issues in changed code."
      }) }]
    };
  }

  if (level === 'compact') {
    return {
      content: [{ type: "text", text: JSON.stringify({
        base, target,
        files_scanned: scannedFiles.length,
        issues_count: allIssues.length,
        issues: allIssues.map(i => ({
          file: i.file,
          line: (i.line || 0) + 1,
          ruleId: i.ruleId,
          severity: i.severity,
          message: i.message
        }))
      }, null, 2) }]
    };
  }

  // full
  return {
    content: [{ type: "text", text: JSON.stringify({
      base, target,
      files_scanned: scannedFiles.length,
      issues_count: allIssues.length,
      issues: allIssues,
      changed_files: Array.from(changes.keys())
    }, null, 2) }]
  };
}
