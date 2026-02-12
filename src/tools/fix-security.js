// src/tools/fix-security.js
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { detectLanguage, runAnalyzer, generateFix } from '../utils.js';

export const fixSecuritySchema = {
  file_path: z.string().describe("Path to the file to fix")
};

export async function fixSecurity({ file_path }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  const issues = runAnalyzer(file_path);

  if (issues.error || !Array.isArray(issues) || issues.length === 0) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          message: issues.error ? "Error scanning file" : "No security issues found",
          details: issues
        })
      }]
    };
  }

  // Read and fix the file
  const content = readFileSync(file_path, 'utf-8');
  const lines = content.split('\n');
  const language = detectLanguage(file_path);
  const fixes = [];

  // Apply fixes (process in reverse order to preserve line numbers)
  const sortedIssues = [...issues].sort((a, b) => b.line - a.line);

  for (const issue of sortedIssues) {
    const lineIndex = issue.line;
    if (lineIndex >= 0 && lineIndex < lines.length) {
      const originalLine = lines[lineIndex];
      const fix = generateFix(issue, originalLine, language);

      if (fix.fixed && fix.fixed !== originalLine) {
        lines[lineIndex] = fix.fixed;
        fixes.push({
          line: lineIndex + 1,
          rule: issue.ruleId,
          original: originalLine.trim(),
          fixed: fix.fixed.trim(),
          description: fix.description
        });
      }
    }
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        file: file_path,
        fixes_applied: fixes.length,
        fixes: fixes,
        fixed_content: lines.join('\n')
      }, null, 2)
    }]
  };
}
