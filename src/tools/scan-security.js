// src/tools/scan-security.js
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { detectLanguage, runAnalyzer, generateFix, toSarif } from '../utils.js';

export const scanSecuritySchema = {
  file_path: z.string().describe("Path to the file to scan"),
  output_format: z.enum(['json', 'sarif']).optional().describe("Output format: 'json' (default) or 'sarif' for GitHub/GitLab integration")
};

export async function scanSecurity({ file_path, output_format }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  const issues = runAnalyzer(file_path);

  if (issues.error) {
    return {
      content: [{ type: "text", text: JSON.stringify(issues) }]
    };
  }

  // Read file content for fix suggestions
  const content = readFileSync(file_path, 'utf-8');
  const lines = content.split('\n');
  const language = detectLanguage(file_path);

  // Enhance issues with fix suggestions
  const enhancedIssues = issues.map(issue => {
    const line = lines[issue.line] || '';
    const fix = generateFix(issue, line, language);
    return {
      ...issue,
      line_content: line.trim(),
      suggested_fix: fix
    };
  });

  // Return SARIF format if requested
  if (output_format === 'sarif') {
    return {
      content: [{
        type: "text",
        text: JSON.stringify(toSarif(file_path, language, enhancedIssues), null, 2)
      }]
    };
  }

  // Default JSON format
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        file: file_path,
        language: language,
        issues_count: enhancedIssues.length,
        issues: enhancedIssues
      }, null, 2)
    }]
  };
}
