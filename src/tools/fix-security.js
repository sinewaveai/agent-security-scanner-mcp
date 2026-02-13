// src/tools/fix-security.js
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { detectLanguage, runAnalyzer, generateFix } from '../utils.js';
import { deduplicateFindings } from '../dedup.js';
import { applyContextFilter, detectFrameworks, applyFrameworkAdjustments } from '../context.js';
import { loadConfig, shouldExcludeFile, applyConfig } from '../config.js';

export const fixSecuritySchema = {
  file_path: z.string().describe("Path to the file to fix"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (summary only), 'compact' (default), 'full' (includes fixed_content)")
};

// Verbosity formatters
function formatFixMinimal(file_path, fixes) {
  return {
    file: file_path,
    fixes_applied: fixes.length,
    message: fixes.length > 0
      ? `Applied ${fixes.length} fix(es). Use verbosity='compact' for details.`
      : "No fixes needed."
  };
}

function formatFixCompact(file_path, fixes) {
  return {
    file: file_path,
    fixes_applied: fixes.length,
    fixes: fixes.map(f => ({
      line: f.line,
      rule: f.rule,
      description: f.description
    }))
  };
}

function formatFixFull(file_path, fixes, fixedContent) {
  return {
    file: file_path,
    fixes_applied: fixes.length,
    fixes: fixes,
    fixed_content: fixedContent
  };
}

export async function fixSecurity({ file_path, verbosity }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  // Load project configuration
  const config = loadConfig(file_path);

  // Check file exclusion
  if (shouldExcludeFile(file_path, config)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ file: file_path, message: "File excluded by configuration", fixes_applied: 0 }) }]
    };
  }

  const rawIssues = runAnalyzer(file_path);

  if (rawIssues.error || !Array.isArray(rawIssues) || rawIssues.length === 0) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          message: rawIssues.error ? "Error scanning file" : "No security issues found",
          details: rawIssues
        })
      }]
    };
  }

  // Cross-engine deduplication
  const dedupedIssues = deduplicateFindings(rawIssues);

  // Read and fix the file
  const content = readFileSync(file_path, 'utf-8');
  const lines = content.split('\n');
  const language = detectLanguage(file_path);

  // Context-aware filtering (suppress known module imports)
  const contextFiltered = applyContextFilter(dedupedIssues, file_path, language);

  // Framework-aware severity adjustment
  const frameworks = detectFrameworks(file_path, language);
  const frameworkAdjusted = applyFrameworkAdjustments(contextFiltered, frameworks);

  // Apply .scannerrc configuration (rule suppression, severity/confidence thresholds)
  const issues = applyConfig(frameworkAdjusted, file_path, config);

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

  // Determine verbosity (default: compact)
  const level = verbosity || 'compact';
  const fixedContent = lines.join('\n');

  let result;
  switch (level) {
    case 'minimal':
      result = formatFixMinimal(file_path, fixes);
      break;
    case 'full':
      result = formatFixFull(file_path, fixes, fixedContent);
      break;
    case 'compact':
    default:
      result = formatFixCompact(file_path, fixes);
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
