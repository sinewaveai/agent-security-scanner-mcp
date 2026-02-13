// src/tools/scan-security.js
import { z } from "zod";
import { existsSync, readFileSync } from "fs";
import { detectLanguage, runAnalyzer, generateFix, toSarif } from '../utils.js';
import { deduplicateFindings } from '../dedup.js';
import { applyContextFilter, detectFrameworks, applyFrameworkAdjustments } from '../context.js';
import { loadConfig, shouldExcludeFile, applyConfig } from '../config.js';

export const scanSecuritySchema = {
  file_path: z.string().describe("Path to the file to scan"),
  output_format: z.enum(['json', 'sarif']).optional().describe("Output format: 'json' (default) or 'sarif' for GitHub/GitLab integration"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (counts only), 'compact' (default, actionable info), 'full' (complete metadata)"),
  engine: z.enum(['auto', 'ast', 'regex']).optional().describe("Analysis engine: 'auto' (default, AST with regex fallback), 'ast' (tree-sitter only), 'regex' (regex only)")
};

// Verbosity formatters
function formatMinimal(file_path, language, issues) {
  const bySeverity = { error: 0, warning: 0, info: 0 };
  issues.forEach(i => bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1);
  return {
    file: file_path,
    language,
    total: issues.length,
    critical: bySeverity.error,
    warning: bySeverity.warning,
    info: bySeverity.info,
    message: issues.length > 0
      ? `Found ${issues.length} issue(s). Use verbosity='compact' for details.`
      : "No security issues found."
  };
}

function formatCompact(file_path, language, issues) {
  return {
    file: file_path,
    language,
    issues_count: issues.length,
    issues: issues.map(i => ({
      line: i.line + 1,
      ruleId: i.ruleId,
      severity: i.severity,
      confidence: i.confidence || 'MEDIUM',
      message: i.message,
      fix: i.suggested_fix?.fixed ? i.suggested_fix.fixed.trim() : null
    }))
  };
}

function formatFull(file_path, language, issues) {
  return {
    file: file_path,
    language,
    issues_count: issues.length,
    issues: issues
  };
}

export async function scanSecurity({ file_path, output_format, verbosity, engine }) {
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
      content: [{ type: "text", text: JSON.stringify({ file: file_path, message: "File excluded by configuration", issues_count: 0 }) }]
    };
  }

  const rawIssues = runAnalyzer(file_path, engine || 'auto');

  if (rawIssues.error) {
    return {
      content: [{ type: "text", text: JSON.stringify(rawIssues) }]
    };
  }

  // Cross-engine deduplication
  const dedupedIssues = deduplicateFindings(rawIssues);

  // Read file content for fix suggestions
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

  // Determine verbosity (default: compact)
  const level = verbosity || 'compact';

  // Return SARIF format if requested (always full detail)
  if (output_format === 'sarif') {
    return {
      content: [{
        type: "text",
        text: JSON.stringify(toSarif(file_path, language, enhancedIssues), null, 2)
      }]
    };
  }

  // Format based on verbosity
  let result;
  switch (level) {
    case 'minimal':
      result = formatMinimal(file_path, language, enhancedIssues);
      break;
    case 'full':
      result = formatFull(file_path, language, enhancedIssues);
      break;
    case 'compact':
    default:
      result = formatCompact(file_path, language, enhancedIssues);
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
