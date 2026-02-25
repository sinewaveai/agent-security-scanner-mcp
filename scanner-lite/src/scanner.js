// src/scanner.js — scan_security tool handler
import { z } from "zod";
import { existsSync, readFileSync, statSync } from "fs";
import { detectLanguage, runAnalyzerAsync, generateFix, toSarif, getEngineMode, extractImports, isTestFile } from './utils.js';
import { deduplicateFindings } from './dedup.js';
import { applyContextFilter, detectFrameworks, applyFrameworkAdjustments } from './context.js';
import { loadConfig, shouldExcludeFile, applyConfig } from './config.js';

const MAX_FILE_SIZE = 1024 * 1024;  // 1MB

export const scanSecuritySchema = {
  file_path: z.string().describe("Path to the file to scan"),
  output_format: z.enum(['json', 'sarif']).optional().describe("Output format: 'json' (default) or 'sarif' for GitHub/GitLab integration"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (counts only), 'compact' (default, actionable info), 'full' (complete metadata)"),
  engine: z.enum(['regex']).optional().describe("Analysis engine: 'regex' (pure JavaScript, no Python)"),
  include_context: z.boolean().optional().describe("Include surrounding code context for each issue")
};

function formatMinimal(file_path, language, issues) {
  const bySeverity = { error: 0, warning: 0, info: 0 };
  issues.forEach(i => bySeverity[i.severity] = (bySeverity[i.severity] || 0) + 1);
  return {
    file: file_path,
    language,
    engine_mode: getEngineMode(),
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
    engine_mode: getEngineMode(),
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
    engine_mode: getEngineMode(),
    issues_count: issues.length,
    issues: issues
  };
}

export async function scanSecurity({ file_path, output_format, verbosity, engine, include_context }) {
  if (!existsSync(file_path)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ error: "File not found" }) }]
    };
  }

  try {
    const stats = statSync(file_path);
    if (stats.size > MAX_FILE_SIZE) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            file: file_path,
            message: `File too large (${(stats.size / 1024).toFixed(0)}KB). Skipping to avoid timeout. Max size: ${MAX_FILE_SIZE / 1024}KB.`,
            issues_count: 0,
            skipped: true
          })
        }]
      };
    }
  } catch (err) {
    // If stat fails, continue anyway
  }

  const config = loadConfig(file_path);

  if (shouldExcludeFile(file_path, config)) {
    return {
      content: [{ type: "text", text: JSON.stringify({ file: file_path, message: "File excluded by configuration", issues_count: 0 }) }]
    };
  }

  const rawResult = await runAnalyzerAsync(file_path, engine || 'regex');

  if (rawResult.error) {
    return {
      content: [{ type: "text", text: JSON.stringify(rawResult) }]
    };
  }

  const rawFindings = rawResult.findings || rawResult;
  const dedupedIssues = deduplicateFindings(rawFindings);
  const content = readFileSync(file_path, 'utf-8');
  const lines = content.split('\n');
  const language = detectLanguage(file_path);
  const contextFiltered = applyContextFilter(dedupedIssues, file_path, language);
  const frameworks = detectFrameworks(file_path, language);
  const frameworkAdjusted = applyFrameworkAdjustments(contextFiltered, frameworks);
  const issues = applyConfig(frameworkAdjusted, file_path, config);

  const enhancedIssues = issues.map(issue => {
    const line = lines[issue.line] || '';
    const fix = generateFix(issue, line, language);
    const enhanced = {
      ...issue,
      line_content: line.trim(),
      suggested_fix: fix
    };

    if (include_context) {
      const lineIdx = issue.line;
      const contextLines = 3;
      enhanced.context_before = [];
      enhanced.context_after = [];
      for (let i = Math.max(0, lineIdx - contextLines); i < lineIdx; i++) {
        enhanced.context_before.push({ line: i + 1, content: lines[i] || '' });
      }
      for (let i = lineIdx + 1; i <= Math.min(lines.length - 1, lineIdx + contextLines); i++) {
        enhanced.context_after.push({ line: i + 1, content: lines[i] || '' });
      }
    }

    return enhanced;
  });

  const level = verbosity || 'compact';

  if (output_format === 'sarif') {
    return {
      content: [{
        type: "text",
        text: JSON.stringify(toSarif(enhancedIssues, file_path, language), null, 2)
      }]
    };
  }

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
