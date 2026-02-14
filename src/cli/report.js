// src/cli/report.js — Generate HTML (or JSON) security report for a project.

import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { resolve, join } from 'path';
import { scanProject } from '../tools/scan-project.js';
import { saveResult, loadHistory, getTrends, diffResults } from '../history.js';

// Grade color mapping
const GRADE_COLORS = {
  A: '#22c55e', // green
  B: '#84cc16', // lime
  C: '#eab308', // yellow
  D: '#f97316', // orange
  F: '#ef4444', // red
};

// Severity color mapping
const SEVERITY_COLORS = {
  error: '#ef4444',
  warning: '#f97316',
  info: '#3b82f6',
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Build SVG bar chart for severity breakdown
function buildSeverityChart(bySeverity) {
  const error = bySeverity.error || 0;
  const warning = bySeverity.warning || 0;
  const info = bySeverity.info || 0;
  const max = Math.max(error, warning, info, 1);

  const barWidth = 200;
  const barHeight = 24;
  const gap = 8;
  const labelWidth = 70;
  const countWidth = 40;

  const bars = [
    { label: 'Critical', count: error, color: SEVERITY_COLORS.error },
    { label: 'Warning', count: warning, color: SEVERITY_COLORS.warning },
    { label: 'Info', count: info, color: SEVERITY_COLORS.info },
  ];

  const svgHeight = bars.length * (barHeight + gap) + gap;
  const svgWidth = labelWidth + barWidth + countWidth + 20;

  let svg = `<svg width="${svgWidth}" height="${svgHeight}" xmlns="http://www.w3.org/2000/svg" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px;">`;

  bars.forEach((bar, i) => {
    const y = gap + i * (barHeight + gap);
    const width = max > 0 ? Math.max((bar.count / max) * barWidth, bar.count > 0 ? 4 : 0) : 0;

    svg += `<text x="0" y="${y + barHeight / 2 + 4}" fill="#374151">${bar.label}</text>`;
    svg += `<rect x="${labelWidth}" y="${y}" width="${width}" height="${barHeight}" rx="4" fill="${bar.color}" opacity="0.85"/>`;
    svg += `<text x="${labelWidth + barWidth + 8}" y="${y + barHeight / 2 + 4}" fill="#374151" font-weight="600">${bar.count}</text>`;
  });

  svg += '</svg>';
  return svg;
}

// Build SVG trend sparkline for grades over time
function buildGradeTrend(grades) {
  if (grades.length < 2) return '';

  const gradeValues = { A: 4, B: 3, C: 2, D: 1, F: 0 };
  const width = 300;
  const height = 80;
  const padding = 20;
  const plotWidth = width - padding * 2;
  const plotHeight = height - padding * 2;

  const points = grades.map((g, i) => {
    const x = padding + (i / (grades.length - 1)) * plotWidth;
    const y = padding + (1 - (gradeValues[g.grade] || 0) / 4) * plotHeight;
    return { x, y, grade: g.grade, date: g.date };
  });

  let svg = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 10px;">`;

  // Grid lines for each grade
  ['A', 'B', 'C', 'D', 'F'].forEach(grade => {
    const y = padding + (1 - (gradeValues[grade]) / 4) * plotHeight;
    svg += `<line x1="${padding}" y1="${y}" x2="${width - padding}" y2="${y}" stroke="#e5e7eb" stroke-width="1"/>`;
    svg += `<text x="${padding - 14}" y="${y + 3}" fill="#9ca3af" font-size="9">${grade}</text>`;
  });

  // Line connecting points
  const pathData = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
  svg += `<path d="${pathData}" fill="none" stroke="#6366f1" stroke-width="2"/>`;

  // Dots
  points.forEach(p => {
    const color = GRADE_COLORS[p.grade] || '#6b7280';
    svg += `<circle cx="${p.x}" cy="${p.y}" r="3" fill="${color}"/>`;
  });

  svg += '</svg>';
  return svg;
}

// Build category breakdown table
function buildCategoryTable(byCategory) {
  if (!byCategory || Object.keys(byCategory).length === 0) return '';

  const sorted = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);

  let html = `<table style="border-collapse: collapse; width: 100%; margin-top: 8px;">
    <thead><tr style="border-bottom: 2px solid #e5e7eb;">
      <th style="text-align: left; padding: 8px 12px; color: #374151;">Category</th>
      <th style="text-align: right; padding: 8px 12px; color: #374151;">Issues</th>
    </tr></thead><tbody>`;

  for (const [category, count] of sorted) {
    html += `<tr style="border-bottom: 1px solid #f3f4f6;">
      <td style="padding: 6px 12px; color: #4b5563;">${escapeHtml(category)}</td>
      <td style="padding: 6px 12px; text-align: right; font-weight: 600; color: #374151;">${count}</td>
    </tr>`;
  }

  html += '</tbody></table>';
  return html;
}

// Build top offending files table
function buildFileTable(byFile) {
  if (!byFile || Object.keys(byFile).length === 0) return '';

  const sorted = Object.entries(byFile)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  if (sorted.length === 0) return '';

  let html = `<table style="border-collapse: collapse; width: 100%; margin-top: 8px;">
    <thead><tr style="border-bottom: 2px solid #e5e7eb;">
      <th style="text-align: left; padding: 8px 12px; color: #374151;">File</th>
      <th style="text-align: right; padding: 8px 12px; color: #374151;">Issues</th>
    </tr></thead><tbody>`;

  for (const [file, count] of sorted) {
    html += `<tr style="border-bottom: 1px solid #f3f4f6;">
      <td style="padding: 6px 12px; color: #4b5563; font-family: monospace; font-size: 13px;">${escapeHtml(file)}</td>
      <td style="padding: 6px 12px; text-align: right; font-weight: 600; color: #374151;">${count}</td>
    </tr>`;
  }

  html += '</tbody></table>';
  return html;
}

// Build diff section showing new/fixed issues
function buildDiffSection(diff) {
  if (!diff) return '';

  let html = '<div style="margin-top: 24px;">';
  html += '<h2 style="color: #1f2937; font-size: 18px; margin-bottom: 12px;">Changes Since Last Scan</h2>';

  html += `<div style="display: flex; gap: 24px; margin-bottom: 16px;">`;
  html += `<div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 12px 20px; flex: 1; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: #ef4444;">${diff.new_issues.length}</div>
    <div style="font-size: 13px; color: #991b1b;">New Issues</div>
  </div>`;
  html += `<div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 12px 20px; flex: 1; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: #22c55e;">${diff.fixed_issues.length}</div>
    <div style="font-size: 13px; color: #166534;">Fixed Issues</div>
  </div>`;
  html += `<div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 20px; flex: 1; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: #6b7280;">${diff.unchanged}</div>
    <div style="font-size: 13px; color: #4b5563;">Unchanged</div>
  </div>`;
  html += '</div>';

  // List new issues
  if (diff.new_issues.length > 0) {
    html += '<h3 style="color: #991b1b; font-size: 15px; margin: 12px 0 8px;">New Issues</h3>';
    html += '<ul style="list-style: none; padding: 0; margin: 0;">';
    for (const issue of diff.new_issues.slice(0, 20)) {
      const sevColor = SEVERITY_COLORS[issue.severity] || '#6b7280';
      html += `<li style="padding: 4px 0; font-size: 13px; color: #374151;">
        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${sevColor}; margin-right: 8px;"></span>
        <strong>${escapeHtml(issue.ruleId || '')}</strong> in <code style="background: #f3f4f6; padding: 1px 4px; border-radius: 3px;">${escapeHtml(issue.file || '')}</code> line ${(issue.line || 0) + 1}
      </li>`;
    }
    html += '</ul>';
  }

  // List fixed issues
  if (diff.fixed_issues.length > 0) {
    html += '<h3 style="color: #166534; font-size: 15px; margin: 12px 0 8px;">Fixed Issues</h3>';
    html += '<ul style="list-style: none; padding: 0; margin: 0;">';
    for (const issue of diff.fixed_issues.slice(0, 20)) {
      html += `<li style="padding: 4px 0; font-size: 13px; color: #374151;">
        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: 8px;"></span>
        <strong>${escapeHtml(issue.ruleId || '')}</strong> in <code style="background: #f3f4f6; padding: 1px 4px; border-radius: 3px;">${escapeHtml(issue.file || '')}</code> line ${(issue.line || 0) + 1}
      </li>`;
    }
    html += '</ul>';
  }

  html += '</div>';
  return html;
}

// Build issues detail table
function buildIssuesTable(issues) {
  if (!issues || issues.length === 0) return '';

  // Sort by severity: error first, then warning, then info
  const order = { error: 0, warning: 1, info: 2 };
  const sorted = [...issues].sort((a, b) => (order[a.severity] ?? 2) - (order[b.severity] ?? 2));
  const shown = sorted.slice(0, 100);

  let html = `<table style="border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 13px;">
    <thead><tr style="border-bottom: 2px solid #e5e7eb;">
      <th style="text-align: left; padding: 8px 8px; color: #374151;">Severity</th>
      <th style="text-align: left; padding: 8px 8px; color: #374151;">Rule</th>
      <th style="text-align: left; padding: 8px 8px; color: #374151;">File</th>
      <th style="text-align: right; padding: 8px 8px; color: #374151;">Line</th>
      <th style="text-align: left; padding: 8px 8px; color: #374151;">Message</th>
    </tr></thead><tbody>`;

  for (const issue of shown) {
    const sevColor = SEVERITY_COLORS[issue.severity] || '#6b7280';
    const sevLabel = issue.severity === 'error' ? 'CRITICAL' : issue.severity === 'warning' ? 'WARNING' : 'INFO';
    html += `<tr style="border-bottom: 1px solid #f3f4f6;">
      <td style="padding: 6px 8px;"><span style="display: inline-block; padding: 2px 8px; border-radius: 4px; background: ${sevColor}; color: white; font-size: 11px; font-weight: 600;">${sevLabel}</span></td>
      <td style="padding: 6px 8px; font-family: monospace; color: #4b5563;">${escapeHtml(issue.ruleId || '')}</td>
      <td style="padding: 6px 8px; font-family: monospace; color: #4b5563; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(issue.file || '')}</td>
      <td style="padding: 6px 8px; text-align: right; color: #6b7280;">${(issue.line || 0) + 1}</td>
      <td style="padding: 6px 8px; color: #374151; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(issue.message || '')}</td>
    </tr>`;
  }

  html += '</tbody></table>';

  if (issues.length > 100) {
    html += `<p style="color: #6b7280; font-size: 13px; margin-top: 8px;">Showing 100 of ${issues.length} issues.</p>`;
  }

  return html;
}

// Generate the full HTML report
function generateHtml(scanResult, history, diff) {
  const grade = scanResult.grade || 'A';
  const gradeColor = GRADE_COLORS[grade] || '#6b7280';
  const bySeverity = scanResult.by_severity || { error: 0, warning: 0, info: 0 };
  const byCategory = scanResult.by_category || {};
  const byFile = scanResult.by_file || {};
  const issues = scanResult.issues || [];
  const filesScanned = scanResult.files_scanned || 0;
  const issuesCount = scanResult.issues_count || scanResult.total || 0;
  const directory = scanResult.directory || '';
  const timestamp = new Date().toISOString();

  // Trend data
  let trendSection = '';
  if (history.grades && history.grades.length >= 2) {
    trendSection = `
      <div style="margin-top: 24px;">
        <h2 style="color: #1f2937; font-size: 18px; margin-bottom: 12px;">Grade Trend</h2>
        ${buildGradeTrend(history.grades)}
      </div>`;
  }

  // Diff section
  const diffSection = diff ? buildDiffSection(diff) : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report - ${escapeHtml(directory)}</title>
</head>
<body style="margin: 0; padding: 0; background: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1f2937;">
  <div style="max-width: 900px; margin: 0 auto; padding: 32px 24px;">

    <!-- Header -->
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 32px;">
      <div>
        <h1 style="margin: 0 0 4px; font-size: 24px; color: #111827;">Security Report</h1>
        <p style="margin: 0; font-size: 14px; color: #6b7280;">${escapeHtml(directory)}</p>
        <p style="margin: 4px 0 0; font-size: 12px; color: #9ca3af;">Generated ${timestamp}</p>
      </div>
      <div style="text-align: center; background: white; border: 3px solid ${gradeColor}; border-radius: 16px; width: 80px; height: 80px; display: flex; flex-direction: column; align-items: center; justify-content: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size: 36px; font-weight: 800; color: ${gradeColor}; line-height: 1;">${grade}</div>
        <div style="font-size: 10px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px;">Grade</div>
      </div>
    </div>

    <!-- Summary Cards -->
    <div style="display: flex; gap: 16px; margin-bottom: 24px;">
      <div style="background: white; border-radius: 12px; padding: 16px 20px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <div style="font-size: 28px; font-weight: 700; color: #111827;">${filesScanned}</div>
        <div style="font-size: 13px; color: #6b7280;">Files Scanned</div>
      </div>
      <div style="background: white; border-radius: 12px; padding: 16px 20px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <div style="font-size: 28px; font-weight: 700; color: ${issuesCount > 0 ? '#ef4444' : '#22c55e'};">${issuesCount}</div>
        <div style="font-size: 13px; color: #6b7280;">Total Issues</div>
      </div>
      <div style="background: white; border-radius: 12px; padding: 16px 20px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <div style="font-size: 28px; font-weight: 700; color: #ef4444;">${bySeverity.error || 0}</div>
        <div style="font-size: 13px; color: #6b7280;">Critical</div>
      </div>
      <div style="background: white; border-radius: 12px; padding: 16px 20px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <div style="font-size: 28px; font-weight: 700; color: #f97316;">${bySeverity.warning || 0}</div>
        <div style="font-size: 13px; color: #6b7280;">Warnings</div>
      </div>
    </div>

    <!-- Severity Chart -->
    <div style="background: white; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
      <h2 style="margin: 0 0 12px; font-size: 18px; color: #1f2937;">Findings by Severity</h2>
      ${buildSeverityChart(bySeverity)}
    </div>

    <!-- Two-column: Categories + Top Files -->
    <div style="display: flex; gap: 24px; margin-bottom: 24px;">
      <div style="background: white; border-radius: 12px; padding: 20px 24px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <h2 style="margin: 0 0 8px; font-size: 18px; color: #1f2937;">Findings by Category</h2>
        ${buildCategoryTable(byCategory)}
      </div>
      <div style="background: white; border-radius: 12px; padding: 20px 24px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
        <h2 style="margin: 0 0 8px; font-size: 18px; color: #1f2937;">Top Offending Files</h2>
        ${buildFileTable(byFile)}
      </div>
    </div>

    <!-- Trend Section (if history exists) -->
    ${trendSection ? `<div style="background: white; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">${trendSection}</div>` : ''}

    <!-- Diff Section (if previous scan exists) -->
    ${diffSection ? `<div style="background: white; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">${diffSection}</div>` : ''}

    <!-- Issues Detail -->
    ${issues.length > 0 ? `
    <div style="background: white; border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
      <h2 style="margin: 0 0 8px; font-size: 18px; color: #1f2937;">All Issues</h2>
      ${buildIssuesTable(issues)}
    </div>` : ''}

    <!-- Footer -->
    <div style="text-align: center; padding: 16px 0; color: #9ca3af; font-size: 12px;">
      Generated by agent-security-scanner-mcp
    </div>

  </div>
</body>
</html>`;
}

/**
 * Run the report CLI command.
 *
 * @param {string[]} args - CLI arguments: <directory> [--json] [--days N]
 */
export async function runReport(args) {
  const dirArg = args.find(a => !a.startsWith('--'));
  if (!dirArg) {
    console.error('Usage: agent-security-scanner-mcp report <directory> [--json] [--days N]');
    process.exit(1);
  }

  const dirPath = resolve(dirArg);
  if (!existsSync(dirPath)) {
    console.error(`  Error: Directory not found: ${dirPath}\n`);
    process.exit(1);
  }

  const jsonOutput = args.includes('--json');
  const daysIdx = args.indexOf('--days');
  const days = daysIdx !== -1 && args[daysIdx + 1] ? parseInt(args[daysIdx + 1], 10) : 90;

  console.log(`\n  Scanning ${dirPath}...\n`);

  // Run the project scan with full verbosity to get all data
  const result = await scanProject({
    directory_path: dirPath,
    verbosity: 'full',
  });
  const scanResult = JSON.parse(result.content[0].text);

  // Save result to history
  const savedPath = saveResult(dirPath, scanResult);
  console.log(`  Results saved to ${savedPath}`);

  // Load history for trends
  const trends = getTrends(dirPath, days);

  // Load previous scan for diff (second-to-last entry, since we just saved the current one)
  const history = loadHistory(dirPath, days);
  let diff = null;
  if (history.length >= 2) {
    const previous = history[history.length - 2];
    diff = diffResults(scanResult, previous);
  }

  if (jsonOutput) {
    // JSON output mode
    const jsonReport = {
      ...scanResult,
      trends,
      diff,
      generated_at: new Date().toISOString(),
    };
    console.log(JSON.stringify(jsonReport, null, 2));
    return;
  }

  // Generate HTML report
  const html = generateHtml(scanResult, trends, diff);
  const scannerDir = join(dirPath, '.scanner');
  mkdirSync(scannerDir, { recursive: true });
  const reportPath = join(scannerDir, 'report.html');
  writeFileSync(reportPath, html);

  console.log(`  Report written to ${reportPath}`);

  // Print summary
  const grade = scanResult.grade || 'A';
  const total = scanResult.issues_count || scanResult.total || 0;
  const filesScanned = scanResult.files_scanned || 0;
  console.log(`\n  Grade: ${grade} | ${total} issue(s) across ${filesScanned} file(s)`);

  if (diff) {
    const newCount = diff.new_issues.length;
    const fixedCount = diff.fixed_issues.length;
    if (newCount > 0 || fixedCount > 0) {
      console.log(`  Changes: +${newCount} new, -${fixedCount} fixed`);
    }
  }

  console.log('');
}
