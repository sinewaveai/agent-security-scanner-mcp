// src/history.js — Scan history tracking for team dashboard.
// Stores results in .scanner/results/ within the scanned project directory.

import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from 'fs';
import { join, basename } from 'path';

const RESULTS_DIR = '.scanner/results';

// Format a Date as YYYY-MM-DDTHH-MM-SS (filesystem-safe ISO timestamp)
function formatTimestamp(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
}

// Parse a YYYY-MM-DDTHH-MM-SS filename back into a Date
function parseTimestamp(filename) {
  // Extract timestamp from filename like "2024-01-15T10-30-45.json"
  const name = basename(filename, '.json');
  const match = name.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const [, year, month, day, hour, min, sec] = match.map(Number);
  return new Date(year, month - 1, day, hour, min, sec);
}

/**
 * Save a scan result to .scanner/results/YYYY-MM-DDTHH-MM-SS.json
 *
 * @param {string} dirPath - The scanned project directory
 * @param {object} scanResult - The scan result object from scanProject (parsed JSON output)
 * @returns {string} Path to the saved result file
 */
export function saveResult(dirPath, scanResult) {
  const resultsDir = join(dirPath, RESULTS_DIR);
  mkdirSync(resultsDir, { recursive: true });

  const now = new Date();
  const timestamp = formatTimestamp(now);
  const filename = `${timestamp}.json`;
  const filePath = join(resultsDir, filename);

  const historyEntry = {
    timestamp: now.toISOString(),
    directory: scanResult.directory || dirPath,
    grade: scanResult.grade || 'A',
    files_scanned: scanResult.files_scanned || 0,
    issues_count: scanResult.issues_count || scanResult.total || 0,
    by_severity: scanResult.by_severity || { error: 0, warning: 0, info: 0 },
    issues: scanResult.issues || [],
  };

  writeFileSync(filePath, JSON.stringify(historyEntry, null, 2) + '\n');
  return filePath;
}

/**
 * Load scan results from .scanner/results/ within the last N days.
 *
 * @param {string} dirPath - The scanned project directory
 * @param {number} days - Number of days to look back (default: 90)
 * @returns {object[]} Array of history entries, sorted oldest-first
 */
export function loadHistory(dirPath, days = 90) {
  const resultsDir = join(dirPath, RESULTS_DIR);
  if (!existsSync(resultsDir)) return [];

  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);

  let files;
  try {
    files = readdirSync(resultsDir).filter(f => f.endsWith('.json'));
  } catch {
    return [];
  }

  const results = [];
  for (const file of files) {
    const fileDate = parseTimestamp(file);
    if (!fileDate || fileDate < cutoff) continue;

    try {
      const content = readFileSync(join(resultsDir, file), 'utf-8');
      const entry = JSON.parse(content);
      results.push(entry);
    } catch {
      // Skip corrupt files
      continue;
    }
  }

  // Sort oldest-first by timestamp
  results.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  return results;
}

/**
 * Get trend data from scan history.
 *
 * @param {string} dirPath - The scanned project directory
 * @param {number} days - Number of days to look back (default: 90)
 * @returns {{ grades: Array<{date: string, grade: string}>, issues: Array<{date: string, total: number, critical: number, warning: number, info: number}> }}
 */
export function getTrends(dirPath, days = 90) {
  const history = loadHistory(dirPath, days);

  const grades = history.map(entry => ({
    date: entry.timestamp,
    grade: entry.grade,
  }));

  const issues = history.map(entry => {
    const severity = entry.by_severity || {};
    return {
      date: entry.timestamp,
      total: entry.issues_count || 0,
      critical: severity.error || 0,
      warning: severity.warning || 0,
      info: severity.info || 0,
    };
  });

  return { grades, issues };
}

/**
 * Compare two scan results to find new, fixed, and unchanged issues.
 * Issues are compared by ruleId + file + line.
 *
 * @param {object} current - Current scan result (must have .issues array)
 * @param {object} previous - Previous scan result (must have .issues array)
 * @returns {{ new_issues: object[], fixed_issues: object[], unchanged: number }}
 */
export function diffResults(current, previous) {
  const currentIssues = current.issues || [];
  const previousIssues = previous.issues || [];

  // Build a key for each issue: ruleId + file + line
  function issueKey(issue) {
    return `${issue.ruleId || ''}::${issue.file || ''}::${issue.line || 0}`;
  }

  const currentKeys = new Set(currentIssues.map(issueKey));
  const previousKeys = new Set(previousIssues.map(issueKey));

  // New issues: in current but not in previous
  const newIssues = currentIssues.filter(i => !previousKeys.has(issueKey(i)));

  // Fixed issues: in previous but not in current
  const fixedIssues = previousIssues.filter(i => !currentKeys.has(issueKey(i)));

  // Unchanged: in both
  const unchanged = currentIssues.filter(i => previousKeys.has(issueKey(i))).length;

  return {
    new_issues: newIssues,
    fixed_issues: fixedIssues,
    unchanged,
  };
}
