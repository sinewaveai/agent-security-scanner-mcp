import type { Finding, Category } from '../types/findings.js';
import type { AnalysisMode } from '../types/config.js';

/**
 * Categories that are never security-relevant on their own.
 * In security mode these are dropped unless they have explicit security evidence.
 */
const NON_SECURITY_CATEGORIES: Set<Category> = new Set([
  'logic-bug',
  'type-error',
  'unhandled-exception',
  'null-ref',
  'other',
]);

/**
 * Categories always kept in security mode.
 */
const SECURITY_CATEGORIES: Set<Category> = new Set([
  'security',
  'boundary',
  'race-condition',
]);

/**
 * Keywords in title/reasoning that indicate security relevance
 * even when the category is generic.
 */
const SECURITY_KEYWORDS = /\b(injection|xss|csrf|ssrf|auth|privilege|escal|rce|command.?exec|deserialization|path.?traversal|directory.?traversal|overflow|underflow|sqli|lfi|rfi|open.?redirect|insecure|credential|secret|token.?leak|session.?fixation|sandbox.?escape)\b/i;

/**
 * Apply mode-aware post-filtering to findings.
 * In review mode, returns findings unchanged.
 * In security mode, drops non-security findings and suppresses weak evidence.
 */
export function postFilterFindings(
  findings: Finding[],
  mode: AnalysisMode,
): Finding[] {
  if (mode === 'review') return findings;

  return findings.filter((f) => isSecurityRelevant(f));
}

/**
 * Determines whether a finding should survive security-mode filtering.
 */
function isSecurityRelevant(finding: Finding): boolean {
  // Always keep explicit security categories
  if (SECURITY_CATEGORIES.has(finding.category)) return true;

  // For non-security categories, check for evidence of real security impact
  if (NON_SECURITY_CATEGORIES.has(finding.category)) {
    // Has a CWE — the LLM mapped it to a known weakness
    if (finding.cwe) return true;

    // Has an OWASP mapping
    if (finding.owasp) return true;

    // Title or reasoning contains security-specific language
    if (SECURITY_KEYWORDS.test(finding.title) || SECURITY_KEYWORDS.test(finding.reasoning)) {
      return true;
    }

    // Violates intent — could indicate a security issue, but only keep if high confidence
    if (finding.intentAlignment === 'violates-intent' && finding.confidence >= 0.8) {
      return true;
    }

    // Not enough security evidence — drop it
    return false;
  }

  // Unknown category — keep if it has any security indicator
  return !!(finding.cwe || finding.owasp || SECURITY_KEYWORDS.test(finding.title));
}

/**
 * Suppress carrier findings when a sink-localized equivalent exists.
 * A carrier finding describes data flowing through a file, while the sink
 * finding describes the actual dangerous operation in a downstream file.
 */
export function suppressCarrierFindings(findings: Finding[]): Finding[] {
  if (findings.length <= 1) return findings;

  // Group findings by normalized signature (CWE or title-based)
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = findingSignature(f);
    const group = groups.get(key) ?? [];
    group.push(f);
    groups.set(key, group);
  }

  const result: Finding[] = [];
  for (const group of groups.values()) {
    if (group.length <= 1) {
      result.push(...group);
      continue;
    }

    // If any finding in the group has higher confidence, it's likely the sink.
    // Keep only the highest-confidence finding per signature group.
    group.sort((a, b) => b.confidence - a.confidence);
    result.push(group[0]);
  }

  return result;
}

/**
 * Generate a normalized signature for grouping related findings.
 */
function findingSignature(f: Finding): string {
  // Use CWE as primary grouping key if available
  if (f.cwe) return `cwe:${f.cwe.toLowerCase()}`;

  // Fall back to a normalized title: lowercase, strip line numbers and file refs
  const normalized = f.title
    .toLowerCase()
    .replace(/\b(line|col|at)\s*\d+/g, '')
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  return `title:${normalized}`;
}
