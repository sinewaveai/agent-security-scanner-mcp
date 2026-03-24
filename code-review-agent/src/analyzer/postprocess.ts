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
 * Patterns in reasoning/title indicating strong guard evidence.
 * Presence of these + no described bypass → suppress the finding.
 */
const STRONG_GUARD_PATTERNS = /\b(allowlist|allow.?list|whitelist|white.?list|hardcoded.*(commands?|hosts?|paths?|domains?)|shell\s*=\s*false|shell.?false|parameterized\s*(query|queries|statement)|bound\s*param|prepared\s*statement|host.?allowlist|scheme.?allowlist|immutable.*(list|set|array)|subprocess\.run\s*\(\s*\[)\b/i;

/**
 * Patterns suggesting the finding is about a guard module, not a sink.
 */
const GUARD_MODULE_PATTERNS = /\b(guard|policy|validator|validation|sanitiz|allowlist|denylist|blocklist|safelist|permission|authorize)\b/i;

/**
 * Phrases indicating the finding describes a weak/theoretical bypass
 * rather than a concrete exploit path.
 */
const WEAK_BYPASS_PHRASES = /\b(could\s+(potentially|theoretically|possibly)|may\s+be\s+bypass\w*|policy\s+(may|could|might)\s+(change|be\s+(expanded|modified|updated))|theoretically|in\s+theory|if\s+the\s+(allowlist|whitelist|policy)\s+(is|were|was)\s+(expanded|changed|modified)|future\s+changes?\s+(could|may|might))\b/i;

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

  return findings
    .filter((f) => isSecurityRelevant(f))
    .filter((f) => !isWeakGuardFinding(f));
}

/**
 * Detect findings that describe guarded code with no concrete bypass.
 * These are the "policy may be bypassed" false positives.
 */
function isWeakGuardFinding(finding: Finding): boolean {
  const text = `${finding.title} ${finding.reasoning}`;

  // Check if the finding mentions strong guard evidence
  const hasStrongGuard = STRONG_GUARD_PATTERNS.test(text);

  // Check if the finding is about a guard module rather than a sink
  const isAboutGuard = GUARD_MODULE_PATTERNS.test(finding.title) ||
    GUARD_MODULE_PATTERNS.test(finding.location.file);

  // Check if the bypass description is weak/theoretical
  const hasWeakBypass = WEAK_BYPASS_PHRASES.test(finding.reasoning);

  // Strong guard + weak/no bypass → suppress
  if (hasStrongGuard && (hasWeakBypass || finding.confidence < 0.7)) {
    return true;
  }

  // Finding is about a guard module + no concrete exploit + low confidence → suppress
  if (isAboutGuard && hasWeakBypass && finding.confidence < 0.8) {
    return true;
  }

  return false;
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
 * Patterns in file paths that suggest the file is a carrier/router, not a sink.
 */
const CARRIER_FILE_PATTERNS = /\b(router|route|planner|controller|handler|middleware|dispatch|orchestrat|wrapper|proxy|gateway|facade|adapter)\b/i;

/**
 * Patterns in file paths that suggest the file contains a dangerous sink.
 */
const SINK_FILE_PATTERNS = /\b(tool|service|executor|worker|client|db|database|query|fetch|request|command|process|infra|util)\b/i;

/**
 * Language in finding titles/reasoning that suggests carrier (pass-through) behavior.
 */
const CARRIER_LANGUAGE = /\b(passed\s+to|forwarded|through|reaches|via\s+(router|wrapper|handler|middleware|planner|controller)|routed\s+to|dispatched|delegates?\s+to|calls?\s+into|relayed|proxied)\b/i;

/**
 * Language suggesting the finding is at the actual dangerous operation.
 */
const SINK_LANGUAGE = /\b(execut(es?|ed|ing)|calls?\s+(subprocess|exec|eval|system|popen|spawn)|queries|fetche[sd]|request[sd]?\s+(to|from)|writes?\s+to|reads?\s+from|sends?\s+(request|query)|connects?\s+to|opens?\s+(file|connection|socket))\b/i;

/**
 * CWEs that are typically associated with sinks, not carriers.
 */
const SINK_CWES = new Set([
  'cwe-78',   // OS command injection
  'cwe-79',   // XSS
  'cwe-89',   // SQL injection
  'cwe-90',   // LDAP injection
  'cwe-91',   // XML injection
  'cwe-94',   // Code injection
  'cwe-95',   // Eval injection
  'cwe-98',   // Remote file inclusion
  'cwe-918',  // SSRF
  'cwe-22',   // Path traversal
  'cwe-77',   // Command injection
  'cwe-502',  // Deserialization
  'cwe-611',  // XXE
]);

/**
 * Compute a carrier/sink score for a finding.
 * Positive = more sink-like, negative = more carrier-like.
 */
function carrierSinkScore(finding: Finding): number {
  let score = 0;
  const text = `${finding.title} ${finding.reasoning}`;
  const filePath = finding.location.file.toLowerCase();

  // File path signals
  if (CARRIER_FILE_PATTERNS.test(filePath)) score -= 2;
  if (SINK_FILE_PATTERNS.test(filePath)) score += 2;

  // Language signals
  if (CARRIER_LANGUAGE.test(text)) score -= 2;
  if (SINK_LANGUAGE.test(text)) score += 2;

  // CWE-based signals — sink CWEs found in a tool/service file are strong sink signals
  if (finding.cwe && SINK_CWES.has(finding.cwe.toLowerCase())) score += 1;

  // Confidence as tiebreaker
  score += finding.confidence;

  return score;
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

    // Score each finding: higher = more sink-like
    const scored = group.map((f) => ({ finding: f, score: carrierSinkScore(f) }));
    scored.sort((a, b) => b.score - a.score);

    // Keep the most sink-like finding
    result.push(scored[0].finding);
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
