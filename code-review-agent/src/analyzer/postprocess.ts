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
  if (mode !== 'security') return findings;

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

  // Strong guard + weak/theoretical bypass language → suppress
  // Low confidence alone is NOT enough — the model may be cautious but correct
  if (hasStrongGuard && hasWeakBypass) {
    return true;
  }

  // Finding is about a guard module + weak bypass language + low confidence → suppress
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

  // Phase 1: group by CWE (cross-file) or per-file title
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = findingSignature(f);
    const group = groups.get(key) ?? [];
    group.push(f);
    groups.set(key, group);
  }

  // Phase 2: for no-CWE findings, merge cross-file groups when carrier/sink signals
  // indicate they describe the same issue flowing across files.
  const titleGroups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.cwe) continue;
    const key = normalizedTitle(f);
    const group = titleGroups.get(key) ?? [];
    group.push(f);
    titleGroups.set(key, group);
  }

  // If a cross-file title group has at least one carrier and one sink signal,
  // collapse it — otherwise leave per-file groups intact.
  const suppressedFiles = new Set<string>();
  for (const group of titleGroups.values()) {
    if (group.length <= 1) continue;
    // Check if group spans multiple files
    const files = new Set(group.map((f) => f.location.file));
    if (files.size <= 1) continue;

    // Require language signals in the finding text, not just file-path patterns.
    // File path alone is too aggressive — a "Missing authorization check" in
    // controller/users.js and service/admin.js are likely distinct real findings.
    const hasCarrier = group.some((f) => {
      const text = `${f.title} ${f.reasoning}`;
      return CARRIER_LANGUAGE.test(text);
    });
    const hasSink = group.some((f) => {
      const text = `${f.title} ${f.reasoning}`;
      return SINK_LANGUAGE.test(text);
    });

    if (hasCarrier && hasSink) {
      // Collapse: keep the most sink-like finding
      const scored = group.map((f) => ({ finding: f, score: carrierSinkScore(f) }));
      scored.sort((a, b) => b.score - a.score);
      // Mark all but the winner for suppression
      for (let i = 1; i < scored.length; i++) {
        const f = scored[i].finding;
        suppressedFiles.add(`${f.location.file}:${f.location.startLine}:${f.title}`);
      }
    }
  }

  // Phase 3: collapse CWE-based groups as before, and apply no-CWE suppression
  const result: Finding[] = [];
  for (const [key, group] of groups) {
    if (group.length <= 1) {
      const f = group[0];
      const suppKey = `${f.location.file}:${f.location.startLine}:${f.title}`;
      if (!suppressedFiles.has(suppKey)) {
        result.push(f);
      }
      continue;
    }

    // For multi-item groups: filter out suppressed findings first, then score
    const unsuppressed = group.filter((f) => {
      const suppKey = `${f.location.file}:${f.location.startLine}:${f.title}`;
      return !suppressedFiles.has(suppKey);
    });

    if (unsuppressed.length === 0) continue;
    if (unsuppressed.length === 1) {
      result.push(unsuppressed[0]);
      continue;
    }

    // CWE groups or remaining multi-item: score and keep best
    const scored = unsuppressed.map((f) => ({ finding: f, score: carrierSinkScore(f) }));
    scored.sort((a, b) => b.score - a.score);
    result.push(scored[0].finding);
  }

  return result;
}

/**
 * Normalize a title for grouping (strips noise, lowercases).
 */
function normalizedTitle(f: Finding): string {
  return f.title
    .toLowerCase()
    .replace(/\b(line|col|at)\s*\d+/g, '')
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Generate a normalized signature for grouping related findings.
 * CWE-based grouping is cross-file (carrier/sink suppression).
 * Title-based grouping is per-file to avoid collapsing distinct findings
 * with generic titles like "Missing authorization check" in different files.
 */
function findingSignature(f: Finding): string {
  // Use CWE as primary grouping key — cross-file is intentional for carrier/sink dedup
  if (f.cwe) return `cwe:${f.cwe.toLowerCase()}`;

  // Per-file title grouping: prevents collapsing distinct findings across files
  return `title:${f.location.file}:${normalizedTitle(f)}`;
}
