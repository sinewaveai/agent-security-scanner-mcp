// src/tools/scan-action.js
import { z } from "zod";

export const scanAgentActionSchema = {
  action_type: z.enum(["bash", "file_write", "file_read", "http_request", "file_delete"])
    .describe("Type of agent action to evaluate"),
  action_value: z.string()
    .describe("The command, file path, or URL to check"),
  verbosity: z.enum(["minimal", "compact", "full"]).optional()
    .describe("Response detail level: 'minimal' (action only), 'compact' (default), 'full' (all details)")
};

// --- Detection rule definitions ---

const BASH_RULES = [
  // BLOCK: Destructive filesystem operations
  {
    rule: "bash.destructive.rm-rf",
    pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+-[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*r[a-zA-Z]*\s+-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*rf[a-zA-Z]*|-[a-zA-Z]*fr[a-zA-Z]*)\s+[/~*]/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Destructive recursive force-delete targeting root, home, or wildcard path"
  },
  // BLOCK: Remote code execution via pipe
  {
    rule: "bash.rce.curl-pipe-sh",
    pattern: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|ksh|dash|python|perl|ruby)\b/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Remote code execution: piping downloaded content directly into a shell interpreter"
  },
  // BLOCK: SQL destructive operations
  {
    rule: "bash.sql.drop-table",
    pattern: /\bDROP\s+TABLE\b/i,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "SQL DROP TABLE detected - destructive database operation"
  },
  {
    rule: "bash.sql.delete-no-where",
    pattern: /\bDELETE\s+FROM\s+\w+\s*(?:;|$)/i,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "SQL DELETE FROM without WHERE clause - will delete all rows"
  },
  // BLOCK: Disk operations
  {
    rule: "bash.disk.dd",
    pattern: /\bdd\s+if=/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Low-level disk write via dd - can destroy disk contents"
  },
  {
    rule: "bash.disk.mkfs",
    pattern: /\bmkfs\b/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Filesystem formatting via mkfs - will erase all data on target device"
  },
  // BLOCK: Credential file access
  {
    rule: "bash.credential.ssh-key-read",
    pattern: /\bcat\s+~?\/?\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Attempting to read SSH private key"
  },
  {
    rule: "bash.credential.etc-shadow",
    pattern: /\bcat\s+\/etc\/shadow\b/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Attempting to read /etc/shadow (password hashes)"
  },
  {
    rule: "bash.credential.aws-creds",
    pattern: /\bcat\s+~?\/?\.aws\/credentials\b/,
    severity: "CRITICAL",
    action: "BLOCK",
    message: "Attempting to read AWS credentials file"
  },
  // WARN: Overly permissive chmod
  {
    rule: "bash.permissions.chmod-777",
    pattern: /\bchmod\s+(777|666)\b/,
    severity: "HIGH",
    action: "WARN",
    message: "Overly permissive file permissions (world-readable/writable)"
  },
  // WARN: sudo usage
  {
    rule: "bash.escalation.sudo",
    pattern: /\bsudo\b/,
    severity: "MEDIUM",
    action: "WARN",
    message: "Privilege escalation via sudo"
  },
  // WARN: SSH key manipulation
  {
    rule: "bash.ssh.keygen",
    pattern: /\bssh-keygen\b/,
    severity: "MEDIUM",
    action: "WARN",
    message: "SSH key generation - may overwrite existing keys"
  },
  {
    rule: "bash.ssh.add",
    pattern: /\bssh-add\b/,
    severity: "MEDIUM",
    action: "WARN",
    message: "SSH agent key addition"
  },
  // WARN: Process killing
  {
    rule: "bash.process.kill-9",
    pattern: /\bkill\s+-9\b/,
    severity: "MEDIUM",
    action: "WARN",
    message: "Forceful process termination (SIGKILL)"
  },
  {
    rule: "bash.process.killall",
    pattern: /\bkillall\b/,
    severity: "MEDIUM",
    action: "WARN",
    message: "Bulk process termination via killall"
  },
  // WARN: Force push
  {
    rule: "bash.git.force-push",
    pattern: /\bgit\s+push\s+--force\b/,
    severity: "HIGH",
    action: "WARN",
    message: "Git force push - can overwrite remote history and cause data loss"
  },
  // WARN: Environment variable dumping with pipe
  {
    rule: "bash.env.dump-pipe",
    pattern: /\b(env|printenv)\b.*\|/,
    severity: "MEDIUM",
    action: "WARN",
    message: "Environment variable dump piped to another command - potential secret exfiltration"
  }
];

const SENSITIVE_FILE_PATTERNS = [
  { pattern: /(^|\/)\.env($|\.)/, label: ".env file", severity: "HIGH" },
  { pattern: /(^|\/)\.ssh\//, label: "SSH directory", severity: "CRITICAL" },
  { pattern: /credentials/i, label: "credentials file", severity: "HIGH" },
  { pattern: /secrets/i, label: "secrets file", severity: "HIGH" },
  { pattern: /(^|\/)\.github\/workflows\//, label: "GitHub Actions workflow", severity: "HIGH" },
  { pattern: /(^|\/)Dockerfile$/, label: "Dockerfile", severity: "MEDIUM" },
  { pattern: /(^|\/)docker-compose/, label: "Docker Compose file", severity: "MEDIUM" }
];

const SYSTEM_FILE_PATTERNS = [
  { pattern: /^\/etc\//, label: "/etc system config", severity: "CRITICAL" },
  { pattern: /^\/usr\//, label: "/usr system directory", severity: "CRITICAL" },
  { pattern: /^\/bin\//, label: "/bin system binaries", severity: "CRITICAL" }
];

const PACKAGE_FILE_PATTERNS = [
  { pattern: /(^|\/)package\.json$/, label: "npm package manifest", severity: "MEDIUM" },
  { pattern: /(^|\/)requirements\.txt$/, label: "Python requirements", severity: "MEDIUM" },
  { pattern: /(^|\/)Gemfile$/, label: "Ruby Gemfile", severity: "MEDIUM" },
  { pattern: /(^|\/)Cargo\.toml$/, label: "Rust Cargo manifest", severity: "MEDIUM" },
  { pattern: /(^|\/)go\.mod$/, label: "Go module file", severity: "MEDIUM" }
];

const CREDENTIAL_READ_PATTERNS = [
  { pattern: /(^|\/)\.env($|\.)/, label: ".env file", severity: "MEDIUM" },
  { pattern: /\.pem$/, label: "PEM certificate/key", severity: "HIGH" },
  { pattern: /\.key$/, label: "private key file", severity: "HIGH" },
  { pattern: /(^|\/)\.ssh\//, label: "SSH directory", severity: "HIGH" },
  { pattern: /credentials/i, label: "credentials file", severity: "HIGH" },
  { pattern: /secret/i, label: "secret file", severity: "HIGH" }
];

const PRIVATE_IP_PATTERNS = [
  { pattern: /\b127\.0\.0\.1\b/, label: "loopback address (127.0.0.1)" },
  { pattern: /\blocalhost\b/, label: "localhost" },
  { pattern: /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, label: "private IP (10.x.x.x)" },
  { pattern: /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/, label: "private IP (172.16-31.x.x)" },
  { pattern: /\b192\.168\.\d{1,3}\.\d{1,3}\b/, label: "private IP (192.168.x.x)" },
  { pattern: /\b169\.254\.\d{1,3}\.\d{1,3}\b/, label: "link-local address (169.254.x.x)" }
];

const EXFILTRATION_PATTERNS = [
  { pattern: /webhook\.site/i, label: "webhook.site" },
  { pattern: /requestbin/i, label: "RequestBin" },
  { pattern: /pastebin\.com/i, label: "Pastebin" },
  { pattern: /hookbin/i, label: "HookBin" },
  { pattern: /pipedream/i, label: "Pipedream" },
  { pattern: /ngrok\.io/i, label: "ngrok tunnel" },
  { pattern: /burpcollaborator/i, label: "Burp Collaborator" }
];

// --- Detection logic per action type ---

function checkBash(value) {
  const findings = [];
  const normalized = value.toLowerCase();

  for (const rule of BASH_RULES) {
    if (rule.pattern.test(value) || rule.pattern.test(normalized)) {
      findings.push({
        rule: rule.rule,
        severity: rule.severity,
        action: rule.action,
        message: rule.message
      });
    }
  }

  return findings;
}

function checkFileWrite(value) {
  const findings = [];

  // System files -> BLOCK
  for (const p of SYSTEM_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_write.system." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "CRITICAL",
        action: "BLOCK",
        message: `Writing to system path (${p.label}) is blocked`
      });
    }
  }

  // Sensitive files -> WARN
  for (const p of SENSITIVE_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_write.sensitive." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: p.severity,
        action: "WARN",
        message: `Writing to sensitive file (${p.label}) - review carefully`
      });
    }
  }

  // Package files -> WARN
  for (const p of PACKAGE_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_write.package." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: p.severity,
        action: "WARN",
        message: `Modifying dependency file (${p.label}) - may introduce supply chain risk`
      });
    }
  }

  return findings;
}

function checkFileRead(value) {
  const findings = [];

  for (const p of CREDENTIAL_READ_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_read.credential." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: p.severity,
        action: "WARN",
        message: `Reading credential/sensitive file (${p.label}) - potential secret exposure`
      });
    }
  }

  return findings;
}

function checkHttpRequest(value) {
  const findings = [];

  // SSRF: private/internal IPs -> BLOCK
  for (const p of PRIVATE_IP_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "http.ssrf." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "CRITICAL",
        action: "BLOCK",
        message: `SSRF risk: request targets internal/private address (${p.label})`
      });
    }
  }

  // Exfiltration patterns -> WARN
  for (const p of EXFILTRATION_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "http.exfiltration." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "HIGH",
        action: "WARN",
        message: `Potential data exfiltration: request targets known exfiltration service (${p.label})`
      });
    }
  }

  return findings;
}

function checkFileDelete(value) {
  const findings = [];

  // System files -> BLOCK
  for (const p of SYSTEM_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_delete.system." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "CRITICAL",
        action: "BLOCK",
        message: `Deleting system file (${p.label}) is blocked`
      });
    }
  }

  // Sensitive files -> BLOCK (upgraded from WARN)
  for (const p of SENSITIVE_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_delete.sensitive." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "CRITICAL",
        action: "BLOCK",
        message: `Deleting sensitive file (${p.label}) is blocked`
      });
    }
  }

  // Package files -> WARN (upgraded severity)
  for (const p of PACKAGE_FILE_PATTERNS) {
    if (p.pattern.test(value)) {
      findings.push({
        rule: "file_delete.package." + p.label.replace(/[^a-z0-9]/gi, '-').toLowerCase(),
        severity: "HIGH",
        action: "WARN",
        message: `Deleting dependency file (${p.label}) - may break project builds`
      });
    }
  }

  return findings;
}

// --- Risk level derivation ---

function deriveRiskLevel(findings) {
  if (findings.length === 0) return "NONE";

  const hasBlock = findings.some(f => f.action === "BLOCK");
  const hasCritical = findings.some(f => f.severity === "CRITICAL");
  const hasHigh = findings.some(f => f.severity === "HIGH");
  const hasMedium = findings.some(f => f.severity === "MEDIUM");

  if (hasBlock || hasCritical) return "CRITICAL";
  if (hasHigh) return "HIGH";
  if (hasMedium) return "MEDIUM";
  return "LOW";
}

// --- Overall action derivation ---

function deriveAction(findings) {
  if (findings.length === 0) return "ALLOW";
  if (findings.some(f => f.action === "BLOCK")) return "BLOCK";
  if (findings.some(f => f.action === "WARN")) return "WARN";
  return "ALLOW";
}

// --- Recommendation generation ---

function generateRecommendation(action, actionType, findings) {
  if (action === "ALLOW") {
    return "Action appears safe to proceed.";
  }

  if (action === "BLOCK") {
    const rules = findings.filter(f => f.action === "BLOCK").map(f => f.rule);
    return `Action BLOCKED due to: ${rules.join(', ')}. Do not execute this action. Consider a safer alternative.`;
  }

  // WARN
  const messages = findings.map(f => f.message);
  const uniqueMessages = [...new Set(messages)];
  return `Proceed with caution. ${uniqueMessages.length} concern(s): ${uniqueMessages.join('; ')}.`;
}

// --- Verbosity formatters ---

function formatMinimal(action, actionType, actionValue, riskLevel, findings) {
  return {
    action,
    action_type: actionType,
    risk_level: riskLevel,
    findings_count: findings.length,
    message: findings.length > 0
      ? `${action}: ${findings.length} concern(s) detected. Use verbosity='compact' for details.`
      : "ALLOW: No security concerns detected."
  };
}

function formatCompact(action, actionType, actionValue, riskLevel, findings, recommendation) {
  return {
    action,
    action_type: actionType,
    action_value: actionValue,
    risk_level: riskLevel,
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      message: f.message
    })),
    recommendation
  };
}

function formatFull(action, actionType, actionValue, riskLevel, findings, recommendation) {
  return {
    action,
    action_type: actionType,
    action_value: actionValue,
    risk_level: riskLevel,
    findings_count: findings.length,
    findings: findings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      action: f.action,
      message: f.message
    })),
    recommendation,
    timestamp: new Date().toISOString()
  };
}

// --- Exported handler ---

export async function scanAgentAction({ action_type, action_value, verbosity }) {
  let findings = [];

  switch (action_type) {
    case "bash":
      findings = checkBash(action_value);
      break;
    case "file_write":
      findings = checkFileWrite(action_value);
      break;
    case "file_read":
      findings = checkFileRead(action_value);
      break;
    case "http_request":
      findings = checkHttpRequest(action_value);
      break;
    case "file_delete":
      findings = checkFileDelete(action_value);
      break;
  }

  const action = deriveAction(findings);
  const riskLevel = deriveRiskLevel(findings);
  const recommendation = generateRecommendation(action, action_type, findings);

  const level = verbosity || "compact";

  let result;
  switch (level) {
    case "minimal":
      result = formatMinimal(action, action_type, action_value, riskLevel, findings);
      break;
    case "full":
      result = formatFull(action, action_type, action_value, riskLevel, findings, recommendation);
      break;
    case "compact":
    default:
      result = formatCompact(action, action_type, action_value, riskLevel, findings, recommendation);
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
