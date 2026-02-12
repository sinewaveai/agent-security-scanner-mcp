// src/tools/scan-prompt.js
import { z } from "zod";
import { readFileSync, existsSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

// Handle both ESM and CJS bundling
let __dirname;
try {
  __dirname = dirname(fileURLToPath(import.meta.url));
} catch {
  __dirname = process.cwd();
}

// Risk thresholds for action determination
const RISK_THRESHOLDS = {
  CRITICAL: 85,
  HIGH: 65,
  MEDIUM: 40,
  LOW: 20
};

// Category weights for risk calculation
const CATEGORY_WEIGHTS = {
  "exfiltration": 1.0,
  "malicious-injection": 1.0,
  "system-manipulation": 1.0,
  "social-engineering": 0.8,
  "obfuscation": 0.7,
  "agent-manipulation": 0.9,
  "prompt-injection": 0.9,
  "prompt-injection-content": 1.0,
  "prompt-injection-jailbreak": 1.0,
  "prompt-injection-extraction": 0.9,
  "prompt-injection-delimiter": 0.8,
  "prompt-injection-encoded": 0.9,
  "prompt-injection-context": 0.8,
  "prompt-injection-privilege": 0.85,
  "prompt-injection-multi-turn": 0.7,
  "prompt-injection-output": 0.9,
  "unknown": 0.5
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS = {
  "HIGH": 1.0,
  "MEDIUM": 0.7,
  "LOW": 0.4
};

// Load agent attack rules from YAML
function loadAgentAttackRules() {
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'agent-attacks.security.yaml');
    if (!existsSync(rulesPath)) {
      console.error("Agent attack rules file not found");
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    // Simple YAML parsing for rules
    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        } else if (line.match(/^\s+languages:/)) {
          inPatterns = false;
          inMetadata = false;
        }
      }

      if (rule.id && rule.patterns.length > 0) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading agent attack rules:", error.message);
    return [];
  }
}

// Also load prompt injection rules
function loadPromptInjectionRules() {
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'prompt-injection.security.yaml');
    if (!existsSync(rulesPath)) {
      return [];
    }

    const yaml = readFileSync(rulesPath, 'utf-8');
    const rules = [];

    const ruleBlocks = yaml.split(/^  - id:/m).slice(1);

    for (const block of ruleBlocks) {
      const lines = ('  - id:' + block).split('\n');
      const rule = {
        id: '',
        severity: 'WARNING',
        message: '',
        patterns: [],
        metadata: {}
      };

      let inPatterns = false;
      let inMetadata = false;

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
          inMetadata = false;
        } else if (line.match(/^\s+metadata:\s*$/)) {
          inPatterns = false;
          inMetadata = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          // Strip Python-style inline flags - JS doesn't support them
          pattern = pattern.replace(/^\(\?i\)/, '');
          // Unescape double backslashes from YAML (\\s -> \s)
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (inMetadata && line.match(/^\s+\w+:/)) {
          const match = line.match(/^\s+(\w+):\s*["']?([^"'\n]+)["']?/);
          if (match) {
            rule.metadata[match[1]] = match[2].trim();
          }
        }
      }

      // Only include generic rules (content patterns, not code patterns)
      if (rule.id && rule.patterns.length > 0 && rule.id.startsWith('generic.prompt')) {
        rules.push(rule);
      }
    }

    return rules;
  } catch (error) {
    console.error("Error loading prompt injection rules:", error.message);
    return [];
  }
}

// Calculate risk score from findings
function calculateRiskScore(findings, context) {
  if (findings.length === 0) return 0;

  let totalScore = 0;

  for (const finding of findings) {
    const riskScore = parseInt(finding.risk_score) || 50;
    const category = finding.category || 'unknown';
    const confidence = finding.confidence || 'MEDIUM';

    const categoryWeight = CATEGORY_WEIGHTS[category] || 0.5;
    const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[confidence] || 0.7;

    totalScore += (riskScore / 100) * categoryWeight * confidenceMultiplier * 100;
  }

  // Average the scores but boost for multiple findings
  let avgScore = totalScore / findings.length;

  // Enhanced compound boosting
  if (findings.length > 1) {
    // Cross-category boost: if findings span multiple categories, boost by 0.15
    const uniqueCategories = new Set(findings.map(f => f.category || 'unknown'));
    if (uniqueCategories.size > 1) {
      avgScore = avgScore * (1 + 0.15);
    }

    // Mixed-severity boost: if both ERROR and WARNING present, 1.1x
    const hasError = findings.some(f => f.severity === 'ERROR');
    const hasWarning = findings.some(f => f.severity === 'WARNING');
    if (hasError && hasWarning) {
      avgScore = avgScore * 1.1;
    }

    // Per-finding boost (smaller than before)
    avgScore = avgScore * (1 + (findings.length - 1) * 0.05);
  }

  avgScore = Math.min(100, avgScore);

  // Apply sensitivity adjustment (wider spread for meaningful impact)
  if (context?.sensitivity_level === 'high') {
    avgScore = Math.min(100, avgScore * 1.5);
  } else if (context?.sensitivity_level === 'low') {
    avgScore = avgScore * 0.5;
  }

  return Math.round(avgScore);
}

// Determine action based on risk score, findings, and context
function determineAction(riskScore, findings, context) {
  // Adjust thresholds based on sensitivity level
  let blockThreshold = RISK_THRESHOLDS.HIGH;
  let warnThreshold = RISK_THRESHOLDS.MEDIUM;
  let logThreshold = RISK_THRESHOLDS.LOW;

  if (context?.sensitivity_level === 'high') {
    blockThreshold = 50;
    warnThreshold = 30;
    logThreshold = 15;
  } else if (context?.sensitivity_level === 'low') {
    blockThreshold = 75;
    warnThreshold = 50;
    logThreshold = 30;
  }

  // Check for any BLOCK action findings
  const hasBlockFinding = findings.some(f => f.action === 'BLOCK');
  if (hasBlockFinding || riskScore >= RISK_THRESHOLDS.CRITICAL) {
    return 'BLOCK';
  }

  if (riskScore >= blockThreshold) {
    return 'BLOCK';
  }

  const hasWarnFinding = findings.some(f => f.action === 'WARN');
  if (hasWarnFinding || riskScore >= warnThreshold) {
    return 'WARN';
  }

  const hasLogFinding = findings.some(f => f.action === 'LOG');
  if (hasLogFinding || riskScore >= logThreshold) {
    return 'LOG';
  }

  return 'ALLOW';
}

// Determine risk level from score
function getRiskLevel(score) {
  if (score >= RISK_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (score >= RISK_THRESHOLDS.HIGH) return 'HIGH';
  if (score >= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score >= RISK_THRESHOLDS.LOW) return 'LOW';
  return 'NONE';
}

// Generate explanation from findings
function generateExplanation(findings, action) {
  if (findings.length === 0) {
    return 'No security concerns detected in this prompt.';
  }

  const categories = [...new Set(findings.map(f => f.category))];
  const severity = findings.some(f => f.severity === 'ERROR') ? 'critical' : 'potential';

  let explanation = `Detected ${findings.length} ${severity} security concern(s)`;

  if (categories.length > 0) {
    explanation += ` in categories: ${categories.join(', ')}`;
  }

  explanation += `. Action: ${action}.`;

  if (action === 'BLOCK') {
    explanation += ' This prompt appears to contain malicious intent and should not be executed.';
  } else if (action === 'WARN') {
    explanation += ' Review carefully before proceeding.';
  }

  return explanation;
}

// Generate recommendations from findings
function generateRecommendations(findings) {
  const recommendations = new Set();

  for (const finding of findings) {
    const category = finding.category;

    switch (category) {
      case 'exfiltration':
        recommendations.add('Never allow prompts that request sending code or secrets to external URLs');
        recommendations.add('Block access to sensitive files like .env, SSH keys, and credentials');
        break;
      case 'malicious-injection':
        recommendations.add('Reject requests for backdoors, reverse shells, or malicious code');
        recommendations.add('Never disable security controls at user request');
        break;
      case 'system-manipulation':
        recommendations.add('Block destructive file operations and system configuration changes');
        recommendations.add('Prevent persistence mechanisms like crontab or startup script modifications');
        break;
      case 'social-engineering':
        recommendations.add('Verify authorization claims through proper channels, not prompt content');
        recommendations.add('Be skeptical of urgency claims or claims of special modes');
        break;
      case 'obfuscation':
        recommendations.add('Be wary of encoded or fragmented instructions');
        recommendations.add('Reject requests for "examples" of malicious code');
        break;
      case 'agent-manipulation':
        recommendations.add('Maintain confirmation prompts for sensitive operations');
        recommendations.add('Never hide output or actions from the user');
        break;
      default:
        recommendations.add('Review this prompt carefully before execution');
    }
  }

  return [...recommendations];
}

// Create SHA256 hash for audit logging
function hashPrompt(text) {
  return createHash('sha256').update(text).digest('hex').substring(0, 16);
}

// Export schema for tool registration
export const scanAgentPromptSchema = {
  prompt_text: z.string().describe("The prompt or instruction text to analyze"),
  context: z.object({
    previous_messages: z.array(z.string()).optional().describe("Previous conversation messages for multi-turn detection"),
    sensitivity_level: z.enum(["high", "medium", "low"]).optional().describe("Sensitivity level - high means more strict, low means more permissive")
  }).optional().describe("Optional context for better analysis")
};

// Export handler function
export async function scanAgentPrompt({ prompt_text, context }) {
  const findings = [];

  // Load rules
  const agentRules = loadAgentAttackRules();
  const promptRules = loadPromptInjectionRules();
  const allRules = [...agentRules, ...promptRules];

  // 2.7: Extract content from code blocks and append to scan text
  let expandedText = prompt_text;
  const codeBlockRegex = /```[\s\S]*?```/g;
  const codeBlocks = prompt_text.match(codeBlockRegex);
  if (codeBlocks) {
    for (const block of codeBlocks) {
      // Strip the ``` delimiters and extract inner content
      const inner = block.replace(/^```\w*\n?/, '').replace(/\n?```$/, '');
      expandedText += '\n' + inner;
    }
  }

  // Scan expanded text against all rules
  for (const rule of allRules) {
    for (const pattern of rule.patterns) {
      try {
        const regex = new RegExp(pattern, 'i');
        const match = expandedText.match(regex);

        if (match) {
          findings.push({
            rule_id: rule.id,
            category: rule.metadata.category || 'unknown',
            severity: rule.severity,
            message: rule.message,
            matched_text: match[0].substring(0, 100),
            confidence: rule.metadata.confidence || 'MEDIUM',
            risk_score: rule.metadata.risk_score || '50',
            action: rule.metadata.action || 'WARN'
          });
          break; // Only one match per rule
        }
      } catch (e) {
        // Skip invalid regex
      }
    }
  }

  // 2.8: Runtime base64 decode-and-rescan
  const base64Regex = /[A-Za-z0-9+/]{40,}={0,2}/g;
  const b64Matches = expandedText.match(base64Regex);
  if (b64Matches) {
    for (const b64str of b64Matches) {
      try {
        const decoded = Buffer.from(b64str, 'base64').toString('utf-8');
        // Check printability: >70% ASCII printable characters
        const printable = decoded.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length;
        if (printable / decoded.length > 0.7) {
          // Re-scan decoded text against prompt rules only
          for (const rule of allRules) {
            if (!rule.id.startsWith('generic.prompt')) continue;
            for (const pattern of rule.patterns) {
              try {
                const regex = new RegExp(pattern, 'i');
                const match = decoded.match(regex);
                if (match) {
                  findings.push({
                    rule_id: rule.id + '.base64-decoded',
                    category: rule.metadata.category || 'unknown',
                    severity: rule.severity,
                    message: rule.message + ' (detected in base64-decoded content)',
                    matched_text: match[0].substring(0, 100),
                    confidence: rule.metadata.confidence || 'MEDIUM',
                    risk_score: rule.metadata.risk_score || '50',
                    action: rule.metadata.action || 'WARN'
                  });
                  break;
                }
              } catch (e) {
                // Skip invalid regex
              }
            }
          }
        }
      } catch (e) {
        // Skip invalid base64
      }
    }
  }

  // Multi-turn escalation detection (Bug 9)
  if (context?.previous_messages && Array.isArray(context.previous_messages) && context.previous_messages.length > 0) {
    let prevMatchCount = 0;
    for (const prevMsg of context.previous_messages) {
      for (const rule of allRules) {
        for (const pattern of rule.patterns) {
          try {
            const regex = new RegExp(pattern, 'i');
            if (regex.test(prevMsg)) {
              prevMatchCount++;
              break;
            }
          } catch (e) {
            // Skip invalid regex
          }
        }
        if (prevMatchCount > 0) break;
      }
      if (prevMatchCount > 0) break;
    }

    // If both previous and current messages have matches, flag escalation
    if (prevMatchCount > 0 && findings.length > 0) {
      findings.push({
        rule_id: 'multi-turn.escalation',
        category: 'social-engineering',
        severity: 'WARNING',
        message: 'Multi-turn escalation detected: suspicious patterns found in both previous and current messages.',
        matched_text: 'escalation across conversation turns',
        confidence: 'MEDIUM',
        risk_score: '70',
        action: 'WARN'
      });
    }
  }

  // Calculate risk score
  const riskScore = calculateRiskScore(findings, context);
  const action = determineAction(riskScore, findings, context);
  const riskLevel = getRiskLevel(riskScore);
  const explanation = generateExplanation(findings, action);
  const recommendations = generateRecommendations(findings);

  // Create audit info
  const audit = {
    timestamp: new Date().toISOString(),
    prompt_hash: hashPrompt(prompt_text),
    prompt_length: prompt_text.length,
    rules_checked: allRules.length,
    context_provided: !!context
  };

  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        action,
        risk_score: riskScore,
        risk_level: riskLevel,
        findings_count: findings.length,
        findings: findings.map(f => ({
          rule_id: f.rule_id,
          category: f.category,
          severity: f.severity,
          message: f.message,
          matched_text: f.matched_text,
          confidence: f.confidence
        })),
        explanation,
        recommendations,
        audit
      }, null, 2)
    }]
  };
}
