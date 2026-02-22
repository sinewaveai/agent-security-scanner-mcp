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
  // OpenClaw-specific categories
  "data_exfiltration": 1.0,
  "messaging_abuse": 0.95,
  "credential_theft": 1.0,
  "autonomous_harm": 0.9,
  "service_attack": 0.95,
  "unknown": 0.5
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS = {
  "HIGH": 1.0,
  "MEDIUM": 0.7,
  "LOW": 0.4
};

// Maximum prompt size to prevent DoS via large inputs (100KB)
const MAX_PROMPT_SIZE = 100 * 1024;

// Rule caches — loaded once per process, not on every call
let _agentAttackRulesCache = null;
let _promptInjectionRulesCache = null;
let _openClawRulesCache = null;

// Load agent attack rules from YAML
function loadAgentAttackRules() {
  if (_agentAttackRulesCache !== null) return _agentAttackRulesCache;
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'agent-attacks.security.yaml');
    if (!existsSync(rulesPath)) {
      console.error("Agent attack rules file not found");
      _agentAttackRulesCache = [];
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

    _agentAttackRulesCache = rules;
    return rules;
  } catch (error) {
    console.error("Error loading agent attack rules:", error.message);
    _agentAttackRulesCache = [];
    return [];
  }
}

// Also load prompt injection rules
function loadPromptInjectionRules() {
  if (_promptInjectionRulesCache !== null) return _promptInjectionRulesCache;
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'prompt-injection.security.yaml');
    if (!existsSync(rulesPath)) {
      _promptInjectionRulesCache = [];
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

    _promptInjectionRulesCache = rules;
    return rules;
  } catch (error) {
    console.error("Error loading prompt injection rules:", error.message);
    _promptInjectionRulesCache = [];
    return [];
  }
}

// Load OpenClaw-specific rules
function loadOpenClawRules() {
  if (_openClawRulesCache !== null) return _openClawRulesCache;
  try {
    const rulesPath = join(__dirname, '..', '..', 'rules', 'openclaw.security.yaml');
    if (!existsSync(rulesPath)) {
      _openClawRulesCache = [];
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

      for (const line of lines) {
        if (line.match(/^\s+- id:\s*/)) {
          rule.id = line.replace(/^\s+- id:\s*/, '').trim();
        } else if (line.match(/^\s+severity:\s*/)) {
          rule.severity = line.replace(/^\s+severity:\s*/, '').trim();
        } else if (line.match(/^\s+category:\s*/)) {
          rule.metadata.category = line.replace(/^\s+category:\s*/, '').trim();
        } else if (line.match(/^\s+action:\s*/)) {
          rule.metadata.action = line.replace(/^\s+action:\s*/, '').trim();
        } else if (line.match(/^\s+message:\s*/)) {
          rule.message = line.replace(/^\s+message:\s*["']?/, '').replace(/["']$/, '').trim();
        } else if (line.match(/^\s+patterns:\s*$/)) {
          inPatterns = true;
        } else if (inPatterns && line.match(/^\s+- /)) {
          let pattern = line.replace(/^\s+- /, '').trim();
          pattern = pattern.replace(/^["']|["']$/g, '');
          pattern = pattern.replace(/\\\\/g, '\\');
          if (pattern) rule.patterns.push(pattern);
        } else if (line.match(/^\s+\w+:/) && !line.match(/^\s+- /)) {
          inPatterns = false;
        }
      }

      if (rule.id && rule.patterns.length > 0) {
        // Set confidence and risk score based on severity
        rule.metadata.confidence = rule.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM';
        rule.metadata.risk_score = rule.severity === 'CRITICAL' ? '90' : '70';
        rules.push(rule);
      }
    }

    _openClawRulesCache = rules;
    return rules;
  } catch (error) {
    console.error("Error loading OpenClaw rules:", error.message);
    _openClawRulesCache = [];
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
  }).optional().describe("Optional context for better analysis"),
  verbosity: z.enum(['minimal', 'compact', 'full']).optional().describe("Response detail level: 'minimal' (action only), 'compact' (default), 'full' (all details)")
};

// Export handler function
export async function scanAgentPrompt({ prompt_text, context, verbosity }) {
  // Guard against oversized inputs that could cause DoS via regex scanning
  if (prompt_text.length > MAX_PROMPT_SIZE) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          action: "BLOCK",
          risk_level: "HIGH",
          error: `Prompt too large (${prompt_text.length} bytes, max ${MAX_PROMPT_SIZE}). Reduce size or split into smaller chunks.`
        }, null, 2)
      }]
    };
  }

  const findings = [];

  // Load rules
  const agentRules = loadAgentAttackRules();
  const promptRules = loadPromptInjectionRules();
  const openclawRules = loadOpenClawRules();
  const allRules = [...agentRules, ...promptRules, ...openclawRules];

  // 2.7: Extract content from code blocks (``` and ~~~) and append to scan text
  let expandedText = prompt_text;
  const codeBlockRegex = /(`{3,})([\s\S]*?)\1|(~{3,})([\s\S]*?)\3/g;
  let codeBlockMatch;
  while ((codeBlockMatch = codeBlockRegex.exec(prompt_text)) !== null) {
    // Group 2 = content inside backtick fences, Group 4 = content inside tilde fences
    const inner = (codeBlockMatch[2] || codeBlockMatch[4] || '')
      .replace(/^\w*\n?/, '');  // strip optional language tag
    expandedText += '\n' + inner;
  }

  // 2.7b: Defragment string concatenation patterns ("a" + "b" → "ab")
  // Handles both "..." + "..." and '...' + '...' and mixed
  let defragmented = expandedText;
  const concatRegex = /(["'])([^"']*?)\1\s*\+\s*(["'])([^"']*?)\3/g;
  let prevDefrag;
  do {
    prevDefrag = defragmented;
    defragmented = defragmented.replace(concatRegex, (_, q1, s1, _q2, s2) => `${q1}${s1}${s2}${q1}`);
  } while (defragmented !== prevDefrag);
  if (defragmented !== expandedText) {
    expandedText += '\n' + defragmented;
  }

  // 2.7c: Detect Morse code and decode common attack patterns
  const morsePattern = /(?:[\.\-]{1,5}\s+){4,}/;
  if (morsePattern.test(expandedText)) {
    const MORSE_MAP = {
      '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
      '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
      '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
      '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
      '.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
      '-....':'6','--...':'7','---..':'8','----.':'9','-----':'0'
    };
    try {
      const decoded = expandedText.split(/\s*\/\s*/).map(word =>
        word.trim().split(/\s+/).map(c => MORSE_MAP[c] || '').join('')
      ).join(' ');
      if (decoded.replace(/\s/g, '').length >= 5) {
        expandedText += '\n' + decoded;
      }
    } catch (e) {
      // Skip invalid morse
    }
  }

  // 2.7d: Strip Zalgo diacritics — NFKD decompose first, then strip combining marks
  const nfkd = expandedText.normalize('NFKD');
  const zalgoStripped = nfkd.replace(/[\u0300-\u036f\u0488\u0489\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/g, '');
  if (zalgoStripped !== expandedText) {
    expandedText += '\n' + zalgoStripped;
  }

  // 2.7e: Detect Braille Unicode and decode to ASCII (standard Braille dot patterns)
  const braillePattern = /[\u2800-\u28FF]{3,}/;
  if (braillePattern.test(expandedText)) {
    const BRAILLE_MAP = {
      1:'a',3:'b',9:'c',25:'d',17:'e',11:'f',27:'g',19:'h',
      10:'i',26:'j',5:'k',7:'l',13:'m',29:'n',21:'o',15:'p',
      31:'q',23:'r',14:'s',30:'t',37:'u',39:'v',58:'w',45:'x',
      61:'y',53:'z',0:' '
    };
    try {
      const decoded = expandedText.replace(/[\u2800-\u28FF]+/g, match => {
        return Array.from(match).map(ch => {
          const cp = ch.codePointAt(0) - 0x2800;
          return BRAILLE_MAP[cp] || '';
        }).join('');
      });
      if (decoded.replace(/\s/g, '').length >= 5) {
        expandedText += '\n' + decoded;
      }
    } catch (e) {
      // Skip invalid braille
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
        if (printable / decoded.length > 0.5) {
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

  // Multi-turn escalation detection — sliding-window risk accumulator
  if (context?.previous_messages && Array.isArray(context.previous_messages) && context.previous_messages.length > 0) {
    // Score each previous message for suspicious content
    let prevTotalScore = 0;
    let prevMessagesWithFindings = 0;

    for (const prevMsg of context.previous_messages) {
      let msgHasMatch = false;
      for (const rule of allRules) {
        for (const pattern of rule.patterns) {
          try {
            const regex = new RegExp(pattern, 'i');
            if (regex.test(prevMsg)) {
              prevTotalScore += parseInt(rule.metadata?.risk_score || '50') / 100;
              msgHasMatch = true;
              break;
            }
          } catch (e) {
            // Skip invalid regex
          }
        }
      }
      if (msgHasMatch) prevMessagesWithFindings++;
    }

    // Sliding window: sensitivity increases proportionally with prior findings
    if (prevMessagesWithFindings > 0 && findings.length > 0) {
      const escalationSeverity = prevMessagesWithFindings >= 2 ? 'ERROR' : 'WARNING';
      const escalationScore = Math.min(90, 50 + prevMessagesWithFindings * 15);
      const escalationAction = prevMessagesWithFindings >= 2 ? 'BLOCK' : 'WARN';

      findings.push({
        rule_id: 'multi-turn.escalation',
        category: 'prompt-injection-multi-turn',
        severity: escalationSeverity,
        message: `Multi-turn escalation detected: ${prevMessagesWithFindings} prior message(s) contained suspicious patterns. Combined with current findings, this indicates a coordinated attack.`,
        matched_text: `escalation across ${prevMessagesWithFindings + 1} conversation turns`,
        confidence: prevMessagesWithFindings >= 2 ? 'HIGH' : 'MEDIUM',
        risk_score: String(escalationScore),
        action: escalationAction
      });
    }

    // Standalone multi-turn escalation: 2+ prior suspicious turns even if current is clean
    if (prevMessagesWithFindings >= 2 && findings.length === 0) {
      const escalationScore = Math.min(75, 40 + prevMessagesWithFindings * 10);
      findings.push({
        rule_id: 'multi-turn.prior-context-escalation',
        category: 'prompt-injection-multi-turn',
        severity: 'WARNING',
        message: `Elevated risk context: ${prevMessagesWithFindings} prior messages contained suspicious patterns. Current message appears benign but conversation context warrants caution.`,
        matched_text: `${prevMessagesWithFindings} prior suspicious messages`,
        confidence: 'MEDIUM',
        risk_score: String(escalationScore),
        action: 'WARN'
      });
    }
  }

  // Composite pattern detection — multiple low-severity indicators = escalated severity
  if (findings.length >= 2) {
    const categories = new Set(findings.map(f => f.category));
    const indicators = {
      hasRoleReassignment: findings.some(f =>
        f.category === 'prompt-injection-jailbreak' || f.category === 'prompt-injection-context'
      ),
      hasEncodedContent: findings.some(f =>
        f.category === 'prompt-injection-encoded' || f.category === 'obfuscation'
      ),
      hasUrgency: findings.some(f =>
        f.category === 'social-engineering'
      ),
      hasExfiltration: findings.some(f =>
        f.category === 'prompt-injection-output' || f.category === 'exfiltration'
      ),
      hasPrivilegeEscalation: findings.some(f =>
        f.category === 'prompt-injection-privilege'
      )
    };

    const activeIndicators = Object.values(indicators).filter(Boolean).length;

    // 2+ distinct indicator types → composite attack (graduated risk_score)
    if (activeIndicators >= 2) {
      const riskScore = activeIndicators >= 3 ? 95 : 80;
      findings.push({
        rule_id: 'composite.multi-vector-attack',
        category: 'prompt-injection-content',
        severity: 'ERROR',
        message: `Composite attack detected: ${activeIndicators} distinct attack vectors identified (${[...categories].join(', ')}). Multiple low-severity indicators combine to form a high-confidence threat.`,
        matched_text: `${activeIndicators} attack vectors across ${findings.length} findings`,
        confidence: 'HIGH',
        risk_score: String(riskScore),
        action: 'BLOCK'
      });
    } else if (categories.size >= 2) {
      findings.push({
        rule_id: 'composite.cross-category-escalation',
        category: 'prompt-injection-content',
        severity: 'WARNING',
        message: `Cross-category escalation: findings span ${categories.size} categories (${[...categories].join(', ')}). Review for coordinated attack attempt.`,
        matched_text: `${categories.size} categories across ${findings.length} findings`,
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

  // Determine verbosity (default: compact)
  const level = verbosity || 'compact';

  let result;
  switch (level) {
    case 'minimal':
      result = {
        action,
        risk_level: riskLevel,
        findings_count: findings.length,
        message: findings.length > 0
          ? `${action}: ${findings.length} concern(s) detected. Use verbosity='compact' for details.`
          : "ALLOW: No security concerns detected."
      };
      break;
    case 'full':
      result = {
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
      };
      break;
    case 'compact':
    default:
      result = {
        action,
        risk_score: riskScore,
        risk_level: riskLevel,
        findings_count: findings.length,
        findings: findings.map(f => ({
          rule_id: f.rule_id,
          severity: f.severity,
          message: f.message
        })),
        recommendations
      };
  }

  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2)
    }]
  };
}
