import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

// Risk thresholds
const RISK_THRESHOLDS = {
    CRITICAL: 85,
    HIGH: 70,
    MEDIUM: 50,
    LOW: 25
};

// Category weights for risk calculation
const CATEGORY_WEIGHTS: Record<string, number> = {
    'exfiltration': 1.0,
    'malicious-injection': 1.0,
    'system-manipulation': 1.0,
    'social-engineering': 0.8,
    'obfuscation': 0.7,
    'agent-manipulation': 0.9,
    'prompt-injection': 0.9,
    'prompt-injection-content': 0.9,
    'prompt-injection-jailbreak': 0.85,
    'prompt-injection-extraction': 0.9,
    'prompt-injection-delimiter': 0.8
};

// Confidence multipliers
const CONFIDENCE_MULTIPLIERS: Record<string, number> = {
    'HIGH': 1.0,
    'MEDIUM': 0.7,
    'LOW': 0.4
};

export type RiskAction = 'BLOCK' | 'WARN' | 'LOG' | 'ALLOW';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

export interface PromptRule {
    id: string;
    severity: string;
    message: string;
    patterns: RegExp[];
    metadata: {
        category?: string;
        confidence?: string;
        risk_score?: string;
        action?: string;
    };
}

export interface PromptFinding {
    ruleId: string;
    category: string;
    severity: string;
    message: string;
    matchedText: string;
    confidence: string;
    riskScore: number;
    action: RiskAction;
    line: number;
    column: number;
}

export interface PromptScanResult {
    action: RiskAction;
    riskScore: number;
    riskLevel: RiskLevel;
    findings: PromptFinding[];
    explanation: string;
    recommendations: string[];
}

// Cached rules
let agentAttackRules: PromptRule[] = [];
let promptInjectionRules: PromptRule[] = [];
let rulesLoaded = false;

/**
 * Load rules from YAML files
 */
export function loadPromptRules(extensionPath: string): void {
    const rulesDir = path.join(extensionPath, 'src', 'rules');

    // Load agent-attacks.security.yaml
    const agentAttacksPath = path.join(rulesDir, 'agent-attacks.security.yaml');
    if (fs.existsSync(agentAttacksPath)) {
        agentAttackRules = parseYamlRules(agentAttacksPath);
        console.log(`Loaded ${agentAttackRules.length} agent attack rules`);
    }

    // Load prompt-injection.security.yaml
    const promptInjectionPath = path.join(rulesDir, 'prompt-injection.security.yaml');
    if (fs.existsSync(promptInjectionPath)) {
        promptInjectionRules = parseYamlRules(promptInjectionPath, true);
        console.log(`Loaded ${promptInjectionRules.length} prompt injection rules`);
    }

    rulesLoaded = true;
}

/**
 * Parse YAML rule file
 */
function parseYamlRules(filePath: string, genericOnly: boolean = false): PromptRule[] {
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const data = yaml.load(content) as { rules?: any[] };

        if (!data?.rules) return [];

        const rules: PromptRule[] = [];

        for (const rule of data.rules) {
            // Filter for generic rules only if specified
            if (genericOnly && !rule.id?.startsWith('generic.prompt')) {
                continue;
            }

            const patterns: RegExp[] = [];
            for (const pattern of rule.patterns || []) {
                try {
                    // Clean up pattern - remove Python-style flags
                    let cleanPattern = pattern.replace(/^\(\?i\)/, '');
                    patterns.push(new RegExp(cleanPattern, 'i'));
                } catch (e) {
                    // Skip invalid regex
                }
            }

            if (patterns.length > 0) {
                rules.push({
                    id: rule.id || '',
                    severity: rule.severity || 'WARNING',
                    message: rule.message || '',
                    patterns,
                    metadata: rule.metadata || {}
                });
            }
        }

        return rules;
    } catch (error) {
        console.error(`Error loading rules from ${filePath}:`, error);
        return [];
    }
}

/**
 * Scan text for prompt injection / agent attacks
 */
export function scanPromptText(text: string, sensitivity: 'high' | 'medium' | 'low' = 'medium'): PromptScanResult {
    const findings: PromptFinding[] = [];
    const allRules = [...agentAttackRules, ...promptInjectionRules];
    const lines = text.split('\n');

    for (const rule of allRules) {
        for (const pattern of rule.patterns) {
            try {
                const match = text.match(pattern);
                if (match) {
                    // Find the line number
                    let charIndex = match.index || 0;
                    let lineNum = 0;
                    let colNum = 0;
                    let charCount = 0;

                    for (let i = 0; i < lines.length; i++) {
                        if (charCount + lines[i].length >= charIndex) {
                            lineNum = i;
                            colNum = charIndex - charCount;
                            break;
                        }
                        charCount += lines[i].length + 1; // +1 for newline
                    }

                    findings.push({
                        ruleId: rule.id,
                        category: rule.metadata.category || 'unknown',
                        severity: rule.severity,
                        message: rule.message,
                        matchedText: match[0].substring(0, 100),
                        confidence: rule.metadata.confidence || 'MEDIUM',
                        riskScore: parseInt(rule.metadata.risk_score || '50'),
                        action: (rule.metadata.action as RiskAction) || 'WARN',
                        line: lineNum,
                        column: colNum
                    });
                    break; // One match per rule
                }
            } catch (e) {
                // Skip invalid regex
            }
        }
    }

    // Calculate risk score
    const riskScore = calculateRiskScore(findings, sensitivity);
    const action = determineAction(riskScore, findings);
    const riskLevel = getRiskLevel(riskScore);
    const explanation = generateExplanation(findings, action);
    const recommendations = generateRecommendations(findings);

    return {
        action,
        riskScore,
        riskLevel,
        findings,
        explanation,
        recommendations
    };
}

/**
 * Calculate risk score from findings
 */
function calculateRiskScore(findings: PromptFinding[], sensitivity: 'high' | 'medium' | 'low'): number {
    if (findings.length === 0) return 0;

    let totalScore = 0;

    for (const finding of findings) {
        const categoryWeight = CATEGORY_WEIGHTS[finding.category] || 0.5;
        const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[finding.confidence] || 0.7;
        totalScore += (finding.riskScore / 100) * categoryWeight * confidenceMultiplier * 100;
    }

    // Average the scores but boost for multiple findings
    let avgScore = totalScore / findings.length;

    if (findings.length > 1) {
        avgScore = Math.min(100, avgScore * (1 + (findings.length - 1) * 0.1));
    }

    // Apply sensitivity adjustment
    if (sensitivity === 'high') {
        avgScore = Math.min(100, avgScore * 1.2);
    } else if (sensitivity === 'low') {
        avgScore = avgScore * 0.8;
    }

    return Math.round(avgScore);
}

/**
 * Determine action based on risk score
 */
function determineAction(riskScore: number, findings: PromptFinding[]): RiskAction {
    const hasBlockFinding = findings.some(f => f.action === 'BLOCK');
    if (hasBlockFinding || riskScore >= RISK_THRESHOLDS.CRITICAL) {
        return 'BLOCK';
    }

    if (riskScore >= RISK_THRESHOLDS.HIGH) {
        return 'BLOCK';
    }

    const hasWarnFinding = findings.some(f => f.action === 'WARN');
    if (hasWarnFinding || riskScore >= RISK_THRESHOLDS.MEDIUM) {
        return 'WARN';
    }

    const hasLogFinding = findings.some(f => f.action === 'LOG');
    if (hasLogFinding || riskScore >= RISK_THRESHOLDS.LOW) {
        return 'LOG';
    }

    return 'ALLOW';
}

/**
 * Get risk level from score
 */
function getRiskLevel(score: number): RiskLevel {
    if (score >= RISK_THRESHOLDS.CRITICAL) return 'CRITICAL';
    if (score >= RISK_THRESHOLDS.HIGH) return 'HIGH';
    if (score >= RISK_THRESHOLDS.MEDIUM) return 'MEDIUM';
    if (score >= RISK_THRESHOLDS.LOW) return 'LOW';
    return 'NONE';
}

/**
 * Generate explanation from findings
 */
function generateExplanation(findings: PromptFinding[], action: RiskAction): string {
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

/**
 * Generate recommendations from findings
 */
function generateRecommendations(findings: PromptFinding[]): string[] {
    const recommendations = new Set<string>();

    for (const finding of findings) {
        switch (finding.category) {
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

/**
 * Check if rules are loaded
 */
export function areRulesLoaded(): boolean {
    return rulesLoaded;
}

/**
 * Get rule count
 */
export function getRuleCount(): { agentAttacks: number; promptInjection: number; total: number } {
    return {
        agentAttacks: agentAttackRules.length,
        promptInjection: promptInjectionRules.length,
        total: agentAttackRules.length + promptInjectionRules.length
    };
}

// Diagnostic collection for prompt security
let promptDiagnostics: vscode.DiagnosticCollection;

// Store prompt findings for sidebar
const promptFindings: Map<string, PromptScanResult> = new Map();

/**
 * Initialize prompt security provider
 */
export function initializePromptScanner(context: vscode.ExtensionContext): vscode.DiagnosticCollection {
    promptDiagnostics = vscode.languages.createDiagnosticCollection('prompt-security');
    context.subscriptions.push(promptDiagnostics);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.scanPrompt', scanPromptCommand)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.analyzeRisk', analyzeRiskCommand)
    );

    return promptDiagnostics;
}

/**
 * Get prompt findings
 */
export function getPromptFindings(): Map<string, PromptScanResult> {
    return promptFindings;
}

/**
 * Scan a document for prompt injection
 */
export function scanDocumentForPromptInjection(
    document: vscode.TextDocument,
    outputChannel: vscode.OutputChannel
): PromptScanResult | null {
    // Check if it's a file type we should scan
    const supportedExtensions = ['.txt', '.md', '.prompt', '.jinja', '.jinja2', '.j2'];
    const ext = path.extname(document.fileName).toLowerCase();

    if (!supportedExtensions.includes(ext)) {
        return null;
    }

    if (!rulesLoaded) {
        outputChannel.appendLine('[Prompt Security] Rules not loaded');
        return null;
    }

    const text = document.getText();
    const config = vscode.workspace.getConfiguration('agentSecurity');
    const sensitivity = config.get<'high' | 'medium' | 'low'>('promptSensitivity', 'medium');

    const result = scanPromptText(text, sensitivity);

    if (result.findings.length > 0) {
        outputChannel.appendLine(`[Prompt Security] Found ${result.findings.length} issue(s) in ${path.basename(document.fileName)}`);
        outputChannel.appendLine(`  Risk Level: ${result.riskLevel} (score: ${result.riskScore})`);
        outputChannel.appendLine(`  Action: ${result.action}`);

        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of result.findings) {
            const range = new vscode.Range(finding.line, finding.column, finding.line, finding.column + finding.matchedText.length);

            const severity = finding.action === 'BLOCK'
                ? vscode.DiagnosticSeverity.Error
                : finding.action === 'WARN'
                    ? vscode.DiagnosticSeverity.Warning
                    : vscode.DiagnosticSeverity.Information;

            const diagnostic = new vscode.Diagnostic(
                range,
                `[${finding.category}] ${finding.message}`,
                severity
            );
            diagnostic.source = 'Agent Security - Prompt';
            diagnostic.code = finding.ruleId;

            diagnostics.push(diagnostic);
        }

        promptDiagnostics.set(document.uri, diagnostics);
        promptFindings.set(document.fileName, result);
    } else {
        promptDiagnostics.delete(document.uri);
        promptFindings.delete(document.fileName);
    }

    return result;
}

/**
 * Command: Scan current file for prompt injection
 */
async function scanPromptCommand() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }

    const outputChannel = vscode.window.createOutputChannel('Agent Security');
    outputChannel.show();

    const result = scanDocumentForPromptInjection(editor.document, outputChannel);

    if (!result) {
        vscode.window.showInformationMessage('File type not supported for prompt scanning');
        return;
    }

    if (result.findings.length === 0) {
        vscode.window.showInformationMessage('✅ No prompt injection risks detected');
    } else {
        const icon = result.action === 'BLOCK' ? '🛑' : result.action === 'WARN' ? '⚠️' : 'ℹ️';
        vscode.window.showWarningMessage(`${icon} ${result.riskLevel} risk detected (${result.findings.length} finding(s))`);
    }
}

/**
 * Command: Analyze risk level of selected text
 */
async function analyzeRiskCommand() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    let text = editor.document.getText(editor.selection);
    if (!text) {
        text = editor.document.getText();
    }

    const config = vscode.workspace.getConfiguration('agentSecurity');
    const sensitivity = config.get<'high' | 'medium' | 'low'>('promptSensitivity', 'medium');

    const result = scanPromptText(text, sensitivity);

    // Show results in a panel
    const panel = vscode.window.createWebviewPanel(
        'promptRiskAnalysis',
        'Prompt Risk Analysis',
        vscode.ViewColumn.Beside,
        {}
    );

    panel.webview.html = generateRiskReportHtml(result);
}

/**
 * Generate HTML report for risk analysis
 */
function generateRiskReportHtml(result: PromptScanResult): string {
    const riskColor = result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH'
        ? '#dc3545'
        : result.riskLevel === 'MEDIUM'
            ? '#ffc107'
            : result.riskLevel === 'LOW'
                ? '#17a2b8'
                : '#28a745';

    const findingsHtml = result.findings.map(f => `
        <div style="border-left: 3px solid ${f.action === 'BLOCK' ? '#dc3545' : '#ffc107'}; padding: 10px; margin: 10px 0; background: #f8f9fa;">
            <strong>${f.category}</strong> (${f.confidence} confidence)<br>
            <span style="color: #666;">${f.message}</span><br>
            <code style="background: #e9ecef; padding: 2px 5px;">${f.matchedText}</code>
        </div>
    `).join('');

    const recommendationsHtml = result.recommendations.map(r => `<li>${r}</li>`).join('');

    return `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; }
                .risk-badge { display: inline-block; padding: 10px 20px; border-radius: 5px; color: white; font-weight: bold; }
                .score { font-size: 48px; font-weight: bold; }
                h2 { border-bottom: 1px solid #ddd; padding-bottom: 10px; }
            </style>
        </head>
        <body>
            <h1>Prompt Risk Analysis</h1>

            <div style="text-align: center; margin: 30px 0;">
                <div class="score" style="color: ${riskColor};">${result.riskScore}</div>
                <div class="risk-badge" style="background: ${riskColor};">${result.riskLevel}</div>
            </div>

            <p><strong>Action:</strong> ${result.action}</p>
            <p>${result.explanation}</p>

            ${result.findings.length > 0 ? `
                <h2>Findings (${result.findings.length})</h2>
                ${findingsHtml}
            ` : ''}

            ${result.recommendations.length > 0 ? `
                <h2>Recommendations</h2>
                <ul>${recommendationsHtml}</ul>
            ` : ''}
        </body>
        </html>
    `;
}
