import * as vscode from 'vscode';
import { getFixSuggestions, hasFixAvailable, FixContext, FixSuggestion } from './fixTemplates';

/**
 * SecurityFixProvider - Agentic Code Action Provider for Security Fixes
 *
 * This provider implements VS Code's CodeActionProvider interface to offer
 * intelligent, context-aware quick fixes for security vulnerabilities detected
 * by the Agent Security analyzer.
 *
 * The "agentic" approach:
 * 1. Analyzes the diagnostic context (matched code, surrounding lines)
 * 2. Determines the most appropriate fix based on code patterns
 * 3. Offers multiple fix options ranked by preference
 * 4. Provides educational descriptions for each fix
 */
export class SecurityFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
        vscode.CodeActionKind.Source
    ];

    private outputChannel: vscode.OutputChannel;

    constructor(outputChannel: vscode.OutputChannel) {
        this.outputChannel = outputChannel;
    }

    /**
     * Provide code actions for security diagnostics
     */
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];

        // Filter for our security diagnostics
        const securityDiagnostics = context.diagnostics.filter(
            diag => diag.source === 'Agent Security'
        );

        for (const diagnostic of securityDiagnostics) {
            const ruleId = diagnostic.code as string;
            if (!ruleId) {
                continue;
            }

            // Get the full line for context-aware fixes
            const line = document.lineAt(diagnostic.range.start.line);
            const matchedText = document.getText(diagnostic.range);

            const fixContext: FixContext = {
                document,
                range: diagnostic.range,
                matchedText,
                fullLine: line.text,
                ruleId
            };

            // Generate fix suggestions using the agentic fix templates
            const suggestions = getFixSuggestions(fixContext);

            for (const suggestion of suggestions) {
                const action = this.createCodeAction(document, diagnostic, suggestion, fixContext);
                if (action) {
                    actions.push(action);
                }
            }

            // Add a "Learn more" action that opens documentation
            const learnMoreAction = this.createLearnMoreAction(diagnostic, ruleId);
            if (learnMoreAction) {
                actions.push(learnMoreAction);
            }
        }

        // Add "Fix All Security Issues in File" if there are multiple issues
        if (securityDiagnostics.length > 1) {
            const fixAllAction = this.createFixAllAction(document, securityDiagnostics);
            if (fixAllAction) {
                actions.push(fixAllAction);
            }
        }

        return actions;
    }

    /**
     * Create a code action from a fix suggestion
     */
    private createCodeAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        suggestion: FixSuggestion,
        context: FixContext
    ): vscode.CodeAction | undefined {
        // Skip suggestions with empty replacement (documentation-only)
        if (!suggestion.replacement) {
            return undefined;
        }

        const action = new vscode.CodeAction(
            `🛡️ ${suggestion.title}`,
            vscode.CodeActionKind.QuickFix
        );

        action.diagnostics = [diagnostic];
        action.isPreferred = suggestion.isPreferred || false;

        // Determine the edit range
        const lineRange = document.lineAt(diagnostic.range.start.line).range;

        // Check if the replacement is a full line or partial
        if (suggestion.replacement.includes('\n') || suggestion.replacement.startsWith('#') || suggestion.replacement.startsWith('//')) {
            // Multi-line or comment replacement - replace the whole line
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(
                document.uri,
                lineRange,
                suggestion.replacement
            );
        } else if (suggestion.replacement === context.fullLine.replace(/\s+$/, '')) {
            // No actual change, skip
            return undefined;
        } else {
            // Smart replacement - replace only what's needed
            action.edit = new vscode.WorkspaceEdit();

            // If the suggestion looks like it replaces the full line, do that
            if (this.looksLikeFullLineReplacement(context.fullLine, suggestion.replacement)) {
                action.edit.replace(document.uri, lineRange, suggestion.replacement);
            } else {
                // Otherwise just replace the matched portion
                action.edit.replace(document.uri, diagnostic.range, suggestion.replacement);
            }
        }

        // Add description as tooltip
        if (suggestion.description) {
            action.command = {
                command: 'agentSecurity.showFixInfo',
                title: 'Show Fix Info',
                arguments: [suggestion.description]
            };
        }

        return action;
    }

    /**
     * Check if a replacement looks like it's meant to replace the whole line
     */
    private looksLikeFullLineReplacement(original: string, replacement: string): boolean {
        // If the replacement contains similar structure to the original line
        const originalTrimmed = original.trim();
        const replacementTrimmed = replacement.trim();

        // Check for common patterns that indicate full-line replacement
        const patterns = [
            /^(import|from|const|let|var|def|class|function)/,
            /^\s*\w+\s*[=:]/,  // Assignment
            /^\s*\w+\.\w+/,    // Method call
        ];

        for (const pattern of patterns) {
            if (pattern.test(originalTrimmed) && pattern.test(replacementTrimmed)) {
                return true;
            }
        }

        // If replacement is significantly different in length, it's likely a full replacement
        const lengthRatio = replacement.length / original.length;
        return lengthRatio > 0.7 && lengthRatio < 1.5;
    }

    /**
     * Create a "Learn More" action that opens OWASP/CWE documentation
     */
    private createLearnMoreAction(
        diagnostic: vscode.Diagnostic,
        ruleId: string
    ): vscode.CodeAction | undefined {
        const action = new vscode.CodeAction(
            `📚 Learn more about this vulnerability`,
            vscode.CodeActionKind.QuickFix
        );

        action.diagnostics = [diagnostic];
        action.isPreferred = false;

        // Extract CWE from rule ID if possible
        const cweMatch = ruleId.match(/CWE-(\d+)/i);
        const url = cweMatch
            ? `https://cwe.mitre.org/data/definitions/${cweMatch[1]}.html`
            : 'https://owasp.org/www-project-top-ten/';

        action.command = {
            command: 'vscode.open',
            title: 'Open Documentation',
            arguments: [vscode.Uri.parse(url)]
        };

        return action;
    }

    /**
     * Create a "Fix All" action for multiple issues
     */
    private createFixAllAction(
        document: vscode.TextDocument,
        diagnostics: vscode.Diagnostic[]
    ): vscode.CodeAction | undefined {
        // Only create if we have fixes for all issues
        const fixableDiagnostics = diagnostics.filter(d => {
            const ruleId = d.code as string;
            return ruleId && hasFixAvailable(ruleId);
        });

        if (fixableDiagnostics.length < 2) {
            return undefined;
        }

        const action = new vscode.CodeAction(
            `🛡️ Fix all ${fixableDiagnostics.length} security issues (auto-apply preferred fixes)`,
            vscode.CodeActionKind.Source
        );

        action.diagnostics = fixableDiagnostics;

        // Apply preferred fixes for each diagnostic
        const edit = new vscode.WorkspaceEdit();
        const processedLines = new Set<number>();

        for (const diagnostic of fixableDiagnostics) {
            const lineNum = diagnostic.range.start.line;

            // Skip if we already processed this line (avoid conflicts)
            if (processedLines.has(lineNum)) {
                continue;
            }

            const ruleId = diagnostic.code as string;
            const line = document.lineAt(lineNum);
            const matchedText = document.getText(diagnostic.range);

            const fixContext: FixContext = {
                document,
                range: diagnostic.range,
                matchedText,
                fullLine: line.text,
                ruleId
            };

            const suggestions = getFixSuggestions(fixContext);
            const preferredFix = suggestions.find(s => s.isPreferred) || suggestions[0];

            if (preferredFix && preferredFix.replacement) {
                edit.replace(document.uri, line.range, preferredFix.replacement);
                processedLines.add(lineNum);
            }
        }

        if (processedLines.size === 0) {
            return undefined;
        }

        action.edit = edit;
        return action;
    }
}

/**
 * Register the security fix provider for all supported languages
 */
export function registerSecurityFixProvider(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel
): void {
    const supportedLanguages = [
        'python',
        'javascript',
        'typescript',
        'javascriptreact',
        'typescriptreact',
        'java',
        'go',
        'ruby',
        'php',
        'csharp',
        'rust',
        'c',
        'cpp',
        'dockerfile',
        'yaml',
        'json',
        'terraform'
    ];

    const provider = new SecurityFixProvider(outputChannel);

    for (const language of supportedLanguages) {
        const disposable = vscode.languages.registerCodeActionsProvider(
            { language, scheme: 'file' },
            provider,
            {
                providedCodeActionKinds: SecurityFixProvider.providedCodeActionKinds
            }
        );
        context.subscriptions.push(disposable);
    }

    // Register the "show fix info" command
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.showFixInfo', (message: string) => {
            vscode.window.showInformationMessage(`🛡️ Security Fix: ${message}`);
        })
    );

    // Register command to apply all fixes in file
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.fixAllInFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }

            const diagnostics = vscode.languages.getDiagnostics(editor.document.uri)
                .filter(d => d.source === 'Agent Security');

            if (diagnostics.length === 0) {
                vscode.window.showInformationMessage('No security issues found in this file');
                return;
            }

            // Trigger code action for all diagnostics
            const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
                'vscode.executeCodeActionProvider',
                editor.document.uri,
                new vscode.Range(0, 0, editor.document.lineCount, 0),
                vscode.CodeActionKind.Source.value
            );

            if (actions && actions.length > 0) {
                const fixAllAction = actions.find(a => a.title.includes('Fix all'));
                if (fixAllAction && fixAllAction.edit) {
                    await vscode.workspace.applyEdit(fixAllAction.edit);
                    vscode.window.showInformationMessage(
                        `Applied security fixes to ${diagnostics.length} issues`
                    );
                }
            }
        })
    );

    outputChannel.appendLine('Security Fix Provider registered for quick fixes');
}
