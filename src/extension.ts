import * as vscode from 'vscode';
import * as path from 'path';
import * as cp from 'child_process';
import { SecurityTreeDataProvider } from './securityProvider';
import { registerSecurityFixProvider } from './securityFixProvider';
import { initializePackageLoader } from './packageLoader';
import {
    initializeHallucinationProvider,
    scanDocumentForHallucinations,
    HallucinationCodeActionProvider
} from './hallucinationProvider';
import {
    initializePromptScanner,
    loadPromptRules,
    scanDocumentForPromptInjection,
    getPromptFindings,
    getRuleCount
} from './promptScanner';

const outputChannel = vscode.window.createOutputChannel("Agent Security");

let diagnosticCollection: vscode.DiagnosticCollection;
let securityProvider: SecurityTreeDataProvider;

export function activate(context: vscode.ExtensionContext) {
    outputChannel.appendLine('Agent Security Analyzer is activating...');

    // Create diagnostic collection for security issues
    diagnosticCollection = vscode.languages.createDiagnosticCollection('security');
    context.subscriptions.push(diagnosticCollection);

    // Initialize package loader for hallucination detection
    const extensionPath = context.extensionPath;
    const packagesPath = path.join(extensionPath, 'src', 'packages');
    outputChannel.appendLine(`Loading package data from: ${packagesPath}`);

    try {
        initializePackageLoader(packagesPath);
        outputChannel.appendLine('Package loader initialized');
    } catch (error) {
        outputChannel.appendLine(`Warning: Failed to initialize package loader: ${error}`);
    }

    // Initialize hallucination detection
    const hallucinationDiagnostics = initializeHallucinationProvider(context);
    outputChannel.appendLine('Hallucination detection initialized');

    // Register hallucination code action provider
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            [
                { scheme: 'file', language: 'javascript' },
                { scheme: 'file', language: 'typescript' },
                { scheme: 'file', language: 'javascriptreact' },
                { scheme: 'file', language: 'typescriptreact' },
                { scheme: 'file', language: 'python' },
                { scheme: 'file', language: 'ruby' },
                { scheme: 'file', language: 'rust' }
            ],
            new HallucinationCodeActionProvider()
        )
    );

    // Load prompt security rules
    try {
        loadPromptRules(extensionPath);
        const ruleCount = getRuleCount();
        outputChannel.appendLine(`Loaded ${ruleCount.total} prompt security rules (${ruleCount.agentAttacks} agent attacks, ${ruleCount.promptInjection} prompt injection)`);
    } catch (error) {
        outputChannel.appendLine(`Warning: Failed to load prompt rules: ${error}`);
    }

    // Initialize prompt security scanner
    const promptDiagnostics = initializePromptScanner(context);
    outputChannel.appendLine('Prompt security scanner initialized');

    // Initialize Sidebar Provider with extended data
    securityProvider = new SecurityTreeDataProvider();
    vscode.window.registerTreeDataProvider('securityExplorer', securityProvider);

    // Register refresh command
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.refreshView', () => {
            securityProvider.refresh();
        })
    );

    // Register Security Fix Provider for agentic auto-fix suggestions
    registerSecurityFixProvider(context, outputChannel);

    // Register scan file command
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                runFullScan(editor.document);
            }
        })
    );

    // Register scan workspace command
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.scanWorkspace', async () => {
            const files = await vscode.workspace.findFiles('**/*.{js,ts,jsx,tsx,py,rb,rs,java,go,php,c,cpp,tf,yaml,yml}', '**/node_modules/**');
            outputChannel.appendLine(`Scanning ${files.length} files...`);

            let scanned = 0;
            for (const file of files) {
                try {
                    const doc = await vscode.workspace.openTextDocument(file);
                    runFullScan(doc);
                    scanned++;
                } catch (e) {
                    // Skip files that can't be opened
                }
            }

            vscode.window.showInformationMessage(`Scanned ${scanned} files for security issues`);
        })
    );

    // Register clear diagnostics command
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.clearDiagnostics', () => {
            diagnosticCollection.clear();
            hallucinationDiagnostics.clear();
            promptDiagnostics.clear();
            securityProvider.clearAllFindings();
            vscode.window.showInformationMessage('Cleared all security diagnostics');
        })
    );

    // Auto-scan on save
    const config = vscode.workspace.getConfiguration('agentSecurity');
    if (config.get<boolean>('autoScan', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(document => {
                runFullScan(document);
            })
        );
    }

    // Scan open files
    vscode.workspace.textDocuments.forEach(doc => {
        if (doc.uri.scheme === 'file') {
            runFullScan(doc);
        }
    });

    // Status bar item for prompt risk
    const promptStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    promptStatusBar.command = 'agentSecurity.analyzeRisk';
    context.subscriptions.push(promptStatusBar);

    // Update status bar on active editor change
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            updatePromptStatusBar(editor, promptStatusBar);
        })
    );

    // Initial status bar update
    updatePromptStatusBar(vscode.window.activeTextEditor, promptStatusBar);

    outputChannel.appendLine('Agent Security Analyzer is now active!');
    outputChannel.appendLine('Features enabled:');
    outputChannel.appendLine('  - Security vulnerability scanning (357 rules)');
    outputChannel.appendLine('  - Package hallucination detection (4.3M packages)');
    outputChannel.appendLine('  - Prompt injection scanning');
}

/**
 * Run full security scan on a document
 */
function runFullScan(document: vscode.TextDocument) {
    if (document.uri.scheme !== 'file') {
        return;
    }

    // Run Python security analyzer
    runPythonAnalyzer(document);

    // Run hallucination detection
    const config = vscode.workspace.getConfiguration('agentSecurity');
    if (config.get<boolean>('enableHallucinationDetection', true)) {
        scanDocumentForHallucinations(document, outputChannel);
    }

    // Run prompt injection scanning
    if (config.get<boolean>('enablePromptScanning', true)) {
        scanDocumentForPromptInjection(document, outputChannel);
    }

    // Update sidebar
    securityProvider.refresh();
}

/**
 * Run Python security analyzer
 */
function runPythonAnalyzer(document: vscode.TextDocument) {
    if (document.uri.scheme !== 'file') {
        return;
    }

    const scriptPath = path.join(__dirname, '..', 'src', 'analyzer.py');
    const filePath = document.fileName;

    outputChannel.appendLine(`[Security] Scanning: ${filePath}`);

    const pythonCommand = process.platform === 'win32' ? 'python' : 'python3';

    cp.exec(`"${pythonCommand}" "${scriptPath}" "${filePath}"`, (error, stdout, stderr) => {
        if (error) {
            outputChannel.appendLine(`[Error] Execution failed: ${error.message}`);
            if (stderr) outputChannel.appendLine(`[Stderr]: ${stderr}`);
            return;
        }

        try {
            const issues = JSON.parse(stdout);

            if (issues.error) {
                outputChannel.appendLine(`[Analyzer Error]: ${issues.error}`);
                return;
            }

            outputChannel.appendLine(`[Security] Found ${issues.length} security issues in ${path.basename(filePath)}`);

            // Update Sidebar View
            securityProvider.updateSecurityFindings(document.uri, issues);

            const diagnostics: vscode.Diagnostic[] = issues.map((issue: any) => {
                const range = new vscode.Range(
                    issue.line,
                    issue.column,
                    issue.line,
                    issue.column + issue.length
                );

                const severity = getSeverity(issue.severity);
                const diagnostic = new vscode.Diagnostic(
                    range,
                    issue.message,
                    severity
                );

                diagnostic.source = 'Agent Security';
                diagnostic.code = issue.ruleId;
                return diagnostic;
            });

            diagnosticCollection.set(document.uri, diagnostics);
        } catch (e) {
            outputChannel.appendLine(`[Parse Error] Failed to parse Python output: ${e}`);
            outputChannel.appendLine(`[Raw Output]: ${stdout}`);
        }
    });
}

/**
 * Update prompt security status bar
 */
function updatePromptStatusBar(editor: vscode.TextEditor | undefined, statusBar: vscode.StatusBarItem) {
    if (!editor) {
        statusBar.hide();
        return;
    }

    const supportedExtensions = ['.txt', '.md', '.prompt', '.jinja', '.jinja2', '.j2'];
    const ext = path.extname(editor.document.fileName).toLowerCase();

    if (!supportedExtensions.includes(ext)) {
        statusBar.hide();
        return;
    }

    const findings = getPromptFindings();
    const result = findings.get(editor.document.fileName);

    if (result && result.findings.length > 0) {
        const icon = result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH'
            ? '$(shield)'
            : result.riskLevel === 'MEDIUM'
                ? '$(warning)'
                : '$(info)';

        statusBar.text = `${icon} Prompt Risk: ${result.riskLevel}`;
        statusBar.tooltip = `${result.findings.length} finding(s) - Click to analyze`;
        statusBar.backgroundColor = result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH'
            ? new vscode.ThemeColor('statusBarItem.errorBackground')
            : result.riskLevel === 'MEDIUM'
                ? new vscode.ThemeColor('statusBarItem.warningBackground')
                : undefined;
        statusBar.show();
    } else {
        statusBar.text = '$(shield) Prompt: Safe';
        statusBar.tooltip = 'No prompt injection risks detected';
        statusBar.backgroundColor = undefined;
        statusBar.show();
    }
}

function getSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity.toLowerCase()) {
        case 'error': return vscode.DiagnosticSeverity.Error;
        case 'warning': return vscode.DiagnosticSeverity.Warning;
        default: return vscode.DiagnosticSeverity.Information;
    }
}

export function deactivate() {
    outputChannel.appendLine('Agent Security Analyzer deactivated');
}
