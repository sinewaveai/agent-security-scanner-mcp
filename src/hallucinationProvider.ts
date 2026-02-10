import * as vscode from 'vscode';
import * as path from 'path';
import {
    scanFileForHallucinations,
    detectEcosystem,
    getPackageStats,
    checkPackage,
    PackageEcosystem,
    isEcosystemLoaded
} from './packageLoader';

// Diagnostic collection for hallucination warnings
let hallucinationDiagnostics: vscode.DiagnosticCollection;

// Store hallucination findings for sidebar
const hallucinationFindings: Map<string, HallucinatedPackage[]> = new Map();

export interface HallucinatedPackage {
    packageName: string;
    ecosystem: PackageEcosystem;
    line: number;
    column: number;
    length: number;
}

/**
 * Initialize the hallucination provider
 */
export function initializeHallucinationProvider(context: vscode.ExtensionContext): vscode.DiagnosticCollection {
    hallucinationDiagnostics = vscode.languages.createDiagnosticCollection('hallucination');
    context.subscriptions.push(hallucinationDiagnostics);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.checkPackage', checkPackageCommand)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.scanPackages', scanPackagesCommand)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.showPackageStats', showPackageStatsCommand)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('agentSecurity.openRegistry', openRegistryCommand)
    );

    return hallucinationDiagnostics;
}

/**
 * Get hallucination findings for a file
 */
export function getHallucinationFindings(): Map<string, HallucinatedPackage[]> {
    return hallucinationFindings;
}

/**
 * Scan a document for hallucinated packages
 */
export function scanDocumentForHallucinations(
    document: vscode.TextDocument,
    outputChannel: vscode.OutputChannel
): HallucinatedPackage[] {
    const filePath = document.fileName;
    const ecosystem = detectEcosystem(filePath);

    if (!ecosystem) {
        return [];
    }

    if (!isEcosystemLoaded(ecosystem)) {
        outputChannel.appendLine(`[Hallucination] ${ecosystem} package list not loaded`);
        return [];
    }

    const code = document.getText();
    const results = scanFileForHallucinations(filePath, code);

    const hallucinated = results.filter(r => r.hallucinated);
    const diagnostics: vscode.Diagnostic[] = [];
    const findings: HallucinatedPackage[] = [];

    if (hallucinated.length > 0) {
        outputChannel.appendLine(`[Hallucination] Found ${hallucinated.length} potentially hallucinated package(s) in ${path.basename(filePath)}`);

        for (const pkg of hallucinated) {
            // Find the import location in the document
            const locations = findImportLocations(document, pkg.package, ecosystem);

            for (const loc of locations) {
                const range = new vscode.Range(loc.line, loc.column, loc.line, loc.column + loc.length);

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `Potentially hallucinated package: "${pkg.package}" not found in ${ecosystem} registry`,
                    vscode.DiagnosticSeverity.Warning
                );
                diagnostic.source = 'Agent Security - Hallucination';
                diagnostic.code = `hallucinated-package-${ecosystem}`;

                diagnostics.push(diagnostic);

                findings.push({
                    packageName: pkg.package,
                    ecosystem: pkg.ecosystem,
                    line: loc.line,
                    column: loc.column,
                    length: loc.length
                });

                outputChannel.appendLine(`  - "${pkg.package}" at line ${loc.line + 1}`);
            }
        }
    }

    hallucinationDiagnostics.set(document.uri, diagnostics);

    if (findings.length > 0) {
        hallucinationFindings.set(filePath, findings);
    } else {
        hallucinationFindings.delete(filePath);
    }

    return findings;
}

/**
 * Find import statement locations for a package
 */
function findImportLocations(
    document: vscode.TextDocument,
    packageName: string,
    ecosystem: PackageEcosystem
): { line: number; column: number; length: number }[] {
    const locations: { line: number; column: number; length: number }[] = [];
    const text = document.getText();
    const lines = text.split('\n');

    // Patterns to match imports
    const patterns: RegExp[] = [];

    switch (ecosystem) {
        case 'npm':
            patterns.push(
                new RegExp(`require\\s*\\(\\s*['"]${escapeRegExp(packageName)}['"]`, 'g'),
                new RegExp(`from\\s+['"]${escapeRegExp(packageName)}['"]`, 'g'),
                new RegExp(`import\\s+['"]${escapeRegExp(packageName)}['"]`, 'g')
            );
            break;
        case 'pypi':
            patterns.push(
                new RegExp(`^import\\s+${escapeRegExp(packageName)}\\b`, 'gm'),
                new RegExp(`^from\\s+${escapeRegExp(packageName)}\\b`, 'gm')
            );
            break;
        case 'rubygems':
            patterns.push(
                new RegExp(`require\\s+['"]${escapeRegExp(packageName)}['"]`, 'g'),
                new RegExp(`gem\\s+['"]${escapeRegExp(packageName)}['"]`, 'g')
            );
            break;
        case 'crates':
            patterns.push(
                new RegExp(`use\\s+${escapeRegExp(packageName)}\\b`, 'g'),
                new RegExp(`extern\\s+crate\\s+${escapeRegExp(packageName)}\\b`, 'g')
            );
            break;
        case 'dart':
            patterns.push(
                new RegExp(`import\\s+['"]package:${escapeRegExp(packageName)}`, 'g')
            );
            break;
        default:
            patterns.push(new RegExp(escapeRegExp(packageName), 'g'));
    }

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        for (const pattern of patterns) {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(line)) !== null) {
                // Find the actual package name position within the match
                const pkgIndex = match[0].indexOf(packageName);
                locations.push({
                    line: lineNum,
                    column: match.index + pkgIndex,
                    length: packageName.length
                });
            }
        }
    }

    // Deduplicate
    const seen = new Set<string>();
    return locations.filter(loc => {
        const key = `${loc.line}:${loc.column}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function escapeRegExp(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Command: Check a specific package
 */
async function checkPackageCommand() {
    const ecosystemOptions: vscode.QuickPickItem[] = [
        { label: 'npm', description: 'Node.js packages (npmjs.com)' },
        { label: 'pypi', description: 'Python packages (PyPI)' },
        { label: 'rubygems', description: 'Ruby packages (RubyGems.org)' },
        { label: 'crates', description: 'Rust packages (crates.io)' },
        { label: 'dart', description: 'Dart packages (pub.dev)' },
        { label: 'perl', description: 'Perl packages (CPAN)' },
        { label: 'raku', description: 'Raku packages (raku.land)' }
    ];

    const selectedEcosystem = await vscode.window.showQuickPick(ecosystemOptions, {
        placeHolder: 'Select package ecosystem'
    });

    if (!selectedEcosystem) return;

    const ecosystem = selectedEcosystem.label as PackageEcosystem;

    if (!isEcosystemLoaded(ecosystem)) {
        vscode.window.showWarningMessage(`${ecosystem} package list is not loaded`);
        return;
    }

    const packageName = await vscode.window.showInputBox({
        prompt: `Enter ${ecosystem} package name to check`,
        placeHolder: 'e.g., express, requests, rails'
    });

    if (!packageName) return;

    const { exists, unknown } = checkPackage(packageName, ecosystem);

    if (unknown) {
        vscode.window.showWarningMessage(`Could not check package "${packageName}" - ecosystem data not available`);
    } else if (exists) {
        vscode.window.showInformationMessage(`✅ "${packageName}" exists in ${ecosystem} registry`);
    } else {
        vscode.window.showWarningMessage(`⚠️ "${packageName}" NOT found in ${ecosystem} registry - may be hallucinated!`);
    }
}

/**
 * Command: Scan current file for hallucinated packages
 */
async function scanPackagesCommand() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }

    const document = editor.document;
    const ecosystem = detectEcosystem(document.fileName);

    if (!ecosystem) {
        vscode.window.showWarningMessage('File type not supported for package scanning');
        return;
    }

    if (!isEcosystemLoaded(ecosystem)) {
        vscode.window.showWarningMessage(`${ecosystem} package list is not loaded`);
        return;
    }

    const outputChannel = vscode.window.createOutputChannel('Agent Security');
    outputChannel.show();

    const findings = scanDocumentForHallucinations(document, outputChannel);

    if (findings.length === 0) {
        vscode.window.showInformationMessage(`✅ No hallucinated packages found in ${path.basename(document.fileName)}`);
    } else {
        vscode.window.showWarningMessage(`⚠️ Found ${findings.length} potentially hallucinated package(s)`);
    }
}

/**
 * Command: Show package statistics
 */
async function showPackageStatsCommand() {
    const stats = getPackageStats();

    const items: vscode.QuickPickItem[] = stats.map(s => ({
        label: `${s.loaded ? '✅' : '❌'} ${s.ecosystem}`,
        description: s.loaded ? `${s.count.toLocaleString()} packages (${s.type})` : 'Not loaded',
        detail: getRegistryUrl(s.ecosystem)
    }));

    const totalPackages = stats.reduce((sum, s) => sum + s.count, 0);
    items.unshift({
        label: `📊 Total`,
        description: `${totalPackages.toLocaleString()} packages across ${stats.filter(s => s.loaded).length} ecosystems`,
        detail: ''
    });

    await vscode.window.showQuickPick(items, {
        placeHolder: 'Package hallucination detection statistics'
    });
}

/**
 * Command: Open package in registry
 */
async function openRegistryCommand(packageName: string, ecosystem: PackageEcosystem) {
    const url = getPackageUrl(packageName, ecosystem);
    if (url) {
        vscode.env.openExternal(vscode.Uri.parse(url));
    }
}

function getRegistryUrl(ecosystem: PackageEcosystem): string {
    const urls: Record<PackageEcosystem, string> = {
        npm: 'https://npmjs.com',
        pypi: 'https://pypi.org',
        rubygems: 'https://rubygems.org',
        crates: 'https://crates.io',
        dart: 'https://pub.dev',
        perl: 'https://metacpan.org',
        raku: 'https://raku.land'
    };
    return urls[ecosystem] || '';
}

function getPackageUrl(packageName: string, ecosystem: PackageEcosystem): string {
    const urls: Record<PackageEcosystem, string> = {
        npm: `https://npmjs.com/package/${packageName}`,
        pypi: `https://pypi.org/project/${packageName}`,
        rubygems: `https://rubygems.org/gems/${packageName}`,
        crates: `https://crates.io/crates/${packageName}`,
        dart: `https://pub.dev/packages/${packageName}`,
        perl: `https://metacpan.org/pod/${packageName}`,
        raku: `https://raku.land/zef:${packageName}`
    };
    return urls[ecosystem] || '';
}

/**
 * Register code actions for hallucinated packages
 */
export class HallucinationCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source?.startsWith('Agent Security - Hallucination')) {
                // Extract package name and ecosystem from diagnostic code
                const code = diagnostic.code?.toString() || '';
                const match = code.match(/hallucinated-package-(\w+)/);
                const ecosystem = (match?.[1] || 'npm') as PackageEcosystem;

                // Get package name from diagnostic message
                const msgMatch = diagnostic.message.match(/"([^"]+)"/);
                const packageName = msgMatch?.[1] || '';

                if (packageName) {
                    // Action: Search in registry
                    const searchAction = new vscode.CodeAction(
                        `Search "${packageName}" on ${ecosystem}`,
                        vscode.CodeActionKind.QuickFix
                    );
                    searchAction.command = {
                        command: 'agentSecurity.openRegistry',
                        title: 'Open Registry',
                        arguments: [packageName, ecosystem]
                    };
                    actions.push(searchAction);

                    // Action: Remove import
                    const removeAction = new vscode.CodeAction(
                        `Remove import of "${packageName}"`,
                        vscode.CodeActionKind.QuickFix
                    );
                    removeAction.edit = new vscode.WorkspaceEdit();
                    const lineRange = document.lineAt(diagnostic.range.start.line).range;
                    removeAction.edit.delete(document.uri, lineRange);
                    actions.push(removeAction);
                }
            }
        }

        return actions;
    }
}
