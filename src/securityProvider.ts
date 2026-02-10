import * as vscode from 'vscode';
import * as path from 'path';
import { getHallucinationFindings, HallucinatedPackage } from './hallucinationProvider';
import { getPromptFindings, PromptScanResult } from './promptScanner';

export class SecurityTreeDataProvider implements vscode.TreeDataProvider<SecurityNode> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecurityNode | undefined | null | void> = new vscode.EventEmitter<SecurityNode | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecurityNode | undefined | null | void> = this._onDidChangeTreeData.event;

    // Map: filePath -> list of security issues
    private securityFindings: Map<string, any[]> = new Map();

    constructor() { }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    /**
     * Update security findings (from Python analyzer)
     */
    updateSecurityFindings(uri: vscode.Uri, issues: any[]) {
        if (issues.length === 0) {
            this.securityFindings.delete(uri.fsPath);
        } else {
            this.securityFindings.set(uri.fsPath, issues);
        }
        this.refresh();
    }

    /**
     * Legacy method for backward compatibility
     */
    updateFindings(uri: vscode.Uri, issues: any[]) {
        this.updateSecurityFindings(uri, issues);
    }

    /**
     * Clear all findings
     */
    clearAllFindings() {
        this.securityFindings.clear();
        this.refresh();
    }

    getTreeItem(element: SecurityNode): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SecurityNode): Thenable<SecurityNode[]> {
        if (!element) {
            // Root level: Return categories
            return Promise.resolve(this.getRootCategories());
        }

        // Handle different node types
        switch (element.nodeType) {
            case 'category':
                return Promise.resolve(this.getCategoryChildren(element.label as string));
            case 'file':
                return Promise.resolve(this.getFileChildren(element));
            default:
                return Promise.resolve([]);
        }
    }

    /**
     * Get root categories
     */
    private getRootCategories(): SecurityNode[] {
        const categories: SecurityNode[] = [];

        // Security Issues category
        const securityCount = this.getTotalSecurityIssueCount();
        if (securityCount > 0) {
            categories.push(new SecurityNode(
                'Security Issues',
                '',
                vscode.TreeItemCollapsibleState.Expanded,
                'category',
                `(${securityCount})`,
                undefined,
                'security'
            ));
        }

        // Hallucinated Packages category
        const hallucinationFindings = getHallucinationFindings();
        const hallucinationCount = this.getTotalHallucinationCount(hallucinationFindings);
        if (hallucinationCount > 0) {
            categories.push(new SecurityNode(
                'Hallucinated Packages',
                '',
                vscode.TreeItemCollapsibleState.Expanded,
                'category',
                `(${hallucinationCount})`,
                undefined,
                'hallucination'
            ));
        }

        // Prompt Security category
        const promptFindings = getPromptFindings();
        const promptCount = this.getTotalPromptFindingCount(promptFindings);
        if (promptCount > 0) {
            categories.push(new SecurityNode(
                'Prompt Security',
                '',
                vscode.TreeItemCollapsibleState.Expanded,
                'category',
                `(${promptCount})`,
                undefined,
                'prompt'
            ));
        }

        if (categories.length === 0) {
            categories.push(new SecurityNode(
                'No issues found',
                '',
                vscode.TreeItemCollapsibleState.None,
                'info'
            ));
        }

        return categories;
    }

    /**
     * Get children for a category
     */
    private getCategoryChildren(category: string): SecurityNode[] {
        switch (category) {
            case 'Security Issues':
                return this.getSecurityFileNodes();
            case 'Hallucinated Packages':
                return this.getHallucinationFileNodes();
            case 'Prompt Security':
                return this.getPromptFileNodes();
            default:
                return [];
        }
    }

    /**
     * Get file nodes for security issues
     */
    private getSecurityFileNodes(): SecurityNode[] {
        const files = Array.from(this.securityFindings.keys());
        return files.map(filePath => {
            const issues = this.securityFindings.get(filePath) || [];
            const fileName = path.basename(filePath);
            return new SecurityNode(
                fileName,
                filePath,
                vscode.TreeItemCollapsibleState.Expanded,
                'file',
                `(${issues.length} issues)`,
                undefined,
                'security'
            );
        });
    }

    /**
     * Get file nodes for hallucination findings
     */
    private getHallucinationFileNodes(): SecurityNode[] {
        const hallucinationFindings = getHallucinationFindings();
        const files = Array.from(hallucinationFindings.keys());
        return files.map(filePath => {
            const packages = hallucinationFindings.get(filePath) || [];
            const fileName = path.basename(filePath);
            return new SecurityNode(
                fileName,
                filePath,
                vscode.TreeItemCollapsibleState.Expanded,
                'file',
                `(${packages.length} packages)`,
                undefined,
                'hallucination'
            );
        });
    }

    /**
     * Get file nodes for prompt findings
     */
    private getPromptFileNodes(): SecurityNode[] {
        const promptFindings = getPromptFindings();
        const files = Array.from(promptFindings.keys());
        return files.map(filePath => {
            const result = promptFindings.get(filePath);
            const fileName = path.basename(filePath);
            const riskLabel = result ? `[${result.riskLevel}]` : '';
            return new SecurityNode(
                fileName,
                filePath,
                vscode.TreeItemCollapsibleState.Expanded,
                'file',
                riskLabel,
                undefined,
                'prompt'
            );
        });
    }

    /**
     * Get children for a file node
     */
    private getFileChildren(fileNode: SecurityNode): SecurityNode[] {
        const filePath = fileNode.fullPath;

        switch (fileNode.categoryType) {
            case 'security':
                return this.getSecurityIssueNodes(filePath);
            case 'hallucination':
                return this.getHallucinationIssueNodes(filePath);
            case 'prompt':
                return this.getPromptIssueNodes(filePath);
            default:
                return [];
        }
    }

    /**
     * Get security issue nodes for a file
     */
    private getSecurityIssueNodes(filePath: string): SecurityNode[] {
        const issues = this.securityFindings.get(filePath) || [];
        return issues.map(issue => {
            return new SecurityNode(
                issue.message,
                filePath,
                vscode.TreeItemCollapsibleState.None,
                'issue',
                undefined,
                issue,
                'security'
            );
        });
    }

    /**
     * Get hallucination issue nodes for a file
     */
    private getHallucinationIssueNodes(filePath: string): SecurityNode[] {
        const hallucinationFindings = getHallucinationFindings();
        const packages = hallucinationFindings.get(filePath) || [];
        return packages.map(pkg => {
            return new SecurityNode(
                `"${pkg.packageName}" not found in ${pkg.ecosystem}`,
                filePath,
                vscode.TreeItemCollapsibleState.None,
                'issue',
                `line ${pkg.line + 1}`,
                { line: pkg.line, column: pkg.column, length: pkg.packageName.length },
                'hallucination'
            );
        });
    }

    /**
     * Get prompt issue nodes for a file
     */
    private getPromptIssueNodes(filePath: string): SecurityNode[] {
        const promptFindings = getPromptFindings();
        const result = promptFindings.get(filePath);
        if (!result) return [];

        return result.findings.map(finding => {
            return new SecurityNode(
                `[${finding.category}] ${finding.message}`,
                filePath,
                vscode.TreeItemCollapsibleState.None,
                'issue',
                `line ${finding.line + 1}`,
                { line: finding.line, column: finding.column, length: finding.matchedText.length },
                'prompt'
            );
        });
    }

    /**
     * Get total security issue count
     */
    private getTotalSecurityIssueCount(): number {
        let count = 0;
        for (const issues of this.securityFindings.values()) {
            count += issues.length;
        }
        return count;
    }

    /**
     * Get total hallucination count
     */
    private getTotalHallucinationCount(findings: Map<string, HallucinatedPackage[]>): number {
        let count = 0;
        for (const packages of findings.values()) {
            count += packages.length;
        }
        return count;
    }

    /**
     * Get total prompt finding count
     */
    private getTotalPromptFindingCount(findings: Map<string, PromptScanResult>): number {
        let count = 0;
        for (const result of findings.values()) {
            count += result.findings.length;
        }
        return count;
    }
}

class SecurityNode extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly fullPath: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly nodeType: 'category' | 'file' | 'issue' | 'info',
        public readonly description?: string,
        public readonly issueData?: any,
        public readonly categoryType?: 'security' | 'hallucination' | 'prompt'
    ) {
        super(label, collapsibleState);
        this.tooltip = this.label;
        this.description = description;

        this.setIcon();
        this.setCommand();
    }

    private setIcon() {
        switch (this.nodeType) {
            case 'category':
                if (this.categoryType === 'security') {
                    this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.red'));
                } else if (this.categoryType === 'hallucination') {
                    this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('charts.orange'));
                } else if (this.categoryType === 'prompt') {
                    this.iconPath = new vscode.ThemeIcon('comment-discussion', new vscode.ThemeColor('charts.purple'));
                }
                break;
            case 'file':
                this.iconPath = vscode.ThemeIcon.File;
                break;
            case 'issue':
                if (this.categoryType === 'security') {
                    const severity = this.issueData?.severity?.toLowerCase();
                    if (severity === 'error') {
                        this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed'));
                    } else {
                        this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconQueued'));
                    }
                } else if (this.categoryType === 'hallucination') {
                    this.iconPath = new vscode.ThemeIcon('question', new vscode.ThemeColor('charts.orange'));
                } else if (this.categoryType === 'prompt') {
                    this.iconPath = new vscode.ThemeIcon('alert', new vscode.ThemeColor('charts.purple'));
                }
                break;
            case 'info':
                this.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('charts.green'));
                break;
        }
    }

    private setCommand() {
        if (this.nodeType === 'issue' && this.fullPath && this.issueData) {
            this.command = {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [
                    vscode.Uri.file(this.fullPath),
                    {
                        selection: new vscode.Range(
                            this.issueData.line,
                            this.issueData.column,
                            this.issueData.line,
                            this.issueData.column + (this.issueData.length || 0)
                        )
                    }
                ]
            };
        }
    }
}
