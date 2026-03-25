import type { FileContext, ProjectContext, DependencyGraph } from '../types/analysis.js';
import type { IntentProfile } from '../types/findings.js';
import type { AnalysisMode } from '../types/config.js';
import type { LLMProvider } from '../llm/provider.js';
import { formatProjectContextForLLM } from './project.js';
import { buildRelatedFileSummaries, formatRelatedFileSummaries, type RelatedFileSummary } from './security-summary.js';

const TOKEN_BUDGETS: Record<string, number> = {
  anthropic: 100_000,
  openai: 60_000,
  'claude-cli': 100_000,
};

const TRUNCATION_MARKER = '\n[TRUNCATED — file too large for context window]\n';

// Reserve 20% of budget for LLM output tokens
const OUTPUT_RESERVE = 0.2;

export class ContextAssembler {
  private mode: AnalysisMode;
  private projectRoot: string;
  private graph?: DependencyGraph;
  private summaryCache = new Map<string, RelatedFileSummary[]>();

  constructor(
    private provider: LLMProvider,
    mode: AnalysisMode = 'review',
    projectRoot: string = '',
    graph?: DependencyGraph,
  ) {
    this.mode = mode;
    this.projectRoot = projectRoot;
    this.graph = graph;
  }

  private getRelatedSummaries(file: FileContext): RelatedFileSummary[] {
    if (this.mode !== 'security' || !this.projectRoot) return [];
    const cached = this.summaryCache.get(file.filePath);
    if (cached) return cached;
    const summaries = buildRelatedFileSummaries(file, this.projectRoot, this.graph);
    this.summaryCache.set(file.filePath, summaries);
    return summaries;
  }

  /**
   * Calculate how many lines of source code fit in the remaining
   * token budget after system prompt, intent, project context, and
   * metadata are accounted for.
   */
  calculateMaxLines(
    intent: IntentProfile,
    project: ProjectContext,
    file: FileContext,
    systemPrompt: string,
  ): number {
    const budget = TOKEN_BUDGETS[this.provider.providerName] ?? 60_000;
    const usableBudget = budget * (1 - OUTPUT_RESERVE);

    // Measure fixed overhead
    const overheadParts = [
      systemPrompt,
      formatIntent(intent),
      formatProjectContextForLLM(project),
      formatFileMetadata(file),
      // Framing text around file content
      `\n## File Content\nFile: ${file.filePath} (${file.language})\n\`\`\`\n\`\`\`\n`,
    ];

    // In security mode, account for cross-file summary section
    const relatedOverhead = formatRelatedFileSummaries(this.getRelatedSummaries(file));
    if (relatedOverhead) {
      overheadParts.push(`\n## Related Files (security-relevant lines)\n${relatedOverhead}\n`);
    }

    const overheadTokens = this.provider.countTokens(overheadParts.join('\n'));

    const remainingTokens = usableBudget - overheadTokens;
    if (remainingTokens <= 0) return 100; // absolute minimum

    // Estimate chars per line from actual file content (avg line length)
    const lines = file.content.split('\n');
    const avgCharsPerLine = lines.length > 0
      ? file.content.length / lines.length
      : 40;
    // ~4 chars per token + line number prefix ("1234: ")
    const charsPerToken = 4;
    const lineNumberOverhead = 6;
    const tokensPerLine = (avgCharsPerLine + lineNumberOverhead) / charsPerToken;

    const maxLines = Math.floor(remainingTokens / tokensPerLine);
    return Math.max(maxLines, 100); // never go below 100 lines
  }

  assembleAnalysisContext(
    intent: IntentProfile,
    project: ProjectContext,
    file: FileContext,
  ): string {
    const budget = TOKEN_BUDGETS[this.provider.providerName] ?? 60_000;

    // Priority order: intent > file content > project context
    const sections: Array<{ label: string; content: string; priority: number }> = [
      {
        label: 'Intent Profile',
        content: formatIntent(intent),
        priority: 1,
      },
      {
        label: 'File Content',
        content: formatFileContent(file),
        priority: 2,
      },
      {
        label: 'Project Context',
        content: formatProjectContextForLLM(project),
        priority: 3,
      },
      {
        label: 'File Metadata',
        content: formatFileMetadata(file),
        priority: 4,
      },
    ];

    // In security mode, add cross-file security context
    const relatedContent = formatRelatedFileSummaries(this.getRelatedSummaries(file));
    if (relatedContent) {
      sections.push({
        label: 'Related Files (security-relevant lines)',
        content: relatedContent,
        priority: 3, // same priority as project context — fits before metadata
      });
    }

    // Sort by priority and assemble within budget
    sections.sort((a, b) => a.priority - b.priority);

    let assembled = '';
    let usedTokens = 0;

    for (const section of sections) {
      const sectionText = `\n## ${section.label}\n${section.content}\n`;
      const sectionTokens = this.provider.countTokens(sectionText);

      if (usedTokens + sectionTokens > budget * 0.8) {
        // Truncate this section to fit
        const remainingBudget = Math.floor((budget * 0.8 - usedTokens) * 4); // rough chars
        if (remainingBudget > 200) {
          assembled += `\n## ${section.label}\n${section.content.slice(0, remainingBudget)}${TRUNCATION_MARKER}`;
        }
        break;
      }

      assembled += sectionText;
      usedTokens += sectionTokens;
    }

    return assembled;
  }

  assembleTriageContext(project: ProjectContext, file: FileContext): string {
    // Triage needs less context — just file overview + project summary
    const sections = [
      `## File: ${file.filePath}`,
      `Language: ${file.language} | Lines: ${file.lineCount}`,
      `Test: ${file.isTestFile} | Config: ${file.isConfigFile} | Generated: ${file.isGenerated}`,
      `Imports: ${file.imports.slice(0, 10).join(', ')}`,
      '',
      `## Project`,
      `Language: ${project.language} | Framework: ${project.framework}`,
      project.readme ? `README excerpt: ${project.readme.slice(0, 500)}` : 'No README',
    ];

    // Include first 100 lines of file content for triage
    const preview = file.content.split('\n').slice(0, 100).join('\n');
    sections.push('', '## File Preview (first 100 lines)', '```', preview, '```');

    return sections.join('\n');
  }
}

function formatIntent(intent: IntentProfile): string {
  return [
    `Purpose: ${intent.purpose}`,
    `Risk Domain: ${intent.riskDomain}`,
    `Framework: ${intent.framework}`,
    `Expected Behaviors: ${intent.expectedBehaviors.join('; ')}`,
    `Unexpected Behaviors: ${intent.unexpectedBehaviors.join('; ')}`,
  ].join('\n');
}

function formatFileContent(file: FileContext): string {
  const numbered = file.content
    .split('\n')
    .map((line, i) => `${i + 1}: ${line}`)
    .join('\n');
  return `File: ${file.filePath} (${file.language})\n\`\`\`\n${numbered}\n\`\`\``;
}

function formatFileMetadata(file: FileContext): string {
  const parts = [
    `Imports: ${file.imports.join(', ') || 'none'}`,
    `Imported by: ${file.importedBy.join(', ') || 'none'}`,
    `Siblings: ${file.siblingFiles.join(', ') || 'none'}`,
  ];
  return parts.join('\n');
}
