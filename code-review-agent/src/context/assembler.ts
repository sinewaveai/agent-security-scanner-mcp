import type { FileContext, ProjectContext } from '../types/analysis.js';
import type { IntentProfile } from '../types/findings.js';
import type { LLMProvider } from '../llm/provider.js';
import { formatProjectContextForLLM } from './project.js';

const TOKEN_BUDGETS: Record<string, number> = {
  anthropic: 100_000,
  openai: 60_000,
};

const TRUNCATION_MARKER = '\n[TRUNCATED — file too large for context window]\n';

export class ContextAssembler {
  constructor(private provider: LLMProvider) {}

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
