import type { Finding, IntentProfile, TriageDecision } from './findings.js';

export interface AnalysisResult {
  findings: Finding[];
  intentProfile: IntentProfile | null;
  fileResults: FileAnalysisResult[];
  stats: AnalysisStats;
}

export interface FileAnalysisResult {
  file: string;
  findings: Finding[];
  triageDecision: TriageDecision | null;
  tokensUsed: number;
  skipped: boolean;
  truncated: boolean;
}

export interface AnalysisStats {
  filesAnalyzed: number;
  filesSkipped: number;
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
  totalTokensUsed: number;
  estimatedCost: number;
  durationMs: number;
}

export interface ProjectContext {
  readme: string;
  packageMeta: Record<string, unknown> | null;
  directoryTree: string;
  envVars: string[];
  hasDockerfile: boolean;
  hasCI: boolean;
  language: string;
  framework: string;
}

export interface FileContext {
  filePath: string;
  content: string;
  language: string;
  lineCount: number;
  imports: string[];
  importedBy: string[];
  siblingFiles: string[];
  isTestFile: boolean;
  isConfigFile: boolean;
  isGenerated: boolean;
}

export interface DependencyNode {
  file: string;
  imports: string[];
  importedBy: string[];
}

export interface DependencyGraph {
  nodes: Map<string, DependencyNode>;
  entryPoints: string[];
}
