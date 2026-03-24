// Core engine
export { AnalysisEngine, type ProgressCallback } from './analyzer/engine.js';
export { IntentProfiler } from './analyzer/intent.js';
export { SemanticAnalyzer } from './analyzer/semantic.js';
export { postFilterFindings, suppressCarrierFindings } from './analyzer/postprocess.js';

// LLM providers
export { AnthropicProvider } from './llm/anthropic.js';
export { ClaudeCliProvider } from './llm/claude-cli.js';
export { OpenAIProvider } from './llm/openai.js';
export { ModelRouter } from './llm/router.js';
export type { LLMProvider, ChatMessage } from './llm/provider.js';
export { SchemaValidationError } from './llm/provider.js';
export { zodToJsonSchema, zodToAnthropicTool, zodToOpenAIResponseFormat } from './llm/schemas.js';

// Context
export { buildProjectContext, formatProjectContextForLLM } from './context/project.js';
export { buildFileContext, isTestFile, isConfigFile, isGeneratedFile } from './context/file.js';
export { ContextAssembler } from './context/assembler.js';
export { buildRelatedFileSummaries, formatRelatedFileSummaries } from './context/security-summary.js';
export type { RelatedFileSummary } from './context/security-summary.js';

// Graph
export { DependencyGraphBuilder } from './graph/dependency.js';
export { resolveImportPath, extractImports, isLocalImport } from './graph/resolver.js';

// Types
export type {
  AnalysisResult,
  AnalysisStats,
  FileAnalysisResult,
  ProjectContext,
  FileContext,
  DependencyNode,
  DependencyGraph,
} from './types/analysis.js';
export type {
  AnalysisMode,
  AnalysisOptions,
  CRAgentConfig,
} from './types/config.js';
export { loadConfig, resolveOptions } from './types/config.js';
export {
  FindingSchema,
  FileAnalysisResponseSchema,
  IntentProfileSchema,
  TriageDecisionSchema,
  SeveritySchema,
  CategorySchema,
  IntentAlignmentSchema,
  RiskDomainSchema,
} from './types/findings.js';
export type {
  Finding,
  FileAnalysisResponse,
  IntentProfile,
  TriageDecision,
  Severity,
  Category,
  IntentAlignment,
  RiskDomain,
} from './types/findings.js';
