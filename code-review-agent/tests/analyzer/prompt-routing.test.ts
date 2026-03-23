import { describe, it, expect } from 'vitest';
import { SemanticAnalyzer } from '../../src/analyzer/semantic.js';
import { MockLLMProvider } from '../helpers/mock-provider.js';
import type { FileContext, ProjectContext } from '../../src/types/analysis.js';
import type { IntentProfile } from '../../src/types/findings.js';

const mockIntent: IntentProfile = {
  purpose: 'REST API for user management',
  expectedBehaviors: ['Handle HTTP requests'],
  unexpectedBehaviors: ['Execute eval'],
  framework: 'express',
  riskDomain: 'web-api',
};

const mockProject: ProjectContext = {
  readme: '# API',
  packageMeta: null,
  directoryTree: 'src/',
  envVars: [],
  hasDockerfile: false,
  hasCI: false,
  language: 'javascript/typescript',
  framework: 'express',
};

const mockFile: FileContext = {
  filePath: 'app.js',
  content: 'const x = 1;',
  language: 'javascript',
  lineCount: 1,
  imports: [],
  importedBy: [],
  siblingFiles: [],
  isTestFile: false,
  isConfigFile: false,
  isGenerated: false,
};

const mockAnalysisResponse = {
  findings: [{
    title: 'Test finding',
    severity: 'medium' as const,
    category: 'security' as const,
    location: { file: 'app.js', startLine: 1, endLine: 1 },
    reasoning: 'Test',
    intentAlignment: 'unclear' as const,
    confidence: 0.8,
    suggestedAction: 'Fix',
  }],
};

describe('prompt routing by mode', () => {
  it('uses broad review prompt in review mode', async () => {
    const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
    const triage = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(provider, triage, 'review');
    await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

    const systemMsg = provider.structuredCalls[0].messages[0].content;
    expect(systemMsg).toContain('logic errors, security vulnerabilities, race conditions');
    expect(systemMsg).not.toContain('SINK LOCALIZATION');
  });

  it('uses focused security prompt in security mode', async () => {
    const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
    const triage = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(provider, triage, 'security');
    await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

    const systemMsg = provider.structuredCalls[0].messages[0].content;
    expect(systemMsg).toContain('EXPLOITABLE SECURITY VULNERABILITIES');
    expect(systemMsg).toContain('SINK LOCALIZATION');
    expect(systemMsg).not.toContain('logic errors, security vulnerabilities, race conditions');
  });

  it('uses security-specific user message in security mode', async () => {
    const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
    const triage = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(provider, triage, 'security');
    await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

    const userMsg = provider.structuredCalls[0].messages[1].content;
    expect(userMsg).toContain('security vulnerabilities');
    expect(userMsg).not.toContain('real bugs and vulnerabilities');
  });

  it('uses broad user message in review mode', async () => {
    const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
    const triage = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(provider, triage, 'review');
    await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

    const userMsg = provider.structuredCalls[0].messages[1].content;
    expect(userMsg).toContain('real bugs and vulnerabilities');
  });

  it('defaults to review mode when mode not specified', async () => {
    const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
    const triage = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(provider, triage);
    await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

    const systemMsg = provider.structuredCalls[0].messages[0].content;
    expect(systemMsg).toContain('logic errors, security vulnerabilities, race conditions');
  });

  it('both modes include untrusted input warning', async () => {
    for (const mode of ['review', 'security'] as const) {
      const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
      const triage = new MockLLMProvider({});

      const analyzer = new SemanticAnalyzer(provider, triage, mode);
      await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

      const systemMsg = provider.structuredCalls[0].messages[0].content;
      expect(systemMsg).toContain('UNTRUSTED INPUT');
    }
  });

  it('both modes include intent-aware analysis block', async () => {
    for (const mode of ['review', 'security'] as const) {
      const provider = new MockLLMProvider({ file_analysis: mockAnalysisResponse });
      const triage = new MockLLMProvider({});

      const analyzer = new SemanticAnalyzer(provider, triage, mode);
      await analyzer.analyzeFile(mockIntent, mockProject, mockFile);

      const systemMsg = provider.structuredCalls[0].messages[0].content;
      expect(systemMsg).toContain('Intent-Aware Analysis');
    }
  });
});
