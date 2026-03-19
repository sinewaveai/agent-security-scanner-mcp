import { describe, it, expect } from 'vitest';
import { SemanticAnalyzer } from '../../src/analyzer/semantic.js';
import { MockLLMProvider } from '../helpers/mock-provider.js';
import type { FileContext, ProjectContext } from '../../src/types/analysis.js';
import type { IntentProfile } from '../../src/types/findings.js';

const mockIntent: IntentProfile = {
  purpose: 'REST API for user management',
  expectedBehaviors: ['Handle HTTP requests', 'Read/write database'],
  unexpectedBehaviors: ['Execute system commands', 'Eval user input'],
  framework: 'express',
  riskDomain: 'web-api',
};

const mockProject: ProjectContext = {
  readme: '# API Server',
  packageMeta: { name: 'api', dependencies: { express: '^4.0.0' } },
  directoryTree: 'src/\n  server.js',
  envVars: [],
  hasDockerfile: false,
  hasCI: false,
  language: 'javascript/typescript',
  framework: 'express',
};

const mockFileContext: FileContext = {
  filePath: 'server.js',
  content: 'const x = eval(req.query.code);',
  language: 'javascript',
  lineCount: 1,
  imports: ['express'],
  importedBy: [],
  siblingFiles: [],
  isTestFile: false,
  isConfigFile: false,
  isGenerated: false,
};

const mockAnalysisResponse = {
  findings: [
    {
      title: 'eval() on user input',
      severity: 'critical' as const,
      category: 'security' as const,
      location: { file: 'server.js', startLine: 1, endLine: 1 },
      reasoning: 'eval() with user-controlled input allows arbitrary code execution',
      intentAlignment: 'violates-intent' as const,
      confidence: 0.95,
      suggestedAction: 'Use a safe parser or whitelist approach instead of eval',
      cwe: 'CWE-94',
    },
  ],
};

const mockTriageResponse = {
  action: 'analyze' as const,
  reason: 'File handles HTTP requests and uses eval',
  areasOfInterest: [{ startLine: 1, endLine: 1, reason: 'eval() call' }],
};

describe('SemanticAnalyzer', () => {
  it('analyzes a file and returns findings', async () => {
    const analysisProvider = new MockLLMProvider({
      file_analysis: mockAnalysisResponse,
    });
    const triageProvider = new MockLLMProvider({
      triage_decision: mockTriageResponse,
    });

    const analyzer = new SemanticAnalyzer(analysisProvider, triageProvider);
    const result = await analyzer.analyzeFile(mockIntent, mockProject, mockFileContext);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].title).toBe('eval() on user input');
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].intentAlignment).toBe('violates-intent');
    expect(result.findings[0].confidence).toBe(0.95);
    expect(result.tokensUsed).toBeGreaterThan(0);
  });

  it('triages a file and returns decision', async () => {
    const analysisProvider = new MockLLMProvider({});
    const triageProvider = new MockLLMProvider({
      triage_decision: mockTriageResponse,
    });

    const analyzer = new SemanticAnalyzer(analysisProvider, triageProvider);
    const decision = await analyzer.triageFile(mockProject, mockFileContext);

    expect(decision.action).toBe('analyze');
    expect(decision.areasOfInterest).toHaveLength(1);
    expect(triageProvider.structuredCalls[0]?.messages[0]?.content).toContain('UNTRUSTED INPUT');
  });

  it('returns skip decision for safe files', async () => {
    const skipResponse = {
      action: 'skip' as const,
      reason: 'Test file with no security-relevant code',
      areasOfInterest: [],
    };

    const analysisProvider = new MockLLMProvider({});
    const triageProvider = new MockLLMProvider({
      triage_decision: skipResponse,
    });

    const analyzer = new SemanticAnalyzer(analysisProvider, triageProvider);
    const decision = await analyzer.triageFile(mockProject, {
      ...mockFileContext,
      filePath: 'test.test.js',
      isTestFile: true,
    });

    expect(decision.action).toBe('skip');
  });

  it('sets correct file path on findings', async () => {
    const analysisProvider = new MockLLMProvider({
      file_analysis: mockAnalysisResponse,
    });
    const triageProvider = new MockLLMProvider({});

    const analyzer = new SemanticAnalyzer(analysisProvider, triageProvider);
    const result = await analyzer.analyzeFile(mockIntent, mockProject, {
      ...mockFileContext,
      filePath: 'src/routes/users.js',
    });

    expect(result.findings[0].location.file).toBe('src/routes/users.js');
  });
});
