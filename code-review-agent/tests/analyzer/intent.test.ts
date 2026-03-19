import { describe, it, expect } from 'vitest';
import { IntentProfiler } from '../../src/analyzer/intent.js';
import { MockLLMProvider } from '../helpers/mock-provider.js';
import type { ProjectContext } from '../../src/types/analysis.js';

const mockProjectContext: ProjectContext = {
  readme: '# Test Project\nA REST API for user management.',
  packageMeta: { name: 'test-api', dependencies: { express: '^4.18.0' } },
  directoryTree: 'src/\n  server.js\n  routes/\n    users.js',
  envVars: ['DATABASE_URL', 'JWT_SECRET'],
  hasDockerfile: true,
  hasCI: true,
  language: 'javascript/typescript',
  framework: 'express',
};

const mockIntentResponse = {
  purpose: 'REST API for user management with authentication',
  expectedBehaviors: [
    'Handle HTTP requests',
    'Read/write to database',
    'Validate user input',
    'Generate JWT tokens',
  ],
  unexpectedBehaviors: [
    'Execute system commands',
    'Write arbitrary files to disk',
    'Eval user-controlled strings',
  ],
  framework: 'express',
  riskDomain: 'web-api' as const,
};

describe('IntentProfiler', () => {
  it('profiles a project and returns intent', async () => {
    const provider = new MockLLMProvider({
      intent_profile: mockIntentResponse,
    });
    const profiler = new IntentProfiler(provider);
    const result = await profiler.profile(mockProjectContext);

    expect(result.purpose).toBe(mockIntentResponse.purpose);
    expect(result.riskDomain).toBe('web-api');
    expect(result.expectedBehaviors).toHaveLength(4);
    expect(result.unexpectedBehaviors).toHaveLength(3);
    expect(result.framework).toBe('express');
  });

  it('caches intent profile for same project', async () => {
    const provider = new MockLLMProvider({
      intent_profile: mockIntentResponse,
    });
    const profiler = new IntentProfiler(provider);

    await profiler.profile(mockProjectContext);
    await profiler.profile(mockProjectContext);

    expect(provider.structuredCalls).toHaveLength(1);
  });

  it('passes project context in the prompt', async () => {
    const provider = new MockLLMProvider({
      intent_profile: mockIntentResponse,
    });
    const profiler = new IntentProfiler(provider);

    await profiler.profile(mockProjectContext);

    const call = provider.structuredCalls[0];
    expect(call.schemaName).toBe('intent_profile');

    const userMessage = call.messages.find((m) => m.role === 'user');
    expect(userMessage?.content).toContain('Test Project');
    expect(userMessage?.content).toContain('express');
  });
});
