import { describe, it, expect, vi, beforeEach } from 'vitest';
import { z } from 'zod';
import { SchemaValidationError } from '../../src/llm/provider.js';

// Mock child_process.spawn before importing the provider
const mockStdin = { write: vi.fn(), end: vi.fn(), on: vi.fn() };
const mockStdout = { on: vi.fn() };
const mockStderr = { on: vi.fn() };
const mockChild = {
  stdin: mockStdin,
  stdout: mockStdout,
  stderr: mockStderr,
  on: vi.fn(),
};

vi.mock('node:child_process', () => ({
  spawn: vi.fn(() => mockChild),
}));

import { ClaudeCliProvider } from '../../src/llm/claude-cli.js';
import { spawn } from 'node:child_process';

function simulateClaudeResponse(result: string, isError = false) {
  const jsonOutput = JSON.stringify({
    type: 'result',
    subtype: 'success',
    is_error: isError,
    result,
  });

  // When stdout.on('data', cb) is called, capture the callback
  mockStdout.on.mockImplementation((event: string, cb: (data: Buffer) => void) => {
    if (event === 'data') {
      cb(Buffer.from(jsonOutput));
    }
  });

  mockStderr.on.mockImplementation(() => {});

  // When child.on('close', cb) is called, trigger immediately
  mockChild.on.mockImplementation((event: string, cb: (code: number) => void) => {
    if (event === 'close') {
      cb(0);
    }
  });
}

function simulateClaudeError(code: number, stderrMsg = '') {
  mockStdout.on.mockImplementation(() => {});
  mockStderr.on.mockImplementation((event: string, cb: (data: Buffer) => void) => {
    if (event === 'data' && stderrMsg) {
      cb(Buffer.from(stderrMsg));
    }
  });
  mockChild.on.mockImplementation((event: string, cb: (code: number) => void) => {
    if (event === 'close') {
      cb(code);
    }
  });
}

function simulateSpawnError(message: string) {
  mockStdout.on.mockImplementation(() => {});
  mockStderr.on.mockImplementation(() => {});
  mockChild.on.mockImplementation((event: string, cb: unknown) => {
    if (event === 'error') {
      (cb as (err: Error) => void)(new Error(message));
    }
  });
}

describe('ClaudeCliProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('defaults to sonnet model', () => {
      const provider = new ClaudeCliProvider();
      expect(provider.modelId).toBe('sonnet');
      expect(provider.providerName).toBe('claude-cli');
    });

    it('accepts custom model', () => {
      const provider = new ClaudeCliProvider('haiku');
      expect(provider.modelId).toBe('haiku');
    });
  });

  describe('chat', () => {
    it('sends prompt via stdin and returns result', async () => {
      simulateClaudeResponse('Hello world');
      const provider = new ClaudeCliProvider();
      const result = await provider.chat([
        { role: 'user', content: 'Say hello' },
      ]);

      expect(result).toBe('Hello world');
      expect(spawn).toHaveBeenCalledWith('claude', [
        '-p', '-',
        '--output-format', 'json',
        '--model', 'sonnet',
        '--no-session-persistence',
      ], expect.any(Object));
      expect(mockStdin.write).toHaveBeenCalled();
      expect(mockStdin.end).toHaveBeenCalled();
    });

    it('formats system messages correctly', async () => {
      simulateClaudeResponse('ok');
      const provider = new ClaudeCliProvider();
      await provider.chat([
        { role: 'system', content: 'You are a helper' },
        { role: 'user', content: 'Help me' },
      ]);

      const writtenPrompt = mockStdin.write.mock.calls[0][0] as string;
      expect(writtenPrompt).toContain('[System Instructions]');
      expect(writtenPrompt).toContain('You are a helper');
      expect(writtenPrompt).toContain('Help me');
    });

    it('formats assistant messages correctly', async () => {
      simulateClaudeResponse('final answer');
      const provider = new ClaudeCliProvider();
      await provider.chat([
        { role: 'user', content: 'Question 1' },
        { role: 'assistant', content: 'Answer 1' },
        { role: 'user', content: 'Question 2' },
      ]);

      const writtenPrompt = mockStdin.write.mock.calls[0][0] as string;
      expect(writtenPrompt).toContain('[Previous response]');
      expect(writtenPrompt).toContain('Answer 1');
    });

    it('handles large prompts via stdin', async () => {
      const largeContent = 'x'.repeat(100_000);
      simulateClaudeResponse('analyzed');
      const provider = new ClaudeCliProvider();
      const result = await provider.chat([
        { role: 'user', content: largeContent },
      ]);

      expect(result).toBe('analyzed');
      const writtenPrompt = mockStdin.write.mock.calls[0][0] as string;
      expect(writtenPrompt.length).toBeGreaterThanOrEqual(100_000);
    });

    it('rejects on non-zero exit code', async () => {
      simulateClaudeError(1, 'something went wrong');
      const provider = new ClaudeCliProvider();

      await expect(provider.chat([
        { role: 'user', content: 'test' },
      ])).rejects.toThrow('claude CLI exited with code 1');
    });

    it('rejects on spawn error', async () => {
      simulateSpawnError('command not found');
      const provider = new ClaudeCliProvider();

      await expect(provider.chat([
        { role: 'user', content: 'test' },
      ])).rejects.toThrow('claude CLI failed to start');
    });

    it('rejects when CLI returns is_error', async () => {
      simulateClaudeResponse('API rate limit exceeded', true);
      const provider = new ClaudeCliProvider();

      await expect(provider.chat([
        { role: 'user', content: 'test' },
      ])).rejects.toThrow('claude CLI error');
    });
  });

  describe('chatStructured', () => {
    const TestSchema = z.object({
      name: z.string(),
      value: z.number(),
    });

    it('parses valid JSON response', async () => {
      simulateClaudeResponse('{"name": "test", "value": 42}');
      const provider = new ClaudeCliProvider();
      const result = await provider.chatStructured(
        [{ role: 'user', content: 'Give me data' }],
        TestSchema,
        'test_schema',
      );

      expect(result).toEqual({ name: 'test', value: 42 });
    });

    it('extracts JSON from markdown code blocks', async () => {
      simulateClaudeResponse('```json\n{"name": "test", "value": 42}\n```');
      const provider = new ClaudeCliProvider();
      const result = await provider.chatStructured(
        [{ role: 'user', content: 'Give me data' }],
        TestSchema,
        'test_schema',
      );

      expect(result).toEqual({ name: 'test', value: 42 });
    });

    it('extracts JSON from surrounding text', async () => {
      simulateClaudeResponse('Here is the result: {"name": "test", "value": 42} done.');
      const provider = new ClaudeCliProvider();
      const result = await provider.chatStructured(
        [{ role: 'user', content: 'Give me data' }],
        TestSchema,
        'test_schema',
      );

      expect(result).toEqual({ name: 'test', value: 42 });
    });

    it('throws SchemaValidationError after max retries with invalid JSON', async () => {
      simulateClaudeResponse('not json at all');
      const provider = new ClaudeCliProvider();

      await expect(provider.chatStructured(
        [{ role: 'user', content: 'Give me data' }],
        TestSchema,
        'test_schema',
      )).rejects.toThrow(SchemaValidationError);
    });

    it('throws SchemaValidationError after max retries with wrong schema', async () => {
      simulateClaudeResponse('{"wrong": "shape"}');
      const provider = new ClaudeCliProvider();

      await expect(provider.chatStructured(
        [{ role: 'user', content: 'Give me data' }],
        TestSchema,
        'test_schema',
      )).rejects.toThrow(SchemaValidationError);
    });
  });

  describe('countTokens', () => {
    it('approximates token count from text length', () => {
      const provider = new ClaudeCliProvider();
      expect(provider.countTokens('hello world')).toBe(3); // ceil(11/4)
      expect(provider.countTokens('')).toBe(0);
      expect(provider.countTokens('a'.repeat(100))).toBe(25);
    });
  });
});
