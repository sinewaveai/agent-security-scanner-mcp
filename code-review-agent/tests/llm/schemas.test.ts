import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  zodToJsonSchema,
  zodToAnthropicTool,
  zodToOpenAIResponseFormat,
} from '../../src/llm/schemas.js';

describe('zodToJsonSchema', () => {
  it('converts string schema', () => {
    const result = zodToJsonSchema(z.string());
    expect(result).toEqual({ type: 'string' });
  });

  it('converts number schema with min/max', () => {
    const result = zodToJsonSchema(z.number().min(0).max(1));
    expect(result).toEqual({ type: 'number', minimum: 0, maximum: 1 });
  });

  it('converts boolean schema', () => {
    const result = zodToJsonSchema(z.boolean());
    expect(result).toEqual({ type: 'boolean' });
  });

  it('converts enum schema', () => {
    const result = zodToJsonSchema(z.enum(['a', 'b', 'c']));
    expect(result).toEqual({ type: 'string', enum: ['a', 'b', 'c'] });
  });

  it('converts array schema', () => {
    const result = zodToJsonSchema(z.array(z.string()));
    expect(result).toEqual({ type: 'array', items: { type: 'string' } });
  });

  it('converts object schema', () => {
    const schema = z.object({
      name: z.string(),
      age: z.number(),
    });
    const result = zodToJsonSchema(schema);
    expect(result).toEqual({
      type: 'object',
      properties: {
        name: { type: 'string' },
        age: { type: 'number' },
      },
      required: ['name', 'age'],
      additionalProperties: false,
    });
  });

  it('handles optional fields', () => {
    const schema = z.object({
      name: z.string(),
      bio: z.string().optional(),
    });
    const result = zodToJsonSchema(schema);
    expect(result).toEqual({
      type: 'object',
      properties: {
        name: { type: 'string' },
        bio: { type: 'string' },
      },
      required: ['name'],
      additionalProperties: false,
    });
  });

  it('converts nested object schema', () => {
    const schema = z.object({
      location: z.object({
        file: z.string(),
        line: z.number(),
      }),
    });
    const result = zodToJsonSchema(schema);
    expect(result).toEqual({
      type: 'object',
      properties: {
        location: {
          type: 'object',
          properties: {
            file: { type: 'string' },
            line: { type: 'number' },
          },
          required: ['file', 'line'],
          additionalProperties: false,
        },
      },
      required: ['location'],
      additionalProperties: false,
    });
  });

  it('converts literal schema', () => {
    const result = zodToJsonSchema(z.literal('analyze'));
    expect(result).toEqual({ type: 'string', const: 'analyze' });
  });

  it('throws for unsupported zod types instead of returning an empty schema', () => {
    expect(() => zodToJsonSchema(z.tuple([z.string()]))).toThrow(
      'unsupported Zod type',
    );
  });
});

describe('zodToAnthropicTool', () => {
  it('wraps schema as Anthropic tool definition', () => {
    const schema = z.object({ name: z.string() });
    const result = zodToAnthropicTool(schema, 'test_tool', 'A test tool');
    expect(result).toEqual({
      name: 'test_tool',
      description: 'A test tool',
      input_schema: {
        type: 'object',
        properties: { name: { type: 'string' } },
        required: ['name'],
        additionalProperties: false,
      },
    });
  });
});

describe('zodToOpenAIResponseFormat', () => {
  it('wraps schema as OpenAI response_format', () => {
    const schema = z.object({ value: z.number() });
    const result = zodToOpenAIResponseFormat(schema, 'test_format');
    expect(result).toEqual({
      type: 'json_schema',
      json_schema: {
        name: 'test_format',
        strict: true,
        schema: {
          type: 'object',
          properties: { value: { type: 'number' } },
          required: ['value'],
          additionalProperties: false,
        },
      },
    });
  });
});
