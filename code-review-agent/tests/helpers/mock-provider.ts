import type { z } from 'zod';
import type { ChatMessage, LLMProvider } from '../../src/llm/provider.js';

export class MockLLMProvider implements LLMProvider {
  readonly modelId: string;
  readonly providerName = 'mock';

  private responses: Map<string, unknown>;
  public chatCalls: Array<{ messages: ChatMessage[] }> = [];
  public structuredCalls: Array<{ messages: ChatMessage[]; schemaName: string }> = [];

  constructor(
    responses: Record<string, unknown>,
    modelId = 'mock-model',
  ) {
    this.responses = new Map(Object.entries(responses));
    this.modelId = modelId;
  }

  async chat(messages: ChatMessage[]): Promise<string> {
    this.chatCalls.push({ messages });
    return 'mock response';
  }

  async chatStructured<T>(
    messages: ChatMessage[],
    schema: z.ZodType<T>,
    schemaName: string,
  ): Promise<T> {
    this.structuredCalls.push({ messages, schemaName });

    const response = this.responses.get(schemaName);
    if (!response) {
      throw new Error(`No mock response for schema: ${schemaName}`);
    }

    const result = schema.safeParse(response);
    if (!result.success) {
      throw new Error(`Mock response failed validation for ${schemaName}: ${result.error.message}`);
    }

    return result.data;
  }

  countTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }
}
