import type { z } from 'zod';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMProvider {
  readonly modelId: string;
  readonly providerName: string;

  chat(messages: ChatMessage[]): Promise<string>;

  chatStructured<T>(
    messages: ChatMessage[],
    schema: z.ZodType<T>,
    schemaName: string,
  ): Promise<T>;

  countTokens(text: string): number;
}

export class SchemaValidationError extends Error {
  constructor(
    public readonly attempts: number,
    public readonly lastError: Error,
  ) {
    super(
      `Schema validation failed after ${attempts} attempts: ${lastError.message}`,
    );
    this.name = 'SchemaValidationError';
  }
}
