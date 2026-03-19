import OpenAI from 'openai';
import { type Tiktoken, encoding_for_model } from 'tiktoken';
import type { z } from 'zod';
import { type ChatMessage, type LLMProvider, SchemaValidationError } from './provider.js';
import { zodToOpenAIResponseFormat } from './schemas.js';

const MAX_RETRIES = 3;

export class OpenAIProvider implements LLMProvider {
  private client: OpenAI;
  private encoder: Tiktoken | null = null;
  readonly modelId: string;
  readonly providerName = 'openai';

  constructor(apiKey: string, model?: string) {
    this.client = new OpenAI({ apiKey });
    this.modelId = model ?? 'gpt-4o';
  }

  async chat(messages: ChatMessage[]): Promise<string> {
    const response = await this.client.chat.completions.create({
      model: this.modelId,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      max_tokens: 4096,
    });

    return response.choices[0]?.message?.content ?? '';
  }

  async chatStructured<T>(
    messages: ChatMessage[],
    schema: z.ZodType<T>,
    schemaName: string,
  ): Promise<T> {
    const responseFormat = zodToOpenAIResponseFormat(schema, schemaName);

    let lastError: Error | null = null;
    const conversationMessages = messages.map((m) => ({
      role: m.role,
      content: m.content,
    }));

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const response = await this.client.chat.completions.create({
        model: this.modelId,
        messages: conversationMessages,
        max_tokens: 8192,
        response_format: responseFormat,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        lastError = new Error('Empty response from OpenAI');
        continue;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(content);
      } catch (e) {
        lastError = e instanceof Error ? e : new Error(String(e));
        continue;
      }

      const result = schema.safeParse(parsed);
      if (result.success) {
        return result.data;
      }

      lastError = new Error(result.error.message);

      conversationMessages.push({
        role: 'assistant' as const,
        content,
      });
      conversationMessages.push({
        role: 'user' as const,
        content: `Schema validation error: ${result.error.message}. Please fix and respond again.`,
      });
    }

    throw new SchemaValidationError(MAX_RETRIES, lastError!);
  }

  countTokens(text: string): number {
    try {
      if (!this.encoder) {
        this.encoder = encoding_for_model(this.modelId as Parameters<typeof encoding_for_model>[0]);
      }
      return this.encoder.encode(text).length;
    } catch {
      return Math.ceil(text.length / 4);
    }
  }
}
