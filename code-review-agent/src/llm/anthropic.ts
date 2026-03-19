import Anthropic from '@anthropic-ai/sdk';
import { countTokens } from '@anthropic-ai/tokenizer';
import type { z } from 'zod';
import { type ChatMessage, type LLMProvider, SchemaValidationError } from './provider.js';
import { zodToAnthropicTool } from './schemas.js';

const MAX_RETRIES = 3;

export class AnthropicProvider implements LLMProvider {
  private client: Anthropic;
  readonly modelId: string;
  readonly providerName = 'anthropic';

  constructor(apiKey: string, model?: string) {
    this.client = new Anthropic({ apiKey });
    this.modelId = model ?? 'claude-sonnet-4-20250514';
  }

  async chat(messages: ChatMessage[]): Promise<string> {
    const { system, userMessages } = this.splitMessages(messages);

    const response = await this.client.messages.create({
      model: this.modelId,
      max_tokens: 4096,
      system: system ?? undefined,
      messages: userMessages,
    });

    const textBlock = response.content.find((b) => b.type === 'text');
    return textBlock?.text ?? '';
  }

  async chatStructured<T>(
    messages: ChatMessage[],
    schema: z.ZodType<T>,
    schemaName: string,
  ): Promise<T> {
    const tool = zodToAnthropicTool(schema, schemaName, `Respond with ${schemaName}`);
    const { system, userMessages } = this.splitMessages(messages);

    let lastError: Error | null = null;
    const conversationMessages = [...userMessages];

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const response = await this.client.messages.create({
        model: this.modelId,
        max_tokens: 8192,
        system: system ?? undefined,
        messages: conversationMessages,
        tools: [tool as Anthropic.Tool],
        tool_choice: { type: 'tool' as const, name: schemaName },
      });

      const toolBlock = response.content.find((b) => b.type === 'tool_use');
      if (!toolBlock || toolBlock.type !== 'tool_use') {
        lastError = new Error('No tool_use block in response');
        continue;
      }

      const result = schema.safeParse(toolBlock.input);
      if (result.success) {
        return result.data;
      }

      lastError = new Error(result.error.message);

      // Append error feedback for retry
      conversationMessages.push({
        role: 'assistant',
        content: JSON.stringify(toolBlock.input),
      });
      conversationMessages.push({
        role: 'user',
        content: `Schema validation error: ${result.error.message}. Please fix and respond again.`,
      });
    }

    throw new SchemaValidationError(MAX_RETRIES, lastError!);
  }

  countTokens(text: string): number {
    try {
      return countTokens(text);
    } catch {
      return Math.ceil(text.length / 4);
    }
  }

  private splitMessages(messages: ChatMessage[]): {
    system: string | null;
    userMessages: Array<{ role: 'user' | 'assistant'; content: string }>;
  } {
    let system: string | null = null;
    const userMessages: Array<{ role: 'user' | 'assistant'; content: string }> = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        system = msg.content;
      } else {
        userMessages.push({ role: msg.role, content: msg.content });
      }
    }

    return { system, userMessages };
  }
}
