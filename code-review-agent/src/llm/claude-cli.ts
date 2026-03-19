import { spawn } from 'node:child_process';
import type { z } from 'zod';
import { type ChatMessage, type LLMProvider, SchemaValidationError } from './provider.js';
import { zodToJsonSchema } from './schemas.js';

const MAX_RETRIES = 3;

interface ClaudeCliResult {
  type: string;
  result: string;
  is_error: boolean;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

export class ClaudeCliProvider implements LLMProvider {
  readonly modelId: string;
  readonly providerName = 'claude-cli';

  constructor(model?: string) {
    this.modelId = model ?? 'sonnet';
  }

  async chat(messages: ChatMessage[]): Promise<string> {
    const prompt = this.formatMessages(messages);
    return this.runClaude(prompt);
  }

  async chatStructured<T>(
    messages: ChatMessage[],
    schema: z.ZodType<T>,
    schemaName: string,
  ): Promise<T> {
    const jsonSchema = zodToJsonSchema(schema);
    const schemaInstruction = [
      `You MUST respond with ONLY a valid JSON object matching this schema (no markdown, no explanation, no wrapping):`,
      `Schema name: ${schemaName}`,
      '```json',
      JSON.stringify(jsonSchema, null, 2),
      '```',
      'Respond with ONLY the JSON object. No other text.',
    ].join('\n');

    let lastError: Error | null = null;
    const conversationParts = [...messages];

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const prompt = this.formatMessages([
        ...conversationParts,
        { role: 'user', content: schemaInstruction },
      ]);

      const raw = await this.runClaude(prompt);

      // Extract JSON from response (handle markdown code blocks)
      const jsonStr = extractJson(raw);

      let parsed: unknown;
      try {
        parsed = JSON.parse(jsonStr);
      } catch (e) {
        lastError = e instanceof Error ? e : new Error(String(e));
        conversationParts.push(
          { role: 'assistant', content: raw },
          { role: 'user', content: `That was not valid JSON. Parse error: ${lastError.message}. Respond with ONLY a valid JSON object.` },
        );
        continue;
      }

      const result = schema.safeParse(parsed);
      if (result.success) {
        return result.data;
      }

      lastError = new Error(result.error.message);
      conversationParts.push(
        { role: 'assistant', content: raw },
        { role: 'user', content: `Schema validation error: ${result.error.message}. Fix the JSON and respond with ONLY the corrected JSON object.` },
      );
    }

    throw new SchemaValidationError(MAX_RETRIES, lastError!);
  }

  countTokens(text: string): number {
    // Approximate — Claude CLI doesn't expose a token counter
    return Math.ceil(text.length / 4);
  }

  private formatMessages(messages: ChatMessage[]): string {
    const parts: string[] = [];

    for (const msg of messages) {
      if (msg.role === 'system') {
        parts.push(`[System Instructions]\n${msg.content}\n`);
      } else if (msg.role === 'user') {
        parts.push(`${msg.content}`);
      } else if (msg.role === 'assistant') {
        parts.push(`[Previous response]\n${msg.content}\n`);
      }
    }

    return parts.join('\n\n');
  }

  private runClaude(prompt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const args = [
        '-p', '-',
        '--output-format', 'json',
        '--model', this.modelId,
        '--no-session-persistence',
      ];

      const child = spawn('claude', args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 180_000,
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
      child.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

      child.on('close', (code) => {
        if (code !== 0 && !stdout) {
          // Sanitize stderr — only show first 200 chars, never leak prompt content
          const safeStderr = stderr ? sanitizeError(stderr) : '';
          reject(new Error(`claude CLI exited with code ${code}${safeStderr ? `: ${safeStderr}` : ''}`));
          return;
        }

        try {
          const result = JSON.parse(stdout) as ClaudeCliResult;
          if (result.is_error) {
            reject(new Error(`claude CLI error: ${sanitizeError(result.result)}`));
            return;
          }
          resolve(result.result);
        } catch {
          resolve(stdout.trim());
        }
      });

      child.on('error', (err) => {
        reject(new Error(`claude CLI failed to start: ${sanitizeError(err.message)}`));
      });

      // Handle stdin write errors (e.g., broken pipe if child exits early)
      child.stdin.on('error', (err) => {
        // Ignore EPIPE — child may have already exited, close handler will deal with it
        if ((err as NodeJS.ErrnoException).code !== 'EPIPE') {
          reject(new Error(`Failed to write prompt to claude CLI: ${sanitizeError(err.message)}`));
        }
      });

      // Write prompt to stdin and close it
      child.stdin.write(prompt);
      child.stdin.end();
    });
  }
}

function sanitizeError(msg: string): string {
  // Never leak prompt content in errors — truncate and strip anything
  // that looks like it could be prompt/code/schema content
  const firstLine = msg.split('\n')[0].trim();
  return firstLine.length > 200 ? firstLine.slice(0, 200) + '...' : firstLine;
}

function extractJson(text: string): string {
  // Try to extract JSON from markdown code blocks
  const codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (codeBlockMatch) {
    return codeBlockMatch[1].trim();
  }

  // Try to find a JSON object directly
  const objectMatch = text.match(/\{[\s\S]*\}/);
  if (objectMatch) {
    return objectMatch[0];
  }

  return text.trim();
}
