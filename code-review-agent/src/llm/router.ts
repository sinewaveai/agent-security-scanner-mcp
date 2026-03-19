import type { AnalysisOptions } from '../types/config.js';
import { AnthropicProvider } from './anthropic.js';
import { ClaudeCliProvider } from './claude-cli.js';
import { OpenAIProvider } from './openai.js';
import type { LLMProvider } from './provider.js';

const TRIAGE_MODELS: Record<string, string> = {
  anthropic: 'claude-haiku-4-5-20251001',
  openai: 'gpt-4o-mini',
  'claude-cli': 'haiku',
};

const ANALYSIS_MODELS: Record<string, string> = {
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-4o',
  'claude-cli': 'sonnet',
};

// Approximate USD per million tokens (input + output averaged)
const COST_PER_MILLION: Record<string, number> = {
  'claude-sonnet-4-20250514': 9,
  'claude-haiku-4-5-20251001': 1.25,
  'gpt-4o': 7.5,
  'gpt-4o-mini': 0.3,
};

export class ModelRouter {
  private triageProvider: LLMProvider | null = null;
  private analysisProvider: LLMProvider | null = null;
  private options: AnalysisOptions;

  constructor(options: AnalysisOptions) {
    this.options = options;
  }

  getTriageProvider(): LLMProvider {
    if (!this.triageProvider) {
      const model =
        this.options.triageModel ?? TRIAGE_MODELS[this.options.provider];
      this.triageProvider = this.createProvider(model);
    }
    return this.triageProvider;
  }

  getAnalysisProvider(): LLMProvider {
    if (!this.analysisProvider) {
      const model =
        this.options.model ?? ANALYSIS_MODELS[this.options.provider];
      this.analysisProvider = this.createProvider(model);
    }
    return this.analysisProvider;
  }

  estimateCost(tokens: number, model?: string): number {
    const modelId =
      model ?? this.options.model ?? ANALYSIS_MODELS[this.options.provider];
    const rate = COST_PER_MILLION[modelId] ?? 5;
    return (tokens / 1_000_000) * rate;
  }

  private createProvider(model: string): LLMProvider {
    const provider = this.options.provider;

    if (provider === 'claude-cli') {
      return new ClaudeCliProvider(model);
    }

    const apiKey = this.getApiKey(provider);
    if (provider === 'anthropic') {
      return new AnthropicProvider(apiKey, model);
    }
    return new OpenAIProvider(apiKey, model);
  }

  private getApiKey(provider: string): string {
    const envVar =
      provider === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY';
    const key = process.env[envVar];
    if (!key) {
      throw new Error(
        `Missing API key. Set ${envVar} environment variable or pass it in options.`,
      );
    }
    return key;
  }
}
