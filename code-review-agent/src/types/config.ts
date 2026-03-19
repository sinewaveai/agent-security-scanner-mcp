import * as fs from 'node:fs';
import * as path from 'node:path';

export interface AnalysisOptions {
  provider: 'anthropic' | 'openai' | 'claude-cli';
  model?: string;
  triageModel?: string;
  confidenceThreshold: number;
  format: 'text' | 'json' | 'sarif';
  verbose: boolean;
  projectRoot: string;
  exclude: string[];
  concurrencyLimit: number;
  maxFileSize: number;
}

export interface CRAgentConfig {
  provider?: 'anthropic' | 'openai' | 'claude-cli';
  model?: string;
  triageModel?: string;
  confidenceThreshold?: number;
  exclude?: string[];
  concurrencyLimit?: number;
  maxFileSize?: number;
}

const DEFAULTS: AnalysisOptions = {
  provider: 'anthropic',
  confidenceThreshold: 0.7,
  format: 'text',
  verbose: false,
  projectRoot: process.cwd(),
  exclude: ['node_modules', 'dist', 'build', '.git', 'vendor', '__pycache__', '.venv', 'venv', 'env', '.env', 'site-packages', '.tox', '.mypy_cache', '.pytest_cache', 'coverage', '.nyc_output', '.next', 'target'],
  concurrencyLimit: 5,
  maxFileSize: 512 * 1024,
};

export function loadConfig(projectRoot: string): CRAgentConfig | null {
  const configPath = path.join(projectRoot, '.cr-agent.json');
  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(raw) as CRAgentConfig;
  } catch {
    return null;
  }
}

export function resolveOptions(
  cliFlags: Partial<AnalysisOptions>,
  config: CRAgentConfig | null,
  env: Record<string, string | undefined> = process.env,
): AnalysisOptions {
  return {
    provider:
      cliFlags.provider ??
      config?.provider ??
      (env.CR_AGENT_PROVIDER as AnalysisOptions['provider'] | undefined) ??
      DEFAULTS.provider,
    model: cliFlags.model ?? config?.model ?? env.CR_AGENT_MODEL ?? undefined,
    triageModel: cliFlags.triageModel ?? config?.triageModel ?? undefined,
    confidenceThreshold:
      cliFlags.confidenceThreshold ??
      config?.confidenceThreshold ??
      (env.CR_AGENT_CONFIDENCE ? parseFloat(env.CR_AGENT_CONFIDENCE) : DEFAULTS.confidenceThreshold),
    format: cliFlags.format ?? DEFAULTS.format,
    verbose: cliFlags.verbose ?? DEFAULTS.verbose,
    projectRoot: cliFlags.projectRoot ?? DEFAULTS.projectRoot,
    exclude: cliFlags.exclude ?? config?.exclude ?? DEFAULTS.exclude,
    concurrencyLimit: Math.max(1, cliFlags.concurrencyLimit ?? config?.concurrencyLimit ?? DEFAULTS.concurrencyLimit),
    maxFileSize: cliFlags.maxFileSize ?? config?.maxFileSize ?? DEFAULTS.maxFileSize,
  };
}
