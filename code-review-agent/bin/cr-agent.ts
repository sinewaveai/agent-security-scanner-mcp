#!/usr/bin/env node

// Suppress Node.js deprecation warnings (e.g. punycode from dependencies)
process.removeAllListeners('warning');

import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import { AnalysisEngine } from '../src/analyzer/engine.js';
import { IntentProfiler } from '../src/analyzer/intent.js';
import { ModelRouter } from '../src/llm/router.js';
import { DependencyGraphBuilder } from '../src/graph/dependency.js';
import { buildProjectContext } from '../src/context/project.js';
import { loadConfig, resolveOptions } from '../src/types/config.js';
import type { AnalysisOptions, AnalysisMode } from '../src/types/config.js';
import type { AnalysisResult, Finding } from '../src/index.js';

const program = new Command();

program
  .name('cr-agent')
  .description('LLM-powered semantic code review agent')
  .version('0.1.0');

program
  .command('analyze')
  .description('Analyze a file or directory for bugs and vulnerabilities')
  .argument('<target>', 'File or directory to analyze')
  .option('--mode <mode>', 'Analysis mode (review|security)')
  .option('--security-only', 'Shorthand for --mode security')
  .option('-p, --provider <provider>', 'LLM provider (anthropic|openai|claude-cli)')
  .option('-m, --model <model>', 'Model to use for analysis')
  .option('--triage-model <model>', 'Model to use for triage')
  .option('-c, --confidence <threshold>', 'Confidence threshold (0-1)', parseFloat)
  .option('-f, --format <format>', 'Output format (text|json|sarif)')
  .option('-v, --verbose', 'Verbose output')
  .option('--exclude <patterns...>', 'Patterns to exclude')
  .option('--concurrency <limit>', 'Concurrency limit', parseInt)
  .action(async (target: string, flags: Record<string, unknown>) => {
    try {
      // Resolve project root from target, not cwd
      const resolvedTarget = path.resolve(target);
      const targetProjectRoot = fs.statSync(resolvedTarget).isDirectory()
        ? resolvedTarget
        : findProjectRoot(resolvedTarget);
      const config = loadConfig(targetProjectRoot);
      const mode: AnalysisMode | undefined = flags.securityOnly
        ? 'security'
        : (flags.mode as AnalysisMode | undefined);
      const options = resolveOptions(
        {
          mode,
          provider: flags.provider as AnalysisOptions['provider'] | undefined,
          model: flags.model as string | undefined,
          triageModel: flags.triageModel as string | undefined,
          confidenceThreshold: flags.confidence as number | undefined,
          format: (flags.format as AnalysisOptions['format']) ?? 'text',
          verbose: flags.verbose as boolean | undefined,
          exclude: flags.exclude as string[] | undefined,
          concurrencyLimit: flags.concurrency as number | undefined,
          projectRoot: targetProjectRoot,
        },
        config,
      );

      const showProgress = options.format === 'text';
      let lastStep = '';
      const engine = new AnalysisEngine(options, showProgress ? (step, detail) => {
        const icons: Record<string, string> = {
          discover: '[1/7 discover]',
          context:  '[2/7 context ]',
          intent:   '[3/7 intent  ]',
          graph:    '[4/7 graph   ]',
          triage:   '[5/7 triage  ]',
          analyze:  '[6/7 analyze ]',
          finalize: '[7/7 finalize]',
          done:     '[  done  ]',
        };
        const label = icons[step] ?? `[${step}]`;
        if (step !== lastStep) {
          // New stage — print on a new line, keep it visible
          if (lastStep) process.stderr.write('\n');
          lastStep = step;
          process.stderr.write(`${chalk.cyan(label)} ${detail ?? ''}`);
        } else {
          // Same stage — overwrite the current line with updated detail
          process.stderr.write(`\r\x1b[K${chalk.dim(label)} ${detail ?? ''}`);
        }
        if (step === 'done') process.stderr.write('\n');
      } : undefined);
      const result = await engine.analyze(target);

      if (options.format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else if (options.format === 'sarif') {
        console.log(JSON.stringify(toSarif(result), null, 2));
      } else {
        printTextResult(result, options.verbose);
      }

      process.exit(result.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0);
    } catch (err) {
      // Never leak full prompt/context in error output
      const msg = err instanceof Error ? err.message : String(err);
      const safeLine = msg.split('\n')[0].slice(0, 300);
      process.stderr.write('\n');
      console.error(chalk.red(`Error: ${safeLine}`));
      process.exit(2);
    }
  });

program
  .command('intent')
  .description('Show the intent profile for a project')
  .argument('<dir>', 'Project directory')
  .option('-p, --provider <provider>', 'LLM provider (anthropic|openai|claude-cli)')
  .option('-m, --model <model>', 'Model to use')
  .action(async (dir: string, flags: Record<string, unknown>) => {
    try {
      const config = loadConfig(dir);
      const options = resolveOptions(
        {
          provider: flags.provider as AnalysisOptions['provider'] | undefined,
          model: flags.model as string | undefined,
          projectRoot: dir,
        },
        config,
      );

      const router = new ModelRouter(options);
      const profiler = new IntentProfiler(router.getAnalysisProvider());
      const projectContext = buildProjectContext(dir);
      const intent = await profiler.profile(projectContext);

      console.log(chalk.bold('\nIntent Profile'));
      console.log(chalk.cyan('Purpose: ') + intent.purpose);
      console.log(chalk.cyan('Risk Domain: ') + intent.riskDomain);
      console.log(chalk.cyan('Framework: ') + intent.framework);
      console.log(chalk.green('\nExpected Behaviors:'));
      for (const b of intent.expectedBehaviors) {
        console.log(`  + ${b}`);
      }
      console.log(chalk.red('\nUnexpected Behaviors:'));
      for (const b of intent.unexpectedBehaviors) {
        console.log(`  - ${b}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`Error: ${msg.split('\n')[0].slice(0, 300)}`));
      process.exit(2);
    }
  });

program
  .command('graph')
  .description('Show the dependency graph for a project')
  .argument('<dir>', 'Project directory')
  .action((dir: string) => {
    const builder = new DependencyGraphBuilder(dir);

    // Discover entry files — support all languages the engine supports
    const codeExtRe = /\.(js|mjs|cjs|jsx|ts|tsx|py|go|rs|java|rb|php|c|cpp|h|hpp|cs|swift|kt)$/;
    const excludeSet = new Set(['node_modules', 'dist', '.git', 'vendor', '__pycache__', 'venv', '.venv']);
    const entries: string[] = [];
    const walkGraph = (d: string) => {
      let dirEntries: import('node:fs').Dirent[];
      try { dirEntries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
      for (const entry of dirEntries) {
        if (excludeSet.has(entry.name) || entry.name.startsWith('.')) continue;
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) walkGraph(full);
        else if (codeExtRe.test(entry.name)) entries.push(full);
      }
    };
    walkGraph(dir);

    const graph = builder.build(entries.map((e: string) => path.relative(dir, e)));

    console.log(chalk.bold(`\nDependency Graph (${graph.nodes.size} files)\n`));
    for (const [file, node] of graph.nodes) {
      console.log(chalk.cyan(file));
      if (node.imports.length > 0) {
        console.log(`  imports: ${node.imports.join(', ')}`);
      }
      if (node.importedBy.length > 0) {
        console.log(`  imported by: ${node.importedBy.join(', ')}`);
      }
    }
  });

program.parse();

// --- Output formatting ---

function printTextResult(result: AnalysisResult, verbose: boolean): void {
  const { findings, intentProfile, stats } = result;

  if (intentProfile) {
    console.log(chalk.bold('\nIntent Profile'));
    console.log(`  Purpose: ${intentProfile.purpose}`);
    console.log(`  Domain: ${intentProfile.riskDomain}`);
    console.log('');
  }

  if (findings.length === 0) {
    console.log(chalk.green('\nNo findings above confidence threshold.\n'));
  } else {
    console.log(chalk.bold(`\n${findings.length} Finding(s)\n`));
    for (const f of findings) {
      printFinding(f, verbose);
    }
  }

  console.log(chalk.bold('Stats'));
  console.log(`  Files analyzed: ${stats.filesAnalyzed}`);
  console.log(`  Files skipped: ${stats.filesSkipped}`);
  console.log(`  Total findings: ${stats.totalFindings}`);
  console.log(`  Tokens used: ${stats.totalTokensUsed.toLocaleString()}`);
  console.log(`  Estimated cost: $${stats.estimatedCost.toFixed(4)}`);
  console.log(`  Duration: ${(stats.durationMs / 1000).toFixed(1)}s`);
  console.log('');
}

function printFinding(f: Finding, verbose: boolean): void {
  const severityColors: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white.bold,
    high: chalk.red.bold,
    medium: chalk.yellow,
    low: chalk.blue,
    info: chalk.gray,
  };

  const colorFn = severityColors[f.severity] ?? chalk.white;
  const badge = colorFn(` ${f.severity.toUpperCase()} `);
  const alignment =
    f.intentAlignment === 'violates-intent' ? chalk.red('VIOLATES INTENT') :
    f.intentAlignment === 'matches-intent' ? chalk.green('MATCHES INTENT') :
    chalk.gray('UNCLEAR');

  console.log(`${badge} ${f.title}`);
  console.log(`  ${chalk.dim(`${f.location.file}:${f.location.startLine}-${f.location.endLine}`)}  ${alignment}  confidence: ${f.confidence}`);
  console.log(`  ${chalk.dim(f.category)}${f.cwe ? ` | ${f.cwe}` : ''}`);

  if (verbose) {
    console.log(`  ${chalk.dim('Reasoning:')} ${f.reasoning}`);
    console.log(`  ${chalk.dim('Action:')} ${f.suggestedAction}`);
  }

  console.log('');
}

function findProjectRoot(filePath: string): string {
  const markers = ['package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'requirements.txt', '.git', '.cr-agent.json'];
  let dir = path.dirname(path.resolve(filePath));
  while (dir !== path.dirname(dir)) {
    if (markers.some((m) => { try { fs.statSync(path.join(dir, m)); return true; } catch { return false; } })) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  return path.dirname(path.resolve(filePath));
}

function toSarif(result: AnalysisResult): object {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'cr-agent',
            version: '0.1.0',
            informationUri: 'https://github.com/sinewaveai/agent-security-scanner-mcp',
            rules: result.findings.map((f, i) => ({
              id: `CR${String(i + 1).padStart(3, '0')}`,
              name: f.title.replace(/\s+/g, ''),
              shortDescription: { text: f.title },
              fullDescription: { text: f.reasoning },
              defaultConfiguration: {
                level: f.severity === 'critical' || f.severity === 'high' ? 'error' :
                       f.severity === 'medium' ? 'warning' : 'note',
              },
              properties: {
                category: f.category,
                intentAlignment: f.intentAlignment,
              },
            })),
          },
        },
        results: result.findings.map((f, i) => ({
          ruleId: `CR${String(i + 1).padStart(3, '0')}`,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' :
                 f.severity === 'medium' ? 'warning' : 'note',
          message: { text: f.reasoning },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: {
                  startLine: f.location.startLine,
                  endLine: f.location.endLine,
                },
              },
            },
          ],
          properties: {
            confidence: f.confidence,
            intentAlignment: f.intentAlignment,
            suggestedAction: f.suggestedAction,
            cwe: f.cwe,
            owasp: f.owasp,
          },
        })),
      },
    ],
  };
}
