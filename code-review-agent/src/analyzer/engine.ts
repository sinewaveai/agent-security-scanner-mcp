import * as fs from 'node:fs';
import * as path from 'node:path';
import type {
  AnalysisResult,
  AnalysisStats,
  FileAnalysisResult,
} from '../types/analysis.js';
import type { Finding, IntentProfile } from '../types/findings.js';
import type { AnalysisOptions } from '../types/config.js';
import { ModelRouter } from '../llm/router.js';
import { IntentProfiler } from './intent.js';
import { SemanticAnalyzer } from './semantic.js';
import { buildProjectContext } from '../context/project.js';
import { buildFileContext } from '../context/file.js';
import { DependencyGraphBuilder } from '../graph/dependency.js';
import { postFilterFindings, suppressCarrierFindings } from './postprocess.js';

const CODE_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.jsx',
  '.ts', '.tsx',
  '.py',
  '.go',
  '.rs',
  '.java',
  '.rb',
  '.php',
  '.c', '.cpp', '.h', '.hpp',
  '.cs',
  '.swift',
  '.kt',
]);

export type ProgressCallback = (step: string, detail?: string) => void;

export class AnalysisEngine {
  private options: AnalysisOptions;
  private router: ModelRouter;
  private onProgress: ProgressCallback;

  constructor(options: AnalysisOptions, onProgress?: ProgressCallback) {
    this.options = options;
    this.router = new ModelRouter(options);
    this.onProgress = onProgress ?? (() => {});
  }

  async analyze(targetPath: string): Promise<AnalysisResult> {
    const startTime = Date.now();
    const resolvedPath = path.resolve(this.options.projectRoot, targetPath);

    // Determine project root and target
    let projectRoot: string;
    let targetFiles: string[];

    this.onProgress('discover', `Scanning ${resolvedPath}`);

    const stat = fs.statSync(resolvedPath);
    if (stat.isDirectory()) {
      projectRoot = resolvedPath;
      targetFiles = this.discoverFiles(resolvedPath);
    } else {
      // For single files, use the configured projectRoot (CLI resolves this from the target)
      projectRoot = this.options.projectRoot;
      targetFiles = [resolvedPath];
    }

    if (targetFiles.length === 0) {
      this.onProgress('done', 'No analyzable files found');
      return { findings: [], intentProfile: null, fileResults: [], stats: { filesAnalyzed: 0, filesSkipped: 0, totalFindings: 0, findingsBySeverity: {}, totalTokensUsed: 0, estimatedCost: 0, durationMs: Date.now() - startTime } };
    }

    this.onProgress('discover', `Found ${targetFiles.length} file(s)`);

    // Build project context and intent profile
    this.onProgress('context', 'Reading project context (README, package.json, structure)');
    const projectContext = buildProjectContext(projectRoot);

    this.onProgress('intent', 'Profiling project intent via LLM...');
    const intentProfiler = new IntentProfiler(this.router.getAnalysisProvider());
    const intentProfile = await intentProfiler.profile(projectContext);
    this.onProgress('intent', `Intent: ${intentProfile.purpose.slice(0, 80)}`);

    // Build dependency graph
    this.onProgress('graph', 'Building dependency graph');
    const graphBuilder = new DependencyGraphBuilder(projectRoot);
    const graph = graphBuilder.build(
      targetFiles.map((f) => path.relative(projectRoot, f)),
    );
    this.onProgress('graph', `Graph: ${graph.nodes.size} node(s)`);

    // Create analyzer
    const analyzer = new SemanticAnalyzer(
      this.router.getAnalysisProvider(),
      this.router.getTriageProvider(),
      this.options.mode,
      projectRoot,
      graph,
    );

    // Triage files in parallel
    this.onProgress('triage', `Triaging ${targetFiles.length} file(s)...`);
    let triageCount = 0;
    const triageResults = await this.runParallel(
      targetFiles,
      async (file) => {
        const fileCtx = buildFileContext(file, projectRoot, graph);

        // Auto-skip test, config, and generated files
        if (fileCtx.isTestFile || fileCtx.isConfigFile || fileCtx.isGenerated) {
          triageCount++;
          this.onProgress('triage', `[${triageCount}/${targetFiles.length}] SKIP ${fileCtx.filePath} (auto: test/config/generated)`);
          return {
            file: fileCtx.filePath,
            findings: [],
            triageDecision: { action: 'skip' as const, reason: 'Auto-skipped (test/config/generated)', areasOfInterest: [] },
            tokensUsed: 0,
            skipped: true,
            truncated: false,
          };
        }

        // On triage failure, default to ANALYZE (don't skip — we'd miss vulns)
        let decision: import('../types/findings.js').TriageDecision;
        try {
          decision = await analyzer.triageFile(projectContext, fileCtx);
        } catch {
          decision = { action: 'analyze', reason: 'Triage failed — defaulting to analyze', areasOfInterest: [] };
        }

        triageCount++;
        const icon = decision.action === 'skip' ? 'SKIP' : 'ANALYZE';
        this.onProgress('triage', `[${triageCount}/${targetFiles.length}] ${icon} ${fileCtx.filePath} — ${decision.reason.slice(0, 60)}`);
        return {
          file: fileCtx.filePath,
          findings: [],
          triageDecision: decision,
          tokensUsed: 0,
          skipped: decision.action === 'skip',
          truncated: false,
        };
      },
      this.options.concurrencyLimit,
    );

    // Analyze files that passed triage
    const filesToAnalyze = triageResults.filter((r) => !r.skipped);
    const skippedCount = triageResults.filter((r) => r.skipped).length;
    const fileResults: FileAnalysisResult[] = [...triageResults.filter((r) => r.skipped)];

    this.onProgress('analyze', `Analyzing ${filesToAnalyze.length} file(s) (${skippedCount} skipped)`);

    let analyzeCount = 0;
    const analysisResults = await this.runParallel(
      filesToAnalyze,
      async (triageResult) => {
        const filePath = path.resolve(projectRoot, triageResult.file);
        const fileCtx = buildFileContext(filePath, projectRoot, graph);

        analyzeCount++;
        this.onProgress('analyze', `[${analyzeCount}/${filesToAnalyze.length}] Analyzing ${triageResult.file} (${fileCtx.lineCount} lines)...`);

        // Retry up to 2 times on transient errors
        let lastErr: Error | null = null;
        for (let attempt = 1; attempt <= 2; attempt++) {
          try {
            const { findings, tokensUsed, truncated } = await analyzer.analyzeFile(
              intentProfile,
              projectContext,
              fileCtx,
            );

            this.onProgress('analyze', `[${analyzeCount}/${filesToAnalyze.length}] ${triageResult.file} → ${findings.length} finding(s)`);

            return {
              file: triageResult.file,
              findings,
              triageDecision: triageResult.triageDecision,
              tokensUsed,
              skipped: false,
              truncated,
            };
          } catch (err) {
            lastErr = err instanceof Error ? err : new Error(String(err));
            if (attempt < 2) {
              this.onProgress('analyze', `[${analyzeCount}/${filesToAnalyze.length}] ${triageResult.file} → retry (${lastErr.message.split('\n')[0].slice(0, 80)})`);
            }
          }
        }

        // Both attempts failed — log error but still return the file (no findings, not skipped)
        this.onProgress('analyze', `[${analyzeCount}/${filesToAnalyze.length}] ${triageResult.file} → FAILED after retries: ${lastErr!.message.split('\n')[0].slice(0, 100)}`);

        return {
          file: triageResult.file,
          findings: [],
          triageDecision: triageResult.triageDecision,
          tokensUsed: 0,
          skipped: false,
          truncated: false,
        };
      },
      this.options.concurrencyLimit,
    );

    fileResults.push(...analysisResults);

    // Collect all findings
    let allFindings = fileResults.flatMap((r) => r.findings);

    // Dedup
    this.onProgress('finalize', `Deduplicating ${allFindings.length} raw finding(s)`);
    allFindings = this.dedup(allFindings);

    // Mode-aware post-filtering
    const beforePostFilter = allFindings.length;
    allFindings = postFilterFindings(allFindings, this.options.mode);
    if (this.options.mode === 'security') {
      allFindings = suppressCarrierFindings(allFindings);
      this.onProgress('finalize', `Security filter: ${beforePostFilter} → ${allFindings.length}`);
    }

    // Filter by confidence
    const beforeFilter = allFindings.length;
    allFindings = allFindings.filter(
      (f) => f.confidence >= this.options.confidenceThreshold,
    );
    this.onProgress('finalize', `Filtered: ${beforeFilter} → ${allFindings.length} (threshold: ${this.options.confidenceThreshold})`);

    // Sort by severity then confidence
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    allFindings.sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });

    // Compute stats
    const totalTokensUsed = fileResults.reduce((sum, r) => sum + r.tokensUsed, 0);
    const stats: AnalysisStats = {
      filesAnalyzed: filesToAnalyze.length,
      filesSkipped: triageResults.filter((r) => r.skipped).length,
      totalFindings: allFindings.length,
      findingsBySeverity: this.countBySeverity(allFindings),
      totalTokensUsed,
      estimatedCost: this.router.estimateCost(totalTokensUsed),
      durationMs: Date.now() - startTime,
    };

    this.onProgress('done', `Complete: ${allFindings.length} finding(s) in ${(stats.durationMs / 1000).toFixed(1)}s`);

    return {
      findings: allFindings,
      intentProfile,
      fileResults,
      stats,
    };
  }

  private discoverFiles(dir: string): string[] {
    const files: string[] = [];
    const excludeSet = new Set(this.options.exclude);

    const walk = (current: string) => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(current, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (excludeSet.has(entry.name) || entry.name.startsWith('.')) continue;

        const fullPath = path.join(current, entry.name);

        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (!CODE_EXTENSIONS.has(ext)) continue;

          try {
            fs.statSync(fullPath);
          } catch {
            continue;
          }

          files.push(fullPath);
        }
      }
    };

    walk(dir);
    return files;
  }

  private dedup(findings: Finding[]): Finding[] {
    // Phase 1: group by file + rich signature (CWE > normalized title > category)
    const groups = new Map<string, Finding[]>();

    for (const finding of findings) {
      const key = `${finding.location.file}:${this.dedupSignature(finding)}`;
      const group = groups.get(key) ?? [];
      group.push(finding);
      groups.set(key, group);
    }

    const result: Finding[] = [];
    for (const group of groups.values()) {
      const merged = this.mergeOverlapping(group);
      result.push(...merged);
    }

    return result;
  }

  /**
   * Generate a dedup signature that's more precise than just category.
   * Priority: CWE (most specific) > normalized title > category fallback.
   */
  private dedupSignature(finding: Finding): string {
    if (finding.cwe) {
      return `cwe:${finding.cwe.toLowerCase()}`;
    }

    // Normalize the title: lowercase, strip numbers/punctuation, collapse whitespace
    const normalized = finding.title
      .toLowerCase()
      .replace(/\b(line|col|at)\s*\d+/g, '')
      .replace(/[^a-z0-9\s]/g, '')
      .replace(/\s+/g, ' ')
      .trim();

    // Use first 60 chars of normalized title + category for grouping
    return `${finding.category}:${normalized.slice(0, 60)}`;
  }

  private mergeOverlapping(findings: Finding[]): Finding[] {
    if (findings.length <= 1) return findings;

    findings.sort((a, b) => a.location.startLine - b.location.startLine);

    const merged: Finding[] = [findings[0]];

    for (let i = 1; i < findings.length; i++) {
      const current = findings[i];
      const last = merged[merged.length - 1];

      if (current.location.startLine <= last.location.endLine + 1) {
        // Overlapping — keep the one with higher confidence
        if (current.confidence > last.confidence) {
          merged[merged.length - 1] = {
            ...current,
            location: {
              ...current.location,
              startLine: Math.min(last.location.startLine, current.location.startLine),
              endLine: Math.max(last.location.endLine, current.location.endLine),
            },
          };
        } else {
          merged[merged.length - 1] = {
            ...last,
            location: {
              ...last.location,
              endLine: Math.max(last.location.endLine, current.location.endLine),
            },
          };
        }
      } else {
        merged.push(current);
      }
    }

    return merged;
  }

  private countBySeverity(findings: Finding[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  }

  private async runParallel<T, R>(
    items: T[],
    fn: (item: T) => Promise<R>,
    limit: number,
  ): Promise<R[]> {
    if (items.length === 0) return [];

    const results: R[] = [];
    let index = 0;

    const runNext = async (): Promise<void> => {
      while (index < items.length) {
        // Safe: index++ between awaits is non-concurrent in single-threaded JS
        const currentIndex = index++;
        results[currentIndex] = await fn(items[currentIndex]);
      }
    };

    const workerCount = Math.min(Math.max(1, limit), items.length);
    const workers = Array.from({ length: workerCount }, () => runNext());
    await Promise.all(workers);

    return results;
  }
}
