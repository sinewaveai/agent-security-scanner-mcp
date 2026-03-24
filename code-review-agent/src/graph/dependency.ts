import * as fs from 'node:fs';
import * as path from 'node:path';
import type { DependencyGraph, DependencyNode } from '../types/analysis.js';
import { extractImports, resolveImportPath } from './resolver.js';

const MAX_DEPTH = 4;
const MAX_FILES = 200;

const LANGUAGE_MAP: Record<string, string> = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.py': 'python',
  '.go': 'go',
  '.rs': 'rust',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.c': 'c',
  '.cpp': 'cpp',
  '.h': 'c',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.kt': 'kotlin',
};

export class DependencyGraphBuilder {
  private nodes = new Map<string, DependencyNode>();
  private visited = new Set<string>();
  private projectRoot: string;

  constructor(projectRoot: string) {
    this.projectRoot = projectRoot;
  }

  build(entryFiles: string[]): DependencyGraph {
    const queue: Array<{ file: string; depth: number }> = entryFiles.map((f) => ({
      file: path.resolve(this.projectRoot, f),
      depth: 0,
    }));

    while (queue.length > 0 && this.nodes.size < MAX_FILES) {
      const item = queue.shift()!;
      const { file, depth } = item;

      if (this.visited.has(file) || depth > MAX_DEPTH) continue;
      this.visited.add(file);

      const relPath = path.relative(this.projectRoot, file);
      const ext = path.extname(file);
      const language = LANGUAGE_MAP[ext];
      if (!language) continue;

      let content: string;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch {
        continue;
      }

      const imports = extractImports(content, language);
      const resolvedImports: string[] = [];

      for (const imp of imports) {
        if (!imp.isLocal) continue;

        // Try resolving from the file's directory first, then from project root
        // (Python bare imports resolve from sys.path which includes project root)
        let resolved = resolveImportPath(imp.specifier, file, language);
        if (!resolved && !imp.specifier.startsWith('.')) {
          // Create a synthetic "from project root" path for resolution
          const rootSentinel = path.join(this.projectRoot, '__resolve_root__.py');
          resolved = resolveImportPath(imp.specifier, rootSentinel, language);
        }
        if (resolved) {
          const resolvedRel = path.relative(this.projectRoot, resolved);
          resolvedImports.push(resolvedRel);

          // Ensure the target node exists
          if (!this.nodes.has(resolvedRel)) {
            this.nodes.set(resolvedRel, {
              file: resolvedRel,
              imports: [],
              importedBy: [],
            });
          }

          // Add reverse edge
          this.nodes.get(resolvedRel)!.importedBy.push(relPath);

          // Queue for traversal
          if (!this.visited.has(resolved)) {
            queue.push({ file: resolved, depth: depth + 1 });
          }
        }
      }

      const existing = this.nodes.get(relPath);
      if (existing) {
        existing.imports = resolvedImports;
      } else {
        this.nodes.set(relPath, {
          file: relPath,
          imports: resolvedImports,
          importedBy: [],
        });
      }
    }

    return {
      nodes: this.nodes,
      entryPoints: entryFiles.map((f) => path.relative(this.projectRoot, path.resolve(this.projectRoot, f))),
    };
  }

  getImporters(file: string): string[] {
    return this.nodes.get(file)?.importedBy ?? [];
  }

  getImportees(file: string): string[] {
    return this.nodes.get(file)?.imports ?? [];
  }
}
