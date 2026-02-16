// src/tools/import-resolver.js
// Import graph resolution — resolves local imports to file paths and builds dependency graphs

import { existsSync, readFileSync, statSync } from 'fs';
import { resolve, dirname, join, extname, relative, isAbsolute } from 'path';
import { createHash } from 'crypto';
import { extractImports, detectLanguage } from '../utils.js';

// In-memory cache: absPath -> { content_hash, imports, resolvedImports }
const importGraphCache = new Map();

/**
 * Clear the import graph cache (for testing).
 */
export function clearImportGraphCache() {
  importGraphCache.clear();
}

/**
 * Check if an import specifier is a local/relative import.
 * @param {string} importSpec - The import string (e.g., './helpers', 'express')
 * @param {string} language - The language: 'javascript', 'typescript', 'python', 'go'
 * @returns {boolean}
 */
export function isLocalImport(importSpec, language) {
  switch (language) {
    case 'javascript':
    case 'typescript':
      return importSpec.startsWith('./') || importSpec.startsWith('../');
    case 'python':
      return importSpec.startsWith('.');
    case 'go':
      return importSpec.startsWith('./') || importSpec.startsWith('../');
    default:
      return importSpec.startsWith('./') || importSpec.startsWith('../');
  }
}

/**
 * Resolve a local import specifier to an actual file path.
 * @param {string} importSpec - The import string (e.g., './routes/users')
 * @param {string} fromFile - Absolute path of the file containing the import
 * @param {string} language - The language
 * @returns {string|null} Absolute resolved path, or null if unresolvable/package
 */
export function resolveImportPath(importSpec, fromFile, language) {
  if (!isLocalImport(importSpec, language)) {
    return null;
  }

  const fromDir = dirname(fromFile);

  switch (language) {
    case 'javascript':
    case 'typescript': {
      const base = resolve(fromDir, importSpec);
      // Try exact path first
      if (existsSync(base) && !isDirectory(base)) return base;
      // Try with extensions
      const jsExtensions = ['.js', '.ts', '.tsx', '.jsx', '.mjs'];
      for (const ext of jsExtensions) {
        const withExt = base + ext;
        if (existsSync(withExt)) return withExt;
      }
      // Try as directory with index file
      const indexFiles = ['index.js', 'index.ts', 'index.tsx', 'index.jsx', 'index.mjs'];
      for (const idx of indexFiles) {
        const indexPath = join(base, idx);
        if (existsSync(indexPath)) return indexPath;
      }
      return null;
    }

    case 'python': {
      // Python relative imports: . = current package, .. = parent package
      // Convert dot-prefix to path
      let dotCount = 0;
      let rest = importSpec;
      while (rest.startsWith('.')) {
        dotCount++;
        rest = rest.slice(1);
      }

      let targetDir = fromDir;
      // Each dot beyond the first goes up one directory
      for (let i = 1; i < dotCount; i++) {
        targetDir = dirname(targetDir);
      }

      if (!rest) {
        // Just dots — refers to __init__.py in the target dir
        const initPath = join(targetDir, '__init__.py');
        if (existsSync(initPath)) return initPath;
        return null;
      }

      // Convert module.sub to module/sub
      const modulePath = rest.replace(/\./g, '/');
      const base = join(targetDir, modulePath);

      // Try as .py file
      const asPy = base + '.py';
      if (existsSync(asPy)) return asPy;
      // Try as package (__init__.py)
      const asInit = join(base, '__init__.py');
      if (existsSync(asInit)) return asInit;
      // Try as sibling .py (same directory)
      const sibling = join(fromDir, modulePath + '.py');
      if (sibling !== asPy && existsSync(sibling)) return sibling;

      return null;
    }

    case 'go': {
      const base = resolve(fromDir, importSpec);
      if (existsSync(base) && !isDirectory(base)) return base;
      const withGo = base + '.go';
      if (existsSync(withGo)) return withGo;
      return null;
    }

    default:
      return null;
  }
}

/**
 * Build an import graph starting from an entry file using BFS traversal.
 * @param {string} filePath - Absolute path to the entry file
 * @param {string} projectRoot - Absolute path to the project root
 * @param {{ maxDepth?: number }} [options]
 * @returns {{ files: Record<string, object>, edges: Array, cycles: Array, unresolved: Array, summary: object }}
 */
export function resolveImportGraph(filePath, projectRoot, options = {}) {
  const { maxDepth = 3 } = options;
  const MAX_FILES = 100;

  const absEntry = isAbsolute(filePath) ? filePath : resolve(filePath);
  const absRoot = isAbsolute(projectRoot) ? projectRoot : resolve(projectRoot);

  const files = {};   // absPath -> { imports, resolvedImports, content_hash }
  const edges = [];    // [{ from, to, importSpec }]
  const cycles = [];   // [[from, to]]
  const unresolved = []; // [{ file, importSpec }]

  // BFS
  // Queue entries: { absPath, depth }
  const queue = [{ absPath: absEntry, depth: 0 }];
  const visited = new Set();

  while (queue.length > 0 && Object.keys(files).length < MAX_FILES) {
    const { absPath, depth } = queue.shift();

    if (visited.has(absPath)) continue;
    visited.add(absPath);

    if (!existsSync(absPath)) continue;

    const language = detectLanguage(absPath);
    let content;
    try {
      content = readFileSync(absPath, 'utf-8');
    } catch {
      continue;
    }

    const contentHash = createHash('sha256').update(content).digest('hex').slice(0, 16);

    // Check cache
    const cached = importGraphCache.get(absPath);
    let rawImports, resolvedImports;

    if (cached && cached.content_hash === contentHash) {
      rawImports = cached.imports;
      resolvedImports = cached.resolvedImports;
    } else {
      rawImports = extractImports(content, language);
      resolvedImports = [];

      for (const spec of rawImports) {
        if (!isLocalImport(spec, language)) continue;

        const resolved = resolveImportPath(spec, absPath, language);
        if (resolved) {
          // Guard: resolved path must stay within projectRoot
          const relToRoot = relative(absRoot, resolved);
          if (relToRoot.startsWith('..') || isAbsolute(relToRoot)) {
            unresolved.push({ file: absPath, importSpec: spec });
            continue;
          }
          resolvedImports.push({ spec, resolvedPath: resolved });
        } else {
          if (isLocalImport(spec, language)) {
            unresolved.push({ file: absPath, importSpec: spec });
          }
        }
      }

      // Update cache
      importGraphCache.set(absPath, {
        content_hash: contentHash,
        imports: rawImports,
        resolvedImports,
      });
    }

    files[absPath] = {
      imports: rawImports,
      resolvedImports,
      content_hash: contentHash,
    };

    // Build edges and enqueue resolved imports
    for (const { spec, resolvedPath } of resolvedImports) {
      edges.push({ from: absPath, to: resolvedPath, importSpec: spec });

      if (visited.has(resolvedPath)) {
        // Cycle detected
        cycles.push([absPath, resolvedPath]);
      } else if (depth < maxDepth) {
        queue.push({ absPath: resolvedPath, depth: depth + 1 });
      }
    }
  }

  const maxDepthReached = queue.some(item => item.depth >= maxDepth);

  return {
    files,
    edges,
    cycles,
    unresolved,
    summary: {
      total_files: Object.keys(files).length,
      total_edges: edges.length,
      has_cycles: cycles.length > 0,
      max_depth_reached: maxDepthReached || false,
    },
  };
}

// Helper: check if a path is a directory
function isDirectory(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}
