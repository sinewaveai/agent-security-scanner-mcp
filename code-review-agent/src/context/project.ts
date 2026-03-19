import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ProjectContext } from '../types/analysis.js';

const README_MAX_CHARS = 2000;
const TREE_MAX_DEPTH = 2;
const LANGUAGE_CENSUS_MAX_FILES = 200;

export function buildProjectContext(projectRoot: string): ProjectContext {
  return {
    readme: readReadme(projectRoot),
    packageMeta: readPackageMeta(projectRoot),
    directoryTree: buildDirectoryTree(projectRoot, TREE_MAX_DEPTH),
    envVars: readEnvVarNames(projectRoot),
    hasDockerfile: fileExists(projectRoot, 'Dockerfile'),
    hasCI:
      dirExists(projectRoot, '.github/workflows') ||
      fileExists(projectRoot, '.gitlab-ci.yml') ||
      fileExists(projectRoot, 'Jenkinsfile'),
    language: detectLanguage(projectRoot),
    framework: detectFramework(projectRoot),
  };
}

export function formatProjectContextForLLM(ctx: ProjectContext): string {
  const sections: string[] = [];

  if (ctx.readme) {
    sections.push(`## Project README\n${ctx.readme}`);
  }

  if (ctx.packageMeta) {
    const meta = ctx.packageMeta;
    const parts: string[] = [];
    if (meta.name) parts.push(`Name: ${meta.name}`);
    if (meta.description) parts.push(`Description: ${meta.description}`);
    if (meta.dependencies) {
      const deps = Object.keys(meta.dependencies as Record<string, string>);
      parts.push(`Dependencies: ${deps.join(', ')}`);
    }
    sections.push(`## Package Metadata\n${parts.join('\n')}`);
  }

  sections.push(`## Directory Structure\n\`\`\`\n${ctx.directoryTree}\n\`\`\``);

  if (ctx.envVars.length > 0) {
    sections.push(`## Environment Variables\n${ctx.envVars.join(', ')}`);
  }

  const infra: string[] = [];
  if (ctx.hasDockerfile) infra.push('Dockerfile');
  if (ctx.hasCI) infra.push('CI/CD');
  if (infra.length > 0) {
    sections.push(`## Infrastructure\n${infra.join(', ')}`);
  }

  sections.push(`## Language: ${ctx.language}\n## Framework: ${ctx.framework}`);

  return sections.join('\n\n');
}

function readReadme(root: string): string {
  for (const name of ['README.md', 'README.txt', 'README', 'readme.md']) {
    const filePath = path.join(root, name);
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return content.slice(0, README_MAX_CHARS);
    } catch {
      continue;
    }
  }
  return '';
}

function readPackageMeta(root: string): Record<string, unknown> | null {
  for (const name of ['package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml']) {
    const filePath = path.join(root, name);
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      if (name === 'package.json') {
        return JSON.parse(content);
      }
      return { _raw: content.slice(0, 500), _type: name };
    } catch {
      continue;
    }
  }
  return null;
}

function readEnvVarNames(root: string): string[] {
  const envPath = path.join(root, '.env.example');
  try {
    const content = fs.readFileSync(envPath, 'utf-8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => line.split('=')[0].trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function buildDirectoryTree(root: string, maxDepth: number, prefix = '', depth = 0): string {
  if (depth >= maxDepth) return '';

  const EXCLUDE = new Set([
    'node_modules', 'dist', 'build', '.git', 'vendor', '__pycache__',
    '.venv', '.next', 'coverage', '.nyc_output',
  ]);

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return '';
  }

  const filtered = entries
    .filter((e) => !EXCLUDE.has(e.name) && !e.name.startsWith('.'))
    .sort((a, b) => {
      if (a.isDirectory() && !b.isDirectory()) return -1;
      if (!a.isDirectory() && b.isDirectory()) return 1;
      return a.name.localeCompare(b.name);
    });

  const lines: string[] = [];
  for (let i = 0; i < filtered.length; i++) {
    const entry = filtered[i];
    const isLast = i === filtered.length - 1;
    const connector = isLast ? '└── ' : '├── ';
    const childPrefix = isLast ? '    ' : '│   ';

    lines.push(`${prefix}${connector}${entry.name}${entry.isDirectory() ? '/' : ''}`);

    if (entry.isDirectory()) {
      const subtree = buildDirectoryTree(
        path.join(root, entry.name),
        maxDepth,
        `${prefix}${childPrefix}`,
        depth + 1,
      );
      if (subtree) lines.push(subtree);
    }
  }

  return lines.join('\n');
}

function detectLanguage(root: string): string {
  // Check manifest files first
  if (fileExists(root, 'package.json') || fileExists(root, 'tsconfig.json')) return 'javascript/typescript';
  if (fileExists(root, 'requirements.txt') || fileExists(root, 'setup.py') || fileExists(root, 'pyproject.toml')) return 'python';
  if (fileExists(root, 'go.mod')) return 'go';
  if (fileExists(root, 'Cargo.toml')) return 'rust';
  if (fileExists(root, 'pom.xml') || fileExists(root, 'build.gradle')) return 'java';

  // Fallback: recursive census of file extensions across the project
  try {
    const extCounts: Record<string, number> = {};
    let countedFiles = 0;
    const exclude = new Set([
      'node_modules', 'dist', 'build', '.git', 'vendor', '__pycache__',
      '.venv', 'venv', 'env', '.next', 'coverage', '.nyc_output',
    ]);

    const walk = (dir: string): void => {
      if (countedFiles >= LANGUAGE_CENSUS_MAX_FILES) return;

      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (countedFiles >= LANGUAGE_CENSUS_MAX_FILES) return;
        if (exclude.has(entry.name) || entry.name.startsWith('.')) continue;

        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
          continue;
        }

        if (!entry.isFile()) continue;
        const ext = path.extname(entry.name);
        if (!ext) continue;
        extCounts[ext] = (extCounts[ext] ?? 0) + 1;
        countedFiles++;
      }
    };

    walk(root);

    if (countedFiles === 0) {
      return 'unknown';
    }

    const jsExts = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'];
    const pyExts = ['.py'];
    const jsCount = jsExts.reduce((n, e) => n + (extCounts[e] ?? 0), 0);
    const pyCount = pyExts.reduce((n, e) => n + (extCounts[e] ?? 0), 0);
    if (jsCount > 0 && jsCount >= pyCount) return 'javascript/typescript';
    if (pyCount > 0) return 'python';
    if (extCounts['.go']) return 'go';
    if (extCounts['.rs']) return 'rust';
    if (extCounts['.java']) return 'java';
  } catch { /* can't read directory */ }

  return 'unknown';
}

function detectFramework(root: string): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf-8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps.next) return 'next.js';
    if (deps.express) return 'express';
    if (deps.fastify) return 'fastify';
    if (deps.react) return 'react';
    if (deps.vue) return 'vue';
    if (deps.hono) return 'hono';
  } catch { /* no package.json */ }

  try {
    const req = fs.readFileSync(path.join(root, 'requirements.txt'), 'utf-8');
    if (req.includes('django')) return 'django';
    if (req.includes('flask')) return 'flask';
    if (req.includes('fastapi')) return 'fastapi';
  } catch { /* no requirements.txt */ }

  return 'none';
}

function fileExists(root: string, name: string): boolean {
  try {
    return fs.statSync(path.join(root, name)).isFile();
  } catch {
    return false;
  }
}

function dirExists(root: string, name: string): boolean {
  try {
    return fs.statSync(path.join(root, name)).isDirectory();
  } catch {
    return false;
  }
}
