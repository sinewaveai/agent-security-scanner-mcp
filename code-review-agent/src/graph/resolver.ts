import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ImportInfo {
  specifier: string;
  isLocal: boolean;
  resolved: string | null;
}

const JS_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];
const PY_EXTENSIONS = ['.py'];

export function extractImports(content: string, language: string): ImportInfo[] {
  const imports: ImportInfo[] = [];

  if (['javascript', 'typescript'].includes(language)) {
    // ES imports
    for (const m of content.matchAll(/import\s+(?:.*?\s+from\s+)?['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
    }
    // Re-exports: export { ... } from '...', export * from '...', export { default } from '...'
    for (const m of content.matchAll(/export\s+(?:\*|{[^}]*})\s+from\s+['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
    }
    // require
    for (const m of content.matchAll(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const spec = m[1];
      imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
    }
    // dynamic import
    for (const m of content.matchAll(/import\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const spec = m[1];
      imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
    }
  } else if (language === 'python') {
    // `from package import name` — emit both `package` and `package.name`
    // since `name` might be a submodule (file) or a symbol within the package.
    for (const m of content.matchAll(/from\s+(\S+)\s+import\s+(\w+)/g)) {
      const pkg = m[1];
      const name = m[2];
      imports.push({ specifier: pkg, isLocal: isLocalImport(pkg, language), resolved: null });
      const sub = `${pkg}.${name}`;
      imports.push({ specifier: sub, isLocal: isLocalImport(sub, language), resolved: null });
    }
    // import module
    for (const m of content.matchAll(/^import\s+(\S+)/gm)) {
      const spec = m[1];
      imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
    }
  } else if (language === 'go') {
    for (const m of content.matchAll(/["']([^"']+)["']/g)) {
      const spec = m[1];
      if (spec.includes('/')) {
        imports.push({ specifier: spec, isLocal: isLocalImport(spec, language), resolved: null });
      }
    }
  }

  return imports;
}

export function resolveImportPath(
  specifier: string,
  fromFile: string,
  language: string,
): string | null {
  if (!isLocalImport(specifier, language)) return null;

  const fromDir = path.dirname(fromFile);

  if (['javascript', 'typescript'].includes(language)) {
    // Try exact path first, then with extensions, then index files
    const candidates: string[] = [];
    const base = path.resolve(fromDir, specifier);

    candidates.push(base);
    for (const ext of JS_EXTENSIONS) {
      candidates.push(base + ext);
    }
    for (const ext of JS_EXTENSIONS) {
      candidates.push(path.join(base, `index${ext}`));
    }

    for (const candidate of candidates) {
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch { /* not found */ }
    }
  } else if (language === 'python') {
    // Handle relative imports: .utils, ..models, .sub.module
    let resolveDir = fromDir;
    let moduleSpec = specifier;

    if (specifier.startsWith('.')) {
      // Count leading dots for parent traversal
      const dotMatch = specifier.match(/^(\.+)(.*)/);
      if (dotMatch) {
        const dots = dotMatch[1].length;
        moduleSpec = dotMatch[2]; // remainder after dots (may be empty for bare ".")
        // Each dot beyond the first goes up one directory
        resolveDir = fromDir;
        for (let i = 1; i < dots; i++) {
          resolveDir = path.dirname(resolveDir);
        }
      }
    }

    // Convert module.path to filesystem path
    const modulePath = moduleSpec ? moduleSpec.replace(/\./g, path.sep) : '';
    const base = modulePath ? path.resolve(resolveDir, modulePath) : resolveDir;

    for (const ext of PY_EXTENSIONS) {
      try {
        const candidate = base + ext;
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch { /* not found */ }
    }

    // Try as package (directory with __init__.py)
    try {
      const initFile = path.join(base, '__init__.py');
      if (fs.statSync(initFile).isFile()) return initFile;
    } catch { /* not found */ }

  }

  return null;
}

export function isLocalImport(specifier: string, language: string): boolean {
  if (['javascript', 'typescript'].includes(language)) {
    return specifier.startsWith('./') || specifier.startsWith('../');
  }
  if (language === 'python') {
    // Relative imports (starts with .) are always local.
    // Bare imports (tools, tools.executor) may be local — let resolveImportPath
    // do a filesystem check rather than rejecting them outright.
    if (specifier.startsWith('.')) return true;
    return /^[a-zA-Z_]\w*(\.[a-zA-Z_]\w*)*$/.test(specifier);
  }
  if (language === 'go') {
    return !specifier.includes('.');
  }
  return false;
}
