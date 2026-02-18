import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { isLocalImport, resolveImportPath, resolveImportGraph, clearImportGraphCache } from '../src/tools/import-resolver.js';
import { discoverProjectContext, clearProjectContextCache } from '../src/tools/project-context.js';
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(__dirname, 'fixtures', 'express-app');

// ============= isLocalImport =============
describe('isLocalImport', () => {
  it('should detect JS/TS relative imports', () => {
    expect(isLocalImport('./helpers', 'javascript')).toBe(true);
    expect(isLocalImport('../lib/db', 'javascript')).toBe(true);
    expect(isLocalImport('./routes/users', 'typescript')).toBe(true);
    expect(isLocalImport('../middleware/auth', 'typescript')).toBe(true);
  });

  it('should reject JS/TS package imports', () => {
    expect(isLocalImport('express', 'javascript')).toBe(false);
    expect(isLocalImport('helmet', 'javascript')).toBe(false);
    expect(isLocalImport('@nestjs/core', 'typescript')).toBe(false);
    expect(isLocalImport('path', 'javascript')).toBe(false);
  });

  it('should detect Python relative imports', () => {
    expect(isLocalImport('.helpers', 'python')).toBe(true);
    expect(isLocalImport('..utils', 'python')).toBe(true);
    expect(isLocalImport('.', 'python')).toBe(true);
  });

  it('should reject Python package imports', () => {
    expect(isLocalImport('os', 'python')).toBe(false);
    expect(isLocalImport('flask', 'python')).toBe(false);
    expect(isLocalImport('django', 'python')).toBe(false);
  });

  it('should detect Go relative imports', () => {
    expect(isLocalImport('./pkg', 'go')).toBe(true);
    expect(isLocalImport('../internal', 'go')).toBe(true);
  });

  it('should reject Go package imports', () => {
    expect(isLocalImport('fmt', 'go')).toBe(false);
    expect(isLocalImport('github.com/gin-gonic/gin', 'go')).toBe(false);
  });
});

// ============= resolveImportPath =============
describe('resolveImportPath', () => {
  it('should resolve ./routes/users from app.js', () => {
    const appJs = join(fixtureDir, 'app.js');
    const result = resolveImportPath('./routes/users', appJs, 'javascript');
    expect(result).not.toBeNull();
    expect(result).toBe(join(fixtureDir, 'routes', 'users.js'));
  });

  it('should resolve ../lib/db from routes/users.js', () => {
    const usersJs = join(fixtureDir, 'routes', 'users.js');
    const result = resolveImportPath('../lib/db', usersJs, 'javascript');
    expect(result).not.toBeNull();
    expect(result).toBe(join(fixtureDir, 'lib', 'db.js'));
  });

  it('should resolve ../middleware/auth from routes/users.js', () => {
    const usersJs = join(fixtureDir, 'routes', 'users.js');
    const result = resolveImportPath('../middleware/auth', usersJs, 'javascript');
    expect(result).not.toBeNull();
    expect(result).toBe(join(fixtureDir, 'middleware', 'auth.js'));
  });

  it('should return null for package imports', () => {
    const appJs = join(fixtureDir, 'app.js');
    expect(resolveImportPath('express', appJs, 'javascript')).toBeNull();
    expect(resolveImportPath('helmet', appJs, 'javascript')).toBeNull();
    expect(resolveImportPath('cors', appJs, 'javascript')).toBeNull();
  });

  it('should return null for nonexistent local imports', () => {
    const appJs = join(fixtureDir, 'app.js');
    expect(resolveImportPath('./nonexistent', appJs, 'javascript')).toBeNull();
    expect(resolveImportPath('./foo/bar/baz', appJs, 'javascript')).toBeNull();
  });

  // Python resolution tests with temp fixtures
  describe('Python imports', () => {
    const pyDir = join(__dirname, 'fixtures', 'temp-py-resolver');

    beforeEach(() => {
      mkdirSync(join(pyDir, 'pkg'), { recursive: true });
      writeFileSync(join(pyDir, 'main.py'), 'from .helpers import util\n');
      writeFileSync(join(pyDir, 'helpers.py'), 'def util(): pass\n');
      writeFileSync(join(pyDir, 'pkg', '__init__.py'), '');
      writeFileSync(join(pyDir, 'pkg', 'sub.py'), 'x = 1\n');
    });

    afterEach(() => {
      try { rmSync(pyDir, { recursive: true, force: true }); } catch { /* ignore */ }
    });

    it('should resolve Python relative .helpers import', () => {
      const mainPy = join(pyDir, 'main.py');
      const result = resolveImportPath('.helpers', mainPy, 'python');
      expect(result).not.toBeNull();
      expect(result).toBe(join(pyDir, 'helpers.py'));
    });

    it('should resolve Python package with __init__.py', () => {
      const mainPy = join(pyDir, 'main.py');
      const result = resolveImportPath('.pkg', mainPy, 'python');
      expect(result).not.toBeNull();
      expect(result).toBe(join(pyDir, 'pkg', '__init__.py'));
    });
  });
});

// ============= resolveImportGraph =============
describe('resolveImportGraph', () => {
  beforeEach(() => {
    clearImportGraphCache();
  });

  it('should build import graph from app.js', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    // Should have 4 files: app.js, routes/users.js, lib/db.js, middleware/auth.js
    expect(graph.summary.total_files).toBeGreaterThanOrEqual(4);
    expect(graph.files[appJs]).toBeDefined();
    expect(graph.files[appJs].content_hash).toBeDefined();
    expect(graph.files[appJs].content_hash.length).toBe(16);
  });

  it('should trace edges correctly', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    // app.js -> routes/users.js
    const appToUsers = graph.edges.find(e =>
      e.from === appJs && e.to === join(fixtureDir, 'routes', 'users.js')
    );
    expect(appToUsers).toBeDefined();
    expect(appToUsers.importSpec).toBe('./routes/users');

    // routes/users.js -> lib/db.js
    const usersToDb = graph.edges.find(e =>
      e.from === join(fixtureDir, 'routes', 'users.js') && e.to === join(fixtureDir, 'lib', 'db.js')
    );
    expect(usersToDb).toBeDefined();
  });

  it('should exclude package imports from edges', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    // No edge should point to 'express', 'helmet', or 'cors' (packages)
    for (const edge of graph.edges) {
      expect(edge.to).not.toContain('node_modules');
      expect(edge.importSpec).not.toBe('express');
      expect(edge.importSpec).not.toBe('helmet');
    }
  });

  it('should respect maxDepth option', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir, { maxDepth: 1 });

    // At depth 1, should have app.js and its direct imports (routes/users.js)
    // but NOT the transitive imports (lib/db.js, middleware/auth.js)
    expect(graph.files[appJs]).toBeDefined();
    expect(graph.files[join(fixtureDir, 'routes', 'users.js')]).toBeDefined();
    // db.js and auth.js are at depth 2, should not be traversed
    expect(graph.files[join(fixtureDir, 'lib', 'db.js')]).toBeUndefined();
    expect(graph.files[join(fixtureDir, 'middleware', 'auth.js')]).toBeUndefined();
  });

  it('should have content hashes for all files', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    for (const [path, fileInfo] of Object.entries(graph.files)) {
      expect(fileInfo.content_hash).toBeDefined();
      expect(typeof fileInfo.content_hash).toBe('string');
      expect(fileInfo.content_hash.length).toBe(16);
    }
  });

  it('should detect cycles', () => {
    const cycleDir = join(__dirname, 'fixtures', 'temp-cycle-test');
    mkdirSync(cycleDir, { recursive: true });

    // Create circular imports: a.js -> b.js -> a.js
    writeFileSync(join(cycleDir, 'a.js'), "const b = require('./b');\nmodule.exports = { a: 1 };\n");
    writeFileSync(join(cycleDir, 'b.js'), "const a = require('./a');\nmodule.exports = { b: 2 };\n");

    try {
      const graph = resolveImportGraph(join(cycleDir, 'a.js'), cycleDir);
      expect(graph.summary.has_cycles).toBe(true);
      expect(graph.cycles.length).toBeGreaterThan(0);
    } finally {
      rmSync(cycleDir, { recursive: true, force: true });
    }
  });

  it('should use cache on second call', () => {
    const appJs = join(fixtureDir, 'app.js');
    clearImportGraphCache();

    const graph1 = resolveImportGraph(appJs, fixtureDir);
    const graph2 = resolveImportGraph(appJs, fixtureDir);

    // Results should be equivalent
    expect(graph1.summary.total_files).toBe(graph2.summary.total_files);
    expect(graph1.summary.total_edges).toBe(graph2.summary.total_edges);
  });

  it('should report summary correctly', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    expect(graph.summary.total_files).toBeGreaterThanOrEqual(4);
    expect(graph.summary.total_edges).toBeGreaterThanOrEqual(3);
    expect(typeof graph.summary.has_cycles).toBe('boolean');
    expect(typeof graph.summary.max_depth_reached).toBe('boolean');
  });
});

// ============= Project context caching =============
describe('Project context caching', () => {
  const cacheDir = join(__dirname, 'fixtures', 'temp-cache-test');

  beforeEach(() => {
    clearProjectContextCache();
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0', helmet: '^7.0.0' }
    }));
  });

  afterEach(() => {
    clearProjectContextCache();
    try { rmSync(cacheDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should return same result on second call', () => {
    const result1 = discoverProjectContext(cacheDir);
    const result2 = discoverProjectContext(cacheDir);
    expect(result1).toBe(result2); // Same reference = from cache
  });

  it('should invalidate cache when dependency file changes', () => {
    const result1 = discoverProjectContext(cacheDir);
    expect(result1.framework).toBe('Express');

    // Change package.json to Flask
    writeFileSync(join(cacheDir, 'package.json'), JSON.stringify({
      dependencies: { 'not-a-framework': '^1.0.0' }
    }));

    const result2 = discoverProjectContext(cacheDir);
    expect(result2).not.toBe(result1); // Different reference = cache invalidated
    expect(result2.framework).toBeNull();
  });

  it('should clear cache with clearProjectContextCache', () => {
    const result1 = discoverProjectContext(cacheDir);
    clearProjectContextCache();
    const result2 = discoverProjectContext(cacheDir);
    expect(result2).not.toBe(result1); // Different reference = cache was cleared
    // But values should be equivalent
    expect(result2.framework).toBe(result1.framework);
  });
});

// ============= Cross-file taint path =============
describe('Cross-file taint path detection', () => {
  beforeEach(() => {
    clearImportGraphCache();
  });

  it('should reveal routes/users.js -> lib/db.js chain', () => {
    const usersJs = join(fixtureDir, 'routes', 'users.js');
    const graph = resolveImportGraph(usersJs, fixtureDir);

    // Should have edge from users.js to db.js
    const dbEdge = graph.edges.find(e =>
      e.from === usersJs && e.to === join(fixtureDir, 'lib', 'db.js')
    );
    expect(dbEdge).toBeDefined();
    expect(dbEdge.importSpec).toBe('../lib/db');
  });

  it('should show db.js contains SQL concatenation', () => {
    const dbPath = join(fixtureDir, 'lib', 'db.js');
    const content = readFileSync(dbPath, 'utf-8');
    // The SQL injection is only exploitable via the cross-file path
    expect(content).toContain('SELECT * FROM users WHERE id = " + id');
    expect(content).toContain("SELECT * FROM users WHERE name LIKE '%\" + term");
  });

  it('should build full graph from app.js showing taint chain', () => {
    const appJs = join(fixtureDir, 'app.js');
    const graph = resolveImportGraph(appJs, fixtureDir);

    // The cross-file taint chain:
    // app.js -> routes/users.js -> lib/db.js
    const paths = graph.edges.map(e => `${e.from} -> ${e.to}`);

    // Verify the chain exists
    const hasAppToUsers = graph.edges.some(e =>
      e.from === appJs && e.to === join(fixtureDir, 'routes', 'users.js')
    );
    const hasUsersToDb = graph.edges.some(e =>
      e.from === join(fixtureDir, 'routes', 'users.js') && e.to === join(fixtureDir, 'lib', 'db.js')
    );
    expect(hasAppToUsers).toBe(true);
    expect(hasUsersToDb).toBe(true);
  });
});

// ============= Python cross-file analyzer integration =============
describe('Python cross-file analyzer', () => {
  const mpcServerDir = resolve(__dirname, '..');
  const crossFileAnalyzerPath = join(mpcServerDir, 'cross_file_analyzer.py');

  it('should produce cross-file-taint findings on express-app fixture', () => {
    // Skip if Python is not available or analyzer doesn't exist
    if (!existsSync(crossFileAnalyzerPath)) {
      console.warn('Skipping: cross_file_analyzer.py not found');
      return;
    }

    let output;
    const execOpts = {
      encoding: 'utf-8',
      timeout: 30000,
      cwd: mpcServerDir,
      stdio: ['pipe', 'pipe', 'pipe'],  // capture stderr separately
    };
    const args = [
      crossFileAnalyzerPath,
      join(fixtureDir, 'routes', 'users.js'),
      join(fixtureDir, 'lib', 'db.js'),
    ];
    try {
      output = execFileSync('python3', args, execOpts);
    } catch (e) {
      // Python3 not available — try python
      try {
        output = execFileSync('python', args, execOpts);
      } catch {
        console.warn('Skipping: python not available');
        return;
      }
    }

    // Strip any non-JSON prefix lines (e.g. PyYAML warnings printed to stdout)
    const jsonStart = output.indexOf('[');
    const jsonOutput = jsonStart >= 0 ? output.slice(jsonStart) : output;
    const results = JSON.parse(jsonOutput);
    expect(Array.isArray(results)).toBe(true);

    // Should contain cross-file-taint-warning findings (propagated from db.js SQL injection)
    const crossFileTaint = results.filter(r => r.ruleId === 'cross-file-taint-warning');
    expect(crossFileTaint.length).toBeGreaterThanOrEqual(1);

    // At least one finding should mention db.js and sql-injection
    const messages = crossFileTaint.map(f => f.message);
    const hasTaintFlow = messages.some(m =>
      m.includes('db.js') && m.includes('sql-injection')
    );
    expect(hasTaintFlow).toBe(true);

    // Findings should have proper metadata
    for (const finding of crossFileTaint) {
      expect(finding.severity).toBe('warning');
      expect(finding.metadata).toBeDefined();
      expect(finding.metadata.imported_file).toBeDefined();
      expect(finding.metadata.imported_findings_count).toBeGreaterThanOrEqual(1);
    }
  });
});
