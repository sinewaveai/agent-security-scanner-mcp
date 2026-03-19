import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { DependencyGraphBuilder } from '../../src/graph/dependency.js';

describe('DependencyGraphBuilder', () => {
  it('builds a graph from fixture files', () => {
    const fixtureDir = path.resolve(__dirname, '../fixtures/vuln-api-server');
    const builder = new DependencyGraphBuilder(fixtureDir);
    const graph = builder.build(['server.js']);

    expect(graph.nodes.size).toBeGreaterThan(0);
    expect(graph.entryPoints).toEqual(['server.js']);

    const serverNode = graph.nodes.get('server.js');
    expect(serverNode).toBeTruthy();
    expect(serverNode!.file).toBe('server.js');
  });

  it('resolves local imports', () => {
    // Create a temp directory with two files that import each other
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-test-'));
    try {
      fs.writeFileSync(
        path.join(tmpDir, 'main.js'),
        "import { helper } from './helper.js';\nconsole.log(helper());",
      );
      fs.writeFileSync(
        path.join(tmpDir, 'helper.js'),
        "export function helper() { return 'hello'; }",
      );

      const builder = new DependencyGraphBuilder(tmpDir);
      const graph = builder.build(['main.js']);

      expect(graph.nodes.size).toBe(2);

      const mainNode = graph.nodes.get('main.js');
      expect(mainNode?.imports).toContain('helper.js');

      const helperNode = graph.nodes.get('helper.js');
      expect(helperNode?.importedBy).toContain('main.js');
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('handles cycles without infinite loop', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-cycle-'));
    try {
      fs.writeFileSync(
        path.join(tmpDir, 'a.js'),
        "import './b.js';",
      );
      fs.writeFileSync(
        path.join(tmpDir, 'b.js'),
        "import './a.js';",
      );

      const builder = new DependencyGraphBuilder(tmpDir);
      const graph = builder.build(['a.js']);

      expect(graph.nodes.size).toBe(2);
      // Should complete without hanging
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('getImporters returns files that import a given file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-importers-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'index.js'), "import './utils.js';");
      fs.writeFileSync(path.join(tmpDir, 'utils.js'), "export const x = 1;");

      const builder = new DependencyGraphBuilder(tmpDir);
      builder.build(['index.js']);

      expect(builder.getImporters('utils.js')).toContain('index.js');
      expect(builder.getImportees('index.js')).toContain('utils.js');
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('ignores non-local imports', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-external-'));
    try {
      fs.writeFileSync(
        path.join(tmpDir, 'app.js'),
        "import express from 'express';\nimport chalk from 'chalk';",
      );

      const builder = new DependencyGraphBuilder(tmpDir);
      const graph = builder.build(['app.js']);

      const appNode = graph.nodes.get('app.js');
      expect(appNode?.imports).toHaveLength(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('includes barrel re-export edges in the graph', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-barrel-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'app.js'), "import { value } from './index.js';");
      fs.writeFileSync(path.join(tmpDir, 'index.js'), "export * from './lib.js';");
      fs.writeFileSync(path.join(tmpDir, 'lib.js'), 'export const value = 1;');

      const builder = new DependencyGraphBuilder(tmpDir);
      const graph = builder.build(['app.js']);

      expect(graph.nodes.get('index.js')?.imports).toContain('lib.js');
      expect(graph.nodes.get('lib.js')?.importedBy).toContain('index.js');
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('keeps supported non-JS entry files in the graph', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-java-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'Main.java'), 'class Main {}');

      const builder = new DependencyGraphBuilder(tmpDir);
      const graph = builder.build(['Main.java']);

      expect(graph.entryPoints).toEqual(['Main.java']);
      expect(graph.nodes.get('Main.java')?.file).toBe('Main.java');
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});
