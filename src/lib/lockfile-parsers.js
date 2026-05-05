// Lock file parsers for transitive dependency extraction.
// Each parser returns an array of { name, version, isDev, scope } objects.
// Uses regex/string-split — no external TOML/YAML libraries.

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { createComponent, createEdge, createComponentList } from './sbom-component.js';

// ─── package-lock.json (npm, v2/v3) ─────────────────────────────────

export function parsePackageLockJson(root) {
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(lockPath)) return null;

  const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
  const deps = [];
  const edges = [];
  const packages = lock.packages || {};
  const projectPurl = `pkg:npm/${lock.name || 'root'}@${lock.version || '0.0.0'}`;

  // Collect direct dependency names from the root entry
  const rootEntry = packages[''] || {};
  const directNames = new Set([
    ...Object.keys(rootEntry.dependencies || {}),
    ...Object.keys(rootEntry.devDependencies || {}),
    ...Object.keys(rootEntry.optionalDependencies || {}),
  ]);

  for (const [key, info] of Object.entries(packages)) {
    if (key === '') continue; // root entry
    // key looks like "node_modules/@scope/pkg" or "node_modules/pkg"
    const name = key.replace(/^node_modules\//, '').replace(/^.*node_modules\//, '');
    if (!name || !info.version) continue;

    const isDev = !!info.dev || !!info.devOptional;
    // A package is direct only if it appears in the root's dependency lists
    const isDirect = directNames.has(name);
    const comp = createComponent({ name, version: info.version, ecosystem: 'npm', isDev, isDirect });
    deps.push(comp);

    // Build edge from root to direct deps only
    if (isDirect) {
      edges.push(createEdge(projectPurl, comp.purl));
    }
  }

  return { ecosystem: 'npm', deps, edges, projectName: lock.name, projectVersion: lock.version };
}

// ─── yarn.lock (Classic v1 and Berry v2+) ────────────────────────────

export function parseYarnLock(root) {
  const lockPath = join(root, 'yarn.lock');
  if (!existsSync(lockPath)) return null;

  const content = readFileSync(lockPath, 'utf-8');
  const deps = [];
  const seen = new Set();

  // Detect Berry format: starts with __metadata
  const isBerry = content.includes('__metadata:');

  if (isBerry) {
    // Berry format: "express@npm:^4.18.2":
    //   version: 4.18.2
    const blockRe = /^"(@?[^@\n]+)@npm:[^"]*":\s*$/gm;
    let blockMatch;
    while ((blockMatch = blockRe.exec(content))) {
      const name = blockMatch[1].trim();
      if (name === '__metadata') continue;
      // Find version: line after the block header
      const after = content.slice(blockMatch.index + blockMatch[0].length, blockMatch.index + blockMatch[0].length + 200);
      const verMatch = after.match(/^\s+version:\s+"?([^"\n\s]+)"?\s*$/m);
      if (verMatch) {
        const key = `${name}@${verMatch[1]}`;
        if (!seen.has(key)) {
          seen.add(key);
          deps.push(createComponent({ name, version: verMatch[1], ecosystem: 'npm' }));
        }
      }
    }
  } else {
    // Classic format: "name@version", "name@version":
    //   version "x.y.z"
    const blockRe = /^"?(@?[^@\s][^@\n]*?)@[^:\n]+"?(?:,\s*"?@?[^@\s][^@\n]*?@[^:\n]+"?)*:\s*$/gm;
    const versionRe = /^\s+version\s+"([^"]+)"/gm;
    let blockMatch;
    while ((blockMatch = blockRe.exec(content))) {
      const rawNames = blockMatch[0].replace(/:$/, '');
      // Extract first name from the resolution
      const nameMatch = rawNames.match(/^"?(@?[^@\s]+)/);
      if (!nameMatch) continue;
      const name = nameMatch[1];

      versionRe.lastIndex = blockMatch.index;
      const verMatch = versionRe.exec(content);
      if (verMatch && verMatch.index - blockMatch.index < 500) {
        const key = `${name}@${verMatch[1]}`;
        if (!seen.has(key)) {
          seen.add(key);
          deps.push(createComponent({ name, version: verMatch[1], ecosystem: 'npm' }));
        }
      }
    }
  }

  return deps.length ? { ecosystem: 'npm', deps, edges: [] } : null;
}

// ─── pnpm-lock.yaml ──────────────────────────────────────────────────

export function parsePnpmLock(root) {
  const lockPath = join(root, 'pnpm-lock.yaml');
  if (!existsSync(lockPath)) return null;

  const content = readFileSync(lockPath, 'utf-8');
  const deps = [];
  const seen = new Set();

  // v6+: packages section with entries like:
  //   /@scope/name@version: or /name@version:
  // v9+: entries like:
  //   '@scope/name@version': or name@version:
  const patterns = [
    /^\s+\/?(@?[^@\s:][^@:]*?)@(\d[^:\s]*)\s*:/gm,       // /name@version: or /@scope/name@version:
    /^\s+'(@?[^@'\s]+)@(\d[^']*)':\s*$/gm,                 // 'name@version':
  ];

  for (const re of patterns) {
    let m;
    while ((m = re.exec(content))) {
      const name = m[1].replace(/^\//, '');
      const version = m[2];
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push(createComponent({ name, version, ecosystem: 'npm' }));
      }
    }
  }

  return deps.length ? { ecosystem: 'npm', deps, edges: [] } : null;
}

// ─── poetry.lock (Python) ────────────────────────────────────────────

export function parsePoetryLock(root) {
  const lockPath = join(root, 'poetry.lock');
  if (!existsSync(lockPath)) return null;

  const content = readFileSync(lockPath, 'utf-8');
  const blocks = content.split(/^\[\[package\]\]\s*$/m).slice(1);
  const deps = [];

  for (const block of blocks) {
    const nameMatch = block.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^version\s*=\s*"([^"]+)"/m);
    const categoryMatch = block.match(/^category\s*=\s*"([^"]+)"/m);
    if (!nameMatch || !versionMatch) continue;

    const isDev = categoryMatch ? categoryMatch[1] === 'dev' : false;
    deps.push(createComponent({
      name: nameMatch[1],
      version: versionMatch[1],
      ecosystem: 'pypi',
      isDev,
    }));
  }

  return deps.length ? { ecosystem: 'pypi', deps, edges: [] } : null;
}

// ─── Pipfile.lock (Python) ───────────────────────────────────────────

export function parsePipfileLock(root) {
  const lockPath = join(root, 'Pipfile.lock');
  if (!existsSync(lockPath)) return null;

  const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
  const deps = [];

  for (const [section, isDev] of [['default', false], ['develop', true]]) {
    const packages = lock[section] || {};
    for (const [name, info] of Object.entries(packages)) {
      const version = (info.version || '').replace(/^==/, '');
      if (!version) continue;
      deps.push(createComponent({ name, version, ecosystem: 'pypi', isDev }));
    }
  }

  return deps.length ? { ecosystem: 'pypi', deps, edges: [] } : null;
}

// ─── Cargo.lock (Rust) ──────────────────────────────────────────────

export function parseCargoLock(root) {
  const lockPath = join(root, 'Cargo.lock');
  if (!existsSync(lockPath)) return null;

  const content = readFileSync(lockPath, 'utf-8');
  const blocks = content.split(/^\[\[package\]\]\s*$/m).slice(1);
  const deps = [];

  for (const block of blocks) {
    const nameMatch = block.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (!nameMatch || !versionMatch) continue;
    deps.push(createComponent({
      name: nameMatch[1],
      version: versionMatch[1],
      ecosystem: 'crates',
    }));
  }

  return deps.length ? { ecosystem: 'crates', deps, edges: [] } : null;
}

// ─── go.sum (Go) ─────────────────────────────────────────────────────

export function parseGoSum(root) {
  const sumPath = join(root, 'go.sum');
  if (!existsSync(sumPath)) return null;

  const content = readFileSync(sumPath, 'utf-8');
  const deps = [];
  const seen = new Set();

  for (const line of content.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const [mod, rawVersion] = parts;
    // go.sum has entries like: module v1.2.3 hash and module v1.2.3/go.mod hash
    const version = rawVersion.replace(/\/go\.mod$/, '');
    const key = `${mod}@${version}`;
    if (!seen.has(key)) {
      seen.add(key);
      deps.push(createComponent({ name: mod, version, ecosystem: 'go' }));
    }
  }

  return deps.length ? { ecosystem: 'go', deps, edges: [] } : null;
}

// ─── Gemfile.lock (Ruby) ─────────────────────────────────────────────

export function parseGemfileLock(root) {
  const lockPath = join(root, 'Gemfile.lock');
  if (!existsSync(lockPath)) return null;

  const content = readFileSync(lockPath, 'utf-8');
  const deps = [];

  // Find the SPECS section under GEM
  const specsMatch = content.match(/GEM[\s\S]*?specs:\n([\s\S]*?)(?:\n\S|\n$)/);
  if (!specsMatch) return null;

  const specsBlock = specsMatch[1];
  // Direct gems are indented 4 spaces, transitive 6+
  const gemRe = /^\s{4}(\S+)\s+\(([^)]+)\)/gm;
  let m;
  while ((m = gemRe.exec(specsBlock))) {
    deps.push(createComponent({ name: m[1], version: m[2], ecosystem: 'rubygems' }));
  }

  return deps.length ? { ecosystem: 'rubygems', deps, edges: [] } : null;
}

// ─── Manifest parsers with versions (direct deps, fallback) ─────────

export function parseManifestWithVersions(root) {
  const results = [];

  // package.json
  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      for (const [name, ver] of Object.entries(pkg.dependencies || {})) {
        results.push(createComponent({ name, version: ver.replace(/^[\^~>=<\s]+/, ''), ecosystem: 'npm', isDirect: true }));
      }
      for (const [name, ver] of Object.entries(pkg.devDependencies || {})) {
        results.push(createComponent({ name, version: ver.replace(/^[\^~>=<\s]+/, ''), ecosystem: 'npm', isDev: true, isDirect: true }));
      }
    } catch { /* skip malformed */ }
  }

  // requirements.txt
  const reqPath = join(root, 'requirements.txt');
  if (existsSync(reqPath)) {
    try {
      const lines = readFileSync(reqPath, 'utf-8').split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
        const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*(?:[=!><~]+\s*(.+))?/);
        if (match) {
          results.push(createComponent({
            name: match[1],
            version: (match[2] || 'unknown').split(',')[0].trim(),
            ecosystem: 'pypi',
            isDirect: true,
          }));
        }
      }
    } catch { /* skip */ }
  }

  // pyproject.toml — [project.dependencies] and [tool.poetry.dependencies]
  const pyprojectPath = join(root, 'pyproject.toml');
  if (existsSync(pyprojectPath)) {
    try {
      const content = readFileSync(pyprojectPath, 'utf-8');

      // PEP 621: [project] dependencies = ["flask>=2.0", ...]
      const projDepsMatch = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
      if (projDepsMatch) {
        const items = projDepsMatch[1].match(/"([^"]+)"/g) || [];
        for (const item of items) {
          const raw = item.replace(/"/g, '');
          const m = raw.match(/^([a-zA-Z0-9_.-]+)\s*(?:[=!><~]+\s*(.+))?/);
          if (m) {
            results.push(createComponent({
              name: m[1],
              version: (m[2] || 'unknown').split(',')[0].trim(),
              ecosystem: 'pypi',
              isDirect: true,
            }));
          }
        }
      }

      // Poetry: [tool.poetry.dependencies]
      const poetryMatch = content.match(/\[tool\.poetry\.dependencies\]\s*\n([\s\S]*?)(?:\n\[|\n$)/);
      if (poetryMatch) {
        const lines = poetryMatch[1].split('\n');
        for (const line of lines) {
          const m = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"([^"]+)"/);
          if (m && m[1] !== 'python') {
            results.push(createComponent({
              name: m[1],
              version: m[2].replace(/^[\^~>=<\s]+/, ''),
              ecosystem: 'pypi',
              isDirect: true,
            }));
          }
        }
      }
    } catch { /* skip */ }
  }

  // go.mod
  const goModPath = join(root, 'go.mod');
  if (existsSync(goModPath)) {
    try {
      const content = readFileSync(goModPath, 'utf-8');
      // Single requires: require module v1.2.3
      const singleRe = /^require\s+(\S+)\s+(v[\d.]+\S*)/gm;
      let m;
      while ((m = singleRe.exec(content))) {
        results.push(createComponent({ name: m[1], version: m[2], ecosystem: 'go', isDirect: true }));
      }
      // Block requires
      const blockMatch = content.match(/require\s*\(([\s\S]*?)\)/g) || [];
      for (const block of blockMatch) {
        const lineRe = /^\s*(\S+)\s+(v[\d.]+\S*)/gm;
        while ((m = lineRe.exec(block))) {
          results.push(createComponent({ name: m[1], version: m[2], ecosystem: 'go', isDirect: true }));
        }
      }
    } catch { /* skip */ }
  }

  // Gemfile
  const gemfilePath = join(root, 'Gemfile');
  if (existsSync(gemfilePath)) {
    try {
      const content = readFileSync(gemfilePath, 'utf-8');
      const gemRe = /gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/g;
      let m;
      while ((m = gemRe.exec(content))) {
        results.push(createComponent({
          name: m[1],
          version: m[2] ? m[2].replace(/^[~>=<\s]+/, '') : 'unknown',
          ecosystem: 'rubygems',
          isDirect: true,
        }));
      }
    } catch { /* skip */ }
  }

  // pom.xml (Maven)
  const pomPath = join(root, 'pom.xml');
  if (existsSync(pomPath)) {
    try {
      const content = readFileSync(pomPath, 'utf-8');
      const depRe = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;
      let m;
      while ((m = depRe.exec(content))) {
        results.push(createComponent({
          name: m[2],
          version: m[3] || 'unknown',
          ecosystem: 'java',
          namespace: m[1],
          isDirect: true,
        }));
      }
    } catch { /* skip */ }
  }

  // build.gradle / build.gradle.kts (Gradle)
  for (const gradleFile of ['build.gradle', 'build.gradle.kts']) {
    const gradlePath = join(root, gradleFile);
    if (existsSync(gradlePath)) {
      try {
        const content = readFileSync(gradlePath, 'utf-8');
        // implementation 'group:artifact:version' or implementation("group:artifact:version")
        const depRe = /(?:implementation|api|compile|runtimeOnly|testImplementation|compileOnly)\s*[\('"]+([^:'"]+):([^:'"]+):([^)'"]+)/g;
        let m;
        while ((m = depRe.exec(content))) {
          results.push(createComponent({
            name: m[2],
            version: m[3],
            ecosystem: 'java',
            namespace: m[1],
            isDev: m[0].startsWith('test'),
            isDirect: true,
          }));
        }
      } catch { /* skip */ }
    }
  }

  return results;
}

// ─── Package-manager CLI fallbacks ───────────────────────────────────

function tryExec(cmd, args, cwd, timeout = 30000) {
  try {
    const result = execFileSync(cmd, args, { cwd, encoding: 'utf-8', timeout, stdio: ['pipe', 'pipe', 'pipe'] });
    return result;
  } catch {
    return null;
  }
}

export function fallbackNpmLs(root) {
  const output = tryExec('npm', ['ls', '--all', '--json', '--silent'], root);
  if (!output) return null;

  try {
    const tree = JSON.parse(output);
    const deps = [];
    const seen = new Set();

    function walk(node) {
      for (const [name, info] of Object.entries(node.dependencies || {})) {
        const key = `${name}@${info.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push(createComponent({ name, version: info.version || 'unknown', ecosystem: 'npm' }));
        walk(info);
      }
    }
    walk(tree);
    return deps.length ? { ecosystem: 'npm', deps, edges: [] } : null;
  } catch {
    return null;
  }
}

export function fallbackPnpmList(root) {
  const output = tryExec('pnpm', ['list', '--json', '--depth', 'Infinity'], root);
  if (!output) return null;

  try {
    const data = JSON.parse(output);
    const deps = [];
    const seen = new Set();
    const list = Array.isArray(data) ? data : [data];

    function walk(node) {
      for (const [name, info] of Object.entries(node.dependencies || {})) {
        const version = info.version;
        if (!version) continue;
        const key = `${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        deps.push(createComponent({ name, version, ecosystem: 'npm' }));
        walk(info);
      }
    }
    for (const entry of list) walk(entry);
    return deps.length ? { ecosystem: 'npm', deps, edges: [] } : null;
  } catch {
    return null;
  }
}

export function fallbackCargoMetadata(root) {
  const output = tryExec('cargo', ['metadata', '--format-version', '1'], root, 60000);
  if (!output) return null;

  try {
    const meta = JSON.parse(output);
    const deps = [];
    const edges = [];
    const seen = new Set();

    // All packages in the resolve graph
    for (const pkg of meta.packages || []) {
      if (seen.has(`${pkg.name}@${pkg.version}`)) continue;
      seen.add(`${pkg.name}@${pkg.version}`);
      deps.push(createComponent({ name: pkg.name, version: pkg.version, ecosystem: 'crates' }));
    }

    // Build dependency edges from resolve.nodes
    if (meta.resolve && meta.resolve.nodes) {
      for (const node of meta.resolve.nodes) {
        const fromMatch = node.id.match(/^([^\s]+)\s+(\S+)/);
        if (!fromMatch) continue;
        const fromPurl = `pkg:cargo/${fromMatch[1]}@${fromMatch[2]}`;
        for (const dep of node.deps || []) {
          const toMatch = dep.pkg.match(/^([^\s]+)\s+(\S+)/);
          if (toMatch) {
            edges.push(createEdge(fromPurl, `pkg:cargo/${toMatch[1]}@${toMatch[2]}`));
          }
        }
      }
    }

    return deps.length ? { ecosystem: 'crates', deps, edges } : null;
  } catch {
    return null;
  }
}

export function fallbackGoListModules(root) {
  const output = tryExec('go', ['list', '-m', 'all'], root);
  if (!output) return null;

  const deps = [];
  for (const line of output.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2) {
      deps.push(createComponent({ name: parts[0], version: parts[1], ecosystem: 'go' }));
    }
  }
  return deps.length ? { ecosystem: 'go', deps, edges: [] } : null;
}

export function fallbackMvnDependencyTree(root) {
  const output = tryExec('mvn', ['dependency:tree', '-DoutputType=text', '-q'], root, 60000);
  if (!output) return null;

  const deps = [];
  // Lines like: [INFO]    +- group:artifact:type:version:scope
  const depRe = /[+-\\|]\s+([^:]+):([^:]+):([^:]+):([^:]+)/g;
  let m;
  while ((m = depRe.exec(output))) {
    deps.push(createComponent({
      name: m[2],
      version: m[4],
      ecosystem: 'java',
      namespace: m[1],
    }));
  }
  return deps.length ? { ecosystem: 'java', deps, edges: [] } : null;
}

// ─── Top-level discovery ─────────────────────────────────────────────

/**
 * Discover all dependencies in a project.
 * Tries lock file parsers first, then CLI fallbacks, then manifest-only.
 * @param {string} projectRoot
 * @param {{ includeDev?: boolean }} [options={}]
 * @returns {ComponentList}
 */
export function discoverDependencies(projectRoot, options = {}) {
  const { includeDev = true } = options;

  const lockParsers = [
    parsePackageLockJson,
    parseYarnLock,
    parsePnpmLock,
    parsePoetryLock,
    parsePipfileLock,
    parseCargoLock,
    parseGoSum,
    parseGemfileLock,
  ];

  const cliFallbacks = [
    fallbackNpmLs,
    fallbackPnpmList,
    fallbackCargoMetadata,
    fallbackGoListModules,
    fallbackMvnDependencyTree,
  ];

  let allDeps = [];
  let allEdges = [];
  const discoveredEcosystems = new Set();

  // Phase 1: Lock file parsers
  for (const parser of lockParsers) {
    const result = parser(projectRoot);
    if (result) {
      discoveredEcosystems.add(result.ecosystem);
      allDeps.push(...result.deps);
      if (result.edges) allEdges.push(...result.edges);
    }
  }

  // Phase 2: CLI fallbacks for ecosystems not covered by lock files
  for (const fallback of cliFallbacks) {
    const result = fallback(projectRoot);
    if (result && !discoveredEcosystems.has(result.ecosystem)) {
      discoveredEcosystems.add(result.ecosystem);
      allDeps.push(...result.deps);
      if (result.edges) allEdges.push(...result.edges);
    }
  }

  // Phase 3: Manifest parsers for any remaining direct deps
  const manifestDeps = parseManifestWithVersions(projectRoot);
  const existingPurls = new Set(allDeps.map(d => d.purl));
  for (const dep of manifestDeps) {
    // Only add if not already discovered from lock file/CLI
    if (!existingPurls.has(dep.purl)) {
      // Check if same package (different version) was already found
      const sameName = allDeps.find(d => d.name === dep.name && d.ecosystem === dep.ecosystem);
      if (!sameName) {
        allDeps.push(dep);
      }
    }
  }

  // Filter dev dependencies if requested
  if (!includeDev) {
    allDeps = allDeps.filter(d => !d.isDev);
  }

  // Deduplicate by purl
  const deduped = new Map();
  for (const dep of allDeps) {
    if (!deduped.has(dep.purl)) {
      deduped.set(dep.purl, dep);
    }
  }

  // Read project metadata
  let projectName = 'unknown';
  let projectVersion = '0.0.0';
  const pkgPath = join(projectRoot, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      projectName = pkg.name || projectName;
      projectVersion = pkg.version || projectVersion;
    } catch { /* skip */ }
  }

  return createComponentList(
    [...deduped.values()],
    allEdges,
    { name: projectName, version: projectVersion }
  );
}
