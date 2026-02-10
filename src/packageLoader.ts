import * as fs from 'fs';
import * as path from 'path';

// Bloom filter implementation for efficient package lookup
// Uses the same format as mcp-server-full for compatibility

interface BloomFilterData {
    _seed: number;
    _size: number;
    _nbHashes: number;
    _filter: number[];
}

class BloomFilter {
    private seed: number;
    private size: number;
    private nbHashes: number;
    private filter: Uint8Array;

    constructor(data: BloomFilterData) {
        this.seed = data._seed;
        this.size = data._size;
        this.nbHashes = data._nbHashes;
        // Convert number array to Uint8Array
        this.filter = new Uint8Array(data._filter);
    }

    // MurmurHash3 implementation for bloom filter
    private hash(key: string, seed: number): number {
        let h1 = seed;
        const c1 = 0xcc9e2d51;
        const c2 = 0x1b873593;

        for (let i = 0; i < key.length; i++) {
            let k1 = key.charCodeAt(i);
            k1 = Math.imul(k1, c1);
            k1 = (k1 << 15) | (k1 >>> 17);
            k1 = Math.imul(k1, c2);
            h1 ^= k1;
            h1 = (h1 << 13) | (h1 >>> 19);
            h1 = Math.imul(h1, 5) + 0xe6546b64;
        }

        h1 ^= key.length;
        h1 ^= h1 >>> 16;
        h1 = Math.imul(h1, 0x85ebca6b);
        h1 ^= h1 >>> 13;
        h1 = Math.imul(h1, 0xc2b2ae35);
        h1 ^= h1 >>> 16;

        return h1 >>> 0;
    }

    has(item: string): boolean {
        for (let i = 0; i < this.nbHashes; i++) {
            const hash = this.hash(item, this.seed + i) % this.size;
            const byteIndex = Math.floor(hash / 8);
            const bitIndex = hash % 8;
            if ((this.filter[byteIndex] & (1 << bitIndex)) === 0) {
                return false;
            }
        }
        return true;
    }
}

export type PackageEcosystem = 'npm' | 'pypi' | 'rubygems' | 'crates' | 'dart' | 'perl' | 'raku';

interface EcosystemData {
    type: 'bloom' | 'set';
    data: BloomFilter | Set<string> | null;
    count: number;
    loaded: boolean;
}

// Package data storage
const ecosystems: Map<PackageEcosystem, EcosystemData> = new Map();

// Known package counts for bloom filter ecosystems
const BLOOM_COUNTS: Record<string, number> = {
    npm: 3329177,
    pypi: 554762,
    rubygems: 180693
};

// Import patterns for different ecosystems
export const IMPORT_PATTERNS: Record<PackageEcosystem, RegExp[]> = {
    npm: [
        /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
        /from\s+['"]([^'"]+)['"]/g,
        /import\s+['"]([^'"]+)['"]/g
    ],
    pypi: [
        /^import\s+([\w]+)/gm,
        /^from\s+([\w]+)/gm
    ],
    rubygems: [
        /require\s+['"]([^'"]+)['"]/g,
        /gem\s+['"]([^'"]+)['"]/g
    ],
    crates: [
        /use\s+([\w_]+)/g,
        /extern\s+crate\s+([\w_]+)/g
    ],
    dart: [
        /import\s+['"]package:([^\/'"]+)/g
    ],
    perl: [
        /use\s+([\w:]+)/g,
        /require\s+([\w:]+)/g
    ],
    raku: [
        /use\s+([\w:]+)/g,
        /need\s+([\w:]+)/g
    ]
};

// File extension to ecosystem mapping
export const EXTENSION_TO_ECOSYSTEM: Record<string, PackageEcosystem> = {
    '.js': 'npm',
    '.jsx': 'npm',
    '.ts': 'npm',
    '.tsx': 'npm',
    '.mjs': 'npm',
    '.cjs': 'npm',
    '.py': 'pypi',
    '.rb': 'rubygems',
    '.rs': 'crates',
    '.dart': 'dart',
    '.pl': 'perl',
    '.pm': 'perl',
    '.raku': 'raku',
    '.rakumod': 'raku'
};

/**
 * Initialize package data from files
 */
export function initializePackageLoader(extensionPath: string): void {
    const packagesDir = path.join(extensionPath, 'packages');

    // Initialize bloom filter ecosystems
    for (const ecosystem of ['npm', 'pypi', 'rubygems'] as PackageEcosystem[]) {
        const bloomPath = path.join(packagesDir, `${ecosystem}-bloom.json`);
        try {
            if (fs.existsSync(bloomPath)) {
                const data = JSON.parse(fs.readFileSync(bloomPath, 'utf-8'));
                const filter = new BloomFilter(data);
                ecosystems.set(ecosystem, {
                    type: 'bloom',
                    data: filter,
                    count: BLOOM_COUNTS[ecosystem] || 0,
                    loaded: true
                });
                console.log(`Loaded ${ecosystem} Bloom filter (${BLOOM_COUNTS[ecosystem]?.toLocaleString()} packages)`);
            } else {
                ecosystems.set(ecosystem, { type: 'bloom', data: null, count: 0, loaded: false });
            }
        } catch (error) {
            console.error(`Failed to load ${ecosystem} Bloom filter:`, error);
            ecosystems.set(ecosystem, { type: 'bloom', data: null, count: 0, loaded: false });
        }
    }

    // Initialize set-based ecosystems
    for (const ecosystem of ['crates', 'dart', 'perl', 'raku'] as PackageEcosystem[]) {
        const filePath = path.join(packagesDir, `${ecosystem}.txt`);
        try {
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf-8');
                const packages = new Set(content.split('\n').filter(p => p.trim()));
                ecosystems.set(ecosystem, {
                    type: 'set',
                    data: packages,
                    count: packages.size,
                    loaded: true
                });
                console.log(`Loaded ${packages.size} ${ecosystem} packages`);
            } else {
                ecosystems.set(ecosystem, { type: 'set', data: null, count: 0, loaded: false });
            }
        } catch (error) {
            console.error(`Failed to load ${ecosystem} packages:`, error);
            ecosystems.set(ecosystem, { type: 'set', data: null, count: 0, loaded: false });
        }
    }
}

/**
 * Check if a package exists in the registry
 */
export function checkPackage(packageName: string, ecosystem: PackageEcosystem): { exists: boolean; unknown: boolean } {
    const ecosystemData = ecosystems.get(ecosystem);

    if (!ecosystemData || !ecosystemData.loaded || !ecosystemData.data) {
        return { exists: false, unknown: true };
    }

    if (ecosystemData.type === 'bloom') {
        const filter = ecosystemData.data as BloomFilter;
        return { exists: filter.has(packageName), unknown: false };
    } else {
        const packageSet = ecosystemData.data as Set<string>;
        return { exists: packageSet.has(packageName), unknown: false };
    }
}

/**
 * Check if an ecosystem is loaded
 */
export function isEcosystemLoaded(ecosystem: PackageEcosystem): boolean {
    const data = ecosystems.get(ecosystem);
    return data?.loaded ?? false;
}

/**
 * Get package count for an ecosystem
 */
export function getPackageCount(ecosystem: PackageEcosystem): number {
    const data = ecosystems.get(ecosystem);
    return data?.count ?? 0;
}

/**
 * Get all ecosystem statistics
 */
export function getPackageStats(): { ecosystem: PackageEcosystem; count: number; loaded: boolean; type: string }[] {
    const stats: { ecosystem: PackageEcosystem; count: number; loaded: boolean; type: string }[] = [];

    for (const [ecosystem, data] of ecosystems) {
        stats.push({
            ecosystem,
            count: data.count,
            loaded: data.loaded,
            type: data.type
        });
    }

    return stats;
}

/**
 * Extract package names from code
 */
export function extractPackages(code: string, ecosystem: PackageEcosystem): string[] {
    const packages = new Set<string>();
    const patterns = IMPORT_PATTERNS[ecosystem] || [];

    for (const pattern of patterns) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match;
        while ((match = regex.exec(code)) !== null) {
            const pkg = match[1];
            if (pkg && !pkg.startsWith('.') && !pkg.startsWith('/')) {
                // Normalize package name (handle scoped packages, subpaths)
                let basePkg = pkg.split('/')[0];
                // Handle scoped packages like @org/package
                if (pkg.startsWith('@') && pkg.includes('/')) {
                    basePkg = pkg.split('/').slice(0, 2).join('/');
                }
                packages.add(basePkg);
            }
        }
    }

    return Array.from(packages);
}

/**
 * Detect ecosystem from file extension
 */
export function detectEcosystem(filePath: string): PackageEcosystem | null {
    const ext = path.extname(filePath).toLowerCase();
    return EXTENSION_TO_ECOSYSTEM[ext] || null;
}

/**
 * Scan a file for potentially hallucinated packages
 */
export function scanFileForHallucinations(
    filePath: string,
    code: string
): { package: string; hallucinated: boolean; ecosystem: PackageEcosystem }[] {
    const ecosystem = detectEcosystem(filePath);
    if (!ecosystem) {
        return [];
    }

    const packages = extractPackages(code, ecosystem);
    const results: { package: string; hallucinated: boolean; ecosystem: PackageEcosystem }[] = [];

    for (const pkg of packages) {
        // Skip built-in modules
        if (isBuiltInModule(pkg, ecosystem)) {
            continue;
        }

        const { exists, unknown } = checkPackage(pkg, ecosystem);

        if (!unknown) {
            results.push({
                package: pkg,
                hallucinated: !exists,
                ecosystem
            });
        }
    }

    return results;
}

/**
 * Check if a module is a built-in (doesn't need to exist in registry)
 */
function isBuiltInModule(pkg: string, ecosystem: PackageEcosystem): boolean {
    const builtIns: Record<PackageEcosystem, Set<string>> = {
        npm: new Set([
            'fs', 'path', 'http', 'https', 'url', 'util', 'os', 'crypto',
            'stream', 'events', 'buffer', 'child_process', 'cluster',
            'dgram', 'dns', 'domain', 'net', 'readline', 'repl', 'tls',
            'tty', 'v8', 'vm', 'zlib', 'assert', 'async_hooks', 'console',
            'constants', 'module', 'perf_hooks', 'process', 'punycode',
            'querystring', 'string_decoder', 'timers', 'worker_threads'
        ]),
        pypi: new Set([
            'os', 'sys', 'json', 're', 'math', 'datetime', 'time', 'random',
            'collections', 'itertools', 'functools', 'operator', 'pathlib',
            'typing', 'abc', 'io', 'pickle', 'copy', 'pprint', 'reprlib',
            'enum', 'graphlib', 'types', 'copy', 'warnings', 'dataclasses',
            'contextlib', 'traceback', 'gc', 'inspect', 'dis', 'ast',
            'subprocess', 'threading', 'multiprocessing', 'concurrent',
            'socket', 'ssl', 'select', 'selectors', 'asyncio', 'signal',
            'email', 'html', 'xml', 'urllib', 'http', 'ftplib', 'imaplib',
            'smtplib', 'uuid', 'hashlib', 'hmac', 'secrets', 'struct',
            'codecs', 'unicodedata', 'stringprep', 'locale', 'gettext',
            'argparse', 'logging', 'platform', 'errno', 'ctypes', 'unittest',
            'doctest', 'pdb', 'profile', 'timeit', 'trace', 'sqlite3', 'csv',
            'configparser', 'tomllib', 'netrc', 'plistlib', 'stat', 'filecmp',
            'tempfile', 'glob', 'fnmatch', 'shutil', 'zipfile', 'tarfile',
            'gzip', 'bz2', 'lzma', 'base64', 'binascii', 'quopri', 'uu'
        ]),
        rubygems: new Set([
            'json', 'yaml', 'csv', 'fileutils', 'pathname', 'tempfile',
            'open-uri', 'net/http', 'uri', 'socket', 'openssl', 'digest',
            'securerandom', 'base64', 'zlib', 'stringio', 'set', 'date',
            'time', 'benchmark', 'logger', 'singleton', 'observer', 'forwardable',
            'delegate', 'ostruct', 'pp', 'prettyprint', 'erb', 'cgi', 'webrick'
        ]),
        crates: new Set(['std', 'core', 'alloc', 'proc_macro', 'test']),
        dart: new Set(['dart:core', 'dart:async', 'dart:collection', 'dart:convert', 'dart:io', 'dart:math']),
        perl: new Set(['strict', 'warnings', 'utf8', 'Exporter', 'Carp', 'Data::Dumper']),
        raku: new Set(['Test', 'NativeCall'])
    };

    return builtIns[ecosystem]?.has(pkg) ?? false;
}
