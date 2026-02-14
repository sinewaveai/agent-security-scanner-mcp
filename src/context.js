// Context-aware filtering to reduce false positives.
// Suppresses findings on import-only lines for known standard/popular modules.

import { existsSync, readFileSync } from 'fs';
import { dirname, join } from 'path';

// Known safe standard library and popular modules per language
const KNOWN_MODULES = {
  javascript: new Set([
    // Node.js builtins
    'assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram',
    'dns', 'events', 'fs', 'http', 'http2', 'https', 'net', 'os',
    'path', 'perf_hooks', 'process', 'querystring', 'readline', 'stream',
    'string_decoder', 'timers', 'tls', 'tty', 'url', 'util', 'v8',
    'vm', 'worker_threads', 'zlib',
    // Popular frameworks/libraries
    'express', 'koa', 'fastify', 'hapi', 'next', 'nuxt',
    'react', 'react-dom', 'vue', 'angular', 'svelte',
    'lodash', 'underscore', 'ramda',
    'axios', 'node-fetch', 'got', 'superagent',
    'moment', 'dayjs', 'date-fns', 'luxon',
    'winston', 'morgan', 'pino', 'bunyan',
    'helmet', 'cors', 'body-parser', 'cookie-parser', 'compression',
    'passport', 'jsonwebtoken', 'bcrypt', 'bcryptjs',
    'jest', 'mocha', 'chai', 'vitest', 'sinon', 'tape',
    'typescript', 'webpack', 'vite', 'esbuild', 'rollup', 'parcel',
    'mysql', 'mysql2', 'pg', 'mongodb', 'mongoose', 'redis', 'ioredis',
    'sequelize', 'knex', 'prisma', 'typeorm', 'drizzle-orm',
    'zod', 'joi', 'yup', 'ajv',
    'dotenv', 'config', 'commander', 'yargs',
    'chalk', 'debug', 'uuid', 'nanoid',
    'socket.io', 'ws',
  ]),
  typescript: new Set([
    // Same as JavaScript - TS shares the same ecosystem
    'assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram',
    'dns', 'events', 'fs', 'http', 'http2', 'https', 'net', 'os',
    'path', 'process', 'querystring', 'readline', 'stream', 'tls',
    'url', 'util', 'worker_threads', 'zlib',
    'express', 'koa', 'fastify', 'next', 'nuxt',
    'react', 'react-dom', 'vue', 'angular', 'svelte',
    'lodash', 'axios', 'node-fetch',
    'helmet', 'cors', 'body-parser',
    'jest', 'mocha', 'vitest',
    'typescript', 'webpack', 'vite', 'esbuild',
    'mysql', 'mysql2', 'pg', 'mongodb', 'mongoose', 'redis',
    'sequelize', 'knex', 'prisma', 'typeorm',
    'zod', 'joi',
  ]),
  python: new Set([
    // Standard library
    'os', 'sys', 'json', 'math', 'datetime', 'collections', 're',
    'pathlib', 'typing', 'abc', 'io', 'subprocess', 'shutil',
    'hashlib', 'hmac', 'secrets', 'sqlite3', 'csv', 'xml',
    'urllib', 'http', 'socket', 'ssl', 'email', 'logging',
    'unittest', 'argparse', 'configparser', 'functools', 'itertools',
    'contextlib', 'dataclasses', 'enum', 'struct', 'copy', 'pprint',
    'textwrap', 'string', 'codecs', 'base64', 'binascii',
    'threading', 'multiprocessing', 'asyncio', 'concurrent',
    'pickle', 'shelve', 'marshal', 'dbm',
    'tempfile', 'glob', 'fnmatch', 'stat',
    'time', 'calendar', 'locale', 'gettext',
    'random', 'statistics',
    // Popular packages
    'pytest', 'mock', 'coverage',
    'flask', 'django', 'fastapi', 'starlette', 'uvicorn', 'gunicorn',
    'requests', 'httpx', 'aiohttp', 'urllib3',
    'sqlalchemy', 'alembic', 'psycopg2', 'pymongo',
    'celery', 'redis', 'boto3', 'botocore',
    'numpy', 'pandas', 'scipy', 'matplotlib',
    'pydantic', 'marshmallow', 'attrs',
    'click', 'typer', 'rich',
    'yaml', 'toml', 'dotenv',
  ]),
  ruby: new Set([
    'rails', 'sinatra', 'rack', 'puma', 'unicorn',
    'bundler', 'rake', 'rspec', 'minitest',
    'activerecord', 'activesupport', 'actionpack',
    'devise', 'pundit', 'cancancan',
    'json', 'yaml', 'csv', 'net/http', 'uri', 'openssl',
    'fileutils', 'pathname', 'tempfile', 'logger',
  ]),
  go: new Set([
    'fmt', 'os', 'io', 'net', 'net/http', 'encoding/json',
    'encoding/xml', 'crypto', 'crypto/tls', 'database/sql',
    'sync', 'context', 'errors', 'strings', 'strconv',
    'path', 'path/filepath', 'log', 'testing', 'time',
    'math', 'sort', 'regexp', 'reflect', 'bufio',
  ]),
};

// Patterns that identify import-only lines (no actual code execution)
const IMPORT_ONLY_PATTERNS = [
  // JS/TS require
  /^\s*(const|let|var)\s+\w+\s*=\s*require\s*\(\s*['"][^'"]+['"]\s*\)\s*;?\s*$/,
  /^\s*(const|let|var)\s+\{[^}]+\}\s*=\s*require\s*\(\s*['"][^'"]+['"]\s*\)\s*;?\s*$/,
  // JS/TS import
  /^\s*import\s+.*\s+from\s+['"][^'"]+['"]\s*;?\s*$/,
  /^\s*import\s+['"][^'"]+['"]\s*;?\s*$/,
  /^\s*import\s+\w+\s*$/,
  // Python import
  /^\s*import\s+[a-zA-Z_][\w.]*\s*(,\s*[a-zA-Z_][\w.]*)*\s*$/,
  /^\s*from\s+[a-zA-Z_][\w.]*\s+import\s+/,
  // Ruby require
  /^\s*require\s+['"][^'"]+['"]\s*$/,
  /^\s*require_relative\s+['"][^'"]+['"]\s*$/,
  // Go import (single line)
  /^\s*"[a-zA-Z_][\w/.]*"\s*$/,
];

export function isImportOnly(line) {
  let trimmed = line.trim();
  if (!trimmed) return false;
  // Strip trailing single-line comments (JS/Python/Ruby)
  trimmed = trimmed.replace(/\s*\/\/.*$/, '').replace(/\s*#(?!!).*$/, '').trim();
  if (!trimmed) return false;
  return IMPORT_ONLY_PATTERNS.some(p => p.test(trimmed));
}

export function isKnownModule(moduleName, language) {
  const modules = KNOWN_MODULES[language];
  if (!modules) return false;
  // Handle scoped packages (@org/pkg -> check full name)
  // Handle subpath imports (child_process -> child_process)
  const baseName = moduleName.split('/')[0];
  return modules.has(moduleName) || modules.has(baseName);
}

// Extract module name from a line of code
function extractModuleName(line) {
  // JS/TS: require("module") or require('module')
  const requireMatch = line.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
  if (requireMatch) return requireMatch[1];

  // JS/TS: import ... from "module"
  const importFromMatch = line.match(/from\s+['"]([^'"]+)['"]/);
  if (importFromMatch) return importFromMatch[1];

  // Python: import module or from module import ...
  const pyImportMatch = line.match(/^\s*import\s+([a-zA-Z_][\w]*)/);
  if (pyImportMatch) return pyImportMatch[1];

  const pyFromMatch = line.match(/^\s*from\s+([a-zA-Z_][\w]*)/);
  if (pyFromMatch) return pyFromMatch[1];

  return null;
}

// Variable names that indicate non-security use of weak hashing (MD5/SHA1)
const NON_SECURITY_HASH_VARS = new Set([
  'checksum', 'digest', 'etag', 'e_tag', 'hash_value', 'file_hash',
  'content_hash', 'cache_key', 'fingerprint', 'hex_digest', 'hexdigest',
]);

// Inline suppression comments
const NOSEC_PATTERN = /(?:\/\/|#|\/\*)\s*nosec\b/i;

// Test file path patterns
const TEST_FILE_PATTERNS = [
  /[/\\]tests?[/\\]/i,
  /[/\\]__tests__[/\\]/i,
  /[/\\]spec[/\\]/i,
  /[._](?:test|spec)\.[^.]+$/i,
  /[/\\]test[-_]?files?[/\\]/i,
  /[/\\]fixtures?[/\\]/i,
  /[/\\]demo[/\\]/i,
];

// Check if a file path looks like a test file
export function isTestFile(filePath) {
  return TEST_FILE_PATTERNS.some(p => p.test(filePath));
}

// Check if a line has a nosec suppression comment
export function hasNosecComment(line) {
  return NOSEC_PATTERN.test(line);
}

// Check if a variable name on a line suggests non-security hash usage
function isNonSecurityHashUsage(line) {
  const lower = line.toLowerCase();
  for (const varName of NON_SECURITY_HASH_VARS) {
    if (lower.includes(varName)) return true;
  }
  return false;
}

// Filter findings based on context awareness
export function applyContextFilter(findings, filePath, language) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;

  let lines = [];
  try {
    if (existsSync(filePath)) {
      lines = readFileSync(filePath, 'utf-8').split('\n');
    }
  } catch {
    return findings;
  }

  const inTestFile = isTestFile(filePath);

  return findings.filter(finding => {
    const line = lines[finding.line] || '';
    const ruleId = finding.ruleId?.toLowerCase() || '';

    // Inline suppression: // nosec or # nosec
    if (hasNosecComment(line)) {
      return false;
    }

    // Variable-name heuristic: MD5/SHA1 used for checksums → downgrade to info
    if ((ruleId.includes('md5') || ruleId.includes('sha1')) && isNonSecurityHashUsage(line)) {
      finding.severity = 'info';
      finding.contextNote = 'Non-security hash usage (checksum/digest/etag)';
    }

    // Test file heuristic: downgrade hardcoded secrets in test files to warning
    if (inTestFile && (ruleId.includes('hardcoded') || ruleId.includes('secret') || ruleId.includes('password') || ruleId.includes('api-key'))) {
      if (finding.severity === 'error') {
        finding.severity = 'warning';
        finding.contextNote = 'Hardcoded secret in test file';
      }
    }

    // Import-only filter
    if (!isImportOnly(line)) return true;

    // Check if the module is known/safe
    const moduleName = extractModuleName(line);
    if (moduleName && isKnownModule(moduleName, language)) {
      return false; // Suppress finding on known module import
    }

    return true;
  });
}

// Framework/middleware detection patterns
const FRAMEWORK_PATTERNS = {
  helmet: { pattern: /require\s*\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]|import\s+.*helmet/, languages: ['javascript', 'typescript'] },
  dompurify: { pattern: /require\s*\(\s*['"](?:dompurify|isomorphic-dompurify)['"]\s*\)|from\s+['"](?:dompurify|isomorphic-dompurify)['"]|import\s+.*(?:dompurify|DOMPurify)/, languages: ['javascript', 'typescript'] },
  csurf: { pattern: /require\s*\(\s*['"]csurf['"]\s*\)|from\s+['"]csurf['"]/, languages: ['javascript', 'typescript'] },
  cors: { pattern: /require\s*\(\s*['"]cors['"]\s*\)|from\s+['"]cors['"]/, languages: ['javascript', 'typescript'] },
  prisma: { pattern: /from\s+prisma|import\s+prisma|@prisma\/client/, languages: ['javascript', 'typescript', 'python'] },
  bcrypt: { pattern: /import\s+bcrypt|from\s+bcrypt|require\s*\(\s*['"]bcryptjs?['"]\s*\)/, languages: ['javascript', 'typescript', 'python'] },
};

// Maps framework -> which rule categories it mitigates -> downgraded severity
const SEVERITY_DOWNGRADE = {
  helmet: { mitigates: ['xss', 'innerhtml', 'outerhtml', 'document-write', 'cors-wildcard'], to: 'warning' },
  dompurify: { mitigates: ['xss', 'innerhtml', 'outerhtml', 'dangerouslysetinnerhtml', 'insertadjacenthtml', 'document-write'], to: 'warning' },
  csurf: { mitigates: ['csrf'], to: 'warning' },
  cors: { mitigates: ['cors-wildcard'], to: 'info' },
  prisma: { mitigates: ['sql-injection', 'nosql-injection', 'raw-query'], to: 'warning' },
  bcrypt: { mitigates: ['md5', 'sha1', 'weak-hash', 'weak-cipher'], to: 'info' },
};

export function detectFrameworks(filePath, language) {
  const detected = [];
  try {
    if (!existsSync(filePath)) return detected;
    const content = readFileSync(filePath, 'utf-8');
    for (const [name, config] of Object.entries(FRAMEWORK_PATTERNS)) {
      if (config.languages.includes(language) && config.pattern.test(content)) {
        detected.push(name);
      }
    }
  } catch {
    // Ignore read errors
  }
  return detected;
}

export function applyFrameworkAdjustments(findings, frameworks) {
  if (!Array.isArray(findings) || findings.length === 0 || frameworks.length === 0) return findings;

  return findings.map(finding => {
    const ruleId = finding.ruleId?.toLowerCase() || '';
    for (const fw of frameworks) {
      const downgrade = SEVERITY_DOWNGRADE[fw];
      if (!downgrade) continue;
      if (downgrade.mitigates.some(m => ruleId.includes(m))) {
        return { ...finding, severity: downgrade.to, frameworkMitigated: fw };
      }
    }
    return finding;
  });
}
