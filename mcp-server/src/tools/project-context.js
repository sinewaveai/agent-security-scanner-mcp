// src/tools/project-context.js
// Project security profile discovery — detects frameworks, middleware, and security libraries

import { existsSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import { createHash } from 'crypto';

// Cache: projectRoot -> { contentHash, result }
const projectContextCache = new Map();

/**
 * Clear the project context cache (for testing).
 */
export function clearProjectContextCache() {
  projectContextCache.clear();
}

// Framework detection: package name → { name, ecosystem }
const FRAMEWORK_MAP = {
  // Node.js
  'express': { name: 'Express', ecosystem: 'node' },
  'koa': { name: 'Koa', ecosystem: 'node' },
  'fastify': { name: 'Fastify', ecosystem: 'node' },
  '@hapi/hapi': { name: 'Hapi', ecosystem: 'node' },
  'hapi': { name: 'Hapi', ecosystem: 'node' },
  '@nestjs/core': { name: 'NestJS', ecosystem: 'node' },
  'next': { name: 'Next.js', ecosystem: 'node' },
  'nuxt': { name: 'Nuxt', ecosystem: 'node' },
  // Python
  'django': { name: 'Django', ecosystem: 'python' },
  'flask': { name: 'Flask', ecosystem: 'python' },
  'fastapi': { name: 'FastAPI', ecosystem: 'python' },
  'tornado': { name: 'Tornado', ecosystem: 'python' },
  'sanic': { name: 'Sanic', ecosystem: 'python' },
  'starlette': { name: 'Starlette', ecosystem: 'python' },
  // Ruby
  'rails': { name: 'Rails', ecosystem: 'ruby' },
  'sinatra': { name: 'Sinatra', ecosystem: 'ruby' },
  // Go (module paths)
  'github.com/gin-gonic/gin': { name: 'Gin', ecosystem: 'go' },
  'github.com/labstack/echo': { name: 'Echo', ecosystem: 'go' },
  'github.com/gofiber/fiber': { name: 'Fiber', ecosystem: 'go' },
  // Java
  'spring-boot-starter-web': { name: 'Spring Boot', ecosystem: 'java' },
  'spring-boot-starter-security': { name: 'Spring Security', ecosystem: 'java' },
};

// Security middleware/library detection: package name → capability category
const SECURITY_MAP = {
  // Node.js security middleware
  'helmet': 'http-headers',
  'cors': 'cors',
  'csurf': 'csrf',
  'express-rate-limit': 'rate-limiting',
  'rate-limiter-flexible': 'rate-limiting',
  'dompurify': 'xss-sanitization',
  'isomorphic-dompurify': 'xss-sanitization',
  'xss': 'xss-sanitization',
  'sanitize-html': 'xss-sanitization',
  'express-validator': 'input-validation',
  'joi': 'input-validation',
  'zod': 'input-validation',
  'yup': 'input-validation',
  'hpp': 'http-parameter-pollution',
  'express-mongo-sanitize': 'nosql-injection',
  'sqlstring': 'sql-sanitization',
  // Node.js auth
  'passport': 'authentication',
  'jsonwebtoken': 'jwt-auth',
  'express-jwt': 'jwt-auth',
  'bcrypt': 'password-hashing',
  'bcryptjs': 'password-hashing',
  'argon2': 'password-hashing',
  'oauth2-server': 'oauth',
  // Python security
  'django-cors-headers': 'cors',
  'flask-cors': 'cors',
  'flask-wtf': 'csrf',
  'flask-limiter': 'rate-limiting',
  'bleach': 'xss-sanitization',
  'python-jose': 'jwt-auth',
  'pyjwt': 'jwt-auth',
  'passlib': 'password-hashing',
  'django-ratelimit': 'rate-limiting',
  'django-csp': 'csp',
  'django-axes': 'brute-force-protection',
  'cerberus': 'input-validation',
  'marshmallow': 'input-validation',
  'pydantic': 'input-validation',
  // Ruby security
  'rack-cors': 'cors',
  'devise': 'authentication',
  'pundit': 'authorization',
  'brakeman': 'sast',
  'rack-attack': 'rate-limiting',
  'secure_headers': 'http-headers',
  // Go security
  'github.com/gorilla/csrf': 'csrf',
  'golang.org/x/crypto': 'crypto',
  'github.com/rs/cors': 'cors',
  'github.com/ulule/limiter': 'rate-limiting',
  'github.com/golang-jwt/jwt': 'jwt-auth',
  // Java security
  'spring-security-core': 'authentication',
  'spring-security-web': 'csrf',
  'spring-security-oauth2': 'oauth',
  'owasp-java-html-sanitizer': 'xss-sanitization',
};

// Test framework detection
const TEST_FRAMEWORK_MAP = {
  'jest': 'jest', 'vitest': 'vitest', 'mocha': 'mocha', 'chai': 'chai',
  'jasmine': 'jasmine', 'ava': 'ava', 'tap': 'tap',
  'pytest': 'pytest', 'unittest': 'unittest', 'nose2': 'nose2',
  'rspec': 'rspec', 'minitest': 'minitest',
  'testing': 'go-testing',
  'junit': 'junit', 'testng': 'testng',
};

// Dependency file parsers

function parsePackageJson(projectRoot) {
  const filePath = join(projectRoot, 'package.json');
  if (!existsSync(filePath)) return null;
  try {
    const pkg = JSON.parse(readFileSync(filePath, 'utf-8'));
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };
    return { language: 'javascript', deps: Object.keys(allDeps), file: 'package.json' };
  } catch {
    return null;
  }
}

function parseRequirementsTxt(projectRoot) {
  const filePath = join(projectRoot, 'requirements.txt');
  if (!existsSync(filePath)) return null;
  try {
    const content = readFileSync(filePath, 'utf-8');
    const deps = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#') && !line.startsWith('-'))
      .map(line => line.split(/[>=<!~\[;]/)[0].trim().toLowerCase());
    return { language: 'python', deps, file: 'requirements.txt' };
  } catch {
    return null;
  }
}

function parsePyprojectToml(projectRoot) {
  const filePath = join(projectRoot, 'pyproject.toml');
  if (!existsSync(filePath)) return null;
  try {
    const content = readFileSync(filePath, 'utf-8');
    // Simple extraction of dependencies from pyproject.toml
    const deps = [];
    const depRegex = /["']([a-zA-Z0-9_-]+)(?:[>=<!~\[].*)?["']/g;
    const inDeps = content.match(/dependencies\s*=\s*\[([^\]]*)\]/s);
    if (inDeps) {
      let match;
      while ((match = depRegex.exec(inDeps[1])) !== null) {
        deps.push(match[1].toLowerCase());
      }
    }
    return deps.length > 0 ? { language: 'python', deps, file: 'pyproject.toml' } : null;
  } catch {
    return null;
  }
}

function parseGoMod(projectRoot) {
  const filePath = join(projectRoot, 'go.mod');
  if (!existsSync(filePath)) return null;
  try {
    const content = readFileSync(filePath, 'utf-8');
    const deps = [];
    const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
    if (requireBlock) {
      const lines = requireBlock[1].split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('//')) {
          const parts = trimmed.split(/\s+/);
          if (parts[0]) deps.push(parts[0]);
        }
      }
    }
    // Also match single-line requires
    const singleRequires = content.matchAll(/require\s+(\S+)\s+/g);
    for (const match of singleRequires) {
      deps.push(match[1]);
    }
    return deps.length > 0 ? { language: 'go', deps, file: 'go.mod' } : null;
  } catch {
    return null;
  }
}

function parseGemfile(projectRoot) {
  const filePath = join(projectRoot, 'Gemfile');
  if (!existsSync(filePath)) return null;
  try {
    const content = readFileSync(filePath, 'utf-8');
    const deps = [];
    const gemRegex = /gem\s+['"]([a-zA-Z0-9_-]+)['"]/g;
    let match;
    while ((match = gemRegex.exec(content)) !== null) {
      deps.push(match[1].toLowerCase());
    }
    return deps.length > 0 ? { language: 'ruby', deps, file: 'Gemfile' } : null;
  } catch {
    return null;
  }
}

function parsePomXml(projectRoot) {
  const filePath = join(projectRoot, 'pom.xml');
  if (!existsSync(filePath)) return null;
  try {
    const content = readFileSync(filePath, 'utf-8');
    const deps = [];
    const artifactRegex = /<artifactId>([^<]+)<\/artifactId>/g;
    let match;
    while ((match = artifactRegex.exec(content)) !== null) {
      deps.push(match[1].toLowerCase());
    }
    return deps.length > 0 ? { language: 'java', deps, file: 'pom.xml' } : null;
  } catch {
    return null;
  }
}

// Dependency files to check for cache hashing
const DEP_FILES = ['package.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Gemfile', 'pom.xml'];

/**
 * Hash the contents of dependency files in a project root for cache invalidation.
 */
function hashDependencyFiles(projectRoot) {
  const hash = createHash('sha256');
  let hasContent = false;
  for (const depFile of DEP_FILES) {
    const filePath = join(projectRoot, depFile);
    if (existsSync(filePath)) {
      try {
        hash.update(depFile + ':' + readFileSync(filePath, 'utf-8'));
        hasContent = true;
      } catch {
        // ignore unreadable files
      }
    }
  }
  return hasContent ? hash.digest('hex').slice(0, 16) : null;
}

/**
 * Discover project security context from dependency files (with caching).
 * Results are cached by projectRoot and invalidated when dependency file contents change.
 * @param {string} projectRoot - Path to project root directory
 * @returns {{ language: string, framework: string|null, security_middleware: string[], sanitizers: string[], auth_libraries: string[], test_frameworks: string[], dependency_file: string|null, raw_security_deps: Record<string, string> }}
 */
export function discoverProjectContext(projectRoot) {
  const contentHash = hashDependencyFiles(projectRoot);
  const cached = projectContextCache.get(projectRoot);
  if (cached && cached.contentHash === contentHash) {
    return cached.result;
  }

  const result = _discoverProjectContextUncached(projectRoot);
  projectContextCache.set(projectRoot, { contentHash, result });
  return result;
}

/**
 * Internal: discover project security context without caching.
 */
function _discoverProjectContextUncached(projectRoot) {
  const parsers = [
    parsePackageJson,
    parseRequirementsTxt,
    parsePyprojectToml,
    parseGoMod,
    parseGemfile,
    parsePomXml,
  ];

  let parsed = null;
  for (const parser of parsers) {
    parsed = parser(projectRoot);
    if (parsed) break;
  }

  if (!parsed) {
    return {
      language: 'unknown',
      framework: null,
      security_middleware: [],
      sanitizers: [],
      auth_libraries: [],
      test_frameworks: [],
      dependency_file: null,
      raw_security_deps: {},
    };
  }

  const { language, deps, file } = parsed;

  // Detect framework
  let framework = null;
  for (const dep of deps) {
    const depLower = dep.toLowerCase();
    if (FRAMEWORK_MAP[depLower]) {
      framework = FRAMEWORK_MAP[depLower].name;
      break;
    }
    // Partial match for Java spring artifacts
    if (depLower.includes('spring-boot-starter-web')) {
      framework = 'Spring Boot';
      break;
    }
  }

  // Detect security packages by category
  const securityMiddleware = [];
  const sanitizers = [];
  const authLibraries = [];
  const testFrameworks = [];
  const rawSecurityDeps = {};

  for (const dep of deps) {
    const depLower = dep.toLowerCase();

    // Security middleware
    const capability = SECURITY_MAP[depLower] || SECURITY_MAP[dep];
    if (capability) {
      rawSecurityDeps[dep] = capability;

      if (['xss-sanitization', 'sql-sanitization', 'nosql-injection'].includes(capability)) {
        sanitizers.push(dep);
      } else if (['authentication', 'jwt-auth', 'password-hashing', 'oauth', 'authorization'].includes(capability)) {
        authLibraries.push(dep);
      } else {
        securityMiddleware.push(dep);
      }
    }

    // Test frameworks
    if (TEST_FRAMEWORK_MAP[depLower]) {
      testFrameworks.push(TEST_FRAMEWORK_MAP[depLower]);
    }
  }

  return {
    language,
    framework,
    security_middleware: securityMiddleware,
    sanitizers,
    auth_libraries: authLibraries,
    test_frameworks: testFrameworks,
    dependency_file: file,
    raw_security_deps: rawSecurityDeps,
  };
}
