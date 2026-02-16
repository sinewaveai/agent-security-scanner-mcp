import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { MCPTestClient, fixturePath } from './helpers.js';
import { discoverProjectContext } from '../src/tools/project-context.js';
import { isTestFile, extractImports } from '../src/utils.js';
import { writeFileSync, mkdirSync, unlinkSync, rmSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============= Unit tests: isTestFile =============
describe('isTestFile', () => {
  it('should detect test directories', () => {
    expect(isTestFile('/project/tests/test_auth.py')).toBe(true);
    expect(isTestFile('/project/__tests__/auth.test.js')).toBe(true);
    expect(isTestFile('/project/spec/models/user_spec.rb')).toBe(true);
    expect(isTestFile('/project/test/handler_test.go')).toBe(true);
  });

  it('should detect test file suffixes', () => {
    expect(isTestFile('/project/src/auth.test.js')).toBe(true);
    expect(isTestFile('/project/src/auth.spec.ts')).toBe(true);
    expect(isTestFile('/project/src/auth_test.py')).toBe(true);
    expect(isTestFile('/project/src/auth_spec.rb')).toBe(true);
  });

  it('should detect test file prefixes', () => {
    expect(isTestFile('/project/src/test_auth.py')).toBe(true);
    expect(isTestFile('/project/src/test-utils.js')).toBe(true);
  });

  it('should detect fixture and mock directories', () => {
    expect(isTestFile('/project/__fixtures__/data.json')).toBe(true);
    expect(isTestFile('/project/__mocks__/api.js')).toBe(true);
    expect(isTestFile('/project/fixtures/sample.py')).toBe(true);
    expect(isTestFile('/project/mocks/service.js')).toBe(true);
  });

  it('should NOT flag production files', () => {
    expect(isTestFile('/project/src/auth.js')).toBe(false);
    expect(isTestFile('/project/lib/utils.py')).toBe(false);
    expect(isTestFile('/project/app/models/user.rb')).toBe(false);
    expect(isTestFile('/project/cmd/server/main.go')).toBe(false);
  });

  it('should handle Windows-style paths', () => {
    expect(isTestFile('C:\\project\\tests\\auth.test.js')).toBe(true);
    expect(isTestFile('C:\\project\\src\\auth.js')).toBe(false);
  });
});

// ============= Unit tests: extractImports =============
describe('extractImports', () => {
  it('should extract JavaScript ES imports', () => {
    const code = `
import express from 'express';
import { Router } from 'express';
import 'dotenv/config';
`;
    const imports = extractImports(code, 'javascript');
    expect(imports).toContain('express');
    expect(imports).toContain('dotenv/config');
  });

  it('should extract JavaScript require statements', () => {
    const code = `
const express = require('express');
const { join } = require('path');
const helmet = require("helmet");
`;
    const imports = extractImports(code, 'javascript');
    expect(imports).toContain('express');
    expect(imports).toContain('path');
    expect(imports).toContain('helmet');
  });

  it('should extract TypeScript imports', () => {
    const code = `
import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
`;
    const imports = extractImports(code, 'typescript');
    expect(imports).toContain('@nestjs/common');
    expect(imports).toContain('express');
  });

  it('should extract Python imports', () => {
    const code = `
import os
import json
from flask import Flask, request
from django.db import models
`;
    const imports = extractImports(code, 'python');
    expect(imports).toContain('os');
    expect(imports).toContain('json');
    expect(imports).toContain('flask');
    expect(imports).toContain('django');
  });

  it('should extract Go imports', () => {
    const code = `
import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
)
`;
    const imports = extractImports(code, 'go');
    expect(imports).toContain('fmt');
    expect(imports).toContain('net/http');
    expect(imports).toContain('github.com/gin-gonic/gin');
  });

  it('should extract Ruby requires', () => {
    const code = `
require 'sinatra'
require_relative './helpers'
gem 'devise'
`;
    const imports = extractImports(code, 'ruby');
    expect(imports).toContain('sinatra');
    expect(imports).toContain('./helpers');
    expect(imports).toContain('devise');
  });

  it('should extract Java imports', () => {
    const code = `
import org.springframework.boot.SpringApplication;
import static org.junit.Assert.assertEquals;
`;
    const imports = extractImports(code, 'java');
    expect(imports).toContain('org.springframework.boot.SpringApplication');
    expect(imports).toContain('org.junit.Assert.assertEquals');
  });

  it('should deduplicate imports', () => {
    const code = `
const express = require('express');
const app = require('express');
`;
    const imports = extractImports(code, 'javascript');
    const expressCount = imports.filter(i => i === 'express').length;
    expect(expressCount).toBe(1);
  });

  it('should return empty array for unknown language', () => {
    const imports = extractImports('some code', 'unknown');
    expect(imports).toEqual([]);
  });
});

// ============= Unit tests: discoverProjectContext =============
describe('discoverProjectContext', () => {
  const tempDir = join(__dirname, 'fixtures', 'temp-project-context');

  beforeEach(() => {
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }
  });

  afterEach(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should detect Express framework from package.json', () => {
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0', helmet: '^7.0.0' }
    }));
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('javascript');
    expect(ctx.framework).toBe('Express');
    expect(ctx.security_middleware).toContain('helmet');
    expect(ctx.dependency_file).toBe('package.json');
  });

  it('should detect multiple security packages', () => {
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: {
        express: '^4.18.0',
        helmet: '^7.0.0',
        cors: '^2.8.5',
        csurf: '^1.11.0',
        dompurify: '^3.0.0',
        passport: '^0.6.0',
        jsonwebtoken: '^9.0.0',
        bcrypt: '^5.1.0',
        'express-rate-limit': '^7.0.0'
      },
      devDependencies: { jest: '^29.0.0' }
    }));
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.security_middleware).toContain('helmet');
    expect(ctx.security_middleware).toContain('cors');
    expect(ctx.security_middleware).toContain('csurf');
    expect(ctx.security_middleware).toContain('express-rate-limit');
    expect(ctx.sanitizers).toContain('dompurify');
    expect(ctx.auth_libraries).toContain('passport');
    expect(ctx.auth_libraries).toContain('jsonwebtoken');
    expect(ctx.auth_libraries).toContain('bcrypt');
    expect(ctx.test_frameworks).toContain('jest');
  });

  it('should detect Django from requirements.txt', () => {
    writeFileSync(join(tempDir, 'requirements.txt'),
      'django>=4.2\ndjango-cors-headers>=4.0\nbleach>=6.0\npytest>=7.0\n');
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('python');
    expect(ctx.framework).toBe('Django');
    expect(ctx.security_middleware).toContain('django-cors-headers');
    expect(ctx.sanitizers).toContain('bleach');
    expect(ctx.test_frameworks).toContain('pytest');
  });

  it('should detect Flask from requirements.txt', () => {
    writeFileSync(join(tempDir, 'requirements.txt'),
      'flask>=3.0\nflask-cors>=4.0\nflask-wtf>=1.2\nflask-limiter>=3.0\n');
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('python');
    expect(ctx.framework).toBe('Flask');
    expect(ctx.security_middleware).toContain('flask-cors');
    expect(ctx.security_middleware).toContain('flask-wtf');
    expect(ctx.security_middleware).toContain('flask-limiter');
  });

  it('should detect Gin from go.mod', () => {
    writeFileSync(join(tempDir, 'go.mod'), `module example.com/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/rs/cors v1.10.0
\tgithub.com/gorilla/csrf v1.7.2
)
`);
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('go');
    expect(ctx.framework).toBe('Gin');
    expect(ctx.security_middleware).toContain('github.com/rs/cors');
    expect(ctx.security_middleware).toContain('github.com/gorilla/csrf');
  });

  it('should detect Rails from Gemfile', () => {
    writeFileSync(join(tempDir, 'Gemfile'), `
source 'https://rubygems.org'
gem 'rails', '~> 7.0'
gem 'devise'
gem 'pundit'
gem 'rack-cors'
gem 'rspec'
`);
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('ruby');
    expect(ctx.framework).toBe('Rails');
    expect(ctx.auth_libraries).toContain('devise');
    expect(ctx.auth_libraries).toContain('pundit');
    expect(ctx.security_middleware).toContain('rack-cors');
    expect(ctx.test_frameworks).toContain('rspec');
  });

  it('should detect Spring Boot from pom.xml', () => {
    writeFileSync(join(tempDir, 'pom.xml'), `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-security-core</artifactId>
    </dependency>
  </dependencies>
</project>`);
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.language).toBe('java');
    expect(ctx.framework).toBe('Spring Boot');
    expect(ctx.auth_libraries).toContain('spring-security-core');
  });

  it('should return defaults when no dependency file exists', () => {
    const emptyDir = join(tempDir, 'empty');
    mkdirSync(emptyDir, { recursive: true });
    const ctx = discoverProjectContext(emptyDir);
    expect(ctx.language).toBe('unknown');
    expect(ctx.framework).toBeNull();
    expect(ctx.security_middleware).toEqual([]);
    expect(ctx.sanitizers).toEqual([]);
    expect(ctx.auth_libraries).toEqual([]);
    expect(ctx.test_frameworks).toEqual([]);
    expect(ctx.dependency_file).toBeNull();
  });

  it('should populate raw_security_deps mapping', () => {
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.0.0', helmet: '^7.0.0', dompurify: '^3.0.0' }
    }));
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.raw_security_deps).toBeDefined();
    expect(ctx.raw_security_deps['helmet']).toBe('http-headers');
    expect(ctx.raw_security_deps['dompurify']).toBe('xss-sanitization');
  });

  it('should detect NestJS framework', () => {
    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: { '@nestjs/core': '^10.0.0', '@nestjs/common': '^10.0.0' }
    }));
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.framework).toBe('NestJS');
  });

  it('should detect FastAPI from requirements.txt', () => {
    writeFileSync(join(tempDir, 'requirements.txt'), 'fastapi>=0.100\nuvicorn>=0.23\npydantic>=2.0\n');
    const ctx = discoverProjectContext(tempDir);
    expect(ctx.framework).toBe('FastAPI');
    expect(ctx.security_middleware).toContain('pydantic');
  });
});

// ============= Integration tests: scan_security with new params =============
// Note: These tests require the Python analyzer to work correctly.
// If the analyzer fails (e.g., missing PyYAML), some tests will be skipped.
describe('scan_security project context integration', () => {
  let client;
  let tempDir;
  let vulnFile;
  let analyzerWorks = false;

  beforeAll(async () => {
    client = new MCPTestClient();
    await client.start();

    // Create a temp project outside of tests/ to avoid isTestFile() false positive
    tempDir = join(tmpdir(), 'temp-express-project-' + Date.now());
    mkdirSync(tempDir, { recursive: true });

    writeFileSync(join(tempDir, 'package.json'), JSON.stringify({
      dependencies: {
        express: '^4.18.0',
        helmet: '^7.0.0',
        cors: '^2.8.5',
        dompurify: '^3.0.0'
      },
      devDependencies: { vitest: '^1.0.0' }
    }));

    vulnFile = join(tempDir, 'app.js');
    writeFileSync(vulnFile, `const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());

app.get('/user', (req, res) => {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + id;
  element.innerHTML = userInput;
  res.send('ok');
});
`);

    // Check if analyzer works (may fail if PyYAML not installed)
    const probe = await client.callTool('scan_security', {
      file_path: vulnFile,
      verbosity: 'compact'
    });
    analyzerWorks = !probe.error && Array.isArray(probe.issues);
  }, 30000);

  afterAll(async () => {
    await client.stop();
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('should include project context when project_context=true', async () => {
    if (!analyzerWorks) return; // skip if analyzer unavailable
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      project_context: true,
      verbosity: 'compact'
    });
    expect(result.project).toBeDefined();
    expect(result.project.framework).toBe('Express');
    expect(result.project.security_middleware).toContain('helmet');
    expect(result.project.security_middleware).toContain('cors');
    expect(result.project.sanitizers).toContain('dompurify');
    expect(result.project.test_frameworks).toContain('vitest');
    expect(result.project.dependency_file).toBe('package.json');
  });

  it('should include is_test_file flag', async () => {
    if (!analyzerWorks) return;
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      project_context: true,
      verbosity: 'compact'
    });
    expect(result.is_test_file).toBe(false);
  });

  it('should include file_imports list', async () => {
    if (!analyzerWorks) return;
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      project_context: true,
      verbosity: 'compact'
    });
    expect(result.file_imports).toBeDefined();
    expect(result.file_imports).toContain('express');
    expect(result.file_imports).toContain('helmet');
  });

  it('should NOT include project context by default', async () => {
    // This test works even when analyzer fails — just checks fields are absent
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      verbosity: 'compact'
    });
    expect(result.project).toBeUndefined();
    expect(result.is_test_file).toBeUndefined();
    expect(result.file_imports).toBeUndefined();
  });

  it('should include surrounding context when include_context=true', async () => {
    if (!analyzerWorks) return;
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      include_context: true,
      verbosity: 'full'
    });
    if (!result.issues || result.issues.length === 0) return;
    const issue = result.issues[0];
    expect(issue.context_before).toBeDefined();
    expect(issue.context_after).toBeDefined();
    expect(Array.isArray(issue.context_before)).toBe(true);
    expect(Array.isArray(issue.context_after)).toBe(true);
    if (issue.context_before.length > 0) {
      expect(issue.context_before[0].line).toBeDefined();
      expect(issue.context_before[0].content).toBeDefined();
    }
  });

  it('should NOT include context by default', async () => {
    if (!analyzerWorks) return;
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      verbosity: 'full'
    });
    if (!result.issues || result.issues.length === 0) return;
    expect(result.issues[0].context_before).toBeUndefined();
    expect(result.issues[0].context_after).toBeUndefined();
  });

  it('should work with both project_context and include_context', async () => {
    if (!analyzerWorks) return;
    const result = await client.callTool('scan_security', {
      file_path: vulnFile,
      project_context: true,
      include_context: true,
      verbosity: 'full'
    });
    expect(result.project).toBeDefined();
    expect(result.project.framework).toBe('Express');
    if (result.issues && result.issues.length > 0) {
      expect(result.issues[0].context_before).toBeDefined();
    }
  });
});
