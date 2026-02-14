import { describe, it, expect } from 'vitest';
import { writeFileSync, unlinkSync, mkdirSync } from 'fs';
import { isImportOnly, isKnownModule, applyContextFilter, detectFrameworks, applyFrameworkAdjustments, isTestFile, hasNosecComment } from '../src/context.js';
import { fixturePath } from './helpers.js';

describe('isImportOnly', () => {
  it('should detect JS require statements', () => {
    expect(isImportOnly("const express = require('express');")).toBe(true);
    expect(isImportOnly("const { exec } = require('child_process');")).toBe(true);
    expect(isImportOnly('var fs = require("fs")')).toBe(true);
  });

  it('should detect JS import statements', () => {
    expect(isImportOnly("import express from 'express';")).toBe(true);
    expect(isImportOnly("import { readFile } from 'fs';")).toBe(true);
    expect(isImportOnly("import 'dotenv/config';")).toBe(true);
  });

  it('should detect Python import statements', () => {
    expect(isImportOnly('import os')).toBe(true);
    expect(isImportOnly('import os, sys')).toBe(true);
    expect(isImportOnly('from os import path')).toBe(true);
    expect(isImportOnly('from flask import Flask')).toBe(true);
  });

  it('should detect Ruby require statements', () => {
    expect(isImportOnly("require 'json'")).toBe(true);
    expect(isImportOnly("require_relative 'helpers'")).toBe(true);
  });

  it('should NOT match actual code lines', () => {
    expect(isImportOnly('exec("ls " + cmd)')).toBe(false);
    expect(isImportOnly('element.innerHTML = data')).toBe(false);
    expect(isImportOnly('subprocess.run(cmd, shell=True)')).toBe(false);
    expect(isImportOnly('const result = exec("ls")')).toBe(false);
  });

  it('should NOT match empty lines', () => {
    expect(isImportOnly('')).toBe(false);
    expect(isImportOnly('   ')).toBe(false);
  });
});

describe('isKnownModule', () => {
  it('should recognize JS builtins', () => {
    expect(isKnownModule('fs', 'javascript')).toBe(true);
    expect(isKnownModule('path', 'javascript')).toBe(true);
    expect(isKnownModule('child_process', 'javascript')).toBe(true);
    expect(isKnownModule('crypto', 'javascript')).toBe(true);
  });

  it('should recognize popular JS libraries', () => {
    expect(isKnownModule('express', 'javascript')).toBe(true);
    expect(isKnownModule('lodash', 'javascript')).toBe(true);
    expect(isKnownModule('helmet', 'javascript')).toBe(true);
    expect(isKnownModule('axios', 'javascript')).toBe(true);
  });

  it('should recognize Python standard library', () => {
    expect(isKnownModule('os', 'python')).toBe(true);
    expect(isKnownModule('sys', 'python')).toBe(true);
    expect(isKnownModule('subprocess', 'python')).toBe(true);
    expect(isKnownModule('json', 'python')).toBe(true);
  });

  it('should recognize popular Python packages', () => {
    expect(isKnownModule('flask', 'python')).toBe(true);
    expect(isKnownModule('django', 'python')).toBe(true);
    expect(isKnownModule('requests', 'python')).toBe(true);
  });

  it('should return false for unknown modules', () => {
    expect(isKnownModule('my-custom-module', 'javascript')).toBe(false);
    expect(isKnownModule('totally-unknown', 'python')).toBe(false);
  });

  it('should return false for unknown languages', () => {
    expect(isKnownModule('os', 'haskell')).toBe(false);
  });

  it('should handle subpath imports', () => {
    expect(isKnownModule('fs/promises', 'javascript')).toBe(true);
    expect(isKnownModule('path/posix', 'javascript')).toBe(true);
  });
});

describe('applyContextFilter', () => {
  it('should filter out findings on known module import lines', () => {
    // Line 4 (0-indexed) is: const express = require('express');
    const findings = [
      { ruleId: 'detect-non-literal-require', line: 4, severity: 'warning' },
      { ruleId: 'eval-detected', line: 13, severity: 'error' },
    ];
    const filePath = fixturePath('vuln-javascript-context.js');
    const result = applyContextFilter(findings, filePath, 'javascript');
    // The import-only finding on a known module should be filtered out
    expect(result.some(f => f.ruleId === 'detect-non-literal-require')).toBe(false);
    // The non-import finding should remain
    expect(result.some(f => f.ruleId === 'eval-detected')).toBe(true);
  });

  it('should NOT filter findings on usage lines', () => {
    // Line 11 (0-indexed) is: cp.exec("ls " + userInput);
    const findings = [
      { ruleId: 'child-process-exec', line: 11, severity: 'error' },
    ];
    const filePath = fixturePath('vuln-javascript-context.js');
    const result = applyContextFilter(findings, filePath, 'javascript');
    expect(result).toHaveLength(1);
  });

  it('should handle empty findings', () => {
    const result = applyContextFilter([], '/tmp/test.js', 'javascript');
    expect(result).toEqual([]);
  });

  it('should handle non-existent files', () => {
    const findings = [{ ruleId: 'test', line: 0, severity: 'warning' }];
    const result = applyContextFilter(findings, '/tmp/nonexistent-12345.js', 'javascript');
    expect(result).toHaveLength(1);
  });
});

describe('detectFrameworks', () => {
  it('should detect helmet in JS files', () => {
    const filePath = fixturePath('vuln-javascript-framework.js');
    const frameworks = detectFrameworks(filePath, 'javascript');
    expect(frameworks).toContain('helmet');
    expect(frameworks).toContain('cors');
  });

  it('should not detect frameworks in wrong language', () => {
    const filePath = fixturePath('vuln-javascript-framework.js');
    const frameworks = detectFrameworks(filePath, 'python');
    expect(frameworks).not.toContain('helmet');
  });

  it('should return empty array for non-existent file', () => {
    const frameworks = detectFrameworks('/tmp/nonexistent-99999.js', 'javascript');
    expect(frameworks).toEqual([]);
  });
});

describe('applyFrameworkAdjustments', () => {
  it('should downgrade XSS severity when helmet is present', () => {
    const findings = [
      { ruleId: 'javascript.security.innerhtml', severity: 'error' },
      { ruleId: 'javascript.security.sql-injection', severity: 'error' },
    ];
    const adjusted = applyFrameworkAdjustments(findings, ['helmet']);
    const xss = adjusted.find(f => f.ruleId.includes('innerhtml'));
    const sql = adjusted.find(f => f.ruleId.includes('sql-injection'));
    expect(xss.severity).toBe('warning');
    expect(xss.frameworkMitigated).toBe('helmet');
    expect(sql.severity).toBe('error'); // not mitigated by helmet
  });

  it('should downgrade cors severity when cors middleware is present', () => {
    const findings = [
      { ruleId: 'cors-wildcard', severity: 'error' },
    ];
    const adjusted = applyFrameworkAdjustments(findings, ['cors']);
    expect(adjusted[0].severity).toBe('info');
  });

  it('should handle empty findings', () => {
    const result = applyFrameworkAdjustments([], ['helmet']);
    expect(result).toEqual([]);
  });

  it('should handle no frameworks', () => {
    const findings = [{ ruleId: 'xss', severity: 'error' }];
    const result = applyFrameworkAdjustments(findings, []);
    expect(result).toEqual(findings);
  });
});

describe('hasNosecComment', () => {
  it('should detect // nosec in JS/TS', () => {
    expect(hasNosecComment('eval(code) // nosec')).toBe(true);
    expect(hasNosecComment('eval(code) // NOSEC')).toBe(true);
    expect(hasNosecComment('eval(code) //nosec')).toBe(true);
  });

  it('should detect # nosec in Python/Ruby', () => {
    expect(hasNosecComment('hashlib.md5(data) # nosec')).toBe(true);
    expect(hasNosecComment('hashlib.md5(data) # NOSEC')).toBe(true);
  });

  it('should detect /* nosec */ in block comments', () => {
    expect(hasNosecComment('eval(code) /* nosec */')).toBe(true);
  });

  it('should NOT match lines without nosec', () => {
    expect(hasNosecComment('eval(code)')).toBe(false);
    expect(hasNosecComment('// this is a normal comment')).toBe(false);
    expect(hasNosecComment('const nosecurity = true')).toBe(false);
  });
});

describe('isTestFile', () => {
  it('should detect test directories', () => {
    expect(isTestFile('/project/tests/test_login.py')).toBe(true);
    expect(isTestFile('/project/test/app.test.js')).toBe(true);
    expect(isTestFile('/project/__tests__/utils.js')).toBe(true);
    expect(isTestFile('/project/spec/helper_spec.rb')).toBe(true);
  });

  it('should detect test file naming patterns', () => {
    expect(isTestFile('app.test.js')).toBe(true);
    expect(isTestFile('app.spec.ts')).toBe(true);
    expect(isTestFile('app_test.py')).toBe(true);
  });

  it('should detect fixture/demo directories', () => {
    expect(isTestFile('/project/fixtures/sample.js')).toBe(true);
    expect(isTestFile('/project/demo/vuln.py')).toBe(true);
    expect(isTestFile('/project/test-files/data.js')).toBe(true);
  });

  it('should NOT match production code', () => {
    expect(isTestFile('/project/src/app.js')).toBe(false);
    expect(isTestFile('/project/lib/utils.py')).toBe(false);
    expect(isTestFile('index.js')).toBe(false);
  });
});

describe('applyContextFilter — FP reduction', () => {
  it('should downgrade MD5 to info when variable name indicates checksum', () => {
    const findings = [
      { ruleId: 'python.security.insecure-hash-md5', line: 0, severity: 'warning' },
    ];
    const tmpPath = '/tmp/test-checksum-context.py';
    writeFileSync(tmpPath, 'checksum = hashlib.md5(file_bytes).hexdigest()\n');
    try {
      const result = applyContextFilter(findings, tmpPath, 'python');
      expect(result).toHaveLength(1);
      expect(result[0].severity).toBe('info');
      expect(result[0].contextNote).toContain('checksum');
    } finally {
      unlinkSync(tmpPath);
    }
  });

  it('should suppress findings with nosec comment', () => {
    const findings = [
      { ruleId: 'python.security.insecure-hash-md5', line: 0, severity: 'warning' },
    ];
    const tmpPath = '/tmp/test-nosec-context.py';
    writeFileSync(tmpPath, 'hashlib.md5(data) # nosec\n');
    try {
      const result = applyContextFilter(findings, tmpPath, 'python');
      expect(result).toHaveLength(0);
    } finally {
      unlinkSync(tmpPath);
    }
  });

  it('should downgrade hardcoded secrets in test files to warning', () => {
    const findings = [
      { ruleId: 'generic.secrets.hardcoded-password', line: 0, severity: 'error' },
    ];
    const tmpPath = '/tmp/tests/test-secrets-context.py';
    mkdirSync('/tmp/tests', { recursive: true });
    writeFileSync(tmpPath, 'password = "test123"\n');
    try {
      const result = applyContextFilter(findings, tmpPath, 'python');
      expect(result).toHaveLength(1);
      expect(result[0].severity).toBe('warning');
      expect(result[0].contextNote).toContain('test file');
    } finally {
      unlinkSync(tmpPath);
    }
  });
});
