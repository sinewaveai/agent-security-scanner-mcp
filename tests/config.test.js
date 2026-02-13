import { describe, it, expect } from 'vitest';
import {
  loadConfig,
  shouldExcludeFile,
  shouldSuppressRule,
  meetsSeverityThreshold,
  meetsConfidenceThreshold,
  applyConfig,
  matchGlob,
} from '../src/config.js';

describe('matchGlob', () => {
  it('should match simple wildcards', () => {
    expect(matchGlob('test.js', '*.js')).toBe(true);
    expect(matchGlob('test.py', '*.js')).toBe(false);
  });

  it('should match double-star globs', () => {
    expect(matchGlob('node_modules/foo/bar.js', 'node_modules/**')).toBe(true);
    expect(matchGlob('dist/bundle.js', 'dist/**')).toBe(true);
    expect(matchGlob('src/app.js', 'dist/**')).toBe(false);
  });

  it('should match minified files', () => {
    expect(matchGlob('jquery.min.js', '**/*.min.js')).toBe(true);
    expect(matchGlob('vendor/lib.min.js', '**/*.min.js')).toBe(true);
    expect(matchGlob('app.js', '**/*.min.js')).toBe(false);
  });

  it('should match rule ID globs', () => {
    expect(matchGlob('weak-hash-md5', 'weak-hash-*')).toBe(true);
    expect(matchGlob('weak-hash-sha1', 'weak-hash-*')).toBe(true);
    expect(matchGlob('sql-injection', 'weak-hash-*')).toBe(false);
  });
});

describe('loadConfig', () => {
  it('should return default config when no config file exists', () => {
    const config = loadConfig('/tmp/no-config-here-12345/test.js');
    expect(config.version).toBe(1);
    expect(config.suppress).toEqual([]);
    expect(config.exclude).toContain('node_modules/**');
    expect(config.severity_threshold).toBe('info');
    expect(config.confidence_threshold).toBe('LOW');
  });
});

describe('shouldExcludeFile', () => {
  const config = {
    exclude: ['node_modules/**', 'dist/**', '**/*.min.js'],
  };

  it('should exclude node_modules files', () => {
    expect(shouldExcludeFile('node_modules/express/index.js', config)).toBe(true);
  });

  it('should exclude dist files', () => {
    expect(shouldExcludeFile('dist/bundle.js', config)).toBe(true);
  });

  it('should exclude minified files', () => {
    expect(shouldExcludeFile('vendor/jquery.min.js', config)).toBe(true);
  });

  it('should NOT exclude regular source files', () => {
    expect(shouldExcludeFile('src/app.js', config)).toBe(false);
    expect(shouldExcludeFile('lib/utils.py', config)).toBe(false);
  });

  it('should handle empty exclude list', () => {
    expect(shouldExcludeFile('anything.js', { exclude: [] })).toBe(false);
  });
});

describe('shouldSuppressRule', () => {
  it('should suppress by exact rule name', () => {
    const config = { suppress: [{ rule: 'insecure-random' }] };
    expect(shouldSuppressRule('insecure-random', 'test.js', config)).toBe(true);
    expect(shouldSuppressRule('sql-injection', 'test.js', config)).toBe(false);
  });

  it('should suppress by glob pattern', () => {
    const config = { suppress: [{ rule: 'weak-hash-*' }] };
    expect(shouldSuppressRule('weak-hash-md5', 'test.js', config)).toBe(true);
    expect(shouldSuppressRule('weak-hash-sha1', 'test.js', config)).toBe(true);
    expect(shouldSuppressRule('sql-injection', 'test.js', config)).toBe(false);
  });

  it('should support path-scoped suppression', () => {
    const config = {
      suppress: [{ rule: 'innerHTML', paths: ['tests/**', '*.test.js'] }],
    };
    expect(shouldSuppressRule('innerHTML', 'tests/app.test.js', config)).toBe(true);
    expect(shouldSuppressRule('innerHTML', 'src/app.js', config)).toBe(false);
  });

  it('should handle string-only suppress entries', () => {
    const config = { suppress: ['insecure-random'] };
    expect(shouldSuppressRule('insecure-random', 'test.js', config)).toBe(true);
  });

  it('should handle empty suppress list', () => {
    expect(shouldSuppressRule('any-rule', 'test.js', { suppress: [] })).toBe(false);
  });
});

describe('meetsSeverityThreshold', () => {
  it('should pass error when threshold is info', () => {
    expect(meetsSeverityThreshold('error', { severity_threshold: 'info' })).toBe(true);
  });

  it('should pass warning when threshold is warning', () => {
    expect(meetsSeverityThreshold('warning', { severity_threshold: 'warning' })).toBe(true);
  });

  it('should fail info when threshold is warning', () => {
    expect(meetsSeverityThreshold('info', { severity_threshold: 'warning' })).toBe(false);
  });

  it('should fail warning when threshold is error', () => {
    expect(meetsSeverityThreshold('warning', { severity_threshold: 'error' })).toBe(false);
  });

  it('should pass error when threshold is error', () => {
    expect(meetsSeverityThreshold('error', { severity_threshold: 'error' })).toBe(true);
  });
});

describe('meetsConfidenceThreshold', () => {
  it('should pass HIGH when threshold is LOW', () => {
    expect(meetsConfidenceThreshold('HIGH', { confidence_threshold: 'LOW' })).toBe(true);
  });

  it('should fail LOW when threshold is HIGH', () => {
    expect(meetsConfidenceThreshold('LOW', { confidence_threshold: 'HIGH' })).toBe(false);
  });

  it('should pass MEDIUM when threshold is MEDIUM', () => {
    expect(meetsConfidenceThreshold('MEDIUM', { confidence_threshold: 'MEDIUM' })).toBe(true);
  });
});

describe('applyConfig', () => {
  it('should filter by rule suppression', () => {
    const config = { suppress: [{ rule: 'insecure-random' }], severity_threshold: 'info', confidence_threshold: 'LOW' };
    const findings = [
      { ruleId: 'insecure-random', severity: 'info', confidence: 'LOW' },
      { ruleId: 'sql-injection', severity: 'error', confidence: 'HIGH' },
    ];
    const result = applyConfig(findings, 'test.js', config);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('sql-injection');
  });

  it('should filter by severity threshold', () => {
    const config = { suppress: [], severity_threshold: 'warning', confidence_threshold: 'LOW' };
    const findings = [
      { ruleId: 'weak-hash-md5', severity: 'info', confidence: 'MEDIUM' },
      { ruleId: 'sql-injection', severity: 'error', confidence: 'HIGH' },
    ];
    const result = applyConfig(findings, 'test.js', config);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('sql-injection');
  });

  it('should filter by confidence threshold', () => {
    const config = { suppress: [], severity_threshold: 'info', confidence_threshold: 'HIGH' };
    const findings = [
      { ruleId: 'weak-hash-md5', severity: 'info', confidence: 'LOW' },
      { ruleId: 'sql-injection', severity: 'error', confidence: 'HIGH' },
    ];
    const result = applyConfig(findings, 'test.js', config);
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe('sql-injection');
  });

  it('should handle null config', () => {
    const findings = [{ ruleId: 'test', severity: 'warning', confidence: 'MEDIUM' }];
    expect(applyConfig(findings, 'test.js', null)).toEqual(findings);
  });

  it('should handle non-array findings', () => {
    expect(applyConfig({ error: 'test' }, 'test.js', {})).toEqual({ error: 'test' });
  });
});
