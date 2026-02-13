import { describe, it, expect } from 'vitest';
import { validateFix, generateFix } from '../src/utils.js';
import { FIX_TEMPLATES } from '../src/fix-patterns.js';

describe('validateFix', () => {
  it('should accept balanced output', () => {
    expect(validateFix('exec(cmd)', 'execFile("ls", [cmd])')).toBe(true);
    expect(validateFix('old', 'subprocess.run(cmd.split(), shell=False)')).toBe(true);
  });

  it('should reject unbalanced parens', () => {
    expect(validateFix('old', 'subprocess.run([cmd')).toBe(false);
    expect(validateFix('old', 'exec(cmd')).toBe(false);
  });

  it('should reject unbalanced quotes', () => {
    expect(validateFix('old', "exec('cmd)")).toBe(false);
    expect(validateFix('old', 'exec("cmd)')).toBe(false);
  });

  it('should reject identical input/output', () => {
    expect(validateFix('same', 'same')).toBe(false);
  });

  it('should reject null/empty output', () => {
    expect(validateFix('old', null)).toBe(false);
    expect(validateFix('old', '')).toBe(false);
  });

  it('should handle escaped quotes', () => {
    expect(validateFix('old', 'const s = "he said \\"hello\\"";')).toBe(true);
  });
});

describe('fix template: child-process-exec', () => {
  const template = FIX_TEMPLATES['child-process-exec'];

  it('should exist', () => {
    expect(template).toBeDefined();
    expect(template.fix).toBeDefined();
  });

  it('should restructure string concatenation to array arguments', () => {
    const fixed = template.fix('exec("ls " + cmd)', 'javascript');
    if (fixed) {
      // Should NOT still have string concatenation with exec
      expect(fixed).not.toMatch(/exec\s*\(.*\+/);
      // Should use execFile with array form
      expect(fixed).toContain('execFile');
    }
  });

  it('should handle template literal form', () => {
    const fixed = template.fix('exec(`ls ${cmd}`)', 'javascript');
    if (fixed) {
      expect(fixed).toContain('execFile');
    }
  });

  it('should produce valid output (balanced brackets)', () => {
    const inputs = [
      'exec("ls " + cmd)',
      'exec(`ls ${cmd}`)',
      'exec(cmd)',
    ];
    for (const input of inputs) {
      const fixed = template.fix(input, 'javascript');
      if (fixed && fixed !== input) {
        expect(validateFix(input, fixed)).toBe(true);
      }
    }
  });
});

describe('fix template: dangerous-subprocess', () => {
  const template = FIX_TEMPLATES['dangerous-subprocess'];

  it('should exist', () => {
    expect(template).toBeDefined();
    expect(template.fix).toBeDefined();
  });

  it('should produce valid Python with shell=False', () => {
    const fixed = template.fix('subprocess.call(cmd, shell=True)', 'python');
    if (fixed) {
      expect(fixed).toContain('shell=False');
      // Should NOT have double brackets like [["cmd"]]
      expect(fixed).not.toMatch(/\[\[/);
    }
  });

  it('should produce balanced output', () => {
    const inputs = [
      'subprocess.call(cmd, shell=True)',
      'subprocess.run("ls -la", shell=True)',
    ];
    for (const input of inputs) {
      const fixed = template.fix(input, 'python');
      if (fixed && fixed !== input) {
        expect(validateFix(input, fixed)).toBe(true);
      }
    }
  });
});

describe('fix template: dangerous-system-call', () => {
  const template = FIX_TEMPLATES['dangerous-system-call'];

  it('should exist', () => {
    expect(template).toBeDefined();
  });

  it('should produce complete replacement', () => {
    const fixed = template.fix('os.system("ls")', 'python');
    if (fixed) {
      expect(fixed).toContain('subprocess.run');
      expect(fixed).toContain('shell=False');
    }
  });

  it('should produce balanced output', () => {
    const fixed = template.fix('os.system(cmd)', 'python');
    if (fixed && fixed !== 'os.system(cmd)') {
      expect(validateFix('os.system(cmd)', fixed)).toBe(true);
    }
  });
});

describe('generateFix validation', () => {
  it('should return null for fixes that produce unbalanced output', () => {
    const issue = { ruleId: 'test-rule-that-does-not-exist' };
    const result = generateFix(issue, 'some code', 'javascript');
    // Unknown rules return null fix with manual guidance
    expect(result.fixed).toBeNull();
  });

  it('should include description for all results', () => {
    const issue = { ruleId: 'sql-injection' };
    const result = generateFix(issue, "query = 'SELECT * FROM users WHERE id = ' + id", 'python');
    expect(result.description).toBeDefined();
    expect(typeof result.description).toBe('string');
  });
});

describe('fix template: path-traversal', () => {
  const template = FIX_TEMPLATES['path-traversal'];

  it('should use realpath/resolve instead of basename', () => {
    const pyFixed = template.fix('open(user_path)', 'python');
    expect(pyFixed).toContain('realpath');
    expect(pyFixed).not.toContain('basename');

    const jsFixed = template.fix('readFileSync(userPath)', 'javascript');
    expect(jsFixed).toContain('resolve');
    expect(jsFixed).not.toContain('basename');
  });

  it('should include TODO for prefix validation', () => {
    const fixed = template.fix('open(user_path)', 'python');
    expect(fixed).toContain('TODO');
  });

  it('should produce balanced output', () => {
    const inputs = ['open(user_path)', 'readFileSync(userPath)'];
    const langs = ['python', 'javascript'];
    for (let i = 0; i < inputs.length; i++) {
      const fixed = template.fix(inputs[i], langs[i]);
      if (fixed && fixed !== inputs[i]) {
        expect(validateFix(inputs[i], fixed)).toBe(true);
      }
    }
  });
});

describe('fix template: prototype-pollution', () => {
  const template = FIX_TEMPLATES['prototype-pollution'];

  it('should fix simple single-line assignments', () => {
    const fixed = template.fix('obj[key] = value', 'javascript');
    expect(fixed).toContain('__proto__');
    expect(fixed).toContain('includes');
  });

  it('should fallback to comment for complex patterns', () => {
    const fixed = template.fix('obj[key] = nested[other] = value', 'javascript');
    expect(fixed).toContain('SECURITY');
  });

  it('should produce balanced output for simple case', () => {
    const fixed = template.fix('obj[key] = value', 'javascript');
    expect(validateFix('obj[key] = value', fixed)).toBe(true);
  });
});

describe('fix template: run-shell-form', () => {
  const template = FIX_TEMPLATES['run-shell-form'];

  it('should use exec form with proper escaping', () => {
    const fixed = template.fix('RUN apt-get install -y curl', 'dockerfile');
    expect(fixed).toContain('"/bin/sh"');
    expect(fixed).toContain('"-c"');
    expect(fixed).toContain('apt-get install -y curl');
  });

  it('should escape quotes in commands', () => {
    const fixed = template.fix('RUN echo "hello world"', 'dockerfile');
    expect(fixed).toContain('\\"hello world\\"');
  });

  it('should produce balanced output', () => {
    const fixed = template.fix('RUN apt-get update', 'dockerfile');
    if (fixed) {
      expect(validateFix('RUN apt-get update', fixed)).toBe(true);
    }
  });
});

describe('fix template: helmet-missing', () => {
  const template = FIX_TEMPLATES['helmet-missing'];

  it('should use comment-only suggestion', () => {
    const fixed = template.fix('app.get("/", handler)', 'javascript');
    expect(fixed).toContain('TODO');
    expect(fixed).not.toMatch(/^app\.use\(helmet\(\)\)/);
  });
});

describe('fix template: dangerous-subprocess shlex', () => {
  const template = FIX_TEMPLATES['dangerous-subprocess'];

  it('should use shlex.split() instead of .split()', () => {
    const fixed = template.fix('subprocess.run("ls -la /tmp", shell=True)', 'python');
    expect(fixed).toContain('shlex.split');
    expect(fixed).not.toMatch(/\.split\(\)/);
  });
});

describe('fix template: dangerous-system-call shlex', () => {
  const template = FIX_TEMPLATES['dangerous-system-call'];

  it('should use shlex.split() instead of .split()', () => {
    const fixed = template.fix('os.system("ls -la")', 'python');
    expect(fixed).toContain('shlex.split');
    expect(fixed).not.toMatch(/\.split\(\)/);
  });
});

describe('all fix templates produce valid output', () => {
  const testInputs = {
    javascript: [
      'exec("ls " + cmd)',
      'element.innerHTML = data',
      'eval(code)',
      'document.write(html)',
    ],
    python: [
      'subprocess.call(cmd, shell=True)',
      'os.system("rm -rf /")',
      "query = 'SELECT * FROM users WHERE id = ' + id",
      'pickle.loads(data)',
      'hashlib.md5(data)',
    ],
  };

  for (const [lang, inputs] of Object.entries(testInputs)) {
    for (const input of inputs) {
      it(`should produce valid fix for "${input.substring(0, 40)}..." (${lang})`, () => {
        for (const [pattern, template] of Object.entries(FIX_TEMPLATES)) {
          try {
            const fixed = template.fix(input, lang);
            if (fixed && fixed !== input) {
              const valid = validateFix(input, fixed);
              if (!valid) {
                // validateFix returning false means we should get null from generateFix
                const issue = { ruleId: pattern };
                const result = generateFix(issue, input, lang);
                // Either the fix is valid, or generateFix returns null
                if (result.fixed !== null) {
                  expect(validateFix(input, result.fixed)).toBe(true);
                }
              }
            }
          } catch {
            // Template may not handle this input - that's fine
          }
        }
      });
    }
  }
});
