import { describe, it, expect } from 'vitest';

// Test the fix patterns directly
describe('SQL Injection Fix Patterns', () => {

  // Pattern definitions (same as in index.js)
  const patterns = {
    pythonFString: {
      match: /f["'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{(\w+)\}.*["']/i,
      fix: (line) => line.replace(/f(["'])(.*?)\{(\w+)\}(.*?)\1/, '"$2?$4", ($3,)')
    },
    pythonFormat: {
      match: /["'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{\}.*["']\.format\s*\(/i,
      fix: (line) => line.replace(
        /(["'])(.*?)\{\}(.*?)\1\.format\s*\(\s*(\w+)\s*\)/,
        '"$2?$3", [$4]'
      )
    },
    jsTemplateLiteral: {
      match: /`.*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}.*`/i,
      fix: (line) => line.replace(/`(.*?)\$\{(\w+)\}(.*?)`/, '"$1?$3", [$2]')
    },
    simpleConcat: {
      match: /["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']+["']\s*\+\s*\w+(?!\s*\+\s*["'])/i,
      fix: (line) => line.replace(
        /(["'])((?:SELECT|INSERT|UPDATE|DELETE)[^"']+)\1\s*\+\s*(\w+)/i,
        '"$2?", [$3]'
      )
    }
  };

  describe('Python f-string SQL injection', () => {
    it('should fix basic f-string SELECT', () => {
      const input = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
      expect(patterns.pythonFString.match.test(input)).toBe(true);
      const fixed = patterns.pythonFString.fix(input);
      expect(fixed).toBe('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))');
    });

    it('should fix f-string with single quotes', () => {
      const input = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')";
      expect(patterns.pythonFString.match.test(input)).toBe(true);
      const fixed = patterns.pythonFString.fix(input);
      // Fix normalizes to double quotes (valid Python)
      expect(fixed).toBe('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))');
    });

    it('should fix f-string DELETE', () => {
      const input = 'cursor.execute(f"DELETE FROM users WHERE id = {id}")';
      expect(patterns.pythonFString.match.test(input)).toBe(true);
      const fixed = patterns.pythonFString.fix(input);
      expect(fixed).toBe('cursor.execute("DELETE FROM users WHERE id = ?", (id,))');
    });

    it('should fix f-string INSERT', () => {
      const input = 'cursor.execute(f"INSERT INTO users VALUES ({id})")';
      expect(patterns.pythonFString.match.test(input)).toBe(true);
      const fixed = patterns.pythonFString.fix(input);
      expect(fixed).toBe('cursor.execute("INSERT INTO users VALUES (?)", (id,))');
    });

    it('should fix f-string UPDATE', () => {
      const input = 'cursor.execute(f"UPDATE users SET name = {name}")';
      expect(patterns.pythonFString.match.test(input)).toBe(true);
      const fixed = patterns.pythonFString.fix(input);
      expect(fixed).toBe('cursor.execute("UPDATE users SET name = ?", (name,))');
    });
  });

  describe('Python .format() SQL injection', () => {
    it('should fix basic format string', () => {
      const input = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))';
      expect(patterns.pythonFormat.match.test(input)).toBe(true);
      const fixed = patterns.pythonFormat.fix(input);
      expect(fixed).toBe('cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])');
    });
  });

  describe('JavaScript template literal SQL injection', () => {
    it('should fix basic template literal', () => {
      const input = 'db.query(`SELECT * FROM users WHERE id = ${userId}`)';
      expect(patterns.jsTemplateLiteral.match.test(input)).toBe(true);
      const fixed = patterns.jsTemplateLiteral.fix(input);
      expect(fixed).toBe('db.query("SELECT * FROM users WHERE id = ?", [userId])');
    });

    it('should fix template literal DELETE', () => {
      const input = 'db.query(`DELETE FROM users WHERE id = ${id}`)';
      expect(patterns.jsTemplateLiteral.match.test(input)).toBe(true);
      const fixed = patterns.jsTemplateLiteral.fix(input);
      expect(fixed).toBe('db.query("DELETE FROM users WHERE id = ?", [id])');
    });
  });

  describe('Simple concatenation SQL injection', () => {
    it('should fix JS string concatenation', () => {
      const input = 'db.query("SELECT * FROM users WHERE id = " + userId)';
      expect(patterns.simpleConcat.match.test(input)).toBe(true);
      const fixed = patterns.simpleConcat.fix(input);
      expect(fixed).toBe('db.query("SELECT * FROM users WHERE id = ?", [userId])');
    });

    it('should fix Python string concatenation', () => {
      const input = 'cursor.execute("DELETE FROM users WHERE id = " + user_id)';
      expect(patterns.simpleConcat.match.test(input)).toBe(true);
      const fixed = patterns.simpleConcat.fix(input);
      expect(fixed).toBe('cursor.execute("DELETE FROM users WHERE id = ?", [user_id])');
    });

    it('should NOT match complex concatenation with quotes inside', () => {
      // This pattern should NOT match - it would produce malformed output
      const input = `db.query("SELECT * FROM products WHERE name = '" + searchTerm + "'")`;
      // The pattern specifically excludes this case with the negative lookahead
      expect(patterns.simpleConcat.match.test(input)).toBe(false);
    });
  });
});

describe('Validation Function', () => {
  // Replicate the validateFix function
  function validateFix(original, fixed, language) {
    if (fixed === original || !fixed) {
      return { valid: false, reason: 'no_change' };
    }

    const unescaped = fixed.replace(/\\["'`]/g, '');
    const singleQuotes = (unescaped.match(/'/g) || []).length;
    const doubleQuotes = (unescaped.match(/"/g) || []).length;
    const backticks = (unescaped.match(/`/g) || []).length;
    if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0 || backticks % 2 !== 0) {
      return { valid: false, reason: 'unbalanced_quotes' };
    }

    const brackets = { '(': 0, '[': 0, '{': 0 };
    const closers = { ')': '(', ']': '[', '}': '{' };
    for (const char of unescaped) {
      if (brackets[char] !== undefined) brackets[char]++;
      if (closers[char]) brackets[closers[char]]--;
    }
    if (Object.values(brackets).some(v => v !== 0)) {
      return { valid: false, reason: 'unbalanced_brackets' };
    }

    const badPatterns = [
      /""[^,\s\]);}]/,
      /\+\s*[)\]}]/,
      /,\s*\+/,
      /\(\s*\+/,
    ];
    for (const pattern of badPatterns) {
      if (pattern.test(fixed)) {
        return { valid: false, reason: 'syntax_error' };
      }
    }

    return { valid: true };
  }

  it('should accept valid parameterized query fix', () => {
    const original = 'db.query("SELECT * FROM users WHERE id = " + userId)';
    const fixed = 'db.query("SELECT * FROM users WHERE id = ?", [userId])';
    expect(validateFix(original, fixed, 'javascript').valid).toBe(true);
  });

  it('should reject unchanged code', () => {
    const line = 'db.query("SELECT * FROM users WHERE id = " + userId)';
    expect(validateFix(line, line, 'javascript').valid).toBe(false);
    expect(validateFix(line, line, 'javascript').reason).toBe('no_change');
  });

  it('should reject unbalanced quotes', () => {
    const original = 'db.query("test")';
    const fixed = 'db.query("test)';
    expect(validateFix(original, fixed, 'javascript').valid).toBe(false);
    expect(validateFix(original, fixed, 'javascript').reason).toBe('unbalanced_quotes');
  });

  it('should reject unbalanced brackets', () => {
    const original = 'db.query("test")';
    const fixed = 'db.query("test"';
    expect(validateFix(original, fixed, 'javascript').valid).toBe(false);
    expect(validateFix(original, fixed, 'javascript').reason).toBe('unbalanced_brackets');
  });

  it('should reject malformed output with dangling +', () => {
    const original = 'db.query("test" + var)';
    const fixed = 'db.query("test" +)';
    expect(validateFix(original, fixed, 'javascript').valid).toBe(false);
    expect(validateFix(original, fixed, 'javascript').reason).toBe('syntax_error');
  });

  it('should accept Python tuple syntax', () => {
    const original = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
    const fixed = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))';
    expect(validateFix(original, fixed, 'python').valid).toBe(true);
  });

  it('should accept JS array syntax', () => {
    const original = 'db.query(`SELECT * FROM users WHERE id = ${userId}`)';
    const fixed = 'db.query("SELECT * FROM users WHERE id = ?", [userId])';
    expect(validateFix(original, fixed, 'javascript').valid).toBe(true);
  });
});
