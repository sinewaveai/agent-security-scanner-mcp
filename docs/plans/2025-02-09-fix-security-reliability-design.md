# fix_security Reliability Improvement

**Date:** 2025-02-09
**Goal:** Make `fix_security` MCP tool reliable enough for frictionless npm adoption

## Problem

The current `fix_security` tool has reliability issues:

1. **SQL injection fix produces malformed code** on complex patterns
2. **Python f-strings not handled** - detection works, fixing doesn't
3. **JS template literals not handled**
4. **No validation** - broken fixes are applied anyway

### Example of Current Breakage

```javascript
// Input
"SELECT * FROM products WHERE name = '" + searchTerm + "'"

// Current output (BROKEN)
"SELECT * FROM products WHERE name = "?", [searchTerm] + "'"
```

## Solution

### 1. Multi-Pattern Fix Templates

Replace single regex per vulnerability with array of patterns:

```javascript
"sql-injection": {
  description: "Use parameterized queries",
  patterns: [
    { match: /f-string-regex/, fix: fn, languages: ['python'] },
    { match: /template-literal-regex/, fix: fn, languages: ['javascript'] },
    { match: /concat-regex/, fix: fn, languages: ['*'] }
  ]
}
```

### 2. Validation Layer

New `validateFix()` function checks:
- Balanced quotes
- Balanced brackets
- No obvious syntax errors
- Fix is different from original

### 3. Graceful Fallback

If no pattern produces valid output, return `fixed: null` instead of broken code.

## Patterns to Add

### SQL Injection

| Pattern | Example | Languages |
|---------|---------|-----------|
| f-string | `f"SELECT * FROM x WHERE id={id}"` | Python |
| .format() | `"SELECT ... {}".format(id)` | Python |
| template literal | `` `SELECT ... ${id}` `` | JS/TS |
| simple concat | `"SELECT ..." + id` | All |

## Files Changed

- `mcp-server/index.js`: Add `validateFix()`, update `generateFix()`, expand `FIX_TEMPLATES`

## Testing

Test files:
- `mcp-server/demo/vulnerable_demo.js` - JS patterns
- `mcp-server/demo/vulnerable_demo.py` - Python patterns
