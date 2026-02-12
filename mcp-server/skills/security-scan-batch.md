---
name: security-scan-batch
description: Use when scanning multiple files or entire directories for security vulnerabilities. Dispatches parallel subagents for efficient batch scanning with consolidated results.
---

# Batch Security Scanner Skill

You are a batch security scanning coordinator. Scan multiple files efficiently and return consolidated results that minimize context consumption.

## Workflow

1. **Identify files to scan** - Use glob patterns or file list provided
2. **Scan each file** using `mcp__security-scanner__scan_security` with `verbosity: 'minimal'`
3. **For files with issues**, get details with `verbosity: 'compact'`
4. **Consolidate results** - Merge findings, deduplicate, prioritize
5. **Return executive summary**

## Response Format

```
## Security Scan Summary

**Files Scanned:** {N}
**Files with Issues:** {N}
**Total Issues:** {critical} critical, {warning} warning

### Files Requiring Attention

| File | Critical | Warning | Top Issue |
|------|----------|---------|-----------|
| path/file1.py | 2 | 3 | SQL Injection (L15) |
| path/file2.js | 0 | 1 | XSS (L42) |

### Priority Fixes (Top 10)
1. **path/file1.py:15** - SQL Injection: Use parameterized query
2. **path/file1.py:28** - Hardcoded secret: Move to env var
3. **path/file2.js:42** - XSS: Use textContent instead of innerHTML
...

### Quick Fix
To auto-fix all issues: scan each file with fix_security tool.
```

## Rules

- DO scan files using `verbosity: 'minimal'` first for quick triage
- DO only fetch `verbosity: 'compact'` for files that have issues
- DO consolidate into single summary
- DO NOT return individual file JSON details
- DO prioritize by: critical severity > file count > line number
- DO limit to top 10 priority fixes in summary

## Scanning Patterns

For common batch operations:

**Python project:**
```
Glob: **/*.py
Exclude: **/venv/**, **/__pycache__/**
```

**JavaScript/TypeScript project:**
```
Glob: **/*.{js,ts,jsx,tsx}
Exclude: **/node_modules/**, **/dist/**
```

**Full project scan:**
```
Glob: **/*.{py,js,ts,java,go,rb,php}
Exclude: **/vendor/**, **/node_modules/**, **/venv/**
```

## Example

User asks: "Scan all Python files in src/"

You run:
1. Glob for `src/**/*.py` - find 15 files
2. Scan each with `verbosity: 'minimal'` - 4 have issues
3. Get `verbosity: 'compact'` for those 4 files
4. Consolidate and return summary

Response:
```
## Security Scan Summary

**Files Scanned:** 15
**Files with Issues:** 4
**Total Issues:** 3 critical, 8 warning

### Files Requiring Attention

| File | Critical | Warning | Top Issue |
|------|----------|---------|-----------|
| src/db.py | 2 | 1 | SQL Injection (L23) |
| src/auth.py | 1 | 3 | Hardcoded secret (L15) |
| src/api.py | 0 | 2 | SSL disabled (L67) |
| src/utils.py | 0 | 2 | Weak crypto (L12) |

### Priority Fixes (Top 10)
1. **src/db.py:23** - SQL Injection: Use parameterized query
2. **src/db.py:45** - SQL Injection: Use parameterized query
3. **src/auth.py:15** - Hardcoded secret: Move API_KEY to env var
...
```
