# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch mode (auto-compile on changes)
npm run watch

# Lint TypeScript
npm run lint

# Run Python tests
python -m pytest src/test_semgrep_rules.py -v

# Run analyzer on a file
python src/analyzer.py <file_path>
```

## Testing the Extension

Press `F5` in VS Code to launch an Extension Development Host with the extension loaded.

## Architecture Overview

This is an MCP (Model Context Protocol) server that provides security scanning tools for AI coding agents.

### Directory Structure

```
mcp-server/
├── index.js                 # Entry point, MCP server setup, tool registration (185 lines)
├── src/
│   ├── fix-patterns.js      # 165 security fix templates (698 lines)
│   ├── utils.js             # Shared utilities: detectLanguage, isTestFile, extractImports
│   ├── tools/
│   │   ├── scan-security.js # scan_security MCP tool (Layer 1)
│   │   ├── fix-security.js  # fix_security MCP tool
│   │   ├── check-package.js # check_package MCP tool + hallucination detection
│   │   ├── scan-packages.js # scan_packages MCP tool
│   │   ├── scan-prompt.js   # scan_agent_prompt MCP tool (535 lines)
│   │   └── project-context.js # Project security profile discovery
│   └── cli/
│       ├── init.js          # Client setup command (288 lines)
│       ├── doctor.js        # Diagnostics command (273 lines)
│       └── demo.js          # Demo generation command (238 lines)
├── analyzer.py              # Python analysis engine
├── ast_parser.py            # Tree-sitter AST parsing
├── taint_analyzer.py        # Dataflow taint analysis
├── rules/                   # 1700+ YAML security rules
└── packages/                # Package lists for hallucination detection
```

### MCP Tools

| Tool | File | Description |
|------|------|-------------|
| `scan_security` | `src/tools/scan-security.js` | Scan code for vulnerabilities |
| `fix_security` | `src/tools/fix-security.js` | Auto-fix vulnerabilities |
| `check_package` | `src/tools/check-package.js` | Verify single package |
| `scan_packages` | `src/tools/scan-packages.js` | Check all imports in file |
| `scan_agent_prompt` | `src/tools/scan-prompt.js` | Detect prompt injection |
| `list_security_rules` | `index.js` | List available rules |

### CLI Commands

| Command | File | Description |
|---------|------|-------------|
| `init <client>` | `src/cli/init.js` | Setup MCP for AI client |
| `doctor` | `src/cli/doctor.js` | Check environment |
| `demo --lang <lang>` | `src/cli/demo.js` | Generate demo file |

### Data Flow

1. MCP client sends tool call (e.g., `scan_security`)
2. `index.js` routes to tool handler in `src/tools/`
3. Tool calls Python analyzer via `execFileSync`
4. `analyzer.py` uses AST + taint analysis
5. Results enhanced with fix suggestions
6. JSON/SARIF response returned to client

### Adding New Rules

Add rules to the appropriate YAML file in `src/rules/` following this format:
```yaml
- id: language.category.rule-name
  languages: [language]
  severity: ERROR|WARNING|INFO
  message: "Description of the vulnerability"
  patterns:
    - "regex_pattern_1"
    - "regex_pattern_2"
  metadata:
    cwe: "CWE-XXX"
    owasp: "Category"
```

## Claude Code Security Integration

**IMPORTANT**: After writing or editing any code file, Claude MUST automatically scan for security vulnerabilities and fix them.

### Automatic Security Scanning Workflow

1. **After any code edit**, run the security analyzer:
   ```bash
   python3 src/analyzer.py <filepath>
   ```

2. **If issues are found**, automatically apply fixes based on these rules:

   | Vulnerability | Fix Strategy |
   |--------------|--------------|
   | SQL Injection | Use parameterized queries with `?` placeholders |
   | XSS (innerHTML) | Replace with `textContent` or use DOMPurify |
   | Command Injection | Use `execFile()`/`spawn()` with `shell: false` |
   | Hardcoded Secrets | Replace with `process.env.VAR` or `os.environ.get()` |
   | Weak Crypto (MD5/SHA1) | Replace with SHA-256 |
   | Insecure Deserialization | Use `json.load()` or `yaml.safe_load()` |
   | SSL verify=False | Set `verify=True` |

3. **Use the `/fix-security` command** to scan and fix all issues in a file.

### Security Fix Examples

**SQL Injection Fix:**
```javascript
// BEFORE (vulnerable)
db.query("SELECT * FROM users WHERE id = " + userId);

// AFTER (safe)
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

**XSS Fix:**
```javascript
// BEFORE (vulnerable)
element.innerHTML = userInput;

// AFTER (safe)
element.textContent = userInput;
// OR for HTML content:
element.innerHTML = DOMPurify.sanitize(userInput);
```

**Hardcoded Secret Fix:**
```python
# BEFORE (vulnerable)
api_key = "stripe_test_FAKE123..."

# AFTER (safe)
api_key = os.environ.get("API_KEY")
```

### Slash Command

Use `/fix-security` to automatically scan the current file and apply all security fixes.

## Two-Layer Security Analysis

This project implements a two-layer security analysis system:

### Layer 1: Pattern-Based Scanning (scan_security)

- **Engine:** Python analyzer with AST + taint analysis + regex fallback + YAML rules
- **Speed:** ~1-2s, deterministic, free
- **Best for:** CI/CD, quick feedback, batch scans
- **Limitations:** No framework awareness, no middleware detection, per-file only

### Layer 2: LLM-Powered Review (security-review skill)

- **Engine:** LLM subagent that reads project context and applies security judgment
- **Speed:** ~10-30s, requires LLM call
- **Best for:** Pre-commit review, PR review, deep analysis
- **Capabilities:**
  - Detects frameworks (Express, Django, Flask, Spring, etc.)
  - Knows about security middleware (helmet, cors, DOMPurify, etc.)
  - Evaluates if Layer 1 findings are real or false positives
  - Catches auth/authz flaws, IDOR, logic bugs, insecure defaults

### Project Context Discovery

The `project_context` parameter on `scan_security` triggers automatic detection of:
- **Frameworks:** Express, Koa, Fastify, Django, Flask, FastAPI, Rails, Gin, Spring Boot
- **Security middleware:** helmet, cors, csurf, rate-limiting, DOMPurify, express-validator
- **Auth libraries:** passport, jsonwebtoken, bcrypt, argon2, devise
- **Sanitizers:** DOMPurify, bleach, sanitize-html

```javascript
// Get findings + project security profile
scan_security({ file_path: "app.js", project_context: true, verbosity: "full" })
// Returns: { issues: [...], project: { framework: "Express", security_middleware: ["helmet", "cors"], ... } }

// Get surrounding code context for each finding
scan_security({ file_path: "app.js", include_context: true })
// Returns: { issues: [{ ..., context_before: [...], context_after: [...] }] }
```

## Context Optimization

All MCP tools support a `verbosity` parameter to minimize context window consumption:

| Level | Tokens | Use Case |
|-------|--------|----------|
| `minimal` | ~50 | Quick checks, CI pipelines, batch scans |
| `compact` | ~200 | Normal development (default) |
| `full` | ~2000 | Debugging, compliance reports |

### Example Usage

```javascript
// Minimal - just counts
scan_security({ file_path: "app.py", verbosity: "minimal" })
// Returns: { total: 5, critical: 2, warning: 3, message: "Found 5 issue(s)" }

// Compact - actionable info (default)
scan_security({ file_path: "app.py", verbosity: "compact" })
// Returns: { issues: [{ line, ruleId, severity, message, fix }] }

// Full - complete metadata
scan_security({ file_path: "app.py", verbosity: "full" })
// Returns: { issues: [{ ...all fields including metadata, CWE, OWASP }] }
```

## Subagent Skills

For context-efficient security scanning in Claude Code, use the provided skills in `skills/`:

| Skill | Use Case |
|-------|----------|
| `security-scanner` | Single file scan with concise summary (~200 tokens output) |
| `security-scan-batch` | Multi-file parallel scanning with consolidated results |
| `security-review` | Deep project-aware review: verifies findings against framework defenses, catches logic bugs |

Layer 1 skills (`security-scanner`, `security-scan-batch`) run fast pattern-based analysis.
Layer 2 skill (`security-review`) uses LLM reasoning with project context for deeper analysis.
