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
│   ├── utils.js             # Shared utilities (153 lines)
│   ├── tools/
│   │   ├── scan-security.js # scan_security MCP tool
│   │   ├── fix-security.js  # fix_security MCP tool
│   │   ├── check-package.js # check_package MCP tool + hallucination detection
│   │   ├── scan-packages.js # scan_packages MCP tool
│   │   └── scan-prompt.js   # scan_agent_prompt MCP tool (535 lines)
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
