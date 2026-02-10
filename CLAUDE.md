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

This is a VS Code extension that performs security vulnerability analysis using a hybrid TypeScript/Python architecture:

### Core Components

1. **TypeScript Layer** (`src/extension.ts`, `src/securityProvider.ts`)
   - VS Code extension entry point and command registration
   - Spawns Python analyzer via `child_process.exec`
   - Manages diagnostics collection and sidebar tree view
   - Parses JSON output from Python analyzer

2. **Python Analysis Engine** (`src/analyzer.py`)
   - Core security scanning logic using regex-based pattern matching
   - Reads YAML rule files and matches patterns against source code
   - Outputs JSON array of security issues (ruleId, message, line, column, severity)
   - Language detection based on file extension

3. **Security Rules** (`src/rules/`)
   - YAML files following Semgrep registry format
   - Rules organized by language: `python.security.yaml`, `javascript.security.yaml`, `java.security.yaml`, `go.security.yaml`, `dockerfile.security.yaml`, `generic.secrets.yaml`
   - Each rule has: id, patterns (regex), message, severity, languages, metadata (CWE, OWASP)
   - Rule loader in `src/rules/__init__.py` with fallback rules if PyYAML unavailable

### Data Flow

1. VS Code triggers scan (on save or command)
2. `extension.ts` calls Python: `python src/analyzer.py <filepath>`
3. `analyzer.py` detects language, loads applicable rules, runs regex matching
4. JSON output parsed by TypeScript, converted to VS Code diagnostics
5. `SecurityTreeDataProvider` updates sidebar with findings

### Extension Configuration

Settings defined in `package.json` under `contributes.configuration`:
- `agentSecurity.enabledRules`: Array of rule IDs to enable
- `agentSecurity.severity`: Default severity level
- `agentSecurity.autoScan`: Auto-scan on file save

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
api_key = "sk_live_abc123..."

# AFTER (safe)
api_key = os.environ.get("API_KEY")
```

### Slash Command

Use `/fix-security` to automatically scan the current file and apply all security fixes.
