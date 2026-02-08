# agent-security-scanner-mcp

A powerful MCP (Model Context Protocol) server for real-time security vulnerability scanning. Integrates with Claude Desktop, Claude Code, OpenCode.ai, Kilo Code, and any MCP-compatible client to automatically detect and fix security issues as you code.

AI coding agents like **Claude Code**, **Cursor**, **Windsurf**, **Cline**, **Copilot**, and **Devin** are transforming software development. But they introduce attack surfaces that traditional security tools weren't designed to handle:

- **Prompt Injection** – Malicious instructions hidden in codebases hijack your AI agent
- **Package Hallucination** – AI invents package names that attackers register as malware
- **Data Exfiltration** – Compromised agents silently leak secrets to external servers
- **Backdoor Insertion** – Manipulated agents inject vulnerabilities into your code

**agent-security-scanner-mcp** is the first security scanner purpose-built for the agentic era. It protects AI coding agents in real-time via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).


**359 Semgrep-aligned security rules | 120 auto-fix templates | 6 ecosystems indexed | AI Agent prompt security**

## What's New in v2.0.2

- **Prompt injection detection overhaul** - Detection rate improved from 33% to 80%+
- **Code block scanning** - Detects attacks hidden inside markdown code blocks
- **Base64 decode-and-rescan** - Runtime decoding of encoded payloads
- **Security fix** - Command injection vulnerability patched (execFileSync)
- **Test suite** - 51 vitest tests with GitHub Actions CI
- **Bug fixes** - Package hallucination detection now correctly uses bloom filters

## What's New in v2.0.0

- **AST-based analysis** - tree-sitter powered parsing for 12 languages with higher accuracy
- **Taint analysis** - Track data flow from sources (user input) to sinks (dangerous functions)
- **Graceful fallback** - Works out-of-the-box with regex; enhanced detection when tree-sitter installed
- **Metavariable patterns** - Semgrep-style `$VAR` patterns for structural matching
- **Doctor command upgrade** - Now checks for AST engine availability

### Enhanced Detection with tree-sitter (Optional)

For maximum detection accuracy, install the AST engine:

```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

The scanner works without tree-sitter using regex-based detection, but AST analysis provides:
- Fewer false positives through structural understanding
- Taint tracking across function boundaries
- Language-aware pattern matching

## What's New in v1.5.0

- **92% smaller package** - Only 2.7 MB (down from 84 MB)
- **6 ecosystems included** - PyPI, RubyGems, crates.io, pub.dev, CPAN, raku.land
- **npm available separately** - Use `agent-security-scanner-mcp-full` for npm support (adds 7.6 MB)
- **Bloom Filters** - Efficient storage for large package lists

## What's New in v1.3.0

- **AI Agent Prompt Security** - New `scan_agent_prompt` tool to detect malicious prompts before execution
- **56 prompt attack detection rules** - Exfiltration, backdoor requests, social engineering, jailbreaks
- **Risk scoring engine** - BLOCK/WARN/LOG/ALLOW actions with 0-100 risk scores
- **Prompt injection detection** - 39 rules for LLM prompt injection patterns

## What's New in v1.2.0

- **110 new security rules** - Now covering 10 languages and IaC
- **PHP support** - SQL injection, XSS, command injection, deserialization, file inclusion
- **Ruby/Rails support** - Mass assignment, CSRF, unsafe eval, YAML deserialization
- **C/C++ support** - Buffer overflow, format strings, memory safety, use-after-free
- **Terraform support** - AWS S3, IAM, RDS, security groups, CloudTrail
- **Kubernetes support** - Privileged containers, RBAC, network policies, secrets

## Features

- **Real-time scanning** - Detect vulnerabilities instantly as you write code
- **Auto-fix suggestions** - Get actionable fixes for every security issue
- **Multi-language support** - JavaScript, TypeScript, Python, Java, Go, PHP, Ruby, C/C++, Dockerfile, Terraform, Kubernetes
- **Semgrep-compatible** - Rules aligned with Semgrep registry format
- **CWE & OWASP mapped** - Every rule includes CWE and OWASP references
- **Hallucination detection** - Detect AI-invented package names across 7 ecosystems via bloom filters and text lists

## Installation

### Default Package (Lightweight - 2.7 MB)

```bash
npm install -g agent-security-scanner-mcp
```

Includes hallucination detection for: **PyPI, RubyGems, crates.io, pub.dev, CPAN, raku.land** (1M+ packages)

### Full Package (With npm - 8.7 MB)

If you need **npm/JavaScript hallucination detection** (3.3M packages):

```bash
npm install -g agent-security-scanner-mcp-full
```

Or run directly with npx:

```bash
npx agent-security-scanner-mcp
```

## Prerequisites

- **Node.js >= 18.0.0** (required)
- **Python 3.x** (required for the analyzer engine)
- **PyYAML** (`pip install pyyaml`) — required for rule loading
- **tree-sitter** (optional, for enhanced AST-based detection): `pip install tree-sitter tree-sitter-python tree-sitter-javascript`

## Works With All Major AI Coding Tools

| Tool | Integration | Status |
|------|-------------|--------|
| **Claude Desktop** | Native MCP | ✅ Full Support |
| **Claude Code** | Native MCP | ✅ Full Support |
| **Cursor** | MCP Server | ✅ Full Support |
| **Windsurf** | MCP Server | ✅ Full Support |
| **Cline** | MCP Server | ✅ Full Support |
| **Kilo Code** | MCP Server | ✅ Full Support |
| **OpenCode** | MCP Server | ✅ Full Support |
| **Cody** | MCP Server | ✅ Full Support |
| **Zed** | MCP Server | ✅ Full Support |
| **Any MCP Client** | MCP Protocol | ✅ Compatible |

## Quick Start

### One-Command Setup

Set up any supported client instantly:

```bash
npx agent-security-scanner-mcp init <client>
```

**Examples:**

```bash
npx agent-security-scanner-mcp init cursor
npx agent-security-scanner-mcp init claude-desktop
npx agent-security-scanner-mcp init windsurf
npx agent-security-scanner-mcp init cline
npx agent-security-scanner-mcp init claude-code
npx agent-security-scanner-mcp init kilo-code
npx agent-security-scanner-mcp init opencode
npx agent-security-scanner-mcp init cody
```

**Interactive mode** — just run `init` with no client to pick from a list:

```bash
npx agent-security-scanner-mcp init
```

The init command auto-detects your OS, locates the config file, creates a timestamped backup, and adds the MCP server entry. Restart your client afterward to activate.

#### Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview changes without writing anything |
| `--yes`, `-y` | Skip prompts, use safe defaults |
| `--force` | Overwrite existing entry if present |
| `--path <file>` | Override the config file path |
| `--name <key>` | Custom server key name (default: `agentic-security`) |

**Advanced examples:**

```bash
# Preview what would change before applying
npx agent-security-scanner-mcp init cursor --dry-run

# Overwrite an existing entry
npx agent-security-scanner-mcp init cline --force

# Use a custom config path and server name
npx agent-security-scanner-mcp init claude-desktop --path ~/my-config.json --name my-scanner
```

### Diagnose Your Setup

Check your environment and all client configurations:

```bash
npx agent-security-scanner-mcp doctor
```

Checks Node.js version, Python availability, analyzer engine, and scans all client configs for issues. Auto-fix trivial problems with `--fix`:

```bash
npx agent-security-scanner-mcp doctor --fix
```

### Try It Now

Generate a vulnerable demo file and scan it instantly:

```bash
npx agent-security-scanner-mcp demo
```

Supports multiple languages:

```bash
npx agent-security-scanner-mcp demo --lang js    # JavaScript (default)
npx agent-security-scanner-mcp demo --lang py    # Python
npx agent-security-scanner-mcp demo --lang go    # Go
npx agent-security-scanner-mcp demo --lang java  # Java
```

Creates a small file with 3 intentional vulnerabilities, runs the scanner, shows findings with CWE/OWASP references, and asks if you want to keep the file for testing.

---

## Manual Configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "agent-security-scanner-mcp"]
    }
  }
}
```

**Config file locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### Claude Code

Add to your MCP settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "agent-security-scanner-mcp"]
    }
  }
}
```

### OpenCode.ai

Add to your `opencode.jsonc` configuration file:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "security-scanner": {
      "type": "local",
      "command": ["npx", "-y", "agent-security-scanner-mcp"],
      "enabled": true
    }
  }
}
```

Or if installed globally:

```json
{
  "mcp": {
    "security-scanner": {
      "type": "local",
      "command": ["agent-security-scanner-mcp"],
      "enabled": true
    }
  }
}
```

### Kilo Code

**Global configuration** - Add to VS Code settings `mcp_settings.json`:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "agent-security-scanner-mcp"],
      "alwaysAllow": [],
      "disabled": false
    }
  }
}
```

**Project-level configuration** - Create `.kilocode/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "agent-security-scanner-mcp"],
      "alwaysAllow": ["scan_security", "list_security_rules"],
      "disabled": false
    }
  }
}
```

**Windows users** - Use cmd wrapper:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "cmd",
      "args": ["/c", "npx", "-y", "agent-security-scanner-mcp"]
    }
  }
}
```

## Available Tools

### `scan_security`

Scan a file for security vulnerabilities and return issues with suggested fixes.

```
Parameters:
  file_path (string): Absolute path to the file to scan

Returns:
  - List of security issues
  - Severity level (ERROR, WARNING, INFO)
  - CWE and OWASP references
  - Line numbers and code context
  - Suggested fixes
```

**Example output:**
```json
{
  "file": "/path/to/file.js",
  "language": "javascript",
  "issues_count": 3,
  "issues": [
    {
      "ruleId": "javascript.lang.security.audit.sql-injection",
      "message": "SQL Injection detected. Use parameterized queries.",
      "line": 15,
      "severity": "error",
      "metadata": {
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection"
      },
      "suggested_fix": {
        "description": "Use parameterized queries instead of string concatenation",
        "original": "db.query(\"SELECT * FROM users WHERE id = \" + userId)",
        "fixed": "db.query(\"SELECT * FROM users WHERE id = ?\", [userId])"
      }
    }
  ]
}
```

### `fix_security`

Automatically fix all security issues in a file.

```
Parameters:
  file_path (string): Absolute path to the file to fix

Returns:
  - Number of fixes applied
  - Details of each fix
  - Fixed file content
```

### `list_security_rules`

List all 105 available auto-fix templates.

---

## AI Agent Prompt Security

Protect AI coding agents (Claude Code, Cursor, Copilot, etc.) from malicious prompts before execution. Detects exfiltration attempts, backdoor requests, social engineering, and obfuscated attacks.

### `scan_agent_prompt`

Scan a prompt for malicious intent before allowing an AI agent to execute it.

```
Parameters:
  prompt_text (string): The prompt text to analyze
  context (object, optional):
    - sensitivity_level: "high" | "medium" | "low" (default: "medium")

Returns:
  - action: "BLOCK" | "WARN" | "LOG" | "ALLOW"
  - risk_score: 0-100
  - risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
  - findings: Array of detected issues
  - explanation: Human-readable summary
  - recommendations: Suggested actions
```

**Risk Thresholds:**

| Risk Level | Score Range | Action |
|------------|-------------|--------|
| CRITICAL | 85-100 | BLOCK |
| HIGH | 65-84 | BLOCK |
| MEDIUM | 40-64 | WARN |
| LOW | 20-39 | LOG |
| NONE | 0-19 | ALLOW |

**Example - Malicious prompt (BLOCKED):**
```json
{
  "action": "BLOCK",
  "risk_score": 100,
  "risk_level": "CRITICAL",
  "findings": [
    {
      "rule_id": "agent.injection.security.backdoor-request",
      "category": "malicious-injection",
      "severity": "error",
      "message": "Request to add backdoor or hidden access mechanism",
      "matched_text": "add a hidden backdoor",
      "confidence": "high"
    }
  ],
  "explanation": "Detected 1 potential security issue(s) in prompt",
  "recommendations": [
    "Do not execute this prompt",
    "Review the flagged patterns",
    "Report if this appears to be an attack attempt"
  ]
}
```

**Example - Safe prompt (ALLOWED):**
```json
{
  "action": "ALLOW",
  "risk_score": 0,
  "risk_level": "NONE",
  "findings": [],
  "explanation": "No security issues detected in prompt",
  "recommendations": []
}
```

**Attack Categories Detected (56 rules):**

| Category | Rules | Examples |
|----------|-------|----------|
| Exfiltration | 10 | Send code to webhook, read .env files, push to external repo |
| Malicious Injection | 11 | Add backdoor, create reverse shell, disable authentication |
| System Manipulation | 9 | rm -rf /, modify /etc/passwd, add cron persistence |
| Social Engineering | 6 | Fake authorization claims, fake debug mode, urgency pressure |
| Obfuscation | 4 | Base64 encoded commands, ROT13, fragmented instructions |
| Agent Manipulation | 3 | Ignore previous instructions, override safety, DAN jailbreaks |

---

## Package Hallucination Detection

Detect AI-hallucinated package names that don't exist in official registries. Prevents supply chain attacks where attackers register fake package names suggested by AI.

**7 ecosystems indexed (bloom filters for npm/PyPI/RubyGems, text lists for the rest):**

| Ecosystem | Method | Packages | Registry |
|-----------|--------|----------|----------|
| npm | Bloom filter | ~3.78M | npmjs.com |
| PyPI | Bloom filter | ~554K | pypi.org |
| RubyGems | Bloom filter | ~180K | rubygems.org |
| crates.io | Text list | 156,489 | crates.io |
| Dart | Text list | 67,353 | pub.dev |
| Perl | Text list | 55,924 | metacpan.org |
| Raku | Text list | 2,138 | raku.land |

> **Note:** Bloom filter lookups have a ~0.1% false positive rate. Text list lookups are exact matches with zero false positives.

### `check_package`

Check if a single package name is legitimate or potentially hallucinated.

```
Parameters:
  package_name (string): The package name to verify
  ecosystem (enum): "dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"

Returns:
  - legitimate: true/false
  - hallucinated: true/false
  - confidence: "high"
  - recommendation: Action to take
```

**Example:**
```json
{
  "package": "flutter_animations",
  "ecosystem": "dart",
  "legitimate": true,
  "hallucinated": false,
  "confidence": "high",
  "total_known_packages": 64721,
  "recommendation": "Package exists in registry - safe to use"
}
```

### `scan_packages`

Scan a code file and detect all potentially hallucinated package imports.

```
Parameters:
  file_path (string): Path to the file to scan
  ecosystem (enum): "dart", "perl", "raku", "npm", "pypi", "rubygems", "crates"

Returns:
  - List of all packages found
  - Which are legitimate vs hallucinated
  - Recommendation
```

**Example output:**
```json
{
  "file": "/path/to/main.dart",
  "ecosystem": "dart",
  "total_packages_found": 5,
  "legitimate_count": 4,
  "hallucinated_count": 1,
  "hallucinated_packages": ["fake_flutter_pkg"],
  "legitimate_packages": ["flutter", "http", "provider", "shared_preferences"],
  "recommendation": "⚠️ Found 1 potentially hallucinated package(s): fake_flutter_pkg"
}
```

### `list_package_stats`

Show statistics about loaded package lists.

```json
{
  "package_lists": [
    { "ecosystem": "npm", "packages_loaded": 3329177, "status": "ready" },
    { "ecosystem": "pypi", "packages_loaded": 554762, "status": "ready" },
    { "ecosystem": "rubygems", "packages_loaded": 180693, "status": "ready" },
    { "ecosystem": "crates", "packages_loaded": 156489, "status": "ready" },
    { "ecosystem": "dart", "packages_loaded": 67348, "status": "ready" },
    { "ecosystem": "perl", "packages_loaded": 55924, "status": "ready" },
    { "ecosystem": "raku", "packages_loaded": 2138, "status": "ready" }
  ],
  "total_packages": 4346531
}
```

### Adding Custom Package Lists

Add your own package lists to `packages/` directory:

```bash
# Format: one package name per line
packages/
├── npm.txt       # 3,329,177 packages (JavaScript)
├── pypi.txt      # 554,762 packages (Python)
├── rubygems.txt  # 180,693 packages (Ruby)
├── crates.txt    # 156,489 packages (Rust)
├── dart.txt      # 67,348 packages (Dart/Flutter)
├── perl.txt      # 55,924 packages (Perl)
└── raku.txt      # 2,138 packages (Raku)
```

### Fetching Package Lists

```bash
# Using the included script (downloads from garak-llm datasets)
cd mcp-server
pip install datasets
python scripts/fetch-garak-packages.py
```

Package lists are sourced from [garak-llm](https://huggingface.co/garak-llm) Hugging Face datasets:

| Ecosystem | Dataset | Snapshot Date |
|-----------|---------|---------------|
| npm | [garak-llm/npm-20241031](https://huggingface.co/datasets/garak-llm/npm-20241031) | Oct 31, 2024 |
| PyPI | [garak-llm/pypi-20241031](https://huggingface.co/datasets/garak-llm/pypi-20241031) | Oct 31, 2024 |
| RubyGems | [garak-llm/rubygems-20241031](https://huggingface.co/datasets/garak-llm/rubygems-20241031) | Oct 31, 2024 |
| crates.io | [garak-llm/crates-20250307](https://huggingface.co/datasets/garak-llm/crates-20250307) | Mar 7, 2025 |
| Dart | [garak-llm/dart-20250811](https://huggingface.co/datasets/garak-llm/dart-20250811) | Aug 11, 2025 |
| Perl | [garak-llm/perl-20250811](https://huggingface.co/datasets/garak-llm/perl-20250811) | Aug 11, 2025 |
| Raku | [garak-llm/raku-20250811](https://huggingface.co/datasets/garak-llm/raku-20250811) | Aug 11, 2025 |

---

## Security Rules (359 total)

### By Language

| Language | Rules | Categories |
|----------|-------|------------|
| JavaScript/TypeScript | 31 | XSS, injection, secrets, crypto |
| Python | 36 | Injection, deserialization, crypto, XXE |
| Java | 27 | Injection, XXE, crypto, deserialization |
| Go | 22 | Injection, crypto, race conditions |
| **PHP** | 25 | SQL injection, XSS, command injection, deserialization |
| **Ruby/Rails** | 25 | Mass assignment, CSRF, eval, YAML deserialization |
| **C/C++** | 25 | Buffer overflow, format string, memory safety |
| **Terraform/K8s** | 35 | AWS misconfig, IAM, privileged containers, RBAC |
| Dockerfile | 18 | Secrets, permissions, best practices |
| Generic (Secrets) | 31 | API keys, tokens, passwords |

### By Category

| Category | Rules | Auto-Fix |
|----------|-------|----------|
| **Injection (SQL, Command, XSS)** | 55 | Yes |
| **Hardcoded Secrets** | 50 | Yes |
| **Weak Cryptography** | 25 | Yes |
| **Insecure Deserialization** | 18 | Yes |
| **Memory Safety (C/C++)** | 20 | Yes |
| **Infrastructure as Code** | 35 | Yes |
| **Path Traversal** | 10 | Yes |
| **SSRF** | 8 | Yes |
| **XXE** | 8 | Yes |
| **SSL/TLS Issues** | 12 | Yes |
| **CSRF** | 6 | Yes |
| **Other** | 28 | Yes |

## Auto-Fix Templates (120 total)

Every detected vulnerability includes an automatic fix suggestion:

| Vulnerability | Fix Strategy |
|--------------|--------------|
| SQL Injection | Parameterized queries with placeholders |
| XSS (innerHTML) | Replace with `textContent` or DOMPurify |
| Command Injection | Use `execFile()` / `spawn()` with `shell: false` |
| Hardcoded Secrets | Environment variables (`process.env` / `os.environ`) |
| Weak Crypto (MD5/SHA1) | Replace with SHA-256 |
| Insecure Deserialization | Use `json.load()` or `yaml.safe_load()` |
| SSL verify=False | Set `verify=True` |
| Path Traversal | Use `path.basename()` / `os.path.basename()` |
| Eval/Exec | Remove or use safer alternatives |
| CORS Wildcard | Specify allowed origins |

## Example Usage

### Scanning a file

Ask Claude: *"Scan my app.js file for security issues"*

Claude will use `scan_security` and return:
- All vulnerabilities found
- Severity levels
- CWE/OWASP references
- Suggested fixes for each issue

### Auto-fixing issues

Ask Claude: *"Fix all security issues in app.js"*

Claude will use `fix_security` to:
- Apply all available auto-fixes
- Return the secured code
- List all changes made

## Supported Vulnerabilities

### Injection
- SQL Injection (multiple databases)
- NoSQL Injection (MongoDB)
- Command Injection (exec, spawn, subprocess)
- XSS (innerHTML, document.write, React dangerouslySetInnerHTML)
- LDAP Injection
- XPath Injection
- Template Injection (Jinja2, SpEL)

### Secrets & Credentials
- AWS Access Keys & Secret Keys
- GitHub Tokens (PAT, OAuth, App)
- Stripe API Keys
- OpenAI API Keys
- Slack Tokens & Webhooks
- Database URLs & Passwords
- Private Keys (RSA, SSH)
- JWT Secrets
- 25+ more token types

### Cryptography
- Weak Hashing (MD5, SHA1)
- Weak Ciphers (DES, RC4)
- ECB Mode Usage
- Insecure Random
- Weak RSA Key Size
- Weak TLS Versions

### Deserialization
- Python pickle/marshal/shelve
- YAML unsafe load
- Java ObjectInputStream
- Node serialize
- Go gob decode

### Network & SSL
- SSL Verification Disabled
- Certificate Validation Bypass
- SSRF Vulnerabilities
- Open Redirects
- CORS Misconfiguration

### Memory Safety (C/C++)
- Buffer Overflow (strcpy, strcat, sprintf, gets)
- Format String Vulnerabilities
- Use-After-Free
- Double-Free
- Integer Overflow in malloc
- Insecure memset (optimized away)
- Unsafe temp files (mktemp, tmpnam)

### Infrastructure as Code
- AWS S3 Public Access
- Security Groups Open to World (SSH, RDP)
- IAM Admin Policies (Action:*, Resource:*)
- RDS Public Access / Unencrypted
- CloudTrail Disabled
- KMS Key Rotation Disabled
- EBS Unencrypted
- EC2 IMDSv1 Enabled
- Kubernetes Privileged Containers
- K8s Run as Root
- K8s Host Network/PID
- RBAC Wildcard Permissions
- Cluster Admin Bindings

### Other
- Path Traversal
- XXE (XML External Entities)
- CSRF Disabled
- Debug Mode Enabled
- Prototype Pollution
- ReDoS (Regex DoS)
- Race Conditions
- Open Redirects
- Mass Assignment (Rails)
- Unsafe Eval/Constantize

### Adding New Rules

Rules are defined in YAML format in the `rules/` directory:

```yaml
- id: language.category.rule-name
  languages: [javascript]
  severity: ERROR
  message: "Description of the vulnerability"
  patterns:
    - "regex_pattern"
  metadata:
    cwe: "CWE-XXX"
    owasp: "Category"
```

## Feedback & Support

We welcome your feedback!

- 🐛 **Bug Reports:** [Report issues](https://github.com/sinewaveai/agent-security-scanner-mcp/issues)
- 💡 **Feature Requests:** [Request features](https://github.com/sinewaveai/agent-security-scanner-mcp/issues)
- 💬 **Questions:** [Ask questions](https://github.com/sinewaveai/agent-security-scanner-mcp/issues)

We actively monitor issues and prioritize based on community feedback.

## License

MIT