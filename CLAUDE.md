# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Install dependencies
npm install

# Run all tests (28 test files, 420+ tests, ~4.5 min)
npm test

# Run specific test file
npx vitest run tests/scan-security.test.js

# Run Python tests
python -m pytest test_ast_engine.py -v
python -m pytest src/test_semgrep_rules.py -v

# Run analyzer on a file
python3 analyzer.py <file_path>

# Run CLI commands
node index.js --help
node index.js scan-security <file>
node index.js scan-prompt <text>
node index.js scan-skill <path>
node index.js audit
node index.js doctor
```

## Architecture Overview

This is an MCP (Model Context Protocol) server that provides security scanning tools for AI coding agents. It also serves as an OpenClaw plugin via the SKILL.md format.

### Directory Structure

```
agent-security-scanner-mcp/
├── index.js                    # Entry point: MCP server, tool registration, CLI routing
├── package.json                # npm package manifest (v3.9.0, ESM)
├── vitest.config.js            # Test config (60s timeout, sequential)
├── openclaw.plugin.json        # OpenClaw plugin metadata
├── server.json                 # MCP server manifest
│
├── src/
│   ├── utils.js                # Shared: detectLanguage, runAnalyzer, extractImports, toSarif
│   ├── fix-patterns.js         # 165 security fix templates
│   ├── config.js               # .scannerrc config loading
│   ├── context.js              # Context-aware filtering, isTestFile
│   ├── daemon-client.js        # Python daemon lifecycle (DaemonClient)
│   ├── dedup.js                # Cross-engine deduplication
│   ├── history.js              # Scan history tracking
│   ├── typosquat.js            # Typosquatting detection
│   ├── plugin-config.js        # Plugin configuration loader
│   ├── plugin-health.js        # Plugin health endpoint
│   ├── tools/
│   │   ├── scan-security.js    # scan_security — file vulnerability scanning
│   │   ├── fix-security.js     # fix_security — auto-fix generation
│   │   ├── check-package.js    # check_package — hallucination detection
│   │   ├── scan-packages.js    # scan_packages — bulk import scanning
│   │   ├── scan-prompt.js      # scan_agent_prompt — prompt injection detection
│   │   ├── scan-action.js      # scan_agent_action — pre-execution safety
│   │   ├── scan-project.js     # scan_project — directory scanning
│   │   ├── scan-diff.js        # scan_git_diff — git diff scanning
│   │   ├── scan-mcp.js         # scan_mcp_server — MCP server audit
│   │   ├── scan-skill.js       # scan_skill — OpenClaw skill scanning
│   │   ├── import-resolver.js  # Import graph resolution
│   │   └── project-context.js  # Project context detection
│   └── cli/
│       ├── init.js             # init — MCP config setup (9 clients incl. OpenClaw)
│       ├── doctor.js           # doctor — environment diagnostics
│       ├── demo.js             # demo — generate vulnerable files
│       ├── init-hooks.js       # init-hooks — git hook installation
│       ├── report.js           # report — HTML/JSON security reports
│       ├── audit.js            # audit — OpenClaw config audit
│       └── harden.js           # harden — auto-hardening
│
├── analyzer.py                 # Python analysis engine (AST + taint + regex)
├── ast_parser.py               # tree-sitter AST wrapper (11 languages)
├── generic_ast.py              # Generic AST converter
├── pattern_matcher.py          # Semgrep-style pattern matching
├── regex_fallback.py           # Line-based regex scanner
├── semgrep_loader.py           # YAML rule loader
├── taint_analyzer.py           # Dataflow/taint analysis
├── cross_file_analyzer.py      # Cross-file taint tracking
├── daemon.py                   # JSONL daemon wrapping analyzer
│
├── rules/                      # 1700+ YAML security rules
├── packages/                   # Bloom filters for 4.3M+ packages
├── skills/                     # OpenClaw and Claude Code skills
├── tests/                      # Vitest test suite (28 files)
├── benchmarks/                 # Accuracy benchmarks
├── templates/                  # CI/CD templates
└── scripts/                    # Build/install scripts
```

### MCP Tools (11 total)

| Tool | File | Description |
|------|------|-------------|
| `scan_security` | `src/tools/scan-security.js` | Scan code for vulnerabilities |
| `fix_security` | `src/tools/fix-security.js` | Auto-fix vulnerabilities |
| `check_package` | `src/tools/check-package.js` | Verify single package |
| `scan_packages` | `src/tools/scan-packages.js` | Check all imports in file |
| `scan_agent_prompt` | `src/tools/scan-prompt.js` | Detect prompt injection |
| `scan_agent_action` | `src/tools/scan-action.js` | Pre-execution safety check |
| `scan_project` | `src/tools/scan-project.js` | Directory scanning with grading |
| `scan_git_diff` | `src/tools/scan-diff.js` | Git diff scanning |
| `scan_mcp_server` | `src/tools/scan-mcp.js` | MCP server audit |
| `scan_skill` | `src/tools/scan-skill.js` | OpenClaw skill scanning |
| `clawproof_health` | `src/plugin-health.js` | Plugin health check |

### CLI Commands

| Command | File | Description |
|---------|------|-------------|
| `init <client>` | `src/cli/init.js` | Setup MCP for AI client |
| `doctor` | `src/cli/doctor.js` | Check environment |
| `demo --lang <lang>` | `src/cli/demo.js` | Generate demo file |
| `init-hooks` | `src/cli/init-hooks.js` | Install git hooks |
| `report <dir>` | `src/cli/report.js` | Generate security report |
| `scan-skill <path>` | `src/tools/scan-skill.js` | Scan OpenClaw skill |
| `audit` | `src/cli/audit.js` | Audit OpenClaw config |
| `harden` | `src/cli/harden.js` | Auto-harden config |

### Data Flow

1. MCP client sends tool call (e.g., `scan_security`)
2. `index.js` routes to tool handler in `src/tools/`
3. Tool calls Python via `runAnalyzerAsync()` → daemon (JSONL over stdin/stdout) → sync fallback
4. `analyzer.py` uses AST + taint + regex analysis
5. Results enhanced with fix suggestions, context filtering, framework adjustments
6. JSON/SARIF response returned to client

### Daemon Architecture

The Python daemon (`daemon.py`) provides persistent analysis with LRU caching:
- `DaemonClient` (`src/daemon-client.js`) manages lifecycle
- Communication: JSONL over stdin/stdout
- Actions: `analyze`, `cross_file_analyze`, `health`, `shutdown`
- Pre-warmed on MCP server startup (set `SCANNER_PREWARM=0` to disable)
- Falls back to `execFileSync` if daemon is unavailable

### Adding New Rules

Add rules to the appropriate YAML file in `rules/` following this format:
```yaml
- id: language.category.rule-name
  languages: [language]
  severity: ERROR|WARNING|INFO
  message: "Description of the vulnerability"
  patterns:
    - "regex_pattern_1"
  metadata:
    cwe: "CWE-XXX"
    owasp: "Category"
```

## Context Optimization

All MCP tools support a `verbosity` parameter:

| Level | Tokens | Use Case |
|-------|--------|----------|
| `minimal` | ~50 | Quick checks, CI pipelines |
| `compact` | ~200 | Normal development (default) |
| `full` | ~2000 | Debugging, compliance reports |
