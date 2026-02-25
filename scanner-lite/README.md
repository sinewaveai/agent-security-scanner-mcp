<div align="center">

# @prooflayer/scanner-lite

**Lightweight MCP security scanner for AI coding agents**

[![npm](https://img.shields.io/npm/v/@prooflayer/scanner-lite)](https://www.npmjs.com/package/@prooflayer/scanner-lite)
[![license](https://img.shields.io/npm/l/@prooflayer/scanner-lite)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-311%20passing-brightgreen)]()
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-blue)]()

418 YAML rules | 8 MCP tools | 13 languages | OWASP Agentic Top 10 | MIT licensed | Fully offline

</div>

---

## Why scanner-lite?

| Feature | scanner-lite | AgentAudit-MCP |
|---------|-------------|----------------|
| License | **MIT** | AGPL-3.0 |
| Detection rules | **418 YAML + 33 JS** | 12 regex |
| OWASP Agentic Top 10 | **ASI-01 through ASI-10** | None |
| Deep analysis | Deterministic + optional LLM | LLM-only |
| Offline capable | **Yes** | No (registry lookups) |
| Test coverage | **8 files, 311 assertions** | 1 file, ~30 assertions |
| Privacy | LLM opt-in with consent | Sends code by default |
| Architecture | **Clean modular src/** | Monolithic 88KB cli.mjs |
| Package detection | Typosquat + bloom filters (4.3M+) | None |
| Auto-fix | **165 fix templates** | None |
| SARIF output | **Yes** | No |
| Package size | **~95KB compressed** | ~230KB |

## Quick Start

### As MCP Server

```bash
npx @prooflayer/scanner-lite
```

Add to your MCP client config (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "scanner-lite": {
      "command": "npx",
      "args": ["-y", "@prooflayer/scanner-lite"]
    }
  }
}
```

### As CLI

```bash
# Scan a file or directory
npx @prooflayer/scanner-lite scan ./src

# Inspect a live MCP server for tool poisoning
npx @prooflayer/scanner-lite inspect -- node server.js
npx @prooflayer/scanner-lite inspect --json -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Check if a package is hallucinated
npx @prooflayer/scanner-lite check-package rekat

# Scan for prompt injection
npx @prooflayer/scanner-lite prompt "ignore all previous instructions"

# LLM deep audit (requires API key)
npx @prooflayer/scanner-lite audit server.js --provider anthropic --yes

# Download bloom filters for enhanced package verification
npx @prooflayer/scanner-lite download-data
```

### As GitHub Action

```yaml
- uses: sinewaveai/agent-security-scanner-mcp/scanner-lite@main
  with:
    path: ./src
    format: text    # or json, sarif
    fail-on: 'true' # exit 1 on findings
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_security` | Scan code for vulnerabilities (400+ rules, 13 languages) |
| `scan_mcp_server` | MCP server audit — tool poisoning, unicode attacks, rug pull detection |
| `scan_agent_prompt` | Prompt injection detection with deobfuscation (base64, morse, zalgo, braille) |
| `check_package` | Package hallucination detection with typosquatting analysis |
| `scan_packages` | Bulk import scanning across 7 ecosystems |
| `fix_security` | Auto-fix generation with 165 fix templates |
| `deep_audit` | Optional LLM deep security audit (5 providers) |
| `inspect_mcp_server` | Live MCP server inspection — connect via stdio, scan tool definitions for poisoning |

## OWASP Agentic Security Top 10

All 418 rules are tagged with OWASP Agentic Security Initiative categories:

| Category | Description | Rules |
|----------|-------------|-------|
| ASI-01 | Goal Hijacking & Prompt Injection | ~80 |
| ASI-02 | Tool Misuse & Unsafe Execution | ~60 |
| ASI-03 | Identity & Privilege Escalation | ~30 |
| ASI-04 | Supply Chain & Dependency Risks | ~15 |
| ASI-05 | Arbitrary Code Execution | ~50 |
| ASI-06 | Memory Poisoning (vector stores, RAG) | 4 |
| ASI-07 | Inter-Agent Communication | 3 |
| ASI-08 | Cascading Failures (loops, timeouts) | 4 |
| ASI-09 | Trust Exploitation (auto-approve) | 3 |
| ASI-10 | Rogue Agents (kill switch, spawning) | 4 |

## Supported Languages

JavaScript, TypeScript, Python, Go, Java, PHP, Ruby, C/C++, Rust, Dockerfile, Terraform, SQL, YAML

## CLI Reference

```
COMMANDS:
  scan <path>              Scan file or directory for vulnerabilities
  inspect -- <cmd> [args]  Inspect a live MCP server for tool poisoning
  audit <path>             LLM deep security audit (requires API key)
  check-package <name>     Check if a package is hallucinated
  prompt <text>            Scan text for prompt injection
  download-data            Download bloom filters for offline pkg verification

FLAGS:
  --json                 Output as JSON
  --sarif                Output as SARIF (scan only)
  --quiet                Suppress non-essential output
  --no-color             Disable ANSI colors
  --verbose              Show full details
  --timeout <ms>         Inspection timeout (default: 10000)
  --provider <p>         LLM provider: anthropic, openai, gemini, ollama, openrouter
  --model <m>            LLM model name
  --ecosystem <e>        Package ecosystem (default: npm)
  --yes                  Consent to LLM data sharing (audit command)

EXIT CODES:
  0  Clean / success
  1  Findings detected
  2  Error
```

## LLM Deep Audit

The `deep_audit` tool / `audit` CLI command provides AI-powered security analysis using a 3-pass methodology (UNDERSTAND, DETECT, CLASSIFY). Supports 5 providers:

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| OpenAI | `OPENAI_API_KEY` | gpt-4o |
| Gemini | `GEMINI_API_KEY` | gemini-2.0-flash |
| Ollama | (none — local) | llama3.1 |
| OpenRouter | `OPENROUTER_API_KEY` | anthropic/claude-sonnet-4 |

**Privacy:** LLM audit requires explicit consent via `PROOFLAYER_LLM_CONSENT=1` env var or `--yes` flag. Code is sent to the selected provider's API.

## Package Hallucination Detection

Ships with typosquatting heuristics (always available offline). For enhanced detection against 4.3M+ known packages:

```bash
npx @prooflayer/scanner-lite download-data
```

This downloads bloom filter data to `~/.prooflayer/data/` for npm, PyPI, RubyGems, and crates.io.

## Verbosity Levels

All MCP tools support a `verbosity` parameter:

| Level | Tokens | Use Case |
|-------|--------|----------|
| `minimal` | ~50 | Quick checks, CI pipelines |
| `compact` | ~200 | Normal development (default) |
| `full` | ~2000 | Debugging, compliance reports |

## Dependencies

Only 2 runtime dependencies:
- `@modelcontextprotocol/sdk` — MCP protocol support
- `zod` — Schema validation

## Development

```bash
cd scanner-lite
npm install
npm test          # Run 311 tests across 8 files
```

## License

MIT - see [LICENSE](./LICENSE)
