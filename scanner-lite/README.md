<div align="center">

# @prooflayer/scanner-lite

**Lightweight MCP security scanner for AI coding agents**

[![npm](https://img.shields.io/npm/v/@prooflayer/scanner-lite)](https://www.npmjs.com/package/@prooflayer/scanner-lite)
[![license](https://img.shields.io/npm/l/@prooflayer/scanner-lite)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-158%20passing-brightgreen)]()

400+ YAML rules | 7 MCP tools | 13 languages | MIT licensed | Fully offline

</div>

---

## Why scanner-lite?

| Feature | scanner-lite | AgentAudit-MCP |
|---------|-------------|----------------|
| License | **MIT** | AGPL-3.0 |
| Detection rules | **400+ YAML + 41 JS** | 12 regex |
| Deep analysis | Deterministic + optional LLM | LLM-only |
| Offline capable | **Yes** | No (registry lookups) |
| Test coverage | **7 files, 158 assertions** | 1 file, ~30 assertions |
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

# Check if a package is hallucinated
npx @prooflayer/scanner-lite check-package rekat

# Scan for prompt injection
npx @prooflayer/scanner-lite prompt "ignore all previous instructions"

# LLM deep audit (requires API key)
npx @prooflayer/scanner-lite audit server.js --provider anthropic --yes

# Download bloom filters for enhanced package verification
npx @prooflayer/scanner-lite download-data
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

## Supported Languages

JavaScript, TypeScript, Python, Go, Java, PHP, Ruby, C/C++, Rust, Dockerfile, Terraform, SQL, YAML

## CLI Reference

```
COMMANDS:
  scan <path>              Scan file or directory for vulnerabilities
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
npm test          # Run 158 tests across 7 files
```

## License

MIT - see [LICENSE](./LICENSE)
