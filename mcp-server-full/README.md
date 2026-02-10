# agent-security-scanner-mcp-full

Full version of the MCP security scanner **with npm hallucination detection** (3.3M npm packages).

For a lightweight version without npm support, use [`agent-security-scanner-mcp`](https://www.npmjs.com/package/agent-security-scanner-mcp) (2.7 MB vs 10 MB).

## Package Comparison

| Package | Size | npm Support | Other Ecosystems |
|---------|------|-------------|------------------|
| `agent-security-scanner-mcp` | 2.7 MB | No | PyPI, RubyGems, crates.io, pub.dev, CPAN, raku.land |
| **`agent-security-scanner-mcp-full`** | **8.7 MB** | **Yes (3.3M packages)** | PyPI, RubyGems, crates.io, pub.dev, CPAN, raku.land |

## Installation

```bash
npm install -g agent-security-scanner-mcp-full
```

## Features

All features from the base package, plus:

- **npm hallucination detection** - 3.3M npm packages indexed
- Detect AI-invented JavaScript/TypeScript package names
- Bloom filter storage for efficient lookups

## Configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "agent-security-scanner-mcp-full"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add security-scanner -- npx -y agent-security-scanner-mcp-full
```

## Documentation

See the main package for full documentation: [agent-security-scanner-mcp](https://www.npmjs.com/package/agent-security-scanner-mcp)
