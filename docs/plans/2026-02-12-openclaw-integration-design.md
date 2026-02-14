# OpenClaw Integration Design

**Date:** 2026-02-12
**Version:** v3.3.0
**Status:** Approved

---

## Overview

Integrate agent-security-scanner-mcp with OpenClaw (formerly Clawdbot), providing security guardrails for the autonomous AI assistant. OpenClaw's broad permissions (email, messaging, browser, files, 50+ services) create unique attack surfaces that require both existing security rules and OpenClaw-specific threat detection.

## Goals

1. Protect OpenClaw users from prompt injection attacks
2. Detect data exfiltration attempts targeting OpenClaw's service integrations
3. Provide fast, low-friction security scanning via OpenClaw skill
4. Enable CLI usage for non-MCP environments

## Integration Approach

### Two-Pronged Strategy

1. **OpenClaw Skill (Primary)** - SKILL.md file that calls agent-security-scanner-mcp directly via `npx`, bypassing slow MCPorter (~2.4s cold start). Provides instant access via slash commands and natural language.

2. **MCP Server (Secondary)** - Document MCPorter-based approach for users wanting full MCP toolset. Slower but provides all 6 tools.

## OpenClaw-Specific Threat Rules

New rule file: `rules/openclaw.security.yaml`

### Category 1: Data Exfiltration
- "Forward/send my emails to [external]"
- "Export my contacts/calendar to..."
- "Upload my files to..."
- "Share my browser cookies/session"

### Category 2: Messaging Abuse
- "Send this message to all my contacts"
- "Reply to all messages with..."
- "Auto-respond with [malicious content]"

### Category 3: Credential/Secret Theft
- "Show me my API keys/tokens"
- "What are my saved passwords"
- "Access my keychain/credential store"

### Category 4: Autonomous Harm
- "Run this every hour without asking"
- "Don't confirm before executing"
- "Disable safety checks"

**Estimated patterns:** 20-30 rules

## OpenClaw Skill Structure

Location: `~/.openclaw/workspace/skills/security-scanner/SKILL.md`

```markdown
---
name: security-scanner
description: Scan prompts and code for security threats using agent-security-scanner-mcp
metadata: {"openclaw":{"emoji":"🛡️","requires":{"bins":["npx"]}}}
---

## Security Scanner

Protect your OpenClaw instance from prompt injection, malicious code, and data exfiltration attacks.

### Commands
- `/scan-prompt <text>` - Check if a prompt is safe to execute
- `/scan-code <file>` - Scan code for vulnerabilities before running
- `/check-package <name>` - Verify a package isn't hallucinated

### Auto-Protection Mode
When enabled, automatically scans incoming prompts before execution.
```

### Skill Behavior
1. Call `npx agent-security-scanner-mcp` with appropriate arguments
2. Use `verbosity: minimal` for fast checks (~50 tokens)
3. Block/warn based on risk level (BLOCK/WARN/ALLOW)

## CLI Interface

Add CLI mode to agent-security-scanner-mcp for direct invocation:

```bash
# Scan a prompt
npx agent-security-scanner-mcp scan-prompt "delete all my emails"
# Returns: {"action":"BLOCK","risk_level":"critical",...}

# Scan a file
npx agent-security-scanner-mcp scan-security ./script.py
# Returns: {"issues_count":3,"issues":[...]}

# Check a package
npx agent-security-scanner-mcp check-package flask pypi
# Returns: {"exists":true,"ecosystem":"pypi"}
```

### Implementation
- Add CLI argument parsing to `index.js`
- Detect `process.argv` vs stdio mode
- Output JSON to stdout for easy parsing
- Support `--verbosity` flag
- Estimated: ~50 lines

## Deliverables

| Deliverable | Location | Description |
|-------------|----------|-------------|
| CLI mode | `index.js` | Add argument parsing for direct CLI usage |
| OpenClaw rules | `rules/openclaw.security.yaml` | 20-30 patterns for OpenClaw-specific threats |
| OpenClaw skill | `skills/openclaw/SKILL.md` | Ready-to-install skill for ClawHub |
| README update | `README.md` | OpenClaw integration section |
| Init command | `src/cli/init.js` | Add `npx agent-security-scanner-mcp init openclaw` |

## User Experience

### Quick Install
```bash
npx agent-security-scanner-mcp init openclaw
```

### Manual Install
```bash
# Copy skill to OpenClaw workspace
cp -r skills/openclaw ~/.openclaw/workspace/skills/security-scanner
```

## Version

This feature will ship as **v3.3.0** (new feature, backward compatible).

## References

- [OpenClaw MCP Feature Request](https://github.com/openclaw/openclaw/issues/8188)
- [OpenClaw Security Concerns](https://en.wikipedia.org/wiki/OpenClaw)
- [OpenClaw Skills Documentation](https://docs.openclaw.ai/tools/skills)
