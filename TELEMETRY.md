# Telemetry

`agent-security-scanner-mcp` collects **anonymous** usage statistics to help us understand how the tool is used and where to focus improvements. This document provides full transparency about what is collected, how to opt out, and how the data is handled.

## Why We Collect Telemetry

- Understand which tools and features are most used
- Track language distribution and engine health (AST vs regex)
- Identify common errors and failure modes
- Measure prompt injection detection adoption
- Guide roadmap priorities based on real-world usage

## What Is Collected

All events include a common envelope:

| Field | Description |
|-------|-------------|
| `schema_version` | Event schema version (currently `1`) |
| `event` | Event name (e.g., `tool.invoked`, `scan.completed`) |
| `timestamp` | ISO 8601 UTC timestamp |
| `machine_id` | SHA-256 hash (see below) — not reversible to identity |
| `session_id` | Random UUID per process |
| `scanner_version` | Package version |
| `os_platform` | `darwin`, `linux`, or `win32` |
| `os_arch` | `x64`, `arm64`, etc. |
| `node_version` | Node.js version |
| `invocation_mode` | `mcp` or `cli` |

### Events

| Event | When | Key Fields |
|-------|------|------------|
| `install` | After `npm install` | `engine_available`, `python_available`, `is_ci` |
| `tool.invoked` | Every tool call | `tool_name`, `duration_ms`, `success`, `error_code` |
| `scan.completed` | After scans | `engine_mode`, `language`, `files_scanned`, `issues_count`, `grade` |
| `prompt.scanned` | Prompt/action scans | `action` (BLOCK/WARN/ALLOW), `risk_level`, `findings_count` |
| `package.checked` | Package checks | `ecosystem`, `packages_checked`, `hallucinated_count` |
| `error` | On tool errors | `error_code`, `error_class` |

**Field values:**
- `engine_available`: `ast` (tree-sitter available), `regex` (Python available but tree-sitter install failed), `regex-only` (no Python)

## What Is NEVER Collected

- File paths or file names
- File contents or source code
- Environment variables or their values
- Usernames, hostnames, or IP addresses
- Rule IDs matched or finding messages
- Prompt text or action values
- Fix suggestions or code snippets
- API keys, secrets, or credentials

## Machine ID

The machine ID is a **SHA-256 hash** of `hostname + homedir + username + platform + arch`. This produces a stable, deterministic identifier that:

- Cannot be reversed to recover hostname, username, or home directory
- Is used only to count unique machines (not identify individuals)
- Can be reset by deleting `~/.agent-security-scanner-mcp/telemetry.json` (note: the same hash will be regenerated since it's derived from stable system properties; to get a different ID, the underlying hostname, homedir, username, platform, or arch must change)

## How to Opt Out

Any of the following will disable telemetry entirely:

1. **Universal standard:** `export DO_NOT_TRACK=1`
2. **Scanner-specific:** `export SCANNER_TELEMETRY_DISABLED=1`
3. **CLI command:** `npx agent-security-scanner-mcp telemetry --off`
4. **CI environments:** Automatically disabled when `CI=true` or `CI=1` (covers GitHub Actions, GitLab CI, CircleCI, Travis CI, Jenkins, and most CI platforms that set this variable)

Check status: `npx agent-security-scanner-mcp telemetry --status`

Re-enable: `npx agent-security-scanner-mcp telemetry --on`

## Debug Mode

Set `SCANNER_TELEMETRY_DEBUG=1` to print events to stderr without sending them:

```bash
SCANNER_TELEMETRY_DEBUG=1 npx agent-security-scanner-mcp scan-security ./app.py
```

## Data Retention

- **Raw events:** 90 days (auto-expired via BigQuery partition expiration)
- **Aggregate views:** Query-time views over raw data — retained as long as underlying partitions exist (90 days)

## Backend Architecture

Events are sent to a GCP Cloud Function via HTTPS POST, which writes to BigQuery. The pipeline:

1. Client batches events in memory (max 10, or every 30s)
2. Fire-and-forget `fetch()` with 5s timeout — failures are silently discarded
3. Cloud Function validates schema, applies server-side field allowlist
4. Sanitized events written to BigQuery (partitioned by date, clustered by event + machine_id)
5. IP addresses are not stored in BigQuery. Note: GCP Cloud Functions may retain request metadata (including source IPs) in Cloud Logging with default settings. Configure a Log Router exclusion filter to prevent this.

## Implementation

The telemetry module (`src/telemetry.js`) has zero external dependencies — it uses only Node.js built-ins (`crypto`, `fs`, `os`, `path`) and the global `fetch` API. Telemetry failures never impact scanner functionality.
