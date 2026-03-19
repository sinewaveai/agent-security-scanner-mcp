# Code Review Agent

LLM-powered semantic code review agent. Uses Claude or GPT to reason about code — not rules-based static analysis.

The key differentiator is **intent profiling**: it reads project context (README, structure, dependencies) to understand what a program is supposed to do, then judges whether code patterns are dangerous in that context.

Same code, different verdicts:
- A file organizer calling `os.remove()` is **expected** — that's its purpose
- An auth API calling `fs.writeFile(req.body.path)` is **dangerous** — an auth service shouldn't write arbitrary files
- A build tool running `subprocess.run()` with hardcoded commands is **expected** — that's its purpose
- An e-commerce app calling `eval(req.query.filter)` is **dangerous** — a product catalog shouldn't eval user input

## Installation

```bash
cd code-review-agent
npm install
npm run build
```

## Usage

### Analyze a project

```bash
# Text output (default)
npx tsx bin/cr-agent.ts analyze ./path/to/project

# JSON output
npx tsx bin/cr-agent.ts analyze ./path/to/project --format json

# SARIF output
npx tsx bin/cr-agent.ts analyze ./path/to/project --format sarif

# Custom confidence threshold
npx tsx bin/cr-agent.ts analyze ./path/to/project --confidence 0.8

# Use OpenAI instead of Anthropic
npx tsx bin/cr-agent.ts analyze ./path/to/project --provider openai
```

### View intent profile

```bash
npx tsx bin/cr-agent.ts intent ./path/to/project
```

### View dependency graph

```bash
npx tsx bin/cr-agent.ts graph ./path/to/project
```

## Configuration

Set API keys via environment variables:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
```

Or create a `.cr-agent.json` in your project root:

```json
{
  "provider": "anthropic",
  "model": "claude-sonnet-4-20250514",
  "triageModel": "claude-haiku-4-5-20251001",
  "confidenceThreshold": 0.7,
  "exclude": ["node_modules", "dist", "vendor"],
  "concurrencyLimit": 5,
  "maxFileSize": 524288
}
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --provider` | LLM provider (`anthropic` or `openai`) | `anthropic` |
| `-m, --model` | Analysis model | `claude-sonnet-4-20250514` / `gpt-4o` |
| `--triage-model` | Triage model | `claude-haiku-4-5-20251001` / `gpt-4o-mini` |
| `-c, --confidence` | Confidence threshold (0-1) | `0.7` |
| `-f, --format` | Output format (`text`, `json`, `sarif`) | `text` |
| `-v, --verbose` | Show reasoning and suggested actions | `false` |
| `--exclude` | Patterns to exclude | `node_modules dist .git` |
| `--concurrency` | Max parallel LLM calls | `5` |

## Architecture

```
Pipeline: discover files → build dependency graph → profile intent
        → triage (parallel, cheap model) → analyze (parallel, analysis model)
        → dedup → filter by confidence → sort by severity → output
```

### Components

- **Intent Profiler** — Reads project README, dependencies, and structure to determine what the project is supposed to do
- **Triage** — Uses a cheap/fast model to decide which files need deep analysis
- **Semantic Analyzer** — Uses a capable model to find real bugs with chain-of-thought reasoning
- **Dependency Graph** — Resolves imports to understand file relationships
- **Context Assembler** — Token-budget-aware assembly of analysis context

### Models

| Stage | Anthropic | OpenAI |
|-------|-----------|--------|
| Triage | claude-haiku-4-5 | gpt-4o-mini |
| Analysis | claude-sonnet-4 | gpt-4o |

## Output Formats

### Text

Colored terminal output with severity badges, intent alignment, and confidence scores.

### JSON

Raw `AnalysisResult` object with findings, intent profile, file results, and stats.

### SARIF

Full SARIF 2.1.0 spec output for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other tools.

## Testing

```bash
npm test           # Run all tests (no API keys needed)
npm run test:watch # Watch mode
npm run lint       # Type check
npm run build      # Compile TypeScript
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical/high findings |
| 1 | Critical or high findings found |
| 2 | Runtime error |
