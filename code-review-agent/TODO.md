# Phase 2 — TODO

## Planned Features

- [ ] **Chunked analysis** — Split large files into chunks for analysis within token limits
- [ ] **File batching** — Send multiple small files in a single LLM call to reduce latency
- [ ] **Git diff mode** — Only analyze changed lines in a git diff, not entire files
- [ ] **Streaming output** — Stream findings as they're discovered instead of waiting for full analysis
- [ ] **Caching layer** — Hash-based LLM response cache to avoid re-analyzing unchanged files
- [ ] **Cost budgeting** — Stop analysis when estimated cost reaches a configurable threshold
- [ ] **Multi-model consensus** — Run Claude + GPT in parallel, intersect findings for higher confidence
- [ ] **MCP server integration** — Expose cr-agent as an MCP tool in the parent scanner
- [ ] **Custom prompt templates** — Allow users to customize system prompts for domain-specific analysis
- [ ] **Cross-file impact analysis** — Trace data flow across file boundaries using the dependency graph
