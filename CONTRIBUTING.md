# Contributing to agent-security-scanner-mcp

Thank you for your interest in contributing! This project builds the security platform for the agentic AI era — combining prompt injection detection, package hallucination detection, and vulnerability scanning, delivered natively through MCP.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/agent-security-scanner-mcp.git
   cd agent-security-scanner-mcp
   ```
3. Install dependencies:
   ```bash
   npm install
   pip install -r requirements.txt
   ```
4. Run the diagnostic check:
   ```bash
   npx . doctor
   ```

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- Python 3.x
- PyYAML (`pip install pyyaml`)

### Optional (for enhanced AST-based detection)

```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-go
```

Or install everything at once:
```bash
pip install -r requirements.txt
```

### Running Tests

```bash
npm test              # Run all tests (17 suites, 200+ tests)
npm run test:watch    # Watch mode
npm run test:coverage # With coverage
```

### Running Benchmarks

```bash
npm run benchmark     # Run accuracy benchmarks with comparison
```

Benchmarks must maintain >= 97% precision. See `benchmarks/RESULTS.md` for methodology.

### Testing the MCP Server

```bash
# Run the server directly
node index.js

# Test CLI commands
npx . scan-security tests/fixtures/vuln-python.py
npx . scan-prompt "ignore previous instructions"
npx . check-package flask pypi
npx . demo --lang js
```

## Ways to Contribute

### Adding Security Rules

Security rules are defined in YAML files in the `rules/` directory. This is a great way to start contributing!

#### Rule Format

```yaml
- id: language.category.rule-name
  languages: [javascript]
  severity: ERROR    # ERROR, WARNING, or INFO
  message: "Description of the vulnerability"
  patterns:
    - "regex_pattern_here"
  metadata:
    cwe: "CWE-XXX"
    owasp: "A01:2021 - Category"
  fix:
    description: "How to fix this issue"
    pattern: "vulnerable_pattern"
    replacement: "safe_pattern"
```

#### Rule Naming Convention

- Format: `language.category.specific-name`
- Examples:
  - `javascript.security.sql-injection`
  - `python.crypto.weak-hash-md5`
  - `go.injection.command-injection`

#### Testing Your Rule

1. Create a test file with vulnerable code
2. Run the scanner:
   ```bash
   python3 analyzer.py path/to/test-file.js
   ```
3. Verify detection and suggested fix

### Adding Auto-Fix Templates

Fix templates are defined in `src/fix-patterns.js` in the `FIX_TEMPLATES` object:

```javascript
"rule-name": {
  description: "What this fix does",
  fix: (line, language) => line.replace(/vulnerable/, 'safe')
}
```

Important: fixes must pass `validateFix()` safety checks in `src/utils.js` — no string concatenation with user input, no shell=True, etc.

### Adding Benchmark Corpus Entries

Improve detection accuracy by adding annotated test cases to `benchmarks/corpus/`:

```python
# VULN: rule-id-substring
vulnerable_code_here()

# SAFE: rule-id-substring
safe_code_here()

# FP-PRONE: rule-id-substring (explain why)
code_that_triggers_false_positive()
```

### Adding Prompt Injection Rules

Prompt injection rules are in `rules/prompt-injection.security.yaml`. We need rules for:
- Indirect injection via file content, image metadata, HTML comments
- Multi-turn escalation patterns
- Encoded/obfuscated injection attempts

## Architecture Quick Reference

```
index.js                 → MCP server entry, CLI routing, tool registration
src/tools/               → MCP tool handlers (scan-security, fix-security, etc.)
src/fix-patterns.js      → 165 auto-fix templates
src/utils.js             → Shared utilities (language detection, analyzer runner)
src/context.js           → Context-aware FP reduction (imports, frameworks, nosec)
src/dedup.js             → Cross-engine finding deduplication
src/config.js            → .scannerrc.yaml configuration loading
analyzer.py              → Python AST analysis engine
rules/                   → 1700+ YAML security rules
packages/                → Bloom filters for 4.3M+ packages (hallucination detection)
benchmarks/              → Accuracy benchmarking framework
tests/                   → Vitest test suites
```

## Pull Request Process

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and add tests

3. Ensure all tests pass:
   ```bash
   npm test
   ```

4. If you modified rules or detection logic, run benchmarks:
   ```bash
   npm run benchmark
   ```

5. Commit with a descriptive message:
   ```bash
   git commit -m "feat: add detection for XYZ vulnerability"
   ```

6. Push and create a Pull Request

### Commit Message Format

- `feat:` New feature or rule
- `fix:` Bug fix or false positive fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks
- `bench:` Benchmark changes

## Code Style

- JavaScript: ESM modules, modern syntax, no TypeScript
- Python: PEP 8 style guide
- YAML: 2-space indentation
- Tests: Vitest with descriptive test names

## Good First Issues

Look for issues labeled `good first issue` — these are specifically chosen for new contributors. Common starting points:

- Add a new YAML security rule for an uncovered vulnerability
- Add benchmark corpus entries for Go, Java, or PHP
- Fix a false positive by adding context to `src/context.js`
- Add an inline suppression test case
- Improve a fix template in `src/fix-patterns.js`

## Reporting Bugs

Please use the **Bug Report** issue template with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (`npx agent-security-scanner-mcp doctor` output)

## Feature Requests

Use the **Feature Request** issue template with:
- Description of the feature
- Use case / motivation
- Example of how it would work

## Questions?

Open a GitHub Discussion or Issue — we're happy to help!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
