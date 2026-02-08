# Contributing to agent-security-scanner-mcp

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

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

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- Python 3.x
- PyYAML (`pip install pyyaml`)

### Optional (for enhanced detection)

```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

### Running Tests

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # With coverage
```

### Testing the MCP Server

```bash
# Run the server directly
node index.js

# Test with demo command
npx . demo --lang js
```

## Adding Security Rules

Security rules are defined in YAML files in the `rules/` directory.

### Rule Format

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

### Rule Naming Convention

- Format: `language.category.specific-name`
- Examples:
  - `javascript.security.sql-injection`
  - `python.crypto.weak-hash-md5`
  - `go.injection.command-injection`

### Testing Your Rule

1. Create a test file with vulnerable code
2. Run the scanner:
   ```bash
   python analyzer.py path/to/test-file.js
   ```
3. Verify detection and suggested fix

## Adding Auto-Fix Templates

Fix templates are defined in `index.js` in the `FIX_TEMPLATES` object:

```javascript
"rule-name": {
  description: "What this fix does",
  fix: (line) => line.replace(/vulnerable/, 'safe')
}
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

4. Commit with a descriptive message:
   ```bash
   git commit -m "feat: add detection for XYZ vulnerability"
   ```

5. Push and create a Pull Request

### Commit Message Format

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Code Style

- JavaScript: ESM modules, modern syntax
- Python: PEP 8 style guide
- YAML: 2-space indentation

## Reporting Bugs

Please use GitHub Issues with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Environment details (Node version, OS)

## Feature Requests

Open a GitHub Issue with:
- Description of the feature
- Use case / motivation
- Example of how it would work

## Questions?

Open a GitHub Discussion or Issue - we're happy to help!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
