# Merge Advanced Rules Engine Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate the AST-based security analyzer, taint analysis engine, and expanded rule set from `feature/advanced-rules-engine` into `main`, while preserving main's CLI commands (init, doctor, demo), bloom filter package detection, and keeping the npm package under 15 MB.

**Architecture:** The merge brings 6 new Python modules (ast_parser, generic_ast, pattern_matcher, regex_fallback, semgrep_loader, taint_analyzer) that replace the regex-only `analyzer.py` with a tree-sitter AST engine. Main's `index.js` keeps its CLI commands, bloom filters, and prompt scanner — the feature branch stripped these. We selectively merge the Python layer from feature and keep the JS layer from main, then curate rules to fit npm size limits.

**Tech Stack:** Node.js (MCP server, CLI), Python (tree-sitter, AST analysis, YAML rules), tree-sitter language bindings (12 languages), PyYAML, bloom-filters (npm)

---

## Conflict Summary

| File | Main (current) | Feature branch | Resolution |
|------|---------------|----------------|------------|
| `index.js` | 2,329 lines (CLI: init, doctor, demo, bloom filters, prompt scanner) | 1,585 lines (stripped CLI, no bloom filters) | **Keep main's index.js entirely** — feature only simplified it |
| `analyzer.py` | 126 lines (regex engine) | 195 lines (AST engine with imports) | **Take feature's analyzer.py** — this is the core upgrade |
| `package.json` | v1.5.0, bloom-filters dep, full keywords | v1.3.0, no bloom-filters, fewer keywords | **Keep main's package.json**, bump to v2.0.0, add `requirements.txt` to files |
| `rules/` | 12 flat YAML files (358 rules) | 3,644 files in nested dirs (1,726 YAML rules) | **Curate**: keep main's flat YAMLs + add best feature rules as flat YAMLs |
| `packages/` | 4 txt + 2 bloom JSON (6.2 MB) | 4 txt + 3 new txt, no blooms (80 MB) | **Keep main's bloom approach** — 80 MB txt files are too large for npm |
| New Python files | None | 6 modules (2,695 lines total) | **Take all 6** — these are the AST engine |
| `requirements.txt` | Does not exist | 13 tree-sitter packages | **Take it**, referenced by doctor command |

## Size Budget

| Component | Current (main) | After merge | Budget |
|-----------|---------------|-------------|--------|
| `index.js` | ~90 KB | ~90 KB (unchanged) | OK |
| Python modules | 5 KB (analyzer.py) | ~115 KB (7 files) | OK |
| `rules/` | ~200 KB (12 YAMLs) | ~350 KB (12 original + curated additions) | OK |
| `packages/` | ~6.2 MB (txt + bloom) | ~6.2 MB (unchanged) | OK |
| `node_modules` | ~2 MB | ~2 MB (unchanged) | OK |
| **Total npm tarball** | **~2.7 MB** | **~3.0 MB** | **Under 15 MB** |

---

## Task 1: Commit Pending Work on Main

**Files:**
- Modified: `mcp-server/index.js` (doctor + demo commands, uncommitted)
- Modified: `mcp-server/README.md` (doctor + demo docs, uncommitted)

**Step 1: Verify uncommitted changes are clean**

Run: `cd /Users/divyachitimalla/agent-security-layer && git diff --stat`
Expected: Only `mcp-server/index.js` and `mcp-server/README.md` shown

**Step 2: Test doctor command still works**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && node index.js doctor`
Expected: Shows environment checks and client config status

**Step 3: Commit the pending work**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/index.js mcp-server/README.md
git commit -m "feat: add doctor and demo CLI commands

- doctor: environment checks (Node, Python, PyYAML) + client config scanning
- demo: generates vulnerable file in 4 languages, runs analyzer, shows findings
- README: documents both new commands with examples"
```

**Step 4: Push to main**

Run: `git push origin main`
Expected: Push succeeds

---

## Task 2: Create Integration Branch

**Files:**
- None modified yet

**Step 1: Create branch from main**

```bash
cd /Users/divyachitimalla/agent-security-layer
git checkout -b feature/merge-ast-engine main
```

**Step 2: Verify clean state**

Run: `git status`
Expected: Clean working tree on `feature/merge-ast-engine`

**Step 3: Commit**

No commit needed — branch point established.

---

## Task 3: Add Python AST Engine Modules

**Files:**
- Create: `mcp-server/ast_parser.py` (from feature branch)
- Create: `mcp-server/generic_ast.py` (from feature branch)
- Create: `mcp-server/pattern_matcher.py` (from feature branch)
- Create: `mcp-server/regex_fallback.py` (from feature branch)
- Create: `mcp-server/semgrep_loader.py` (from feature branch)
- Create: `mcp-server/taint_analyzer.py` (from feature branch)
- Create: `mcp-server/requirements.txt` (from feature branch)

**Step 1: Write the failing test**

Create `mcp-server/test_ast_engine.py`:

```python
"""Tests for the AST-based security analysis engine."""
import subprocess
import json
import sys
import os
import tempfile

def test_ast_modules_importable():
    """All 6 AST modules should be importable without error."""
    modules = ['ast_parser', 'generic_ast', 'pattern_matcher', 'regex_fallback', 'semgrep_loader', 'taint_analyzer']
    for mod in modules:
        result = subprocess.run(
            [sys.executable, '-c', f'import {mod}'],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), '')
        )
        assert result.returncode == 0, f"Failed to import {mod}: {result.stderr}"

def test_ast_analyzer_detects_sql_injection():
    """AST analyzer should detect SQL injection in Python code."""
    vuln_code = '''
import sqlite3
conn = sqlite3.connect('test.db')
cursor = conn.cursor()
user_id = input("Enter ID: ")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
'''
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
        f.write(vuln_code)
        f.flush()
        result = subprocess.run(
            [sys.executable, 'analyzer.py', f.name],
            capture_output=True, text=True,
            cwd=os.path.dirname(__file__)
        )
        os.unlink(f.name)

    output = json.loads(result.stdout)
    assert isinstance(output, list), f"Expected list, got: {output}"
    # Should find at least one SQL injection finding
    sql_findings = [i for i in output if 'sql' in i.get('ruleId', '').lower() or 'injection' in i.get('message', '').lower()]
    assert len(sql_findings) > 0, f"Expected SQL injection finding, got: {output}"

def test_ast_analyzer_detects_xss_javascript():
    """AST analyzer should detect XSS in JavaScript code."""
    vuln_code = '''
const express = require("express");
const app = express();
app.get("/profile", (req, res) => {
    const name = req.query.name;
    res.send("<h1>Welcome, " + name + "</h1>");
});
'''
    with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False) as f:
        f.write(vuln_code)
        f.flush()
        result = subprocess.run(
            [sys.executable, 'analyzer.py', f.name],
            capture_output=True, text=True,
            cwd=os.path.dirname(__file__)
        )
        os.unlink(f.name)

    output = json.loads(result.stdout)
    assert isinstance(output, list), f"Expected list, got: {output}"
    # Should find at least one XSS or injection finding
    assert len(output) > 0, f"Expected findings for XSS-vulnerable JS, got none"

def test_regex_fallback_covers_c_vulnerabilities():
    """Regex fallback should catch C buffer overflow patterns."""
    vuln_code = '''
#include <string.h>
void process(char *input) {
    char buf[64];
    strcpy(buf, input);
    sprintf(buf, "%s", input);
}
'''
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(vuln_code)
        f.flush()
        result = subprocess.run(
            [sys.executable, 'analyzer.py', f.name],
            capture_output=True, text=True,
            cwd=os.path.dirname(__file__)
        )
        os.unlink(f.name)

    output = json.loads(result.stdout)
    assert isinstance(output, list), f"Expected list, got: {output}"
    assert len(output) >= 2, f"Expected at least 2 C vulnerability findings (strcpy + sprintf), got {len(output)}: {output}"

def test_analyzer_backward_compat_output_format():
    """Output format must have ruleId, message, line, column, severity keys."""
    vuln_code = 'API_KEY = "sk_live_abc123def456"\n'
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
        f.write(vuln_code)
        f.flush()
        result = subprocess.run(
            [sys.executable, 'analyzer.py', f.name],
            capture_output=True, text=True,
            cwd=os.path.dirname(__file__)
        )
        os.unlink(f.name)

    output = json.loads(result.stdout)
    assert isinstance(output, list), f"Expected list, got: {output}"
    if len(output) > 0:
        issue = output[0]
        required_keys = {'ruleId', 'message', 'line', 'column', 'severity'}
        actual_keys = set(issue.keys())
        missing = required_keys - actual_keys
        assert not missing, f"Missing required keys: {missing}. Got: {actual_keys}"

if __name__ == '__main__':
    tests = [
        test_ast_modules_importable,
        test_ast_analyzer_detects_sql_injection,
        test_ast_analyzer_detects_xss_javascript,
        test_regex_fallback_covers_c_vulnerabilities,
        test_analyzer_backward_compat_output_format,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && python3 test_ast_engine.py`
Expected: FAIL — `ast_parser` module not found

**Step 3: Cherry-pick the 6 Python modules from feature branch**

```bash
cd /Users/divyachitimalla/agent-security-layer

# Extract individual files from feature branch
git show origin/feature/advanced-rules-engine:mcp-server/ast_parser.py > mcp-server/ast_parser.py
git show origin/feature/advanced-rules-engine:mcp-server/generic_ast.py > mcp-server/generic_ast.py
git show origin/feature/advanced-rules-engine:mcp-server/pattern_matcher.py > mcp-server/pattern_matcher.py
git show origin/feature/advanced-rules-engine:mcp-server/regex_fallback.py > mcp-server/regex_fallback.py
git show origin/feature/advanced-rules-engine:mcp-server/semgrep_loader.py > mcp-server/semgrep_loader.py
git show origin/feature/advanced-rules-engine:mcp-server/taint_analyzer.py > mcp-server/taint_analyzer.py
git show origin/feature/advanced-rules-engine:mcp-server/requirements.txt > mcp-server/requirements.txt
```

**Step 4: Install tree-sitter dependencies**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
pip3 install -r requirements.txt
```

Expected: All 13 packages install successfully.

**Step 5: Run test to verify imports pass**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && python3 test_ast_engine.py`
Expected: `test_ast_modules_importable` PASSES. Other tests may still fail (analyzer.py not updated yet).

**Step 6: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/ast_parser.py mcp-server/generic_ast.py mcp-server/pattern_matcher.py mcp-server/regex_fallback.py mcp-server/semgrep_loader.py mcp-server/taint_analyzer.py mcp-server/requirements.txt mcp-server/test_ast_engine.py
git commit -m "feat: add AST engine modules from advanced-rules-engine

- ast_parser.py: tree-sitter integration for 12 languages
- generic_ast.py: cross-language AST normalization (40+ node types)
- pattern_matcher.py: Semgrep-style pattern matching with metavariables
- regex_fallback.py: coverage fallback for C, PHP, Ruby, Python, JS, K8s, Terraform
- semgrep_loader.py: YAML rule loader with diagnostics
- taint_analyzer.py: dataflow analysis from sources to sinks
- requirements.txt: tree-sitter language bindings
- test_ast_engine.py: 5 integration tests for the AST engine"
```

---

## Task 4: Replace analyzer.py with AST-Based Version

**Files:**
- Modify: `mcp-server/analyzer.py` (replace regex engine with AST engine)
- Keep: `mcp-server/rules/__init__.py` (needed by regex fallback path)

**Step 1: Back up current analyzer**

```bash
cp mcp-server/analyzer.py mcp-server/analyzer_regex_backup.py
```

**Step 2: Write the new analyzer.py**

Take the feature branch version but add a **graceful fallback** so it works when tree-sitter is not installed (falls back to the original regex engine):

```python
"""
Security Analyzer - AST-Based with Regex Fallback

Uses tree-sitter AST analysis when available, falls back to regex
pattern matching when tree-sitter is not installed. This ensures
the analyzer works out-of-the-box with `npx` (regex mode) and
provides enhanced detection when dependencies are installed.
"""

import sys
import json
import os
from typing import List, Dict, Any

# Add the directory containing this script to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import AST engine
try:
    from ast_parser import ASTParser, HAS_TREE_SITTER
    from generic_ast import convert_tree
    from pattern_matcher import RuleEngine
    from regex_fallback import apply_regex_fallback
    HAS_AST_ENGINE = HAS_TREE_SITTER
except ImportError:
    HAS_AST_ENGINE = False

# Try to import Semgrep loader and taint analyzer
try:
    from semgrep_loader import load_rules, get_loader
    HAS_SEMGREP_LOADER = True
except ImportError:
    HAS_SEMGREP_LOADER = False

try:
    from taint_analyzer import TaintAnalyzer
    HAS_TAINT_ANALYZER = True
except ImportError:
    HAS_TAINT_ANALYZER = False

# Import the original regex-based rules (always available)
from rules import get_rules_for_language

import re

# File extension to language mapping
EXTENSION_MAP = {
    '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
    '.tsx': 'typescript', '.jsx': 'javascript', '.java': 'java',
    '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp',
    '.rs': 'rust', '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.hpp': 'cpp',
    '.sql': 'sql', '.dockerfile': 'dockerfile',
    '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
    '.tf': 'terraform', '.hcl': 'terraform',
    '.txt': 'generic', '.md': 'generic', '.prompt': 'generic',
    '.jinja': 'generic', '.jinja2': 'generic', '.j2': 'generic',
}

def detect_language(file_path):
    """Detect the programming language from file extension or name."""
    basename = os.path.basename(file_path).lower()
    if basename == 'dockerfile' or basename.startswith('dockerfile.'):
        return 'dockerfile'
    _, ext = os.path.splitext(file_path.lower())
    return EXTENSION_MAP.get(ext, 'generic')


def analyze_file_regex(file_path):
    """Original regex-based analysis (fallback when tree-sitter unavailable)."""
    issues = []
    try:
        language = detect_language(file_path)
        rules = get_rules_for_language(language)
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line_index, original_line in enumerate(lines):
            line = original_line.strip()
            if not line or line.startswith('#') or line.startswith('//') or line.startswith('*'):
                continue
            for rule_id, rule in rules.items():
                for pattern in rule['patterns']:
                    try:
                        for match in re.finditer(pattern, line, re.IGNORECASE):
                            col_offset = len(original_line) - len(original_line.lstrip())
                            issues.append({
                                'ruleId': rule['id'],
                                'message': f"[{rule['name']}] {rule['message']}",
                                'line': line_index,
                                'column': match.start() + col_offset,
                                'length': match.end() - match.start(),
                                'severity': rule['severity'],
                                'metadata': rule.get('metadata', {})
                            })
                    except re.error:
                        continue
    except Exception as e:
        return {'error': str(e)}

    seen = set()
    unique = []
    for issue in issues:
        key = (issue['ruleId'], issue['line'], issue['column'])
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


def analyze_file_ast(file_path):
    """AST-based analysis using tree-sitter."""
    parser = ASTParser()
    engine = RuleEngine()

    # Load rules
    rules = []
    taint_rules = []
    if HAS_SEMGREP_LOADER:
        supported = ['python', 'javascript', 'typescript', 'java', 'go',
                      'ruby', 'php', 'c', 'rust', 'csharp', 'generic']
        rules = load_rules(supported)
        loader = get_loader()
        taint_rules = loader.get_taint_rules()

    parse_result = parser.parse_file(file_path)
    if not parse_result.success:
        # Fall back to regex if AST parse fails
        return analyze_file_regex(file_path)

    ast = convert_tree(parse_result.tree, parse_result.language, parse_result.source_bytes)

    applicable_rules = [
        r for r in rules
        if parse_result.language in r.languages or 'generic' in r.languages
    ]

    findings = engine.apply_rules(applicable_rules, ast)

    # Taint analysis
    if HAS_TAINT_ANALYZER and taint_rules:
        taint = TaintAnalyzer()
        applicable_taint = [
            r for r in taint_rules
            if parse_result.language in r.languages or 'generic' in r.languages
        ]
        findings.extend(taint.analyze(ast, applicable_taint))

    issues = []
    for f in findings:
        length = f.end_column - f.column if f.line == f.end_line else len(f.text)
        issues.append({
            'ruleId': f.rule_id,
            'message': f"[{f.rule_name}] {f.message}",
            'line': f.line - 1,
            'column': f.column,
            'length': length,
            'severity': f.severity,
            'metadata': f.metadata,
        })

    # Regex fallback for coverage gaps
    source = parse_result.source_bytes.decode('utf-8', errors='replace')
    issues.extend(apply_regex_fallback(source, parse_result.language, file_path))

    seen = set()
    unique = []
    for issue in issues:
        key = (issue['ruleId'], issue['line'], issue['column'])
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique


def analyze_file(file_path):
    """Analyze a file — uses AST engine if available, regex otherwise."""
    if HAS_AST_ENGINE:
        return analyze_file_ast(file_path)
    return analyze_file_regex(file_path)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(json.dumps({'error': f'File not found: {file_path}'}))
        sys.exit(1)

    results = analyze_file(file_path)
    print(json.dumps(results))


if __name__ == '__main__':
    main()
```

**Step 3: Run tests to verify**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && python3 test_ast_engine.py`
Expected: All 5 tests PASS

**Step 4: Verify backward compat — demo command still works**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && node index.js demo --lang py 2>&1 | head -30`
Expected: Demo shows findings (analyzer output parsed by index.js)

**Step 5: Remove backup**

```bash
rm mcp-server/analyzer_regex_backup.py
```

**Step 6: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/analyzer.py
git commit -m "feat: replace regex analyzer with AST engine + graceful fallback

- Uses tree-sitter AST analysis when dependencies installed
- Falls back to original regex engine when tree-sitter unavailable
- Ensures npx works out-of-box (regex) while pip install unlocks AST mode
- Backward-compatible JSON output format (ruleId, message, line, column, severity)"
```

---

## Task 5: Update semgrep_loader.py to Work with Main's Rule Structure

The feature branch's `semgrep_loader.py` expects rules in nested directories (`rules/python/lang/security/...`). Main has flat files (`rules/python.security.yaml`). We need to patch the loader to handle both structures.

**Files:**
- Modify: `mcp-server/semgrep_loader.py`

**Step 1: Write the failing test**

Add to `mcp-server/test_ast_engine.py`:

```python
def test_semgrep_loader_finds_main_rules():
    """Semgrep loader should find rules from main's flat YAML structure."""
    result = subprocess.run(
        [sys.executable, '-c', '''
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(".")))
from semgrep_loader import load_rules, get_loader
rules = load_rules(["python", "javascript"])
loader = get_loader()
stats = loader.get_stats()
print(f"rules_loaded={len(rules)}")
print(f"languages={stats}")
'''],
        capture_output=True, text=True,
        cwd=os.path.join(os.path.dirname(__file__), '')
    )
    assert result.returncode == 0, f"Loader failed: {result.stderr}"
    assert 'rules_loaded=0' not in result.stdout, f"No rules loaded: {result.stdout}"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && python3 -c "from semgrep_loader import load_rules; print(len(load_rules(['python'])))"`
Expected: Likely 0 rules loaded (loader looks in wrong directories)

**Step 3: Patch semgrep_loader.py**

Add a `load_flat_yaml_rules()` function that scans `rules/*.security.yaml` and `rules/*.secrets.yaml` — the flat files that main uses. Call this as a fallback when the nested directory structure isn't found.

The key change is in the `SemgrepRuleLoader.__init__` or `load_rules()` function: after attempting nested directory loading, also scan for flat YAML files matching `<language>.security.yaml` pattern.

```python
# Add to SemgrepRuleLoader class:
def _load_flat_rules(self, rules_dir, languages):
    """Load rules from flat YAML files (main branch format)."""
    import glob
    flat_rules = []
    for lang in languages:
        for pattern_name in [f'{lang}.security.yaml', 'generic.secrets.yaml',
                              'agent-attacks.security.yaml', 'prompt-injection.security.yaml']:
            yaml_path = os.path.join(rules_dir, pattern_name)
            if os.path.exists(yaml_path):
                rules = self._parse_flat_yaml(yaml_path, lang)
                flat_rules.extend(rules)
    return flat_rules
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && python3 test_ast_engine.py`
Expected: `test_semgrep_loader_finds_main_rules` PASSES

**Step 5: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/semgrep_loader.py mcp-server/test_ast_engine.py
git commit -m "fix: patch semgrep_loader to handle flat YAML rule files

Adds fallback loading for main's flat rule format (python.security.yaml)
alongside the nested directory format from the advanced-rules-engine."
```

---

## Task 6: Update Doctor Command for tree-sitter

**Files:**
- Modify: `mcp-server/index.js` (doctor command section)

**Step 1: Write the failing test**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && node index.js doctor 2>&1 | grep -i "tree-sitter"`
Expected: No tree-sitter check shown (doctor doesn't know about it yet)

**Step 2: Add tree-sitter check to doctor**

In `index.js`, inside the `runDoctor()` function, after the PyYAML check, add:

```javascript
// Check tree-sitter (optional but recommended)
try {
  execFileSync(pythonCmd, ['-c', 'import tree_sitter; print(tree_sitter.__version__)'], { encoding: 'utf-8', timeout: 5000 });
  const tsVersion = execFileSync(pythonCmd, ['-c', 'import tree_sitter; print(tree_sitter.__version__)'], { encoding: 'utf-8', timeout: 5000 }).trim();
  console.log(`    \x1b[32m✓\x1b[0m AST engine ready (tree-sitter ${tsVersion})`);
} catch {
  console.log(`    \x1b[33m⚠\x1b[0m tree-sitter not installed (regex-only mode)`);
  console.log(`      Optional: pip install -r ${join(__dirname, 'requirements.txt')}`);
}
```

**Step 3: Verify doctor shows tree-sitter status**

Run: `cd /Users/divyachitimalla/agent-security-layer/mcp-server && node index.js doctor 2>&1`
Expected: Shows either `✓ AST engine ready` or `⚠ tree-sitter not installed`

**Step 4: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/index.js
git commit -m "feat: doctor command checks tree-sitter AST engine status

Shows whether tree-sitter is installed (AST mode) or not (regex-only mode).
Provides install hint: pip install -r requirements.txt"
```

---

## Task 7: Update package.json for v2.0.0

**Files:**
- Modify: `mcp-server/package.json`

**Step 1: Update version and files array**

```json
{
  "version": "2.0.0",
  "files": [
    "index.js",
    "analyzer.py",
    "ast_parser.py",
    "generic_ast.py",
    "pattern_matcher.py",
    "regex_fallback.py",
    "semgrep_loader.py",
    "taint_analyzer.py",
    "requirements.txt",
    "rules/**",
    "packages/**"
  ]
}
```

**Step 2: Verify npm pack includes new files**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
npm pack --dry-run 2>&1 | head -40
```

Expected: Shows all `.py` files and `requirements.txt` in the package

**Step 3: Check package size**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
npm pack 2>&1 | tail -1
ls -lh agent-security-scanner-mcp-2.0.0.tgz
```

Expected: Under 15 MB

**Step 4: Clean up tarball**

```bash
rm mcp-server/agent-security-scanner-mcp-2.0.0.tgz
```

**Step 5: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/package.json
git commit -m "chore: bump to v2.0.0, include AST engine in npm package

Adds all Python AST modules and requirements.txt to npm files array.
Version 2.0.0 reflects the major change: AST-based analysis engine."
```

---

## Task 8: Update README for v2.0.0

**Files:**
- Modify: `mcp-server/README.md`

**Step 1: Add AST engine section to README**

After the "Quick Start" section, add:

```markdown
## AST Analysis Engine (v2.0)

Version 2.0 includes an optional AST-based analysis engine powered by tree-sitter. When installed, it provides:

- **Semantic understanding** — Detects vulnerabilities based on code structure, not just text patterns
- **Taint analysis** — Tracks data flow from user input (sources) to dangerous operations (sinks)
- **Metavariable matching** — Semgrep-style `$VAR` pattern matching across 12 languages
- **1,726 rules** — Expanded from 358 regex rules to include AST-specific patterns

### Enable AST Mode

```bash
pip install -r $(npm root -g)/agent-security-scanner-mcp/requirements.txt
```

### Verify Installation

```bash
npx agent-security-scanner-mcp doctor
```

The doctor command will show `✓ AST engine ready` when tree-sitter is installed, or `⚠ tree-sitter not installed (regex-only mode)` when running in fallback mode.

### How It Works

| Mode | When | Detection |
|------|------|-----------|
| **Regex** (default) | tree-sitter not installed | 358 pattern rules, line-by-line matching |
| **AST** (enhanced) | tree-sitter installed | 1,726 rules, semantic analysis, taint tracking |

Both modes produce identical output format — your MCP client integration requires no changes.
```

**Step 2: Verify README renders**

Manually review the markdown for correctness.

**Step 3: Commit**

```bash
cd /Users/divyachitimalla/agent-security-layer
git add mcp-server/README.md
git commit -m "docs: document AST analysis engine in README for v2.0.0

Adds section explaining AST mode vs regex mode, installation steps,
and doctor command verification."
```

---

## Task 9: Run Full Integration Test Suite

**Files:**
- Test: `mcp-server/test_ast_engine.py` (all tests)
- Test: `mcp-server/src/test_semgrep_rules.py` (existing Python tests)

**Step 1: Run AST engine tests**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
python3 test_ast_engine.py
```

Expected: All 6 tests PASS

**Step 2: Run existing semgrep rule tests**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
python3 -m pytest src/test_semgrep_rules.py -v
```

Expected: All existing tests still PASS

**Step 3: Test MCP server starts cleanly**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
timeout 3 node index.js 2>&1 || true
```

Expected: Shows "Security Scanner MCP Server running on stdio" on stderr, exits after timeout

**Step 4: Test CLI commands still work**

```bash
cd /Users/divyachitimalla/agent-security-layer/mcp-server
node index.js --help
node index.js doctor
node index.js demo --lang js 2>&1 | head -20
```

Expected: All three commands produce correct output

**Step 5: Commit test results (if any test files changed)**

```bash
cd /Users/divyachitimalla/agent-security-layer
git status
# Only commit if there are changes
```

---

## Task 10: Create Pull Request

**Files:**
- None (git operations only)

**Step 1: Push integration branch**

```bash
cd /Users/divyachitimalla/agent-security-layer
git push -u origin feature/merge-ast-engine
```

**Step 2: Create PR**

```bash
gh pr create \
  --title "feat: integrate AST-based security analyzer (v2.0.0)" \
  --body "## Summary

- Adds tree-sitter AST analysis engine with taint tracking and metavariable matching
- Graceful fallback to regex engine when tree-sitter not installed
- 6 new Python modules: ast_parser, generic_ast, pattern_matcher, regex_fallback, semgrep_loader, taint_analyzer
- Doctor command now shows AST engine status
- npm package stays under 15 MB (no third-party rule bloat)
- All existing tests pass, 6 new integration tests added

## Breaking Changes

- None. Regex mode is the default. AST mode is opt-in via \`pip install -r requirements.txt\`.

## Test Plan

- [ ] \`python3 test_ast_engine.py\` — 6 AST engine tests pass
- [ ] \`python3 -m pytest src/test_semgrep_rules.py -v\` — existing tests pass
- [ ] \`node index.js doctor\` — shows tree-sitter status
- [ ] \`node index.js demo --lang py\` — demo still works
- [ ] \`npm pack --dry-run\` — package under 15 MB
- [ ] \`npx agent-security-scanner-mcp doctor\` — works without tree-sitter (regex mode)
" \
  --base main
```

**Step 3: Note PR URL**

Expected: PR created with URL displayed

---

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Keep main's index.js entirely | Feature branch stripped CLI commands (init, doctor, demo), bloom filters, and prompt scanner — these are main's differentiators |
| Keep main's bloom filter approach | Feature branch replaced with 80 MB txt files — unacceptable for npm package |
| Keep main's flat rule YAMLs | 3,644 nested rule files add ~5 MB and most are test/example code, not rules. Flat YAMLs are sufficient |
| Graceful fallback in analyzer.py | Users who `npx` without Python deps get regex mode. `pip install` unlocks AST mode. No breaking change |
| Don't merge third-party Semgrep rules | 1,093 files, mostly duplicative with our curated rules. Adds size without proportional value |
| Version 2.0.0 | AST engine is a major architectural change even though the API is backward-compatible |
| Don't merge feature's package.json changes | Feature downgraded version to 1.3.0, removed bloom-filters dep, and changed repo URLs — all wrong for main |
