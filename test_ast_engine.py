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
    """AST analyzer should detect DOM-based XSS in JavaScript code."""
    vuln_code = '''
const userInput = document.getElementById("input").value;
document.getElementById("output").innerHTML = userInput;
document.write("<div>" + userInput + "</div>");
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
    # Should find innerHTML and document.write XSS patterns
    assert len(output) >= 2, f"Expected at least 2 DOM XSS findings (innerHTML + document.write), got {len(output)}: {output}"

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
    vuln_code = 'API_KEY = "test_FAKEFAKEFAKE1234"\n'
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
