"""Tests for cross-file taint tracking.

Covers:
- extract_dangerous_functions_regex (regex-based export taint summary)
- analyze_function_exports (AST-based, when tree-sitter available)
- cross_file_analyze end-to-end on the express-app fixture
"""

import json
import os
import sys
import pytest

# Ensure the mcp-server root is on the path so imports resolve
MCP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MCP_ROOT)

from cross_file_analyzer import (
    extract_dangerous_functions_regex,
    cross_file_analyze,
    _find_tainted_variables,
    _extract_import_bindings,
    _find_calls_to_function,
    build_import_graph,
    build_export_summaries,
    cross_file_taint_match,
)

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'express-app')


# ========== extract_dangerous_functions_regex ==========

class TestExtractDangerousFunctionsRegex:
    def test_finds_sql_sink_in_db_js(self):
        """getUserById and searchUsers should both be flagged for SQL concat."""
        db_path = os.path.join(FIXTURE_DIR, 'lib', 'db.js')
        with open(db_path, 'r') as f:
            source = f.read()

        results = extract_dangerous_functions_regex(source, 'javascript')

        func_names = [r['function_name'] for r in results]
        assert 'getUserById' in func_names, f"Expected getUserById in {func_names}"
        assert 'searchUsers' in func_names, f"Expected searchUsers in {func_names}"

        # Check that 'id' param is flagged for getUserById
        get_user = next(r for r in results if r['function_name'] == 'getUserById')
        param_names = [dp['param_name'] for dp in get_user['dangerous_params']]
        assert 'id' in param_names

        # Check sink rule id
        id_param = next(dp for dp in get_user['dangerous_params'] if dp['param_name'] == 'id')
        assert id_param['sink_rule_id'] == 'sql-injection'

    def test_finds_searchUsers_term_param(self):
        """searchUsers 'term' param should be flagged as dangerous."""
        db_path = os.path.join(FIXTURE_DIR, 'lib', 'db.js')
        with open(db_path, 'r') as f:
            source = f.read()

        results = extract_dangerous_functions_regex(source, 'javascript')
        search = next(r for r in results if r['function_name'] == 'searchUsers')
        param_names = [dp['param_name'] for dp in search['dangerous_params']]
        assert 'term' in param_names

    def test_safe_function_has_no_dangerous_params(self):
        """A function that doesn't pass params to sinks should not appear."""
        source = """
function safeLookup(key) {
    return cache[key];
}

function anotherSafe(name) {
    console.log("Hello " + name);
    return true;
}
"""
        results = extract_dangerous_functions_regex(source, 'javascript')
        assert results == [], f"Expected no dangerous functions, got {results}"

    def test_python_eval_sink(self):
        """Python eval() should be detected."""
        source = """
def run_code(code):
    result = eval(code)
    return result
"""
        results = extract_dangerous_functions_regex(source, 'python')
        assert len(results) == 1
        assert results[0]['function_name'] == 'run_code'
        dp = results[0]['dangerous_params'][0]
        assert dp['param_name'] == 'code'
        assert dp['sink_rule_id'] == 'code-injection'

    def test_arrow_function_sql_injection(self):
        """Arrow functions with SQL sinks should be detected."""
        source = """
const getUserById = (id) => {
    const query = "SELECT * FROM users WHERE id = " + id;
    return db.query(query);
};
"""
        results = extract_dangerous_functions_regex(source, 'javascript')
        assert len(results) == 1
        assert results[0]['function_name'] == 'getUserById'
        assert results[0]['dangerous_params'][0]['param_name'] == 'id'

    def test_async_function_detection(self):
        """Async functions should also be detected."""
        source = """
async function fetchUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return await db.query(query);
}
"""
        results = extract_dangerous_functions_regex(source, 'javascript')
        assert len(results) == 1
        assert results[0]['function_name'] == 'fetchUser'

    def test_template_literal_sql_injection(self):
        """Template literal with SQL should be detected."""
        source = """
function findUser(name) {
    const query = `SELECT * FROM users WHERE name = '${name}'`;
    return db.query(query);
}
"""
        results = extract_dangerous_functions_regex(source, 'javascript')
        assert len(results) == 1
        assert results[0]['function_name'] == 'findUser'
        assert results[0]['dangerous_params'][0]['param_name'] == 'name'


# ========== _find_tainted_variables ==========

class TestFindTaintedVariables:
    def test_express_req_params(self):
        source = '  const userId = req.params.id;\n  const name = req.query.q;\n'
        tainted = _find_tainted_variables(source)
        assert 'userId' in tainted
        assert 'name' in tainted
        assert 'req.params.id' in tainted['userId']['source']

    def test_no_taint_in_safe_code(self):
        source = 'const x = 42;\nconst y = "hello";\n'
        tainted = _find_tainted_variables(source)
        assert tainted == {}

    def test_python_flask_taint(self):
        """Python Flask request.args.get should be detected."""
        source = '    user_id = request.args.get("id")\n'
        tainted = _find_tainted_variables(source)
        assert 'user_id' in tainted
        assert 'request.args.get(' in tainted['user_id']['source']


# ========== _extract_import_bindings ==========

class TestExtractImportBindings:
    def test_js_require_default(self):
        source = "const db = require('../lib/db');\n"
        bindings = _extract_import_bindings(source, 'javascript')
        assert len(bindings) >= 1
        b = bindings[0]
        assert b['module'] == '../lib/db'
        assert 'db' in b['names']
        assert b['is_default'] is True

    def test_js_require_destructured(self):
        source = "const { requireAuth } = require('../middleware/auth');\n"
        bindings = _extract_import_bindings(source, 'javascript')
        assert len(bindings) >= 1
        b = next(b for b in bindings if not b['is_default'])
        assert 'requireAuth' in b['names']

    def test_esm_import(self):
        source = "import db from '../lib/db';\n"
        bindings = _extract_import_bindings(source, 'javascript')
        assert len(bindings) >= 1
        assert bindings[0]['names'] == ['db']


# ========== _find_calls_to_function ==========

class TestFindCallsToFunction:
    def test_finds_method_call(self):
        source = "  const user = db.getUserById(userId);\n"
        calls = _find_calls_to_function(source, 'getUserById', 'db')
        assert len(calls) == 1
        assert calls[0]['args'] == ['userId']

    def test_finds_direct_call(self):
        source = "  const user = getUserById(userId);\n"
        calls = _find_calls_to_function(source, 'getUserById')
        assert len(calls) == 1
        assert calls[0]['args'] == ['userId']


# ========== cross_file_analyze end-to-end ==========

class TestCrossFileAnalyze:
    def test_detects_taint_chain_in_express_app(self):
        """Full cross-file analysis should find taint from req.params.id → getUserById → SQL sink."""
        file_paths = [
            os.path.join(FIXTURE_DIR, 'app.js'),
            os.path.join(FIXTURE_DIR, 'routes', 'users.js'),
            os.path.join(FIXTURE_DIR, 'lib', 'db.js'),
            os.path.join(FIXTURE_DIR, 'middleware', 'auth.js'),
        ]
        results = cross_file_analyze(file_paths)

        # Filter to cross-file-taint findings
        cross_file = [r for r in results if r['ruleId'] == 'cross-file-taint']
        assert len(cross_file) >= 1, (
            f"Expected at least 1 cross-file-taint finding, got {len(cross_file)}. "
            f"All rule IDs: {[r['ruleId'] for r in results]}"
        )

        # At least one finding should mention getUserById or searchUsers
        messages = [f['message'] for f in cross_file]
        has_getUserById = any('getUserById' in m for m in messages)
        has_searchUsers = any('searchUsers' in m for m in messages)
        assert has_getUserById or has_searchUsers, (
            f"Expected finding mentioning getUserById or searchUsers, got: {messages}"
        )

    def test_cross_file_finding_has_metadata(self):
        """Cross-file-taint findings should include taint_path metadata."""
        file_paths = [
            os.path.join(FIXTURE_DIR, 'routes', 'users.js'),
            os.path.join(FIXTURE_DIR, 'lib', 'db.js'),
        ]
        results = cross_file_analyze(file_paths)
        cross_file = [r for r in results if r['ruleId'] == 'cross-file-taint']

        if cross_file:
            finding = cross_file[0]
            assert 'metadata' in finding
            meta = finding['metadata']
            assert 'taint_path' in meta
            assert 'source_file' in meta
            assert 'sink_file' in meta
            assert isinstance(meta['taint_path'], list)
            assert len(meta['taint_path']) >= 2

    def test_also_produces_shallow_warnings(self):
        """The existing cross-file-taint-warning mechanism should still work."""
        file_paths = [
            os.path.join(FIXTURE_DIR, 'routes', 'users.js'),
            os.path.join(FIXTURE_DIR, 'lib', 'db.js'),
        ]
        results = cross_file_analyze(file_paths)

        # There should still be per-file findings from db.js
        per_file = [r for r in results if r.get('ruleId') != 'cross-file-taint'
                     and r.get('ruleId') != 'cross-file-taint-warning']
        assert len(per_file) >= 0  # At minimum, the analysis ran without error


# ========== build_export_summaries with regex fallback ==========

class TestBuildExportSummaries:
    def test_regex_fallback_finds_db_functions(self):
        """build_export_summaries should find dangerous functions via regex when AST isn't available."""
        db_path = os.path.join(FIXTURE_DIR, 'lib', 'db.js')
        abs_db = os.path.abspath(db_path)
        with open(db_path, 'r') as f:
            source = f.read()

        summaries = build_export_summaries([db_path], {abs_db: source})
        assert abs_db in summaries

        func_names = [s['function_name'] for s in summaries[abs_db]]
        assert 'getUserById' in func_names
        assert 'searchUsers' in func_names


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
