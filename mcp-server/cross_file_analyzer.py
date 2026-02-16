#!/usr/bin/env python3
"""Cross-file taint analysis for security scanning.

Builds an import graph across local files, runs per-file analysis,
and propagates taint warnings when a file imports from another file
that has ERROR-severity findings.

Phase 2+3 add real cross-file taint tracking:
  - Phase 2: Build "export taint summaries" for each file
    (which function params flow to which sinks?)
  - Phase 3: Cross-file propagation — if a caller passes tainted data
    to a dangerous param, emit a cross-file-taint finding.
"""

import json
import os
import re
import sys

# Import the per-file analyzer
from analyzer import analyze_file

# Try to import AST-based export analysis
try:
    from ast_parser import ASTParser, HAS_TREE_SITTER
    from generic_ast import convert_tree
    from semgrep_loader import get_loader
    from taint_analyzer import TaintAnalyzer, FunctionTaintSummary, DangerousParam
    HAS_AST_EXPORTS = HAS_TREE_SITTER
except ImportError:
    HAS_AST_EXPORTS = False


def extract_js_imports(source):
    """Extract import/require statements from JavaScript/TypeScript."""
    imports = []
    # require('...')
    for m in re.finditer(r'''require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
        imports.append(m.group(1))
    # import ... from '...'
    for m in re.finditer(r'''from\s+['"]([^'"]+)['"]''', source):
        imports.append(m.group(1))
    # import '...'
    for m in re.finditer(r'''import\s+['"]([^'"]+)['"]''', source):
        imports.append(m.group(1))
    return imports


def extract_py_imports(source):
    """Extract import statements from Python."""
    imports = []
    # import module
    for m in re.finditer(r'^import\s+(\S+)', source, re.MULTILINE):
        imports.append(m.group(1).split('.')[0])
    # from module import ...
    for m in re.finditer(r'^from\s+(\S+)\s+import', source, re.MULTILINE):
        imports.append(m.group(1).split('.')[0])
    return imports


def detect_language(file_path):
    """Detect language from file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    lang_map = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
        '.tsx': 'typescript', '.jsx': 'javascript',
    }
    return lang_map.get(ext, 'unknown')


def resolve_local_import(module, base_dir, lang):
    """Resolve a relative/local import to an actual file path."""
    if lang in ('javascript', 'typescript'):
        # Only resolve relative imports
        if not module.startswith('.'):
            return None
        # Try common extensions
        candidates = [
            module,
            module + '.js', module + '.ts', module + '.tsx', module + '.jsx',
            os.path.join(module, 'index.js'), os.path.join(module, 'index.ts'),
        ]
        for candidate in candidates:
            full = os.path.normpath(os.path.join(base_dir, candidate))
            if os.path.isfile(full):
                return full
    elif lang == 'python':
        # Only resolve relative imports (starting with .)
        if module.startswith('.'):
            rel = module.lstrip('.')
            candidates = [
                os.path.join(base_dir, rel.replace('.', os.sep) + '.py'),
                os.path.join(base_dir, rel.replace('.', os.sep), '__init__.py'),
            ]
            for candidate in candidates:
                if os.path.isfile(candidate):
                    return candidate
        # Also check if the module name matches a sibling file
        sibling = os.path.join(base_dir, module + '.py')
        if os.path.isfile(sibling):
            return sibling
    return None


def extract_exports(source, lang):
    """Extract exported function/class names."""
    exports = []
    if lang in ('javascript', 'typescript'):
        for m in re.finditer(r'export\s+(?:function|class|const|let|var)\s+(\w+)', source):
            exports.append(m.group(1))
        for m in re.finditer(r'module\.exports\s*=', source):
            exports.append('default')
    elif lang == 'python':
        for m in re.finditer(r'^(?:def|class)\s+(\w+)', source, re.MULTILINE):
            exports.append(m.group(1))
    return exports


def build_import_graph(file_paths):
    """Build import graph: {file -> [{module, resolved_path, line}]}."""
    graph = {}
    file_set = set(os.path.abspath(f) for f in file_paths)

    for file_path in file_paths:
        abs_path = os.path.abspath(file_path)
        lang = detect_language(file_path)
        if lang == 'unknown':
            continue

        try:
            source = open(file_path, 'r', encoding='utf-8', errors='ignore').read()
        except (OSError, IOError):
            continue

        if lang in ('javascript', 'typescript'):
            modules = extract_js_imports(source)
        elif lang == 'python':
            modules = extract_py_imports(source)
        else:
            continue

        base_dir = os.path.dirname(abs_path)
        edges = []
        for mod in modules:
            resolved = resolve_local_import(mod, base_dir, lang)
            if resolved:
                resolved_abs = os.path.abspath(resolved)
                if resolved_abs in file_set and resolved_abs != abs_path:
                    edges.append({
                        'module': mod,
                        'resolved_path': resolved_abs,
                    })

        graph[abs_path] = edges

    return graph


# ---------------------------------------------------------------------------
# Phase 2: Export taint summaries
# ---------------------------------------------------------------------------

def extract_dangerous_functions_regex(source, lang):
    """Regex fallback: find functions where params appear in SQL concat/eval/exec.

    Returns a list of dicts with the same shape as FunctionTaintSummary:
      [{ function_name, line, dangerous_params: [{ param_name, param_index, sink_rule_id, sink_message, sink_line }] }]
    """
    results = []

    # Extract function definitions with their bodies
    if lang in ('javascript', 'typescript'):
        # Match: function name(...), async function name(...), name(...) { (method), const name = (...) =>
        func_patterns = [
            r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)',
        ]
        func_pattern = '|'.join(f'(?:{p})' for p in func_patterns)
    elif lang == 'python':
        func_pattern = r'def\s+(\w+)\s*\(([^)]*)\):'
    else:
        return results

    lines = source.split('\n')
    for m in re.finditer(func_pattern, source):
        # Extract name and params from whichever alternative matched
        groups = m.groups()
        # For JS, we have 3 alternatives with 2 groups each = 6 groups
        # For Python, we have 1 alternative with 2 groups
        func_name = None
        params_str = None
        for i in range(0, len(groups), 2):
            if groups[i] is not None:
                func_name = groups[i]
                params_str = groups[i + 1] if i + 1 < len(groups) else ''
                break
        if not func_name:
            continue
        params_str = (params_str or '').strip()
        if not params_str:
            continue

        params = [p.strip().split('=')[0].strip().split(':')[0].strip()
                  for p in params_str.split(',')]
        params = [p for p in params if p and p not in ('self', 'cls')]

        func_start = source[:m.start()].count('\n')

        # Extract function body: from the match to the next function or end of file
        rest = source[m.end():]
        # Find the next top-level function definition or end of source
        next_func = re.search(func_pattern, rest)
        if next_func:
            body = rest[:next_func.start()]
        else:
            body = rest

        body_lines = body.split('\n')

        dangerous_params = []
        for idx, param in enumerate(params):
            # Escape param for regex
            ep = re.escape(param)

            # SQL concatenation patterns (line-based to handle embedded quotes)
            sql_patterns = [
                # Line contains SQL keyword AND string concat with param
                rf'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\+\s*{ep}''',
                # Line contains SQL keyword in template literal with param
                rf'''`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{{{ep}\}}[^`]*`''',
                # param concatenated into a string on a line with SQL keyword
                rf'''{ep}\s*\+.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b''',
                # f-string with SQL keyword and param (Python)
                rf'''f['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*\{{{ep}\}}''',
            ]

            # eval/exec patterns
            eval_patterns = [
                rf'\beval\s*\(\s*{ep}\s*\)',
                rf'\bexec\s*\(\s*{ep}\s*\)',
                rf'child_process\.\w+\s*\(\s*{ep}',
                rf'\bsubprocess\.\w+\s*\(\s*{ep}',
            ]

            for line_offset, body_line in enumerate(body_lines):
                sink_line = func_start + line_offset + 1  # 1-indexed

                for pat in sql_patterns:
                    if re.search(pat, body_line, re.IGNORECASE):
                        dangerous_params.append({
                            'param_name': param,
                            'param_index': idx,
                            'sink_rule_id': 'sql-injection',
                            'sink_message': f"Parameter '{param}' used in SQL string concatenation",
                            'sink_line': sink_line,
                        })
                        break
                else:
                    for pat in eval_patterns:
                        if re.search(pat, body_line, re.IGNORECASE):
                            dangerous_params.append({
                                'param_name': param,
                                'param_index': idx,
                                'sink_rule_id': 'code-injection',
                                'sink_message': f"Parameter '{param}' passed to eval/exec",
                                'sink_line': sink_line,
                            })
                            break

        if dangerous_params:
            # Deduplicate by (param_name, sink_rule_id)
            seen = set()
            unique = []
            for dp in dangerous_params:
                key = (dp['param_name'], dp['sink_rule_id'], dp['sink_line'])
                if key not in seen:
                    seen.add(key)
                    unique.append(dp)

            results.append({
                'function_name': func_name,
                'line': func_start + 1,
                'dangerous_params': unique,
            })

    return results


def build_export_summaries(file_paths, file_sources):
    """Phase 2: Build export taint summaries for each file.

    Returns: { abs_path: [{ function_name, line, dangerous_params }] }
    """
    summaries = {}

    for file_path in file_paths:
        abs_path = os.path.abspath(file_path)
        lang = detect_language(file_path)
        if lang == 'unknown':
            continue

        source = file_sources.get(abs_path, '')
        if not source:
            continue

        # Try AST-based analysis first
        if HAS_AST_EXPORTS:
            try:
                parser = ASTParser()
                parse_result = parser.parse_file(file_path)
                if parse_result.success:
                    ast = convert_tree(parse_result.tree, parse_result.language, parse_result.source_bytes)
                    loader = get_loader()
                    taint_rules = loader.get_taint_rules()
                    applicable = [r for r in taint_rules
                                  if parse_result.language in r.languages or 'generic' in r.languages]
                    if applicable:
                        analyzer = TaintAnalyzer()
                        fn_summaries = analyzer.analyze_function_exports(ast, applicable)
                        if fn_summaries:
                            summaries[abs_path] = [
                                {
                                    'function_name': s.function_name,
                                    'line': s.line,
                                    'dangerous_params': [
                                        {
                                            'param_name': dp.param_name,
                                            'param_index': dp.param_index,
                                            'sink_rule_id': dp.sink_rule_id,
                                            'sink_message': dp.sink_message,
                                            'sink_line': dp.sink_line,
                                        }
                                        for dp in s.dangerous_params
                                    ],
                                }
                                for s in fn_summaries
                            ]
                            continue
            except Exception:
                pass

        # Regex fallback
        regex_summaries = extract_dangerous_functions_regex(source, lang)
        if regex_summaries:
            summaries[abs_path] = regex_summaries

    return summaries


# ---------------------------------------------------------------------------
# Phase 3: Cross-file taint matching
# ---------------------------------------------------------------------------

# Common taint source patterns (user input in web frameworks)
_TAINT_SOURCE_PATTERNS = [
    # Express / Node.js
    r'req\.params\.\w+', r'req\.query\.\w+', r'req\.body\.\w+',
    r'req\.headers\.\w+', r'req\.cookies\.\w+',
    # Flask / Django
    r'request\.args\.get\(', r'request\.form\.get\(', r'request\.json',
    r'request\.GET\[', r'request\.POST\[',
    # Generic
    r'input\s*\(', r'process\.argv',
]


def _extract_import_bindings(source, lang):
    """Extract what names are imported from which modules.

    Returns: [{ module: str, names: [str], is_default: bool }]
    """
    bindings = []
    if lang in ('javascript', 'typescript'):
        # const db = require('../lib/db')
        for m in re.finditer(r'''(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
            bindings.append({'module': m.group(2), 'names': [m.group(1)], 'is_default': True})
        # const { getUserById } = require('../lib/db')
        for m in re.finditer(r'''(?:const|let|var)\s+\{\s*([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)''', source):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(1).split(',') if n.strip()]
            bindings.append({'module': m.group(2), 'names': names, 'is_default': False})
        # import db from '../lib/db'
        for m in re.finditer(r'''import\s+(\w+)\s+from\s+['"]([^'"]+)['"]''', source):
            bindings.append({'module': m.group(2), 'names': [m.group(1)], 'is_default': True})
        # import { getUserById } from '../lib/db'
        for m in re.finditer(r'''import\s+\{\s*([^}]+)\}\s+from\s+['"]([^'"]+)['"]''', source):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(1).split(',') if n.strip()]
            bindings.append({'module': m.group(2), 'names': names, 'is_default': False})
    elif lang == 'python':
        # from module import name1, name2
        for m in re.finditer(r'^from\s+(\S+)\s+import\s+(.+)', source, re.MULTILINE):
            names = [n.strip().split(' as ')[-1].strip() for n in m.group(2).split(',') if n.strip()]
            bindings.append({'module': m.group(1), 'names': names, 'is_default': False})
        # import module
        for m in re.finditer(r'^import\s+(\w+)', source, re.MULTILINE):
            bindings.append({'module': m.group(1), 'names': [m.group(1)], 'is_default': True})
    return bindings


def _find_tainted_variables(source):
    """Find variables that receive tainted data from common source patterns."""
    tainted = {}
    lines = source.split('\n')

    # Assignment patterns: JS (const/let/var x = ...) and Python (x = ...)
    _ASSIGN_PATTERNS = [
        r'\s*(?:const|let|var)\s+(\w+)\s*=\s*',   # JS declaration
        r'\s*(\w+)\s*=\s*',                         # Python / bare assignment
    ]

    for line_num, line in enumerate(lines, 1):
        for pat in _TAINT_SOURCE_PATTERNS:
            if re.search(pat, line):
                # Try to find the variable assignment on this line
                for assign_pat in _ASSIGN_PATTERNS:
                    assign_match = re.match(assign_pat + '.*' + pat, line)
                    if assign_match:
                        var_name = assign_match.group(1)
                        # Skip keywords that look like variables
                        if var_name in ('const', 'let', 'var', 'return', 'if', 'else', 'for', 'while'):
                            continue
                        source_text = re.search(pat, line).group(0)
                        tainted[var_name] = {
                            'source': source_text,
                            'line': line_num,
                        }
                        break
    return tainted


def _find_calls_to_function(source, func_name, module_alias=None):
    """Find calls to a function in source, returning arg lists.

    Returns: [{ line: int, args: [str] }]
    """
    calls = []
    lines = source.split('\n')

    # Build patterns: db.getUserById(...) or getUserById(...)
    patterns = []
    if module_alias:
        patterns.append(rf'{re.escape(module_alias)}\.{re.escape(func_name)}\s*\(([^)]*)\)')
    patterns.append(rf'(?<!\w){re.escape(func_name)}\s*\(([^)]*)\)')

    seen_lines = set()
    for line_num, line in enumerate(lines, 1):
        for pat in patterns:
            for m in re.finditer(pat, line):
                if line_num in seen_lines:
                    continue
                seen_lines.add(line_num)
                args_str = m.group(1).strip()
                if args_str:
                    args = [a.strip() for a in args_str.split(',')]
                else:
                    args = []
                calls.append({'line': line_num, 'args': args})

    return calls


def cross_file_taint_match(file_paths, file_sources, graph, export_summaries):
    """Phase 3: Match tainted call-sites to dangerous function parameters.

    Returns list of cross-file-taint findings.
    """
    findings = []

    for caller_path, edges in graph.items():
        caller_source = file_sources.get(caller_path, '')
        if not caller_source:
            continue

        lang = detect_language(caller_path)
        tainted_vars = _find_tainted_variables(caller_source)
        if not tainted_vars:
            continue

        # Extract import bindings for this file
        bindings = _extract_import_bindings(caller_source, lang)

        for edge in edges:
            imported_path = edge['resolved_path']
            imported_module = edge['module']

            imported_summaries = export_summaries.get(imported_path, [])
            if not imported_summaries:
                continue

            # Find alias used for the imported module
            module_alias = None
            imported_names = set()
            for binding in bindings:
                if binding['module'] == imported_module:
                    if binding['is_default']:
                        module_alias = binding['names'][0] if binding['names'] else None
                    else:
                        imported_names.update(binding['names'])

            for summary in imported_summaries:
                func_name = summary['function_name']

                # Find calls to this function in the caller
                # Check both default import alias (db.getUserById) and named imports (getUserById)
                alias = module_alias if func_name not in imported_names else None
                calls = _find_calls_to_function(caller_source, func_name, alias)

                for call in calls:
                    for dp in summary['dangerous_params']:
                        param_idx = dp['param_index']
                        if param_idx < len(call['args']):
                            arg = call['args'][param_idx]
                            # Check if this argument is a tainted variable
                            if arg in tainted_vars:
                                taint_info = tainted_vars[arg]
                                caller_rel = os.path.basename(caller_path)
                                sink_rel = os.path.basename(imported_path)

                                findings.append({
                                    'ruleId': 'cross-file-taint',
                                    'severity': 'error',
                                    'message': (
                                        f"Tainted data from {taint_info['source']} "
                                        f"flows through {func_name}() to "
                                        f"{dp['sink_rule_id']} sink in "
                                        f"{sink_rel}:{dp['sink_line']}"
                                    ),
                                    'file': caller_path,
                                    'line': call['line'],
                                    'metadata': {
                                        'source_file': caller_path,
                                        'sink_file': imported_path,
                                        'taint_source': taint_info['source'],
                                        'taint_source_line': taint_info['line'],
                                        'called_function': func_name,
                                        'dangerous_param': dp['param_name'],
                                        'sink_rule_id': dp['sink_rule_id'],
                                        'sink_line': dp['sink_line'],
                                        'taint_path': [
                                            f"{caller_rel}:{taint_info['line']} {arg} = {taint_info['source']}",
                                            f"{caller_rel}:{call['line']} {func_name}({arg})",
                                            f"{sink_rel}:{dp['sink_line']} {dp['sink_message']}",
                                        ],
                                    }
                                })

    return findings


def cross_file_analyze(file_paths):
    """Run cross-file taint analysis.

    Phase 1: Analyze each file independently + build import graph
    Phase 2: Build export taint summaries for each file
    Phase 3: Cross-file taint matching
    """
    # ------------------------------------------------------------------
    # Phase 1: Per-file analysis + import graph
    # ------------------------------------------------------------------
    file_findings = {}
    all_findings = []
    file_sources = {}

    for file_path in file_paths:
        abs_path = os.path.abspath(file_path)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_sources[abs_path] = f.read()
        except (OSError, IOError):
            pass

        try:
            results = analyze_file(file_path)
            if isinstance(results, list):
                file_findings[abs_path] = results
                for finding in results:
                    finding['file'] = file_path
                all_findings.extend(results)
        except Exception:
            continue

    # Build import graph
    graph = build_import_graph(file_paths)

    # Shallow cross-file warnings (existing Phase 1 behaviour)
    cross_file_warnings = []
    for file_path, edges in graph.items():
        for edge in edges:
            imported_path = edge['resolved_path']
            imported_findings = file_findings.get(imported_path, [])

            # Check for ERROR-severity findings in imported file
            error_findings = [f for f in imported_findings if f.get('severity') == 'error']
            if error_findings:
                warning = {
                    'ruleId': 'cross-file-taint-warning',
                    'severity': 'warning',
                    'message': f"Imports from '{os.path.basename(imported_path)}' which has {len(error_findings)} critical finding(s): {', '.join(set(f.get('ruleId', 'unknown') for f in error_findings))}",
                    'file': file_path,
                    'line': 0,
                    'metadata': {
                        'imported_file': imported_path,
                        'imported_findings_count': len(error_findings),
                    }
                }
                cross_file_warnings.append(warning)

    # ------------------------------------------------------------------
    # Phase 2: Build export taint summaries
    # ------------------------------------------------------------------
    export_summaries = build_export_summaries(file_paths, file_sources)

    # ------------------------------------------------------------------
    # Phase 3: Cross-file taint matching
    # ------------------------------------------------------------------
    cross_file_taint_findings = cross_file_taint_match(
        file_paths, file_sources, graph, export_summaries
    )

    # Combine: per-file findings + shallow warnings + deep cross-file taint
    combined = all_findings + cross_file_warnings + cross_file_taint_findings
    return combined


def main():
    """CLI entry point. Accepts file paths as arguments, outputs JSON."""
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'Usage: cross_file_analyzer.py file1 file2 ...'}))
        sys.exit(1)

    file_paths = sys.argv[1:]
    # Filter to existing files
    file_paths = [f for f in file_paths if os.path.isfile(f)]

    if not file_paths:
        print(json.dumps({'error': 'No valid files provided'}))
        sys.exit(1)

    results = cross_file_analyze(file_paths)
    print(json.dumps(results))


if __name__ == '__main__':
    main()
