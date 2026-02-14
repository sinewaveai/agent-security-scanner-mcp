#!/usr/bin/env python3
"""Cross-file taint analysis for security scanning.

Builds an import graph across local files, runs per-file analysis,
and propagates taint warnings when a file imports from another file
that has ERROR-severity findings.
"""

import json
import os
import re
import sys

# Import the per-file analyzer
from analyzer import analyze_file


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


def cross_file_analyze(file_paths):
    """Run cross-file taint analysis.

    1. Analyze each file independently
    2. Build import graph
    3. For each file importing from another file with ERROR-severity findings,
       add a cross-file-taint-warning
    """
    # Analyze each file
    file_findings = {}
    all_findings = []

    for file_path in file_paths:
        try:
            results = analyze_file(file_path)
            if isinstance(results, list):
                file_findings[os.path.abspath(file_path)] = results
                for finding in results:
                    finding['file'] = file_path
                all_findings.extend(results)
        except Exception:
            continue

    # Build import graph
    graph = build_import_graph(file_paths)

    # Propagate taint warnings
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

    # Combine: per-file findings + cross-file warnings
    combined = all_findings + cross_file_warnings
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
