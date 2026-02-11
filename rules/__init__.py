# Rule loader for YAML-based security rules
# Aligned with Semgrep registry format
# Recursively loads rules from subdirectories (csharp/, rust/, c/, etc.)

import os
import re

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

RULES_DIR = os.path.dirname(os.path.abspath(__file__))


def _is_semgrep_ast_pattern(s):
    """Check if a string is a Semgrep AST pattern (not a regex)."""
    semgrep_indicators = ['...', '$', 'pattern-not', 'pattern-inside', 'metavariable']
    return any(ind in s for ind in semgrep_indicators)


def _extract_patterns_from_semgrep_rule(rule_data):
    """Extract regex patterns from Semgrep-format rule definitions.

    Handles:
    - patterns: [list of regex strings] -> use directly (skip Semgrep AST patterns)
    - pattern: single string -> extract if no $metavariables or ...
    - pattern-regex: string -> use as regex
    - pattern-either with pattern-regex items -> extract regex patterns
    - Complex metavariable/AST patterns -> skip
    """
    patterns = []

    # Standard format: list of regex strings
    if 'patterns' in rule_data:
        raw = rule_data['patterns']
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    # Skip Semgrep AST patterns (contain ... or $)
                    if not _is_semgrep_ast_pattern(item):
                        patterns.append(item)
                elif isinstance(item, dict):
                    # Semgrep-style pattern-either or pattern-regex inside patterns list
                    patterns.extend(_extract_from_dict(item))

    # Single pattern string (Semgrep format)
    if 'pattern' in rule_data and isinstance(rule_data['pattern'], str):
        p = rule_data['pattern']
        if not _is_semgrep_ast_pattern(p):
            patterns.append(re.escape(p) if not _looks_like_regex(p) else p)

    # Explicit regex pattern
    if 'pattern-regex' in rule_data and isinstance(rule_data['pattern-regex'], str):
        patterns.append(rule_data['pattern-regex'])

    return patterns


def _extract_from_dict(d):
    """Extract patterns from a Semgrep dict node (pattern-either, etc.)."""
    patterns = []
    if 'pattern-regex' in d and isinstance(d['pattern-regex'], str):
        patterns.append(d['pattern-regex'])
    if 'pattern' in d and isinstance(d['pattern'], str):
        p = d['pattern']
        if not _is_semgrep_ast_pattern(p):
            patterns.append(re.escape(p) if not _looks_like_regex(p) else p)
    if 'pattern-either' in d and isinstance(d['pattern-either'], list):
        for item in d['pattern-either']:
            if isinstance(item, dict):
                patterns.extend(_extract_from_dict(item))
            elif isinstance(item, str) and not _is_semgrep_ast_pattern(item):
                patterns.append(item)
    return patterns


def _looks_like_regex(s):
    """Heuristic: check if a string looks like it's already a regex."""
    regex_chars = set(r'\.*+?[](){}|^$')
    return any(c in regex_chars for c in s)


def load_yaml_rules():
    """Load all YAML rule files from the rules directory, recursively."""
    rules = {}

    if not HAS_YAML:
        print("Warning: PyYAML not installed. Using fallback rules.")
        return rules

    for dirpath, _dirnames, filenames in os.walk(RULES_DIR):
        for filename in filenames:
            if not (filename.endswith('.yaml') or filename.endswith('.yml')):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if not data or 'rules' not in data:
                        continue
                    for rule in data['rules']:
                        rule_id = rule.get('id', '')
                        if not rule_id:
                            continue

                        extracted = _extract_patterns_from_semgrep_rule(rule)
                        if not extracted:
                            continue

                        rules[rule_id] = {
                            'id': rule_id,
                            'name': rule_id.split('.')[-1].replace('-', ' ').title(),
                            'patterns': extracted,
                            'message': rule.get('message', ''),
                            'severity': rule.get('severity', 'WARNING').lower(),
                            'languages': rule.get('languages', ['generic']),
                            'metadata': rule.get('metadata', {})
                        }
            except Exception as e:
                print(f"Error loading {filepath}: {e}")

    return rules


# Fallback rules if YAML is not available
FALLBACK_RULES = {
    'python.lang.security.audit.sql-injection': {
        'id': 'python.lang.security.audit.sql-injection',
        'name': 'SQL Injection',
        'patterns': [
            r'execute\s*\(\s*["\'].*\$\{.*\}.*["\']',
            r'query\s*\(\s*["\'].*\+.*["\']',
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*\+',
            r'cursor\.execute\s*\(\s*[^)]*%.*\)',
        ],
        'message': 'Possible SQL injection vulnerability detected. Use parameterized queries.',
        'severity': 'error',
        'languages': ['python'],
        'metadata': {
            'cwe': 'CWE-89',
            'owasp': 'A03:2021 - Injection',
            'confidence': 'MEDIUM'
        }
    },
    'javascript.browser.security.dom-based-xss': {
        'id': 'javascript.browser.security.dom-based-xss',
        'name': 'Cross-Site Scripting (XSS)',
        'patterns': [
            r'innerHTML\s*=\s*',
            r'outerHTML\s*=\s*',
            r'document\.write\s*\(',
            r'\.html\s*\(\s*[^)]*\+',
        ],
        'message': 'Possible XSS vulnerability. Sanitize user input before rendering.',
        'severity': 'error',
        'languages': ['javascript', 'typescript'],
        'metadata': {
            'cwe': 'CWE-79',
            'owasp': 'A03:2021 - Injection',
            'confidence': 'MEDIUM'
        }
    },
    'generic.secrets.security.hardcoded-secret': {
        'id': 'generic.secrets.security.hardcoded-secret',
        'name': 'Hardcoded Secrets',
        'patterns': [
            r'(api|secret|private)[_-]?key\s*[:=]\s*["\'][^"\']{20,}["\']',
            r'password\s*[:=]\s*["\'][^"\']{6,}["\']',
            r'["\'](sk_live_[A-Za-z0-9]{24,})["\']',
            r'["\'](sk_test_[A-Za-z0-9]{24,})["\']',
            r'["\'](ghp_[A-Za-z0-9]{30,})["\']',
        ],
        'message': 'Possible hardcoded secret detected. Use environment variables instead.',
        'severity': 'warning',
        'languages': ['generic'],
        'metadata': {
            'cwe': 'CWE-798',
            'owasp': 'A07:2021 - Identification and Authentication Failures',
            'confidence': 'HIGH'
        }
    }
}


def get_rules():
    """Get all rules - merge YAML rules with fallback rules.
    Fallback rules provide regex-based detection baseline.
    YAML rules add additional patterns (prompt injection, subdirectory rules).
    """
    rules = dict(FALLBACK_RULES)
    yaml_rules = load_yaml_rules()
    rules.update(yaml_rules)
    return rules


def get_rules_for_language(language):
    """Get rules applicable to a specific language"""
    all_rules = get_rules()
    applicable_rules = {}

    language = language.lower()

    for rule_id, rule in all_rules.items():
        rule_languages = [lang.lower() for lang in rule.get('languages', ['generic'])]
        if language in rule_languages or 'generic' in rule_languages:
            applicable_rules[rule_id] = rule

    return applicable_rules


def get_rules_by_category(category):
    """Get rules by category (e.g., 'injection', 'crypto', 'secrets')"""
    all_rules = get_rules()
    category_rules = {}

    category = category.lower()

    for rule_id, rule in all_rules.items():
        if category in rule_id.lower():
            category_rules[rule_id] = rule

    return category_rules


def get_rule_stats():
    """Get statistics about loaded rules"""
    all_rules = get_rules()

    stats = {
        'total': len(all_rules),
        'by_severity': {'error': 0, 'warning': 0, 'info': 0},
        'by_language': {},
        'by_category': {}
    }

    for rule_id, rule in all_rules.items():
        severity = rule.get('severity', 'warning').lower()
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

        for lang in rule.get('languages', ['generic']):
            lang = lang.lower()
            stats['by_language'][lang] = stats['by_language'].get(lang, 0) + 1

        parts = rule_id.split('.')
        if len(parts) >= 3:
            category = parts[2] if parts[2] != 'lang' else parts[3] if len(parts) > 3 else parts[2]
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

    return stats


# Export for backward compatibility
RULES = get_rules()
