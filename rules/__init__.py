# Rule loader for YAML-based security rules
# Aligned with Semgrep registry format

import os
import re

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

RULES_DIR = os.path.dirname(os.path.abspath(__file__))

def load_yaml_rules():
    """Load all YAML rule files from the rules directory"""
    rules = {}
    
    if not HAS_YAML:
        print("Warning: PyYAML not installed. Using fallback rules.")
        return rules
    
    for filename in os.listdir(RULES_DIR):
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            filepath = os.path.join(RULES_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        for rule in data['rules']:
                            rule_id = rule.get('id', '')
                            if rule_id:
                                rules[rule_id] = {
                                    'id': rule_id,
                                    'name': rule_id.split('.')[-1].replace('-', ' ').title(),
                                    'patterns': rule.get('patterns', []),
                                    'message': rule.get('message', ''),
                                    'severity': rule.get('severity', 'WARNING').lower(),
                                    'languages': rule.get('languages', ['generic']),
                                    'metadata': rule.get('metadata', {})
                                }
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    
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
    """Get all rules - from YAML if available, otherwise fallback"""
    yaml_rules = load_yaml_rules()
    if yaml_rules:
        return yaml_rules
    return FALLBACK_RULES

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
