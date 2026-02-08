"""
Semgrep YAML Rule Loader
Converts Semgrep-style YAML rules to our AST pattern format
"""

import os
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from pattern_matcher import Rule, TaintRule, Pattern, create_pattern
    HAS_PATTERN_MATCHER = True
except ImportError:
    HAS_PATTERN_MATCHER = False


class SemgrepRuleLoader:
    """Load and convert Semgrep YAML rules to AST patterns"""
    
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        self.rules_dir = Path(rules_dir)
        self.loaded_rules = []
        self.taint_rules = []  # Separate list for taint analysis rules
        
        # Loader diagnostics
        self.stats = {
            'rules_loaded': 0,
            'rules_skipped_no_patterns': 0,
            'rules_skipped_taint': 0,
            'patterns_skipped_multiline': 0,
            'patterns_skipped_no_anchor': 0,
        }
        
    def load_all_rules(self, languages: List[str] = None) -> List[Rule]:
        """Load all YAML rules for specified languages"""
        if languages is None:
            languages = ['python', 'javascript', 'typescript', 'java', 'go', 'ruby', 'php', 'c', 'rust', 'csharp', 'generic']

        all_rules = []

        # Load from flat YAML files first (main branch format: python.security.yaml, etc.)
        all_rules.extend(self._load_flat_rules(languages))

        # Load from main language directories (feature branch format: python/lang/security/...)
        for language in languages:
            lang_dir = self.rules_dir / language
            if lang_dir.exists() and lang_dir.is_dir():
                all_rules.extend(self._load_language_rules(lang_dir, language))

        # Load from third-party directory (all languages)
        third_party_dir = self.rules_dir / 'third-party'
        if third_party_dir.exists():
            all_rules.extend(self._load_third_party_rules(third_party_dir))

        self.loaded_rules = all_rules
        return all_rules

    def _load_flat_rules(self, languages: List[str]) -> List[Rule]:
        """Load rules from flat YAML files (main branch format).

        Handles files like:
        - python.security.yaml
        - javascript.security.yaml
        - generic.secrets.yaml
        - agent-attacks.security.yaml
        - prompt-injection.security.yaml
        """
        rules = []

        # Language-specific security rules
        for lang in languages:
            yaml_file = self.rules_dir / f'{lang}.security.yaml'
            if yaml_file.exists():
                rules.extend(self._load_flat_yaml_file(yaml_file, lang))

        # Generic rules that apply to all languages
        generic_files = [
            'generic.secrets.yaml',
            'agent-attacks.security.yaml',
            'prompt-injection.security.yaml',
        ]
        for filename in generic_files:
            yaml_file = self.rules_dir / filename
            if yaml_file.exists():
                rules.extend(self._load_flat_yaml_file(yaml_file, 'generic'))

        return rules

    def _load_flat_yaml_file(self, yaml_file: Path, default_language: str) -> List[Rule]:
        """Load rules from a flat YAML file (main branch format).

        These files have a different format than Semgrep rules - they have
        'rules' as a list with 'id', 'patterns' (as regex strings), etc.
        """
        rules = []
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                return rules

            # Handle main branch format: list of rules under 'rules' key
            rule_list = data.get('rules', data) if isinstance(data, dict) else data
            if not isinstance(rule_list, list):
                rule_list = [rule_list]

            for rule_data in rule_list:
                if not isinstance(rule_data, dict):
                    continue

                # Try Semgrep format first
                if 'pattern' in rule_data or 'patterns' in rule_data or 'pattern-either' in rule_data:
                    converted = self._convert_semgrep_rule(rule_data, default_language)
                    if converted:
                        rules.append(converted)
                        continue

                # Handle main branch format (regex patterns as strings)
                rule_id = rule_data.get('id', 'unknown')
                message = rule_data.get('message', '')
                severity = rule_data.get('severity', 'WARNING').lower()
                languages = rule_data.get('languages', [default_language])
                metadata = rule_data.get('metadata', {})

                # Get patterns (list of regex strings in main format)
                pattern_list = rule_data.get('patterns', [])
                if not pattern_list:
                    continue

                # Convert regex patterns to Pattern objects
                patterns = []
                for p in pattern_list:
                    if isinstance(p, str):
                        patterns.append(Pattern(pattern_text=p, is_regex=True))

                if not patterns:
                    continue

                self.stats['rules_loaded'] += 1

                # Map severity
                severity_map = {'error': 'error', 'warning': 'warning', 'info': 'info'}
                severity = severity_map.get(severity.lower(), 'warning')

                rules.append(Rule(
                    id=rule_id,
                    name=rule_data.get('name', rule_id.split('.')[-1].replace('-', ' ').title()),
                    patterns=patterns,
                    pattern_not=[],
                    message=message,
                    severity=severity,
                    languages=languages,
                    metadata=metadata
                ))

        except Exception:
            pass

        return rules
    
    def _load_third_party_rules(self, third_party_dir: Path) -> List[Rule]:
        """Load all rules from third-party sources"""
        rules = []
        
        # Find all .yaml and .yml files recursively
        for yaml_file in third_party_dir.rglob('*.yaml'):
            rules.extend(self._load_yaml_file(yaml_file))
        for yml_file in third_party_dir.rglob('*.yml'):
            rules.extend(self._load_yaml_file(yml_file))
        
        return rules
    
    def _load_yaml_file(self, yaml_file: Path) -> List[Rule]:
        """Load rules from a single YAML file"""
        rules = []
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and 'rules' in data:
                    for rule_data in data['rules']:
                        # Detect language from file path or rule
                        language = self._detect_language(yaml_file, rule_data)
                        converted_rule = self._convert_semgrep_rule(rule_data, language)
                        if converted_rule:
                            rules.append(converted_rule)
        except Exception:
            pass
        return rules
    
    def _detect_language(self, yaml_file: Path, rule_data: Dict[str, Any]) -> str:
        """Detect language from file path or rule data"""
        # Check rule data first
        if 'languages' in rule_data and rule_data['languages']:
            return rule_data['languages'][0]
        
        # Detect from path
        path_str = str(yaml_file).lower()
        lang_map = {
            'python': 'python', 'javascript': 'javascript', 'typescript': 'typescript',
            'java': 'java', 'go': 'go', 'ruby': 'ruby', 'php': 'php', 'c/': 'c',
            'rust': 'rust', 'csharp': 'csharp'
        }
        for key, lang in lang_map.items():
            if key in path_str:
                return lang
        return 'generic'
    
    def _load_language_rules(self, lang_dir: Path, language: str) -> List[Rule]:
        """Load all YAML files from a language directory"""
        rules = []
        
        # Find all .yaml files recursively (load everything, no filtering)
        for yaml_file in lang_dir.rglob('*.yaml'):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        for rule_data in data['rules']:
                            converted_rule = self._convert_semgrep_rule(rule_data, language)
                            if converted_rule:
                                rules.append(converted_rule)
            except Exception as e:
                # Silently skip files that fail to load
                pass
        
        return rules
    
    def _convert_semgrep_rule(self, rule_data: Dict[str, Any], default_language: str) -> Optional[Rule]:
        """Convert a Semgrep rule to our Rule format"""
        if not HAS_PATTERN_MATCHER:
            return None
        
        # Check if this is a taint rule (mode: taint)
        if rule_data.get('mode') == 'taint':
            taint_rule = self._convert_taint_rule(rule_data, default_language)
            if taint_rule:
                self.taint_rules.append(taint_rule)
            # Return None - taint rules are stored separately
            return None
            
        rule_id = rule_data.get('id', 'unknown')
        message = rule_data.get('message', '')
        severity = rule_data.get('severity', 'WARNING').lower()
        
        # Parse languages and map 'regex' to 'generic'
        languages = rule_data.get('languages', [default_language])
        if 'regex' in languages and 'generic' not in languages:
            languages.append('generic')

        metadata = rule_data.get('metadata', {})
        
        # Convert Semgrep patterns to our AST patterns
        patterns = self._extract_patterns(rule_data)
        pattern_nots = self._extract_pattern_nots(rule_data)
        
        if not patterns:
            self.stats['rules_skipped_no_patterns'] += 1
            return None
        
        self.stats['rules_loaded'] += 1
        
        # Map severity
        severity_map = {
            'error': 'error',
            'warning': 'warning',
            'info': 'info'
        }
        severity = severity_map.get(severity, 'warning')
        
        return Rule(
            id=rule_id,
            name=rule_id.split('.')[-1].replace('-', ' ').title(),
            patterns=patterns,
            pattern_not=pattern_nots,
            message=message,
            severity=severity,
            languages=languages,
            metadata=metadata
        )
    
    def _convert_taint_rule(self, rule_data: Dict[str, Any], default_language: str) -> Optional[TaintRule]:
        """Convert a Semgrep taint rule to our TaintRule format"""
        rule_id = rule_data.get('id', 'unknown')
        message = rule_data.get('message', '')
        severity = rule_data.get('severity', 'ERROR').lower()
        languages = rule_data.get('languages', [default_language])
        metadata = rule_data.get('metadata', {})
        
        # Extract source patterns
        sources = self._extract_taint_patterns(rule_data.get('pattern-sources', []))
        
        # Extract sink patterns
        sinks = self._extract_taint_patterns(rule_data.get('pattern-sinks', []))
        
        # Extract optional sanitizer patterns
        sanitizers = self._extract_taint_patterns(rule_data.get('pattern-sanitizers', []))
        
        if not sources or not sinks:
            return None
        
        # Map severity
        severity_map = {'error': 'error', 'warning': 'warning', 'info': 'info'}
        severity = severity_map.get(severity, 'error')
        
        return TaintRule(
            id=rule_id,
            name=rule_id.split('.')[-1].replace('-', ' ').title(),
            sources=sources,
            sinks=sinks,
            message=message,
            severity=severity,
            languages=languages,
            metadata=metadata,
            sanitizers=sanitizers
        )
    
    def _extract_taint_patterns(self, pattern_list: List[Any]) -> List[Pattern]:
        """Extract patterns from taint source/sink definitions"""
        patterns = []
        
        for item in pattern_list:
            if isinstance(item, dict):
                # Handle nested patterns structure
                if 'pattern' in item:
                    patterns.append(create_pattern(item['pattern']))
                elif 'patterns' in item:
                    # Recursively extract from patterns list
                    patterns.extend(self._extract_patterns_deep(item['patterns']))
                elif 'pattern-either' in item:
                    # Multiple alternative patterns
                    for either in item['pattern-either']:
                        if isinstance(either, dict) and 'pattern' in either:
                            patterns.append(create_pattern(either['pattern']))
                        elif isinstance(either, str):
                            patterns.append(create_pattern(either))
            elif isinstance(item, str):
                patterns.append(create_pattern(item))
        
        return patterns
    
    def _extract_patterns_deep(self, patterns_list: List[Any]) -> List[Pattern]:
        """Recursively extract patterns from nested structures"""
        patterns = []
        
        for item in patterns_list:
            if isinstance(item, dict):
                if 'pattern' in item:
                    patterns.append(create_pattern(item['pattern']))
                elif 'pattern-either' in item:
                    for either in item['pattern-either']:
                        if isinstance(either, dict) and 'pattern' in either:
                            patterns.append(create_pattern(either['pattern']))
                        elif isinstance(either, str):
                            patterns.append(create_pattern(either))
        
        return patterns
    
    def _is_supported_pattern(self, pattern_text: str) -> bool:
        """Check if pattern is supported by the AST matcher.
        
        Filters out:
        - Multi-line patterns (require statement sequence matching)
        - Patterns without concrete function/method anchors
        - Pure ellipsis patterns
        """
        if not pattern_text or not pattern_text.strip():
            return False
        
        # Multi-line patterns are not supported
        if '\n' in pattern_text:
            self.stats['patterns_skipped_multiline'] += 1
            return False
        
        # Pure ellipsis is not a useful pattern
        if pattern_text.strip() == '...':
            return False
        
        # Must have at least one concrete identifier (not just metavariables)
        import re
        tokens = re.findall(r'[\w\.]+|\$[A-Z_][A-Z0-9_]*', pattern_text)
        has_concrete = False
        for token in tokens:
            # Check if token is a metavariable
            if re.match(r'^\$[A-Z_][A-Z0-9_]*$', token):
                continue
            # Check if token contains a concrete identifier (like function name)
            if re.match(r'^[a-z_][a-z0-9_\.]*$', token, re.IGNORECASE):
                has_concrete = True
                break
        
        if not has_concrete:
            self.stats['patterns_skipped_no_anchor'] += 1
        
        return has_concrete
    
    def get_stats(self) -> Dict[str, int]:
        """Get loader statistics for diagnostics"""
        return self.stats.copy()
    
    
    def _extract_patterns(self, rule_data: Dict[str, Any]) -> List[Pattern]:
        """Extract and convert Semgrep patterns to our format"""
        patterns = []
        
        # Handle simple pattern field
        if 'pattern' in rule_data:
            pattern_str = rule_data['pattern']
            if self._is_supported_pattern(pattern_str):
                patterns.append(create_pattern(pattern_str))
        
        # Handle regex pattern field
        if 'pattern-regex' in rule_data:
            pattern_str = rule_data['pattern-regex']
            # Regex patterns are always supported (parsed by re module)
            patterns.append(Pattern(pattern_text=pattern_str, is_regex=True))
        
        # Handle patterns list
        if 'patterns' in rule_data:
            for pattern_item in rule_data['patterns']:
                if isinstance(pattern_item, dict):
                    # Handle pattern-either
                    if 'pattern-either' in pattern_item:
                        for either_pattern in pattern_item['pattern-either']:
                            if isinstance(either_pattern, dict) and 'pattern' in either_pattern:
                                p = either_pattern['pattern']
                                if self._is_supported_pattern(p):
                                    patterns.append(create_pattern(p))
                            elif isinstance(either_pattern, dict) and 'pattern-regex' in either_pattern:
                                p = either_pattern['pattern-regex']
                                patterns.append(Pattern(pattern_text=p, is_regex=True))
                            elif isinstance(either_pattern, str):
                                if self._is_supported_pattern(either_pattern):
                                    patterns.append(create_pattern(either_pattern))
                    
                    # Handle simple pattern in list
                    elif 'pattern' in pattern_item:
                        p = pattern_item['pattern']
                        if self._is_supported_pattern(p):
                            patterns.append(create_pattern(p))

                    # Handle regex pattern in list
                    elif 'pattern-regex' in pattern_item:
                        p = pattern_item['pattern-regex']
                        patterns.append(Pattern(pattern_text=p, is_regex=True))
                
                elif isinstance(pattern_item, str):
                    if self._is_supported_pattern(pattern_item):
                        patterns.append(create_pattern(pattern_item))
        
        # Handle pattern-either at top level
        if 'pattern-either' in rule_data:
            for either_pattern in rule_data['pattern-either']:
                if isinstance(either_pattern, dict) and 'pattern' in either_pattern:
                    p = either_pattern['pattern']
                    if self._is_supported_pattern(p):
                        patterns.append(create_pattern(p))
                elif isinstance(either_pattern, dict) and 'pattern-regex' in either_pattern:
                    p = either_pattern['pattern-regex']
                    patterns.append(Pattern(pattern_text=p, is_regex=True))
                elif isinstance(either_pattern, str):
                    if self._is_supported_pattern(either_pattern):
                        patterns.append(create_pattern(either_pattern))
        
        return patterns
    
    def _extract_pattern_nots(self, rule_data: Dict[str, Any]) -> List[Pattern]:
        """Extract pattern-not negation patterns from a rule.
        
        These are used to exclude false positives from matches.
        """
        pattern_nots = []
        
        # Handle pattern-not at top level
        if 'pattern-not' in rule_data:
            p = rule_data['pattern-not']
            if isinstance(p, str) and self._is_supported_pattern(p):
                pattern_nots.append(create_pattern(p))
        
        # Handle pattern-not-regex at top level
        if 'pattern-not-regex' in rule_data:
            p = rule_data['pattern-not-regex']
            pattern_nots.append(Pattern(pattern_text=p, is_regex=True))
        
        # Handle pattern-not in patterns list
        if 'patterns' in rule_data:
            for pattern_item in rule_data['patterns']:
                if isinstance(pattern_item, dict):
                    if 'pattern-not' in pattern_item:
                        p = pattern_item['pattern-not']
                        if isinstance(p, str) and self._is_supported_pattern(p):
                            pattern_nots.append(create_pattern(p))
                    if 'pattern-not-regex' in pattern_item:
                        p = pattern_item['pattern-not-regex']
                        pattern_nots.append(Pattern(pattern_text=p, is_regex=True))
        
        return pattern_nots
    
    def get_rules_by_language(self, language: str) -> List[Rule]:
        """Get all rules for a specific language"""
        return [rule for rule in self.loaded_rules if language in rule.languages]
    
    def get_rules_by_severity(self, severity: str) -> List[Rule]:
        """Get all rules of a specific severity"""
        return [rule for rule in self.loaded_rules if rule.severity == severity]
    
    def get_taint_rules(self) -> List[TaintRule]:
        """Get all loaded taint analysis rules"""
        return self.taint_rules
    
    def get_taint_rules_by_language(self, language: str) -> List[TaintRule]:
        """Get taint rules for a specific language"""
        return [rule for rule in self.taint_rules if language in rule.languages]
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules"""
        stats = {
            'total': len(self.loaded_rules),
            'taint_rules': len(self.taint_rules),
            'by_language': {},
            'by_severity': {'error': 0, 'warning': 0, 'info': 0}
        }
        
        for rule in self.loaded_rules:
            # Count by language
            for lang in rule.languages:
                stats['by_language'][lang] = stats['by_language'].get(lang, 0) + 1
            
            # Count by severity
            stats['by_severity'][rule.severity] = stats['by_severity'].get(rule.severity, 0) + 1
        
        return stats


# Global loader instance
_loader = None

def get_loader() -> SemgrepRuleLoader:
    """Get or create the global rule loader"""
    global _loader
    if _loader is None:
        _loader = SemgrepRuleLoader()
    return _loader


def load_rules(languages: List[str] = None) -> List[Rule]:
    """Load all rules for specified languages"""
    loader = get_loader()
    return loader.load_all_rules(languages)


if __name__ == '__main__':
    # Test the loader
    loader = SemgrepRuleLoader()
    rules = loader.load_all_rules(['python'])
    stats = loader.get_rule_stats()
    
    print(f"Loaded {stats['total']} rules")
    print(f"By language: {stats['by_language']}")
    print(f"By severity: {stats['by_severity']}")
    
    # Show a sample rule
    if rules:
        sample = rules[0]
        print(f"\nSample rule: {sample.id}")
        print(f"Message: {sample.message[:100]}...")
        print(f"Patterns: {len(sample.patterns)}")
