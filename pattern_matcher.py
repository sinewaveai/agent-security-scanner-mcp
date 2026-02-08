"""
Pattern Matcher Module - Semgrep-style AST Pattern Matching

Implements pattern matching with metavariables ($VAR, $FUNC, etc.)
against the generic AST representation.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Callable
from enum import Enum

from generic_ast import GenericNode, NodeKind


class PatternType(Enum):
    """Types of pattern operators"""
    PATTERN = "pattern"              # Match this pattern
    PATTERN_NOT = "pattern-not"      # Exclude matches of this pattern
    PATTERN_INSIDE = "pattern-inside"  # Match only inside this context
    PATTERN_EITHER = "pattern-either"  # Match any of these patterns (OR)
    PATTERNS = "patterns"            # Match all of these patterns (AND)


@dataclass
class Metavariable:
    """Represents a captured metavariable like $VAR or $FUNC"""
    name: str  # e.g., "$VAR"
    node: GenericNode  # The matched node
    text: str  # The source text


@dataclass
class MatchResult:
    """Result of a pattern match"""
    matched: bool
    node: Optional[GenericNode] = None
    metavariables: Dict[str, Metavariable] = field(default_factory=dict)
    line: int = 0
    column: int = 0
    
    def __bool__(self):
        return self.matched


@dataclass
class Pattern:
    """
    Represents a pattern to match against AST nodes.
    
    Patterns support:
    - Metavariables: $VAR matches any identifier, $FUNC matches function name
    - Ellipsis: ... matches any sequence of nodes
    - Literal text: matches exact text
    - Regex: matches node text against regex
    """
    pattern_text: str
    pattern_type: PatternType = PatternType.PATTERN
    is_regex: bool = False
    
    # Parsed components
    _tokens: List[str] = field(default_factory=list)
    _regex_obj: Optional[re.Pattern] = None
    _is_parsed: bool = False
    
    def __post_init__(self):
        if self.is_regex:
            try:
                self._regex_obj = re.compile(self.pattern_text)
            except re.error:
                # Fallback or log? For now just ignore
                pass
        elif not self._is_parsed:
            self._parse()
    
    def _parse(self):
        """Parse the pattern into tokens"""
        # Tokenize the pattern
        # Match: metavariables ($VAR), ellipsis (...), identifiers with dots, 
        # strings, individual punctuation marks
        # Important: Match ellipsis BEFORE individual dots, and parentheses individually
        token_pattern = r'(\$[A-Z_][A-Z0-9_]*|\.\.\.|\w+(?:\.\w+)*|"[^"]*"|\'[^\']*\'|[()\[\],=+\-*/<>!&|]|\s+)'
        self._tokens = [t for t in re.findall(token_pattern, self.pattern_text) if t.strip()]
        self._is_parsed = True


class PatternMatcher:
    """
    Matches Semgrep-style patterns against generic AST nodes.
    
    Example patterns:
    - "$FUNC($ARG)" - matches any function call
    - "$VAR = $EXPR" - matches any assignment
    - "cursor.execute($SQL)" - matches specific function call
    - "eval(...)" - matches eval with any arguments
    """
    
    # Metavariable pattern
    METAVAR_RE = re.compile(r'^\$[A-Z_][A-Z0-9_]*$')
    
    def __init__(self):
        self.debug = False
    
    def match(self, pattern: Pattern, node: GenericNode) -> MatchResult:
        """
        Match a pattern against a node and all its descendants.
        Returns the first match found.
        """
        # Try matching at this node
        result = self._match_node(pattern, node)
        if result.matched:
            return result
        
        # Recursively try children
        for child in node.children:
            result = self.match(pattern, child)
            if result.matched:
                return result
        
        return MatchResult(matched=False)
    
    def find_all(self, pattern: Pattern, node: GenericNode) -> List[MatchResult]:
        """Find all matches of the pattern in the AST"""
        results = []
        
        # Try matching at this node
        result = self._match_node(pattern, node)
        if result.matched:
            results.append(result)
        
        # Recursively search children
        for child in node.children:
            results.extend(self.find_all(pattern, child))
        
        return results
    
    def _match_node(self, pattern: Pattern, node: GenericNode) -> MatchResult:
        """Try to match a pattern at a specific node"""
        # Handle Regex patterns
        if pattern.is_regex and pattern._regex_obj:
            match = pattern._regex_obj.search(node.text)
            if match:
                # Calculate correct line number based on match offset
                match_start = match.start()
                relative_line = node.text[:match_start].count('\n')
                actual_line = node.line + relative_line
                
                return MatchResult(
                    matched=True,
                    node=node,
                    line=actual_line,
                    column=node.column  # Approximate column
                )
            return MatchResult(matched=False)

        tokens = pattern._tokens
        
        if not tokens:
            return MatchResult(matched=False)
        
        # Skip patterns that don't have concrete anchors (would match too broadly)
        if not self._has_concrete_anchor(tokens):
            return MatchResult(matched=False)
        
        metavariables: Dict[str, Metavariable] = {}
        
        # Function call pattern: $FUNC(...) or func_name(...)
        if self._is_call_pattern(tokens):
            if node.kind == NodeKind.CALL:
                func_token = tokens[0]
                
                # Check function name
                if self.METAVAR_RE.match(func_token):
                    # Metavariable - matches any function
                    if node.name:
                        metavariables[func_token] = Metavariable(
                            name=func_token,
                            node=node,
                            text=node.name
                        )
                elif node.name and not self._text_matches(func_token, node.name):
                    return MatchResult(matched=False)
                
                # Match arguments
                arg_match = self._match_arguments(tokens, node, metavariables)
                if arg_match:
                    return MatchResult(
                        matched=True,
                        node=node,
                        metavariables=metavariables,
                        line=node.line,
                        column=node.column
                    )
        
        # Assignment pattern: $VAR = $EXPR
        elif self._is_assignment_pattern(tokens):
            if node.kind == NodeKind.ASSIGNMENT:
                target_token = tokens[0]
                value_start_idx = 2  # After "="
                
                if node.target:
                    if self.METAVAR_RE.match(target_token):
                        metavariables[target_token] = Metavariable(
                            name=target_token,
                            node=node.target,
                            text=node.target.text
                        )
                    elif not self._text_matches(target_token, node.target.text):
                        return MatchResult(matched=False)
                
                if node.value and value_start_idx < len(tokens):
                    value_token = tokens[value_start_idx]
                    if self.METAVAR_RE.match(value_token):
                        metavariables[value_token] = Metavariable(
                            name=value_token,
                            node=node.value,
                            text=node.value.text
                        )
                
                return MatchResult(
                    matched=True,
                    node=node,
                    metavariables=metavariables,
                    line=node.line,
                    column=node.column
                )
        
        # NOTE: Single-token metavariable patterns (like $VAR) are intentionally
        # NOT matched here - they would match every node in the AST.
        # Metavariables should only capture within larger patterns.
        
        # Literal text match (for identifiers, strings, etc.)
        elif len(tokens) == 1:
            if self._text_matches(tokens[0], node.text.strip()):
                return MatchResult(
                    matched=True,
                    node=node,
                    line=node.line,
                    column=node.column
                )
        
        return MatchResult(matched=False)
    
    def _has_concrete_anchor(self, tokens: List[str]) -> bool:
        """Check if pattern has at least one non-metavariable concrete token.
        
        Patterns without concrete anchors (like just '$VAR' or '$FUNC(...)') 
        would match too broadly. We require at least one literal token.
        """
        for t in tokens:
            # Skip metavariables, punctuation, and ellipsis
            if self.METAVAR_RE.match(t):
                continue
            if t in ('(', ')', ',', '...', '=', '+', '-', '*', '/', '[', ']'):
                continue
            # This is a concrete token (function name, identifier, etc.)
            return True
        return False
    
    def _is_call_pattern(self, tokens: List[str]) -> bool:
        """Check if tokens represent a function call pattern"""
        if len(tokens) < 3:
            return False
        return '(' in tokens and ')' in tokens
    
    def _is_assignment_pattern(self, tokens: List[str]) -> bool:
        """Check if tokens represent an assignment pattern"""
        return '=' in tokens and tokens.index('=') > 0
    
    def _match_arguments(self, tokens: List[str], node: GenericNode, 
                         metavariables: Dict[str, Metavariable]) -> bool:
        """Match function arguments against pattern"""
        # Find argument section in tokens
        try:
            paren_start = tokens.index('(')
            paren_end = tokens.index(')')
        except ValueError:
            return False
        
        arg_tokens = tokens[paren_start + 1:paren_end]
        
        # Ellipsis matches any arguments
        if arg_tokens == ['...'] or arg_tokens == []:
            return True
        
        # Match individual arguments
        token_args = [t for t in arg_tokens if t not in (',',)]
        node_args = node.args
        
        # Split tokens by ellipsis '...'
        segments = []
        current_segment = []
        for t in token_args:
            if t == '...':
                segments.append(current_segment)
                current_segment = []
            else:
                current_segment.append(t)
        segments.append(current_segment)
        
        # Helper to match a segment at a specific index
        def match_segment(segment, start_idx, out_metavars) -> bool:
            for i, token in enumerate(segment):
                if start_idx + i >= len(node_args):
                    return False
                node_arg = node_args[start_idx + i]
                
                if self.METAVAR_RE.match(token):
                    out_metavars[token] = Metavariable(
                        name=token, node=node_arg, text=node_arg.text
                    )
                elif not self._text_matches(token, node_arg.text):
                    return False
            return True

        # Case 1: No ellipsis
        if len(segments) == 1:
            if len(node_args) != len(segments[0]):
                return False
            return match_segment(segments[0], 0, metavariables)
            
        # Case 2: Using ellipsis
        node_idx = 0
        
        # Match first segment (anchored at start)
        first_seg = segments[0]
        if first_seg:
            if not match_segment(first_seg, 0, metavariables):
                return False
            node_idx += len(first_seg)
            
        # Match middle segments (search forward)
        for i in range(1, len(segments) - 1):
            seg = segments[i]
            if not seg: continue
            
            found_idx = -1
            # Search for segment in remaining args
            # Optimization: ensure enough space for remaining segments? ignoring for now
            for k in range(node_idx, len(node_args) - len(seg) + 1):
                temp_metavars = {}
                if match_segment(seg, k, temp_metavars):
                    found_idx = k
                    metavariables.update(temp_metavars)
                    break
            
            if found_idx == -1:
                return False
            node_idx = found_idx + len(seg)
            
        # Match last segment (anchored at end)
        last_seg = segments[-1]
        if last_seg:
            remaining_len = len(node_args) - node_idx
            if len(last_seg) > remaining_len:
                return False
            
            # Must match exactly at the end
            start_k = len(node_args) - len(last_seg)
            return match_segment(last_seg, start_k, metavariables)
            
        return True
    
    def _text_matches(self, pattern_text: str, node_text: str) -> bool:
        """Check if node text matches pattern text (case-insensitive for identifiers)"""
        # Remove quotes if present
        pattern_text = pattern_text.strip('"\'')
        node_text = node_text.strip('"\'').strip()
        
        # Exact match or starts with (for method chains)
        return pattern_text == node_text or node_text.startswith(pattern_text + '.')


@dataclass
class Rule:
    """A security rule with patterns to match"""
    id: str
    name: str
    patterns: List[Pattern]
    message: str
    severity: str = "warning"
    languages: List[str] = field(default_factory=lambda: ["generic"])
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Pattern operators
    pattern_not: List[Pattern] = field(default_factory=list)
    pattern_inside: List[Pattern] = field(default_factory=list)


@dataclass
class TaintRule:
    """A taint analysis rule with sources, sinks, and optional sanitizers.
    
    Taint analysis tracks data flow from sources (user input) to sinks
    (dangerous functions). A vulnerability is reported when tainted data
    reaches a sink without being sanitized.
    
    Example:
        sources: [request.args.get(...), input(...)]
        sinks: [subprocess.run($CMD), eval($CODE)]
        sanitizers: [shlex.quote(...)]
    """
    id: str
    name: str
    sources: List[Pattern]      # Patterns that introduce tainted data
    sinks: List[Pattern]        # Patterns where tainted data is dangerous
    message: str
    severity: str = "error"
    languages: List[str] = field(default_factory=lambda: ["generic"])
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Optional: patterns that clean/sanitize tainted data
    sanitizers: List[Pattern] = field(default_factory=list)
    
    # Optional: patterns that propagate taint (default: all assignments propagate)
    propagators: List[Pattern] = field(default_factory=list)


@dataclass
class Finding:
    """A security finding from pattern matching"""
    rule_id: str
    rule_name: str
    message: str
    severity: str
    line: int
    column: int
    text: str
    end_line: int = 0
    end_column: int = 0
    metavariables: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    """Applies security rules to AST and collects findings"""
    
    def __init__(self):
        self.matcher = PatternMatcher()
    
    def apply_rule(self, rule: Rule, ast: GenericNode) -> List[Finding]:
        """Apply a single rule to the AST and return findings"""
        findings = []
        
        # Find all matches for the main patterns
        for pattern in rule.patterns:
            matches = self.matcher.find_all(pattern, ast)
            
            for match in matches:
                # Check pattern-not (exclusions)
                excluded = False
                for not_pattern in rule.pattern_not:
                    if match.node and self.matcher.match(not_pattern, match.node).matched:
                        excluded = True
                        break
                
                if excluded:
                    continue
                
                # Create finding
                end_line = match.node.end_line if match.node else match.line
                end_column = match.node.end_column if match.node else match.column
                
                finding = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=rule.message,
                    severity=rule.severity,
                    line=match.line,
                    column=match.column,
                    end_line=end_line,
                    end_column=end_column,
                    text=match.node.text if match.node else "",
                    metavariables={k: v.text for k, v in match.metavariables.items()},
                    metadata=rule.metadata
                )
                findings.append(finding)
        
        return findings
    
    def apply_rules(self, rules: List[Rule], ast: GenericNode) -> List[Finding]:
        """Apply multiple rules and return all findings"""
        findings = []
        for rule in rules:
            findings.extend(self.apply_rule(rule, ast))
        return findings


# Convenience functions
def create_pattern(pattern_text: str) -> Pattern:
    """Create a pattern from text"""
    return Pattern(pattern_text=pattern_text)


def match_pattern(pattern_text: str, node: GenericNode) -> MatchResult:
    """Quick pattern match"""
    pattern = create_pattern(pattern_text)
    matcher = PatternMatcher()
    return matcher.match(pattern, node)


def find_all_matches(pattern_text: str, node: GenericNode) -> List[MatchResult]:
    """Find all matches of a pattern"""
    pattern = create_pattern(pattern_text)
    matcher = PatternMatcher()
    return matcher.find_all(pattern, node)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    
    from ast_parser import ASTParser
    from generic_ast import convert_tree
    
    # Test patterns
    test_code = '''
import os
password = "secret123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
eval(user_input)
'''
    
    parser = ASTParser()
    result = parser.parse_string(test_code, 'python')
    
    if result.success:
        ast = convert_tree(result.tree, 'python', result.source_bytes)
        
        # Test patterns
        patterns_to_test = [
            "$FUNC($ARG)",
            "$VAR = $EXPR",
            "eval(...)",
            "cursor.execute($SQL)",
        ]
        
        print("Test code:")
        print(test_code)
        print("\nPattern matching results:")
        print("-" * 50)
        
        for pattern_text in patterns_to_test:
            matches = find_all_matches(pattern_text, ast)
            print(f"\nPattern: {pattern_text}")
            print(f"  Matches: {len(matches)}")
            for m in matches:
                print(f"    Line {m.line}: {m.node.text[:50] if m.node else 'N/A'}...")
                if m.metavariables:
                    print(f"    Captured: {', '.join(f'{k}={v.text}' for k, v in m.metavariables.items())}")
