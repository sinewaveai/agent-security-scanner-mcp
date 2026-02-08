"""
Taint Analysis Engine

Tracks dataflow from user-controlled sources to dangerous sinks.
Detects vulnerabilities only when tainted data reaches a sink.

Algorithm:
1. Find source patterns (user input) and mark matched variables as tainted
2. Track taint through assignments (y = x means y inherits x's taint)
3. Check if any tainted variable reaches a sink pattern
4. Report vulnerability if tainted data flows to sink
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from generic_ast import GenericNode, NodeKind
from pattern_matcher import (
    Pattern, TaintRule, Finding, PatternMatcher, 
    MatchResult, create_pattern
)


@dataclass
class TaintedVariable:
    """Represents a tainted variable and its source"""
    name: str
    source_pattern: str       # Which source pattern matched
    source_line: int          # Line where taint originated
    propagation_path: List[str] = field(default_factory=list)  # How taint flowed


@dataclass
class VariableAssignment:
    """Represents a variable assignment in the code"""
    target: str              # Variable being assigned to
    source_vars: Set[str]    # Variables used in the right-hand side
    line: int
    column: int
    node: GenericNode


class TaintAnalyzer:
    """
    Performs taint analysis on an AST using TaintRule definitions.
    
    Tracks how data flows from sources (user input) to sinks (dangerous functions).
    """
    
    def __init__(self):
        self.matcher = PatternMatcher()
        self.tainted: Dict[str, TaintedVariable] = {}
        self.assignments: List[VariableAssignment] = []
    
    def analyze(self, ast: GenericNode, rules: List[TaintRule]) -> List[Finding]:
        """
        Analyze AST for taint vulnerabilities using the provided rules.
        
        Returns list of findings where tainted data reaches a sink.
        """
        all_findings = []
        
        for rule in rules:
            findings = self._analyze_rule(ast, rule)
            all_findings.extend(findings)
        
        return all_findings
    
    def _analyze_rule(self, ast: GenericNode, rule: TaintRule) -> List[Finding]:
        """Analyze a single taint rule against the AST"""
        # Reset state for each rule
        self.tainted = {}
        self.assignments = []
        
        # Step 1: Collect all variable assignments
        self._collect_assignments(ast)
        
        # Step 2: Find sources and mark initial tainted variables
        self._find_sources(ast, rule)
        
        # Step 3: Propagate taint through assignments
        self._propagate_taint(rule)
        
        # Step 4: Check sinks for tainted input
        findings = self._check_sinks(ast, rule)
        
        return findings
    
    def _collect_assignments(self, node: GenericNode):
        """Collect all variable assignments in the AST"""
        if node.kind == NodeKind.ASSIGNMENT:
            # Extract target and source variables
            target = self._get_assignment_target(node)
            source_vars = self._get_referenced_variables(node)
            
            if target:
                # Remove target from source vars (x = x + 1 shouldn't include x as source twice)
                source_vars.discard(target)
                
                self.assignments.append(VariableAssignment(
                    target=target,
                    source_vars=source_vars,
                    line=node.line,
                    column=node.column,
                    node=node
                ))
        
        # Recurse into children
        for child in node.children:
            self._collect_assignments(child)
    
    def _get_assignment_target(self, node: GenericNode) -> Optional[str]:
        """Extract the target variable name from an assignment"""
        # Look for identifier on the left side
        for child in node.children:
            if child.kind == NodeKind.IDENTIFIER:
                return child.text
            # Handle attribute access (obj.attr = ...)
            if child.kind == NodeKind.ATTRIBUTE:
                return child.text
        return None
    
    def _get_referenced_variables(self, node: GenericNode) -> Set[str]:
        """Get all variable names referenced in a node"""
        vars_found = set()
        
        def collect(n: GenericNode, skip_first: bool = False):
            # Skip the first identifier in assignments (that's the target)
            if n.kind == NodeKind.IDENTIFIER:
                if not skip_first:
                    vars_found.add(n.text)
            elif n.kind == NodeKind.CALL:
                # For function calls, check arguments
                for child in n.children:
                    collect(child, False)
            else:
                first_child = True
                for child in n.children:
                    collect(child, skip_first and first_child)
                    first_child = False
        
        collect(node, skip_first=True)
        return vars_found

    def _find_sources(self, ast: GenericNode, rule: TaintRule):
        """Find source patterns and mark matched variables as tainted"""
        for source_pattern in rule.sources:
            matches = self.matcher.find_all(source_pattern, ast)
            
            for match in matches:
                # Check if this source match is sanitized directly
                if match.node and self._is_sanitized(match.node, rule):
                    continue

                # Get the variable that receives the tainted value
                tainted_var = self._find_receiving_variable(match, ast)
                
                if tainted_var:
                    # Check if the assignment itself is sanitized (e.g. x = sanitize(source))
                    assignment = self._get_assignment_by_target(tainted_var)
                    if assignment and self._is_assignment_sanitized(assignment, rule):
                        continue
                        
                    self.tainted[tainted_var] = TaintedVariable(
                        name=tainted_var,
                        source_pattern=source_pattern.pattern_text,
                        source_line=match.line,
                        propagation_path=[f"Source: {source_pattern.pattern_text}"]
                    )
                
                # Check captured metavariables
                for meta_name, meta in match.metavariables.items():
                    if meta.text and meta.text not in self.tainted:
                        if meta.node and self._is_sanitized(meta.node, rule):
                            continue
                            
                        self.tainted[meta.text] = TaintedVariable(
                            name=meta.text,
                            source_pattern=source_pattern.pattern_text,
                            source_line=match.line,
                            propagation_path=[f"Captured: {meta_name}={meta.text}"]
                        )

    def _get_assignment_by_target(self, target: str) -> Optional[VariableAssignment]:
        for assignment in self.assignments:
            if assignment.target == target:
                return assignment
        return None

    def _is_sanitized(self, node: GenericNode, rule: TaintRule) -> bool:
        """Check if a node is covered by a sanitizer"""
        if not rule.sanitizers:
            return False
        for sanitizer in rule.sanitizers:
            if self.matcher.match(sanitizer, node):
                return True
        return False
    
    def _find_receiving_variable(self, match: MatchResult, ast: GenericNode) -> Optional[str]:
        """Find which variable receives the matched expression"""
        for assignment in self.assignments:
            if assignment.line == match.line:
                return assignment.target
        return None
    
    def _propagate_taint(self, rule: TaintRule):
        """Propagate taint through variable assignments"""
        changed = True
        iterations = 0
        max_iterations = 100
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for assignment in self.assignments:
                if assignment.target in self.tainted:
                    continue
                
                if self._is_assignment_sanitized(assignment, rule):
                    continue

                for source_var in assignment.source_vars:
                    if source_var in self.tainted:
                        source_taint = self.tainted[source_var]
                        new_path = source_taint.propagation_path.copy()
                        new_path.append(f"Line {assignment.line}: {assignment.target} = ... {source_var} ...")
                        
                        self.tainted[assignment.target] = TaintedVariable(
                            name=assignment.target,
                            source_pattern=source_taint.source_pattern,
                            source_line=source_taint.source_line,
                            propagation_path=new_path
                        )
                        changed = True
                        break
    
    def _is_assignment_sanitized(self, assignment: VariableAssignment, rule: TaintRule) -> bool:
        """Check if an assignment is sanitized"""
        if not rule.sanitizers:
            return False
        for sanitizer in rule.sanitizers:
            if self.matcher.find_all(sanitizer, assignment.node):
                return True
        return False
    
    def _check_sinks(self, ast: GenericNode, rule: TaintRule) -> List[Finding]:
        """Check if any tainted data reaches a sink"""
        findings = []
        
        for sink_pattern in rule.sinks:
            matches = self.matcher.find_all(sink_pattern, ast)
            
            for match in matches:
                # Find all tainted variables used in this sink match
                tainted_nodes = self._find_tainted_nodes_in_match(match)
                
                for var_name, var_node in tainted_nodes:
                    # Check if this usage is sanitized
                    if self._is_node_sanitized_in_context(var_node, match.node, rule):
                        continue
                        
                    taint_info = self.tainted[var_name]
                    path_str = " -> ".join(taint_info.propagation_path[-3:])
                    message = f"{rule.message}\n\nTaint flow: {path_str}\n\nTainted variable '{var_name}' flows to sink."
                    
                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        message=message,
                        severity=rule.severity,
                        line=match.line,
                        column=match.column,
                        text=match.node.text if match.node else "",
                        end_line=match.node.end_line if match.node else match.line,
                        end_column=match.node.end_column if match.node else match.column,
                        metavariables={k: v.text for k, v in match.metavariables.items()},
                        metadata={
                            **rule.metadata,
                            'taint_source': taint_info.source_pattern,
                            'taint_source_line': taint_info.source_line,
                            'tainted_variable': var_name
                        }
                    ))
        
        return findings

    def _find_tainted_nodes_in_match(self, match: MatchResult) -> List[Tuple[str, GenericNode]]:
        """Find tainted variables and their nodes within a match"""
        results = []
        
        # Check metavariables
        for meta in match.metavariables.values():
            if meta.text in self.tainted and meta.node:
                results.append((meta.text, meta.node))
                
        # If no metavariables, check all identifiers in the match node
        if not results and match.node:
            referenced = self._get_referenced_variables_with_nodes(match.node)
            for var_name, var_node in referenced:
                if var_name in self.tainted:
                    results.append((var_name, var_node))
                    
        return results

    def _get_referenced_variables_with_nodes(self, node: GenericNode) -> List[Tuple[str, GenericNode]]:
        """Get all variable names and nodes referenced in a node"""
        vars_found = []
        
        def collect(n: GenericNode):
            if n.kind == NodeKind.IDENTIFIER:
                vars_found.append((n.text, n))
            for child in n.children:
                collect(child)
        
        collect(node)
        return vars_found

    def _is_node_sanitized_in_context(self, target: GenericNode, context: GenericNode, rule: TaintRule) -> bool:
        """Check if target node is inside a sanitizer within context"""
        if not rule.sanitizers:
            return False
            
        # Find all sanitizer matches within context
        for sanitizer in rule.sanitizers:
            sanitizer_matches = self.matcher.find_all(sanitizer, context)
            for s_match in sanitizer_matches:
                if s_match.node and self._contains_range(s_match.node, target):
                    return True
        return False
        
    def _contains_range(self, outer: GenericNode, inner: GenericNode) -> bool:
        """Check if outer node lexically contains inner node"""
        # Simple line/column check
        if outer.line < inner.line or (outer.line == inner.line and outer.column <= inner.column):
            if outer.end_line > inner.end_line or (outer.end_line == inner.end_line and outer.end_column >= inner.end_column):
                return True
        return False
    
    # _find_tainted_in_match removed (replaced by _find_tainted_nodes_in_match)


def analyze_taint(ast: GenericNode, rules: List[TaintRule]) -> List[Finding]:
    """Convenience function to run taint analysis"""
    analyzer = TaintAnalyzer()
    return analyzer.analyze(ast, rules)


if __name__ == '__main__':
    # Quick test
    print("TaintAnalyzer module loaded successfully")
    print("Use analyze_taint(ast, rules) to run taint analysis")
