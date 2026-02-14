"""
Generic AST Module - Cross-Language AST Normalization

Defines a common AST representation that normalizes language-specific
tree-sitter nodes into a unified format for pattern matching.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class NodeKind(Enum):
    """Generic node kinds for cross-language matching"""
    # Top-level
    MODULE = "module"
    
    # Declarations
    FUNCTION_DEF = "function_def"
    CLASS_DEF = "class_def"
    VARIABLE_DEF = "variable_def"
    PARAMETER = "parameter"
    
    # Statements
    ASSIGNMENT = "assignment"
    RETURN = "return"
    IF = "if"
    FOR = "for"
    WHILE = "while"
    TRY = "try"
    WITH = "with"
    IMPORT = "import"
    EXPRESSION_STMT = "expression_stmt"
    
    # Expressions
    CALL = "call"
    ATTRIBUTE = "attribute"
    SUBSCRIPT = "subscript"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    COMPARISON = "comparison"
    
    # Literals
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NONE = "none"
    LIST = "list"
    DICT = "dict"
    
    # Identifiers
    IDENTIFIER = "identifier"
    
    # Other
    COMMENT = "comment"
    BLOCK = "block"
    ARGUMENT = "argument"
    UNKNOWN = "unknown"


@dataclass
class GenericNode:
    """
    Normalized AST node that works across all languages.
    
    Attributes:
        kind: The generic node type
        text: The source text of this node
        children: Child nodes
        line: 1-indexed line number
        column: 0-indexed column number
        end_line: End line number
        end_column: End column number
        metadata: Additional language-specific info
    """
    kind: NodeKind
    text: str
    children: List['GenericNode'] = field(default_factory=list)
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Named child accessors for pattern matching
    name: Optional[str] = None
    value: Optional['GenericNode'] = None
    target: Optional['GenericNode'] = None
    args: List['GenericNode'] = field(default_factory=list)
    operator: Optional[str] = None
    
    def find_all(self, kind: NodeKind) -> List['GenericNode']:
        """Find all descendant nodes of a specific kind"""
        results = []
        if self.kind == kind:
            results.append(self)
        for child in self.children:
            results.extend(child.find_all(kind))
        return results
    
    def find_first(self, kind: NodeKind) -> Optional['GenericNode']:
        """Find first descendant node of a specific kind"""
        if self.kind == kind:
            return self
        for child in self.children:
            result = child.find_first(kind)
            if result:
                return result
        return None
    
    def __repr__(self):
        return f"GenericNode({self.kind.value}, {self.text[:30]!r}...)" if len(self.text) > 30 else f"GenericNode({self.kind.value}, {self.text!r})"


# Language-specific node type mappings to generic kinds
PYTHON_NODE_MAP = {
    'module': NodeKind.MODULE,
    'function_definition': NodeKind.FUNCTION_DEF,
    'class_definition': NodeKind.CLASS_DEF,
    'assignment': NodeKind.ASSIGNMENT,
    'augmented_assignment': NodeKind.ASSIGNMENT,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'try_statement': NodeKind.TRY,
    'with_statement': NodeKind.WITH,
    'import_statement': NodeKind.IMPORT,
    'import_from_statement': NodeKind.IMPORT,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'call': NodeKind.CALL,
    'attribute': NodeKind.ATTRIBUTE,
    'subscript': NodeKind.SUBSCRIPT,
    'binary_operator': NodeKind.BINARY_OP,
    'unary_operator': NodeKind.UNARY_OP,
    'comparison_operator': NodeKind.COMPARISON,
    'string': NodeKind.STRING,
    'integer': NodeKind.NUMBER,
    'float': NodeKind.NUMBER,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'none': NodeKind.NONE,
    'list': NodeKind.LIST,
    'dictionary': NodeKind.DICT,
    'identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'block': NodeKind.BLOCK,
    'parameters': NodeKind.PARAMETER,
    'argument_list': NodeKind.ARGUMENT,
}

JAVASCRIPT_NODE_MAP = {
    'program': NodeKind.MODULE,
    'function_declaration': NodeKind.FUNCTION_DEF,
    'arrow_function': NodeKind.FUNCTION_DEF,
    'method_definition': NodeKind.FUNCTION_DEF,
    'class_declaration': NodeKind.CLASS_DEF,
    'variable_declaration': NodeKind.VARIABLE_DEF,
    'lexical_declaration': NodeKind.VARIABLE_DEF,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'for_in_statement': NodeKind.FOR,
    'for_of_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'try_statement': NodeKind.TRY,
    'import_statement': NodeKind.IMPORT,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'call_expression': NodeKind.CALL,
    'member_expression': NodeKind.ATTRIBUTE,
    'subscript_expression': NodeKind.SUBSCRIPT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_expression': NodeKind.UNARY_OP,
    'string': NodeKind.STRING,
    'template_string': NodeKind.STRING,
    'number': NodeKind.NUMBER,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'null': NodeKind.NONE,
    'undefined': NodeKind.NONE,
    'array': NodeKind.LIST,
    'object': NodeKind.DICT,
    'identifier': NodeKind.IDENTIFIER,
    'property_identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'statement_block': NodeKind.BLOCK,
    'arguments': NodeKind.ARGUMENT,
}

JAVA_NODE_MAP = {
    'program': NodeKind.MODULE,
    'method_declaration': NodeKind.FUNCTION_DEF,
    'constructor_declaration': NodeKind.FUNCTION_DEF,
    'class_declaration': NodeKind.CLASS_DEF,
    'interface_declaration': NodeKind.CLASS_DEF,
    'local_variable_declaration': NodeKind.VARIABLE_DEF,
    'field_declaration': NodeKind.VARIABLE_DEF,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'enhanced_for_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'try_statement': NodeKind.TRY,
    'import_declaration': NodeKind.IMPORT,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'method_invocation': NodeKind.CALL,
    'field_access': NodeKind.ATTRIBUTE,
    'array_access': NodeKind.SUBSCRIPT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_expression': NodeKind.UNARY_OP,
    'string_literal': NodeKind.STRING,
    'decimal_integer_literal': NodeKind.NUMBER,
    'decimal_floating_point_literal': NodeKind.NUMBER,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'null_literal': NodeKind.NONE,
    'array_initializer': NodeKind.LIST,
    'identifier': NodeKind.IDENTIFIER,
    'line_comment': NodeKind.COMMENT,
    'block_comment': NodeKind.COMMENT,
    'block': NodeKind.BLOCK,
    'argument_list': NodeKind.ARGUMENT,
}

# C language node map (tree-sitter-c)
C_NODE_MAP = {
    'translation_unit': NodeKind.MODULE,
    'function_definition': NodeKind.FUNCTION_DEF,
    'declaration': NodeKind.VARIABLE_DEF,
    'call_expression': NodeKind.CALL,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_expression': NodeKind.UNARY_OP,
    'string_literal': NodeKind.STRING,
    'number_literal': NodeKind.NUMBER,
    'char_literal': NodeKind.STRING,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'null': NodeKind.NONE,
    'identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'compound_statement': NodeKind.BLOCK,
    'argument_list': NodeKind.ARGUMENT,
    'field_expression': NodeKind.ATTRIBUTE,
    'subscript_expression': NodeKind.SUBSCRIPT,
}

# PHP language node map (tree-sitter-php)
PHP_NODE_MAP = {
    'program': NodeKind.MODULE,
    'function_definition': NodeKind.FUNCTION_DEF,
    'method_declaration': NodeKind.FUNCTION_DEF,
    'class_declaration': NodeKind.CLASS_DEF,
    'property_declaration': NodeKind.VARIABLE_DEF,
    'simple_parameter': NodeKind.PARAMETER,
    'function_call_expression': NodeKind.CALL,
    'method_call_expression': NodeKind.CALL,
    'member_call_expression': NodeKind.CALL,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'foreach_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'try_statement': NodeKind.TRY,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_op_expression': NodeKind.UNARY_OP,
    'encapsed_string': NodeKind.STRING,
    'string': NodeKind.STRING,
    'integer': NodeKind.NUMBER,
    'float': NodeKind.NUMBER,
    'boolean': NodeKind.BOOLEAN,
    'null': NodeKind.NONE,
    'name': NodeKind.IDENTIFIER,
    'variable_name': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'compound_statement': NodeKind.BLOCK,
    'arguments': NodeKind.ARGUMENT,
    'member_access_expression': NodeKind.ATTRIBUTE,
    'subscript_expression': NodeKind.SUBSCRIPT,
}

# Ruby language node map (tree-sitter-ruby)
RUBY_NODE_MAP = {
    'program': NodeKind.MODULE,
    'method': NodeKind.FUNCTION_DEF,
    'singleton_method': NodeKind.FUNCTION_DEF,
    'class': NodeKind.CLASS_DEF,
    'module': NodeKind.MODULE,
    'assignment': NodeKind.ASSIGNMENT,
    'call': NodeKind.CALL,
    'method_call': NodeKind.CALL,
    'return': NodeKind.RETURN,
    'if': NodeKind.IF,
    'unless': NodeKind.IF,
    'for': NodeKind.FOR,
    'while': NodeKind.WHILE,
    'until': NodeKind.WHILE,
    'begin': NodeKind.TRY,
    'binary': NodeKind.BINARY_OP,
    'unary': NodeKind.UNARY_OP,
    'string': NodeKind.STRING,
    'integer': NodeKind.NUMBER,
    'float': NodeKind.NUMBER,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'nil': NodeKind.NONE,
    'identifier': NodeKind.IDENTIFIER,
    'constant': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'do_block': NodeKind.BLOCK,
    'block': NodeKind.BLOCK,
    'argument_list': NodeKind.ARGUMENT,
    'element_reference': NodeKind.SUBSCRIPT,
}

# Go language node map (tree-sitter-go)  
GO_NODE_MAP = {
    'source_file': NodeKind.MODULE,
    'function_declaration': NodeKind.FUNCTION_DEF,
    'method_declaration': NodeKind.FUNCTION_DEF,
    'type_declaration': NodeKind.CLASS_DEF,
    'short_var_declaration': NodeKind.VARIABLE_DEF,
    'var_declaration': NodeKind.VARIABLE_DEF,
    'assignment_statement': NodeKind.ASSIGNMENT,
    'call_expression': NodeKind.CALL,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_expression': NodeKind.UNARY_OP,
    'interpreted_string_literal': NodeKind.STRING,
    'raw_string_literal': NodeKind.STRING,
    'int_literal': NodeKind.NUMBER,
    'float_literal': NodeKind.NUMBER,
    'true': NodeKind.BOOLEAN,
    'false': NodeKind.BOOLEAN,
    'nil': NodeKind.NONE,
    'identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'block': NodeKind.BLOCK,
    'argument_list': NodeKind.ARGUMENT,
    'selector_expression': NodeKind.ATTRIBUTE,
    'index_expression': NodeKind.SUBSCRIPT,
}

# Rust language node map (tree-sitter-rust)
RUST_NODE_MAP = {
    'source_file': NodeKind.MODULE,
    'function_item': NodeKind.FUNCTION_DEF,
    'impl_item': NodeKind.CLASS_DEF,
    'struct_item': NodeKind.CLASS_DEF,
    'let_declaration': NodeKind.VARIABLE_DEF,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'call_expression': NodeKind.CALL,
    'return_expression': NodeKind.RETURN,
    'if_expression': NodeKind.IF,
    'for_expression': NodeKind.FOR,
    'while_expression': NodeKind.WHILE,
    'loop_expression': NodeKind.WHILE,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'binary_expression': NodeKind.BINARY_OP,
    'unary_expression': NodeKind.UNARY_OP,
    'string_literal': NodeKind.STRING,
    'raw_string_literal': NodeKind.STRING,
    'integer_literal': NodeKind.NUMBER,
    'float_literal': NodeKind.NUMBER,
    'boolean_literal': NodeKind.BOOLEAN,
    'identifier': NodeKind.IDENTIFIER,
    'line_comment': NodeKind.COMMENT,
    'block_comment': NodeKind.COMMENT,
    'block': NodeKind.BLOCK,
    'arguments': NodeKind.ARGUMENT,
    'field_expression': NodeKind.ATTRIBUTE,
    'index_expression': NodeKind.SUBSCRIPT,
}

# C# language node map (tree-sitter-c-sharp)
CSHARP_NODE_MAP = {
    'compilation_unit': NodeKind.MODULE,
    'method_declaration': NodeKind.FUNCTION_DEF,
    'constructor_declaration': NodeKind.FUNCTION_DEF,
    'class_declaration': NodeKind.CLASS_DEF,
    'interface_declaration': NodeKind.CLASS_DEF,
    'variable_declaration': NodeKind.VARIABLE_DEF,
    'assignment_expression': NodeKind.ASSIGNMENT,
    'invocation_expression': NodeKind.CALL,
    'return_statement': NodeKind.RETURN,
    'if_statement': NodeKind.IF,
    'for_statement': NodeKind.FOR,
    'foreach_statement': NodeKind.FOR,
    'while_statement': NodeKind.WHILE,
    'try_statement': NodeKind.TRY,
    'expression_statement': NodeKind.EXPRESSION_STMT,
    'binary_expression': NodeKind.BINARY_OP,
    'prefix_unary_expression': NodeKind.UNARY_OP,
    'string_literal': NodeKind.STRING,
    'interpolated_string_expression': NodeKind.STRING,
    'integer_literal': NodeKind.NUMBER,
    'real_literal': NodeKind.NUMBER,
    'boolean_literal': NodeKind.BOOLEAN,
    'null_literal': NodeKind.NONE,
    'identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
    'block': NodeKind.BLOCK,
    'argument_list': NodeKind.ARGUMENT,
    'member_access_expression': NodeKind.ATTRIBUTE,
    'element_access_expression': NodeKind.SUBSCRIPT,
}

# Generic mapping for languages not specifically mapped
GENERIC_NODE_MAP = {
    'source_file': NodeKind.MODULE,
    'program': NodeKind.MODULE,
    'module': NodeKind.MODULE,
    'function': NodeKind.FUNCTION_DEF,
    'method': NodeKind.FUNCTION_DEF,
    'class': NodeKind.CLASS_DEF,
    'call': NodeKind.CALL,
    'call_expression': NodeKind.CALL,
    'string': NodeKind.STRING,
    'string_literal': NodeKind.STRING,
    'identifier': NodeKind.IDENTIFIER,
    'comment': NodeKind.COMMENT,
}

# Combined language map
LANGUAGE_NODE_MAPS = {
    'python': PYTHON_NODE_MAP,
    'javascript': JAVASCRIPT_NODE_MAP,
    'typescript': JAVASCRIPT_NODE_MAP,
    'tsx': JAVASCRIPT_NODE_MAP,
    'java': JAVA_NODE_MAP,
    'c': C_NODE_MAP,
    'cpp': C_NODE_MAP,  # C++ uses similar structure
    'php': PHP_NODE_MAP,
    'ruby': RUBY_NODE_MAP,
    'go': GO_NODE_MAP,
    'rust': RUST_NODE_MAP,
    'csharp': CSHARP_NODE_MAP,
    'c_sharp': CSHARP_NODE_MAP,
}


class ASTConverter:
    """
    Converts tree-sitter AST to generic AST representation.
    """
    
    def __init__(self, language: str):
        self.language = language
        self.node_map = LANGUAGE_NODE_MAPS.get(language, GENERIC_NODE_MAP)
    
    def convert(self, ts_node, source_bytes: bytes) -> GenericNode:
        """Convert a tree-sitter node to a generic node"""
        # Handle MockNode or standard tree-sitter node
        node_type = getattr(ts_node, 'type', 'unknown')
        
        # Get the generic kind for this node type
        kind = self.node_map.get(node_type, NodeKind.UNKNOWN)
        
        # Extract text
        start_byte = getattr(ts_node, 'start_byte', 0)
        end_byte = getattr(ts_node, 'end_byte', len(source_bytes))
        text = source_bytes[start_byte:end_byte].decode('utf-8', errors='replace')
        
        # Get position info
        start_point = getattr(ts_node, 'start_point', (0, 0))
        end_point = getattr(ts_node, 'end_point', (0, 0))
        
        # Create generic node
        node = GenericNode(
            kind=kind,
            text=text,
            line=start_point[0] + 1,  # Convert to 1-indexed
            column=start_point[1],
            end_line=end_point[0] + 1,
            end_column=end_point[1],
            metadata={'ts_type': node_type}
        )
        
        # Convert children
        for child in ts_node.children:
            node.children.append(self.convert(child, source_bytes))
        
        # Extract named parts for common node types
        self._extract_named_parts(node, ts_node, source_bytes)
        
        return node
    
    def _extract_named_parts(self, node: GenericNode, ts_node, source_bytes: bytes):
        """Extract named parts (name, args, etc.) for pattern matching"""
        
        # For function calls, extract function name and arguments
        if node.kind == NodeKind.CALL:
            for child in ts_node.children:
                child_text = source_bytes[child.start_byte:child.end_byte].decode('utf-8')
                if child.type in ('identifier', 'attribute', 'member_expression'):
                    node.name = child_text
                elif child.type in ('argument_list', 'arguments'):
                    for arg_child in child.children:
                        if arg_child.type not in ('(', ')', ','):
                            node.args.append(self.convert(arg_child, source_bytes))
        
        # For assignments, extract target and value
        elif node.kind == NodeKind.ASSIGNMENT:
            children = [c for c in ts_node.children if c.type not in ('=', ':=')]
            if len(children) >= 2:
                node.target = self.convert(children[0], source_bytes)
                node.value = self.convert(children[-1], source_bytes)
        
        # For binary operations, extract operator
        elif node.kind == NodeKind.BINARY_OP:
            for child in ts_node.children:
                if child.type in ('+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=', 'and', 'or', '&&', '||', '+'):
                    node.operator = source_bytes[child.start_byte:child.end_byte].decode('utf-8')
        
        # For function definitions, extract name
        elif node.kind == NodeKind.FUNCTION_DEF:
            for child in ts_node.children:
                if child.type == 'identifier' or child.type == 'name':
                    node.name = source_bytes[child.start_byte:child.end_byte].decode('utf-8')
                    break


def convert_tree(ts_tree, language: str, source_bytes: bytes) -> GenericNode:
    """Convenience function to convert a tree-sitter tree to generic AST"""
    converter = ASTConverter(language)
    return converter.convert(ts_tree.root_node, source_bytes)


if __name__ == '__main__':
    # Quick test with ast_parser
    import sys
    sys.path.insert(0, '.')
    
    from ast_parser import ASTParser
    
    if len(sys.argv) < 2:
        print("Usage: python generic_ast.py <file_path>")
        sys.exit(1)
    
    parser = ASTParser()
    result = parser.parse_file(sys.argv[1])
    
    if result.success:
        generic_root = convert_tree(result.tree, result.language, result.source_bytes)
        
        print(f"Language: {result.language}")
        print(f"Root: {generic_root}")
        print(f"\nChildren ({len(generic_root.children)}):")
        
        for i, child in enumerate(generic_root.children[:15]):
            print(f"  [{i}] {child.kind.value}: {child.text[:40]!r}...")
        
        # Find all function calls
        calls = generic_root.find_all(NodeKind.CALL)
        if calls:
            print(f"\nFunction calls found ({len(calls)}):")
            for call in calls[:10]:
                print(f"  - {call.name or call.text[:30]} at line {call.line}")
    else:
        print(f"Error: {result.error}")
