"""
AST Parser Module - tree-sitter Integration

This module provides multi-language AST parsing using tree-sitter.
Supports: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, Rust, C#
"""

import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

# tree-sitter imports
try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjavascript
    import tree_sitter_java as tsjava
    import tree_sitter_go as tsgo
    import tree_sitter_ruby as tsruby
    import tree_sitter_php as tsphp
    import tree_sitter_c as tsc
    import tree_sitter_cpp as tscpp
    import tree_sitter_rust as tsrust
    import tree_sitter_c_sharp as tscsharp
    import tree_sitter_typescript as tstypescript
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
    # Define stub types for type hints when tree-sitter not installed
    Parser = None
    Language = None


# Language registry - maps file extensions to tree-sitter languages
LANGUAGE_REGISTRY: Dict[str, Any] = {}

if HAS_TREE_SITTER:
    LANGUAGE_REGISTRY = {
        'python': Language(tspython.language()),
        'javascript': Language(tsjavascript.language()),
        'typescript': Language(tstypescript.language_typescript()),
        'tsx': Language(tstypescript.language_tsx()),
        'java': Language(tsjava.language()),
        'go': Language(tsgo.language()),
        'ruby': Language(tsruby.language()),
        'php': Language(tsphp.language_php()),
        'c': Language(tsc.language()),
        'cpp': Language(tscpp.language()),
        'rust': Language(tsrust.language()),
        'csharp': Language(tscsharp.language()),
    }


# File extension to language mapping
EXTENSION_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hpp': 'cpp',
    '.rs': 'rust',
    '.cs': 'csharp',
    # Additions for fallback support
    '.yaml': 'kubernetes', 
    '.yml': 'kubernetes',
    '.tf': 'terraform',
    '.txt': 'generic',
    '.md': 'generic',
    '.json': 'json',
}


@dataclass
class ParseResult:
    """Result of parsing a source file"""
    tree: Any  # tree_sitter.Tree or MockTree
    language: str
    source_bytes: bytes
    success: bool
    error: Optional[str] = None


class MockNode:
    """Mock tree-sitter node for fallback parsing"""
    def __init__(self, type_name: str, source_bytes: bytes):
        self.type = type_name
        self.start_byte = 0
        self.end_byte = len(source_bytes)
        self.start_point = (0, 0)
        self.end_point = (source_bytes.count(b'\n'), 0)
        self.child_count = 0
        self.children = []


class MockTree:
    """Mock tree-sitter tree for fallback parsing"""
    def __init__(self, source_bytes: bytes, language: str):
        self.root_node = MockNode("source_file", source_bytes)
        self.language = language


class ASTParser:
    """
    Multi-language AST parser using tree-sitter.
    
    Example usage:
        parser = ASTParser()
        result = parser.parse_file("example.py")
        if result.success:
            root = result.tree.root_node
            print(root.sexp())
    """
    
    def __init__(self):
        if not HAS_TREE_SITTER:
            raise ImportError(
                "tree-sitter and language bindings are required. "
                "Install with: pip install -r requirements.txt"
            )
        self._parsers: Dict[str, Parser] = {}
    
    def _get_parser(self, language: str) -> Optional[Parser]:
        """Get or create a parser for the specified language"""
        if language not in LANGUAGE_REGISTRY:
            return None
        
        if language not in self._parsers:
            parser = Parser()
            parser.language = LANGUAGE_REGISTRY[language]
            self._parsers[language] = parser
        
        return self._parsers[language]
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect programming language from file extension"""
        _, ext = os.path.splitext(file_path.lower())
        return EXTENSION_MAP.get(ext)
    
    def parse_file(self, file_path: str) -> ParseResult:
        """Parse a source file and return the AST"""
        language = self.detect_language(file_path)
        
        if not language:
            # Fallback for unknown extensions
            language = 'generic'
        
        parser = self._get_parser(language)
        if not parser:
            # Fallback to generic parsing for unsupported languages
            try:
                with open(file_path, 'rb') as f:
                    source_bytes = f.read()
                return ParseResult(
                    tree=MockTree(source_bytes, language),
                    language=language,
                    source_bytes=source_bytes,
                    success=True
                )
            except Exception as e:
                return ParseResult(
                    tree=None,
                    language=language,
                    source_bytes=b'',
                    success=False,
                    error=str(e)
                )
        
        try:
            with open(file_path, 'rb') as f:
                source_bytes = f.read()
            
            tree = parser.parse(source_bytes)
            
            return ParseResult(
                tree=tree,
                language=language,
                source_bytes=source_bytes,
                success=True
            )
        except Exception as e:
            return ParseResult(
                tree=None,
                language=language,
                source_bytes=b'',
                success=False,
                error=str(e)
            )
    
    def parse_string(self, source: str, language: str) -> ParseResult:
        """Parse source code string and return the AST"""
        parser = self._get_parser(language)
        if not parser:
            return ParseResult(
                tree=None,
                language=language,
                source_bytes=b'',
                success=False,
                error=f"No parser available for language: {language}"
            )
        
        try:
            source_bytes = source.encode('utf-8')
            tree = parser.parse(source_bytes)
            
            return ParseResult(
                tree=tree,
                language=language,
                source_bytes=source_bytes,
                success=True
            )
        except Exception as e:
            return ParseResult(
                tree=None,
                language=language,
                source_bytes=b'',
                success=False,
                error=str(e)
            )
    
    def get_supported_languages(self) -> List[str]:
        """Return list of supported languages"""
        return list(LANGUAGE_REGISTRY.keys())


def walk_tree(node, callback, depth=0):
    """
    Walk the AST tree and call callback for each node.
    
    Args:
        node: tree_sitter.Node to walk
        callback: function(node, depth) -> bool, return False to stop descent
        depth: current depth in tree
    """
    if callback(node, depth) is False:
        return
    
    for child in node.children:
        walk_tree(child, callback, depth + 1)


def get_node_text(node, source_bytes: bytes) -> str:
    """Extract the text of a node from source bytes"""
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8')


def find_nodes_by_type(root_node, node_type: str) -> List[Any]:
    """Find all nodes of a specific type in the tree"""
    results = []
    
    def collect(node, depth):
        if node.type == node_type:
            results.append(node)
        return True
    
    walk_tree(root_node, collect)
    return results


# Convenience function for quick parsing
def parse(file_path: str) -> ParseResult:
    """Quick parse a file - creates a new parser each time"""
    parser = ASTParser()
    return parser.parse_file(file_path)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ast_parser.py <file_path>")
        sys.exit(1)
    
    result = parse(sys.argv[1])
    
    if result.success:
        print(f"Language: {result.language}")
        print(f"Root node type: {result.tree.root_node.type}")
        print(f"Child count: {result.tree.root_node.child_count}")
        
        # Print first few child nodes as demo
        print("\nTop-level nodes:")
        for i, child in enumerate(result.tree.root_node.children[:10]):
            text_preview = get_node_text(child, result.source_bytes)[:50].replace('\n', '\\n')
            print(f"  [{i}] {child.type}: {text_preview}...")
    else:
        print(f"Error: {result.error}")
