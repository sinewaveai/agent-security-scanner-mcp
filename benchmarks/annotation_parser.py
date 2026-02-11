"""Parse VULN/SAFE/FP-PRONE annotations from benchmark corpus files."""
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

# Import detect_language from the analyzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from analyzer import detect_language

ANNOTATION_RE = re.compile(r'^(VULN|SAFE|FP-PRONE)\s*:\s*(\S+)\s*(.*)?$')

COMMENT_PREFIXES = {
    'python': '#', 'javascript': '//', 'typescript': '//',
    'java': '//', 'go': '//', 'generic': '#', 'dockerfile': '#',
    'c': '//', 'ruby': '#', 'php': '//', 'terraform': '#', 'yaml': '#',
}


class AnnotationType(Enum):
    VULN = "VULN"
    SAFE = "SAFE"
    FP_PRONE = "FP-PRONE"


@dataclass
class Annotation:
    line_number: int  # 0-indexed, points to the CODE line (set after parsing)
    annotation_type: AnnotationType
    rule_pattern: str
    description: str = ''
    raw_comment: str = ''


@dataclass
class AnnotatedCorpusFile:
    file_path: str
    language: str
    annotations: List[Annotation] = field(default_factory=list)
    vuln_by_line: Dict[int, List[Annotation]] = field(default_factory=dict)
    safe_by_line: Dict[int, List[Annotation]] = field(default_factory=dict)
    annotated_lines: Set[int] = field(default_factory=set)


def _extract_comment_text(line: str, language: str) -> Optional[str]:
    """Extract text after comment prefix, or None if not a comment."""
    stripped = line.strip()
    prefix = COMMENT_PREFIXES.get(language, '#')
    if stripped.startswith(prefix):
        return stripped[len(prefix):].strip()
    # Also check # for all languages
    if prefix != '#' and stripped.startswith('#'):
        return stripped[1:].strip()
    return None


def _try_parse_annotation(comment_text: str, raw_line: str) -> Optional[Annotation]:
    """Try to parse an annotation from comment text. Returns None if not an annotation."""
    match = ANNOTATION_RE.match(comment_text)
    if not match:
        return None
    tag, rule_pattern, description = match.groups()
    return Annotation(
        line_number=-1,  # Will be set when attached to code line
        annotation_type=AnnotationType(tag),
        rule_pattern=rule_pattern,
        description=(description or '').strip().strip('()'),
        raw_comment=raw_line,
    )


def parse_corpus_string(content: str, extension: str) -> AnnotatedCorpusFile:
    """Parse annotations from a string of code. Extension determines language."""
    # Determine language from extension
    fd, tmp = tempfile.mkstemp(suffix=extension)
    os.close(fd)
    try:
        language = detect_language(tmp)
    finally:
        os.unlink(tmp)

    return _parse_lines(content.splitlines(True), '', language)


def parse_corpus_file(file_path: str) -> AnnotatedCorpusFile:
    """Parse annotations from a corpus file on disk."""
    language = detect_language(file_path)
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    return _parse_lines(lines, file_path, language)


def _parse_lines(lines: list, file_path: str, language: str) -> AnnotatedCorpusFile:
    """Core parsing logic."""
    pending = []
    annotations = []

    for i, raw_line in enumerate(lines):
        stripped = raw_line.strip()

        # Empty line flushes pending annotations
        if not stripped:
            pending = []
            continue

        # Check if this is a comment line
        comment_text = _extract_comment_text(stripped, language)
        if comment_text is not None:
            ann = _try_parse_annotation(comment_text, raw_line)
            if ann is not None:
                pending.append(ann)
            else:
                # Non-annotation comment breaks the chain
                pending = []
            continue

        # Code line — attach pending annotations
        if pending:
            for ann in pending:
                ann.line_number = i
                annotations.append(ann)
            pending = []

    # Trailing annotations at EOF are discarded (no code line follows)

    result = AnnotatedCorpusFile(file_path=file_path, language=language, annotations=annotations)
    for ann in annotations:
        if ann.annotation_type == AnnotationType.VULN:
            result.vuln_by_line.setdefault(ann.line_number, []).append(ann)
        else:
            result.safe_by_line.setdefault(ann.line_number, []).append(ann)
        result.annotated_lines.add(ann.line_number)

    return result
