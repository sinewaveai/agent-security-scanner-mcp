"""Tests for annotation parser."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from annotation_parser import (
    parse_corpus_file, parse_corpus_string,
    AnnotationType, Annotation, AnnotatedCorpusFile,
)


class TestParseAnnotations:
    def test_vuln_annotation(self):
        content = '# VULN: sqli\ncursor.execute("SELECT * FROM users WHERE id=" + uid)\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 1
        assert result.annotations[0].annotation_type == AnnotationType.VULN
        assert result.annotations[0].rule_pattern == "sqli"
        assert result.annotations[0].line_number == 1  # 0-indexed, points to code line

    def test_safe_annotation(self):
        content = '# SAFE: sqli\ncursor.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 1
        assert result.annotations[0].annotation_type == AnnotationType.SAFE

    def test_fp_prone_annotation(self):
        content = '# FP-PRONE: hardcoded-password\nlog.info("password policy requires 8 chars")\n'
        result = parse_corpus_string(content, ".py")
        assert result.annotations[0].annotation_type == AnnotationType.FP_PRONE

    def test_multiple_annotations_stacked(self):
        content = '# VULN: hardcoded-password\n# VULN: generic.secrets\npassword = "secret123"\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 2
        assert all(a.line_number == 2 for a in result.annotations)

    def test_blank_line_breaks_association(self):
        content = '# VULN: sqli\n\ncursor.execute("SELECT * FROM users")\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 0

    def test_non_annotation_comment_breaks_pending(self):
        content = '# VULN: sqli\n# This is a normal comment\ncursor.execute("...")\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 0

    def test_javascript_comment_syntax(self):
        content = '// VULN: innerHTML\nelement.innerHTML = data;\n'
        result = parse_corpus_string(content, ".js")
        assert len(result.annotations) == 1

    def test_annotation_with_description(self):
        content = '# VULN: sqli (string concat in WHERE)\ncursor.execute("..." + x)\n'
        result = parse_corpus_string(content, ".py")
        assert "string concat" in result.annotations[0].description

    def test_empty_file(self):
        result = parse_corpus_string("", ".py")
        assert len(result.annotations) == 0

    def test_vuln_by_line_index(self):
        content = '# VULN: sqli\ncode_line_1\n# SAFE: sqli\ncode_line_2\n'
        result = parse_corpus_string(content, ".py")
        assert 1 in result.vuln_by_line
        assert 3 in result.safe_by_line

    def test_trailing_annotation_at_eof(self):
        content = 'some_code()\n# VULN: sqli\n'
        result = parse_corpus_string(content, ".py")
        assert len(result.annotations) == 0

    def test_annotated_lines_set(self):
        content = '# VULN: sqli\ncode1\n# SAFE: xss\ncode2\ncode3\n'
        result = parse_corpus_string(content, ".py")
        assert result.annotated_lines == {1, 3}

    def test_parse_corpus_file_from_disk(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text('# VULN: sqli\ncursor.execute("..." + x)\n')
        result = parse_corpus_file(str(f))
        assert len(result.annotations) == 1
        assert result.language == "python"
