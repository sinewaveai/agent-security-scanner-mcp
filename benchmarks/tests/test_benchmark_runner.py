"""Tests for benchmark runner."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from benchmark_runner import classify_findings, run_benchmark
from annotation_parser import (
    AnnotatedCorpusFile, Annotation, AnnotationType,
)
from metrics import Outcome


def make_annotated(file_path='test.py', language='python', vuln=None, safe=None):
    """Helper to build an AnnotatedCorpusFile."""
    result = AnnotatedCorpusFile(file_path=file_path, language=language)
    for ann in (vuln or []):
        result.annotations.append(ann)
        result.vuln_by_line.setdefault(ann.line_number, []).append(ann)
        result.annotated_lines.add(ann.line_number)
    for ann in (safe or []):
        result.annotations.append(ann)
        result.safe_by_line.setdefault(ann.line_number, []).append(ann)
        result.annotated_lines.add(ann.line_number)
    return result


class TestClassifyFindings:
    def test_tp_vuln_flagged(self):
        annotated = make_annotated(vuln=[
            Annotation(1, AnnotationType.VULN, 'sqli'),
        ])
        findings = [{'ruleId': 'python.lang.security.sqli.cursor', 'line': 1, 'column': 0}]
        outcomes = classify_findings(annotated, findings)
        assert any(o.outcome_type == 'TP' for o in outcomes)

    def test_fn_vuln_not_flagged(self):
        annotated = make_annotated(vuln=[
            Annotation(1, AnnotationType.VULN, 'sqli'),
        ])
        findings = []
        outcomes = classify_findings(annotated, findings)
        assert any(o.outcome_type == 'FN' for o in outcomes)

    def test_fp_safe_flagged(self):
        annotated = make_annotated(safe=[
            Annotation(1, AnnotationType.SAFE, 'sqli'),
        ])
        findings = [{'ruleId': 'python.lang.security.sqli.cursor', 'line': 1, 'column': 0}]
        outcomes = classify_findings(annotated, findings)
        assert any(o.outcome_type == 'FP' for o in outcomes)

    def test_tn_safe_not_flagged(self):
        annotated = make_annotated(safe=[
            Annotation(1, AnnotationType.SAFE, 'sqli'),
        ])
        findings = []
        outcomes = classify_findings(annotated, findings)
        assert any(o.outcome_type == 'TN' for o in outcomes)

    def test_unannotated_finding(self):
        annotated = make_annotated()
        findings = [{'ruleId': 'python.sqli', 'line': 5, 'column': 0}]
        outcomes = classify_findings(annotated, findings)
        assert any(o.outcome_type == 'UNANNOTATED_FINDING' for o in outcomes)

    def test_safe_line_with_unrelated_rule(self):
        """SAFE:sqli on line also flagged for hardcoded-password."""
        annotated = make_annotated(safe=[
            Annotation(1, AnnotationType.SAFE, 'sqli'),
        ])
        findings = [
            {'ruleId': 'python.sqli.cursor', 'line': 1, 'column': 0},
            {'ruleId': 'generic.hardcoded-password', 'line': 1, 'column': 0},
        ]
        outcomes = classify_findings(annotated, findings)
        fps = [o for o in outcomes if o.outcome_type == 'FP']
        unann = [o for o in outcomes if o.outcome_type == 'UNANNOTATED_FINDING']
        assert len(fps) == 1
        assert len(unann) == 1


class TestRunBenchmark:
    def test_integration_with_real_analyzer(self, tmp_path):
        """Write a corpus file and run the full benchmark pipeline."""
        corpus_file = tmp_path / "test_sqli.py"
        corpus_file.write_text(
            '# VULN: sqli\n'
            'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n'
            '# SAFE: sqli\n'
            'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
        )
        result = run_benchmark(str(tmp_path))
        assert result.overall.tp >= 1
        assert result.overall.tn >= 1
