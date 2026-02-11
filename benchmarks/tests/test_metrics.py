"""Tests for metrics calculation module."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from metrics import MetricSet, Outcome, BenchmarkResult, compute_metrics


class TestMetricSet:
    def test_precision_basic(self):
        m = MetricSet(tp=8, fp=2, fn=0, tn=0)
        assert m.precision == pytest.approx(0.8)

    def test_recall_basic(self):
        m = MetricSet(tp=8, fp=0, fn=2, tn=0)
        assert m.recall == pytest.approx(0.8)

    def test_f1_basic(self):
        m = MetricSet(tp=8, fp=2, fn=2, tn=0)
        # P=0.8, R=0.8, F1=0.8
        assert m.f1 == pytest.approx(0.8)

    def test_precision_zero_when_no_findings(self):
        m = MetricSet(tp=0, fp=0, fn=5, tn=10)
        assert m.precision == 0.0

    def test_recall_zero_when_no_expected(self):
        m = MetricSet(tp=0, fp=5, fn=0, tn=10)
        assert m.recall == 0.0

    def test_f1_zero_when_both_zero(self):
        m = MetricSet(tp=0, fp=0, fn=0, tn=10)
        assert m.f1 == 0.0

    def test_false_positive_rate(self):
        m = MetricSet(tp=10, fp=3, fn=0, tn=7)
        assert m.false_positive_rate == pytest.approx(0.3)

    def test_annotation_coverage(self):
        m = MetricSet(tp=10, fp=3, fn=0, tn=5, unannotated=2)
        # annotated findings (10+3) / total findings (10+3+2) = 13/15
        assert m.annotation_coverage == pytest.approx(13 / 15)

    def test_perfect_scores(self):
        m = MetricSet(tp=50, fp=0, fn=0, tn=50)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0
        assert m.false_positive_rate == 0.0


class TestComputeMetrics:
    def test_overall_aggregation(self):
        outcomes = [
            Outcome('TP', 'python.sqli.cursor', 'sqli', 1, 'f.py'),
            Outcome('FP', 'python.sqli.cursor', 'sqli', 2, 'f.py'),
            Outcome('FN', '', 'sqli', 3, 'f.py'),
            Outcome('TN', '', 'sqli', 4, 'f.py'),
        ]
        result = compute_metrics(outcomes)
        assert result.overall.tp == 1
        assert result.overall.fp == 1
        assert result.overall.fn == 1
        assert result.overall.tn == 1

    def test_by_language_aggregation(self):
        outcomes = [
            Outcome('TP', 'python.lang.security.sqli', 'sqli', 1, 'f.py'),
            Outcome('FP', 'python.lang.security.sqli', 'sqli', 2, 'f.py'),
            Outcome('TP', 'javascript.browser.security.xss', 'innerHTML', 1, 'f.js'),
        ]
        result = compute_metrics(outcomes)
        assert result.by_language['python'].tp == 1
        assert result.by_language['python'].fp == 1
        assert result.by_language['javascript'].tp == 1

    def test_unannotated_tracked_separately(self):
        outcomes = [
            Outcome('TP', 'python.sqli', 'sqli', 1, 'f.py'),
            Outcome('UNANNOTATED_FINDING', 'generic.secrets.password', '', 5, 'f.py'),
        ]
        result = compute_metrics(outcomes)
        assert result.overall.tp == 1
        assert result.overall.unannotated == 1
