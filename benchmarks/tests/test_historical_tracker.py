"""Tests for historical tracking."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from historical_tracker import save_snapshot, load_latest_snapshot, load_all_snapshots, compare_snapshots
from metrics import BenchmarkResult, MetricSet


def make_result(tp=10, fp=2, fn=1, tn=8):
    ms = MetricSet(tp=tp, fp=fp, fn=fn, tn=tn)
    return BenchmarkResult(
        timestamp='2026-02-02T10:00:00Z',
        git_commit='abc1234',
        git_branch='main',
        overall=ms,
    )


class TestSaveAndLoad:
    def test_save_and_load_roundtrip(self, tmp_path):
        result = make_result(tp=15, fp=3)
        save_snapshot(result, str(tmp_path))
        loaded = load_latest_snapshot(str(tmp_path))
        assert loaded is not None
        assert loaded.overall.tp == 15
        assert loaded.overall.fp == 3

    def test_load_latest_returns_none_when_empty(self, tmp_path):
        loaded = load_latest_snapshot(str(tmp_path))
        assert loaded is None

    def test_load_all_sorted_by_time(self, tmp_path):
        r1 = make_result(tp=10)
        r1.timestamp = '2026-01-01T12:00:00Z'
        save_snapshot(r1, str(tmp_path), filename='2026-01-01_120000_aaa.json')
        r2 = make_result(tp=20)
        r2.timestamp = '2026-01-02T12:00:00Z'
        save_snapshot(r2, str(tmp_path), filename='2026-01-02_120000_bbb.json')
        all_results = load_all_snapshots(str(tmp_path))
        assert len(all_results) == 2
        assert all_results[0].overall.tp == 10
        assert all_results[1].overall.tp == 20


class TestCompare:
    def test_precision_delta(self):
        prev = make_result(tp=8, fp=2, fn=2, tn=8)
        curr = make_result(tp=9, fp=1, fn=1, tn=9)
        comp = compare_snapshots(curr, prev)
        assert comp.precision_delta > 0
        assert comp.recall_delta > 0
