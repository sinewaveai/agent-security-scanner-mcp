"""Save, load, and compare benchmark snapshots over time."""
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from metrics import BenchmarkResult, MetricSet
from benchmark_report import result_to_json


@dataclass
class ComparisonReport:
    precision_delta: float
    recall_delta: float
    f1_delta: float
    new_false_positives: list
    fixed_false_positives: list


def save_snapshot(result: BenchmarkResult, results_dir: str, filename: str = None):
    """Save a benchmark result as a JSON file."""
    os.makedirs(results_dir, exist_ok=True)
    if filename is None:
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
        commit = result.git_commit or 'unknown'
        filename = f"{ts}_{commit}.json"
    path = os.path.join(results_dir, filename)
    with open(path, 'w') as f:
        json.dump(result_to_json(result), f, indent=2)


def _load_snapshot_from_file(path: str) -> Optional[BenchmarkResult]:
    """Load a single snapshot from a JSON file."""
    with open(path, 'r') as f:
        data = json.load(f)
    ms = data.get('overall', {})
    result = BenchmarkResult(
        timestamp=data.get('timestamp', ''),
        git_commit=data.get('git_commit', ''),
        git_branch=data.get('git_branch', ''),
        overall=MetricSet(
            tp=ms.get('tp', 0), fp=ms.get('fp', 0),
            fn=ms.get('fn', 0), tn=ms.get('tn', 0),
            unannotated=ms.get('unannotated', 0),
        ),
    )
    return result


def load_latest_snapshot(results_dir: str) -> Optional[BenchmarkResult]:
    """Load the most recent snapshot from a results directory."""
    snapshots = load_all_snapshots(results_dir)
    return snapshots[-1] if snapshots else None


def load_all_snapshots(results_dir: str) -> List[BenchmarkResult]:
    """Load all snapshots sorted by filename (chronological)."""
    if not os.path.isdir(results_dir):
        return []
    files = sorted(f for f in os.listdir(results_dir) if f.endswith('.json'))
    results = []
    for f in files:
        try:
            result = _load_snapshot_from_file(os.path.join(results_dir, f))
            if result:
                results.append(result)
        except Exception:
            continue
    return results


def compare_snapshots(current: BenchmarkResult, previous: BenchmarkResult) -> ComparisonReport:
    """Compare two benchmark runs."""
    return ComparisonReport(
        precision_delta=current.overall.precision - previous.overall.precision,
        recall_delta=current.overall.recall - previous.overall.recall,
        f1_delta=current.overall.f1 - previous.overall.f1,
        new_false_positives=[],
        fixed_false_positives=[],
    )
