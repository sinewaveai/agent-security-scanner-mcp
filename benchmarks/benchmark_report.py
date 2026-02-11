"""Terminal and JSON report generation for benchmark results."""
from metrics import BenchmarkResult, MetricSet


def _fmt(val: float) -> str:
    return f"{val:.3f}"


def print_terminal_report(result: BenchmarkResult):
    """Print a human-readable benchmark report to stdout."""
    print("=" * 72)
    print("  SECURITY SCANNER QUALITY BENCHMARK")
    print(f"  {result.timestamp} | commit: {result.git_commit} | branch: {result.git_branch}")
    print("=" * 72)
    print()

    o = result.overall
    print("OVERALL METRICS")
    print(f"  Precision:       {_fmt(o.precision)}  ({o.tp} TP / {o.tp + o.fp} flagged)")
    print(f"  Recall:          {_fmt(o.recall)}  ({o.tp} TP / {o.tp + o.fn} expected)")
    print(f"  F1 Score:        {_fmt(o.f1)}")
    print(f"  FP Rate:         {_fmt(o.false_positive_rate)}  ({o.fp} FP / {o.fp + o.tn} safe)")
    print(f"  Annotation Cov:  {_fmt(o.annotation_coverage)}")
    print()

    # By language
    if result.by_language:
        print("BY LANGUAGE")
        print(f"  {'Language':<15} {'Prec':>6} {'Recall':>6} {'F1':>6} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>5}")
        print("  " + "-" * 60)
        for lang in sorted(result.by_language):
            m = result.by_language[lang]
            print(f"  {lang:<15} {_fmt(m.precision):>6} {_fmt(m.recall):>6} {_fmt(m.f1):>6} {m.tp:>5} {m.fp:>5} {m.fn:>5} {m.tn:>5}")
        print()

    # False positives detail
    fps = [o for o in result.outcomes if o.outcome_type == 'FP']
    if fps:
        print(f"FALSE POSITIVES ({len(fps)} total)")
        for fp in fps[:10]:
            print(f"  - {fp.file_path}:{fp.line_number}  rule={fp.rule_id}")
        print()

    # False negatives detail
    fns = [o for o in result.outcomes if o.outcome_type == 'FN']
    if fns:
        print(f"FALSE NEGATIVES ({len(fns)} total)")
        for fn in fns[:10]:
            print(f"  - {fn.file_path}:{fn.line_number}  expected={fn.rule_pattern}")
        print()

    # Unannotated
    unann = [o for o in result.outcomes if o.outcome_type == 'UNANNOTATED_FINDING']
    if unann:
        print(f"UNANNOTATED FINDINGS ({len(unann)} -- add annotations to improve coverage)")
        for u in unann[:10]:
            print(f"  - {u.file_path}:{u.line_number}  rule={u.rule_id}")
        print()

    print("=" * 72)


def _metric_set_to_dict(ms: MetricSet) -> dict:
    return {
        'precision': round(ms.precision, 4),
        'recall': round(ms.recall, 4),
        'f1': round(ms.f1, 4),
        'fp_rate': round(ms.false_positive_rate, 4),
        'annotation_coverage': round(ms.annotation_coverage, 4),
        'tp': ms.tp, 'fp': ms.fp, 'fn': ms.fn, 'tn': ms.tn,
        'unannotated': ms.unannotated,
    }


def result_to_json(result: BenchmarkResult) -> dict:
    """Convert a BenchmarkResult to a JSON-serializable dict."""
    return {
        'timestamp': result.timestamp,
        'git_commit': result.git_commit,
        'git_branch': result.git_branch,
        'overall': _metric_set_to_dict(result.overall),
        'by_language': {k: _metric_set_to_dict(v) for k, v in result.by_language.items()},
        'by_rule': {k: _metric_set_to_dict(v) for k, v in result.by_rule.items()},
        'by_category': {k: _metric_set_to_dict(v) for k, v in result.by_category.items()},
        'false_positives': [
            {'file': o.file_path, 'line': o.line_number, 'rule': o.rule_id, 'pattern': o.rule_pattern}
            for o in result.outcomes if o.outcome_type == 'FP'
        ],
        'false_negatives': [
            {'file': o.file_path, 'line': o.line_number, 'pattern': o.rule_pattern}
            for o in result.outcomes if o.outcome_type == 'FN'
        ],
    }


def print_comparison(comparison):
    """Print a comparison between two benchmark runs."""
    print()
    print("COMPARISON WITH PREVIOUS RUN")
    print(f"  Precision: {comparison.precision_delta:+.3f}")
    print(f"  Recall:    {comparison.recall_delta:+.3f}")
    print(f"  F1:        {comparison.f1_delta:+.3f}")
    if comparison.new_false_positives:
        print(f"  New FPs:   {len(comparison.new_false_positives)}")
    if comparison.fixed_false_positives:
        print(f"  Fixed FPs: {len(comparison.fixed_false_positives)}")
