"""Metrics calculation for security scanner benchmarking."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Outcome:
    """Single classification outcome from comparing annotation to finding."""
    outcome_type: str        # 'TP', 'FP', 'FN', 'TN', 'UNANNOTATED_FINDING'
    rule_id: str             # Full rule ID (empty for FN/TN)
    rule_pattern: str        # Annotation's rule pattern (empty for unannotated)
    line_number: int         # 0-indexed
    file_path: str
    finding: Optional[dict] = None
    annotation_type: Optional[str] = None


@dataclass
class MetricSet:
    """Holds TP/FP/FN/TN counts and computes precision/recall/F1."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    unannotated: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def annotation_coverage(self) -> float:
        total_findings = self.tp + self.fp + self.unannotated
        annotated_findings = self.tp + self.fp
        return annotated_findings / total_findings if total_findings > 0 else 1.0


@dataclass
class BenchmarkResult:
    """Complete benchmark result with multi-level breakdowns."""
    timestamp: str = ''
    git_commit: str = ''
    git_branch: str = ''
    overall: MetricSet = field(default_factory=MetricSet)
    by_language: Dict[str, MetricSet] = field(default_factory=dict)
    by_rule: Dict[str, MetricSet] = field(default_factory=dict)
    by_category: Dict[str, MetricSet] = field(default_factory=dict)
    by_file: Dict[str, MetricSet] = field(default_factory=dict)
    outcomes: List[Outcome] = field(default_factory=list)


def _extract_language(rule_id: str) -> str:
    """Extract language from rule ID like 'python.lang.security.sqli'."""
    parts = rule_id.split('.')
    if parts:
        return parts[0]
    return 'unknown'


def _extract_category(rule_id: str) -> str:
    """Extract category from rule ID."""
    parts = rule_id.split('.')
    if len(parts) >= 4:
        return parts[3] if parts[2] == 'security' else parts[2]
    if len(parts) >= 3:
        return parts[2]
    return 'unknown'


def _add_to_metric_set(ms: MetricSet, outcome_type: str):
    """Increment the appropriate counter on a MetricSet."""
    if outcome_type == 'TP':
        ms.tp += 1
    elif outcome_type == 'FP':
        ms.fp += 1
    elif outcome_type == 'FN':
        ms.fn += 1
    elif outcome_type == 'TN':
        ms.tn += 1
    elif outcome_type == 'UNANNOTATED_FINDING':
        ms.unannotated += 1


def compute_metrics(outcomes: List[Outcome]) -> BenchmarkResult:
    """Aggregate outcomes into multi-level metrics."""
    result = BenchmarkResult(outcomes=outcomes)

    for o in outcomes:
        _add_to_metric_set(result.overall, o.outcome_type)

        # By language (extracted from rule_id)
        if o.rule_id:
            lang = _extract_language(o.rule_id)
            if lang not in result.by_language:
                result.by_language[lang] = MetricSet()
            _add_to_metric_set(result.by_language[lang], o.outcome_type)

            # By rule
            if o.rule_id not in result.by_rule:
                result.by_rule[o.rule_id] = MetricSet()
            _add_to_metric_set(result.by_rule[o.rule_id], o.outcome_type)

            # By category
            cat = _extract_category(o.rule_id)
            if cat not in result.by_category:
                result.by_category[cat] = MetricSet()
            _add_to_metric_set(result.by_category[cat], o.outcome_type)

        # By file
        if o.file_path not in result.by_file:
            result.by_file[o.file_path] = MetricSet()
        _add_to_metric_set(result.by_file[o.file_path], o.outcome_type)

    return result
