"""Benchmark runner: parse annotations, run analyzer, classify, compute metrics."""
import os
import sys
import json
import subprocess
from datetime import datetime, timezone
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from analyzer import analyze_file

from annotation_parser import parse_corpus_file, AnnotatedCorpusFile
from metrics import Outcome, BenchmarkResult, compute_metrics


CORPUS_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.go', '.txt', '.dockerfile', '.c', '.rb', '.php', '.tf', '.yaml'}


def classify_findings(annotated: AnnotatedCorpusFile, findings: list) -> List[Outcome]:
    """Compare analyzer findings against annotations to classify each outcome."""
    outcomes = []
    if isinstance(findings, dict) and 'error' in findings:
        return outcomes

    # Index findings by line
    findings_by_line = {}
    for f in findings:
        findings_by_line.setdefault(f['line'], []).append(f)

    # Track which findings have been matched (to identify unannotated ones)
    matched_findings = set()

    # Process VULN annotations
    for line_num, vuln_anns in annotated.vuln_by_line.items():
        line_findings = findings_by_line.get(line_num, [])
        for ann in vuln_anns:
            matched = False
            for i, f in enumerate(line_findings):
                if ann.rule_pattern in f['ruleId']:
                    outcomes.append(Outcome(
                        'TP', f['ruleId'], ann.rule_pattern,
                        line_num, annotated.file_path, finding=f,
                    ))
                    matched_findings.add((line_num, i))
                    matched = True
                    break
            if not matched:
                outcomes.append(Outcome(
                    'FN', '', ann.rule_pattern,
                    line_num, annotated.file_path,
                ))

    # Process SAFE / FP-PRONE annotations
    for line_num, safe_anns in annotated.safe_by_line.items():
        line_findings = findings_by_line.get(line_num, [])
        for ann in safe_anns:
            matched_finding = None
            matched_idx = None
            for i, f in enumerate(line_findings):
                if ann.rule_pattern in f['ruleId']:
                    matched_finding = f
                    matched_idx = i
                    break
            if matched_finding:
                outcomes.append(Outcome(
                    'FP', matched_finding['ruleId'], ann.rule_pattern,
                    line_num, annotated.file_path, finding=matched_finding,
                ))
                matched_findings.add((line_num, matched_idx))
            else:
                outcomes.append(Outcome(
                    'TN', '', ann.rule_pattern,
                    line_num, annotated.file_path,
                ))

    # Unannotated findings: any finding not matched to an annotation
    for line_num, line_findings in findings_by_line.items():
        for i, f in enumerate(line_findings):
            if (line_num, i) not in matched_findings:
                outcomes.append(Outcome(
                    'UNANNOTATED_FINDING', f['ruleId'], '',
                    line_num, annotated.file_path, finding=f,
                ))

    return outcomes


def _discover_corpus_files(corpus_dir: str) -> List[str]:
    """Find all corpus files in the directory."""
    files = []
    for f in sorted(os.listdir(corpus_dir)):
        full = os.path.join(corpus_dir, f)
        if os.path.isfile(full):
            _, ext = os.path.splitext(f)
            basename = os.path.basename(f).lower()
            if ext in CORPUS_EXTENSIONS or basename.startswith('dockerfile'):
                files.append(full)
    return files


def _git_info() -> tuple:
    """Get current git commit and branch."""
    try:
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        commit = 'unknown'
    try:
        branch = subprocess.check_output(
            ['git', 'branch', '--show-current'],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        branch = 'unknown'
    return commit, branch


def run_benchmark(corpus_dir: str) -> BenchmarkResult:
    """Run the full benchmark pipeline on a corpus directory."""
    corpus_files = _discover_corpus_files(corpus_dir)
    all_outcomes = []

    for corpus_file in corpus_files:
        annotated = parse_corpus_file(corpus_file)
        findings = analyze_file(corpus_file)
        if isinstance(findings, dict) and 'error' in findings:
            print(f"Warning: analyzer error on {corpus_file}: {findings['error']}")
            continue
        outcomes = classify_findings(annotated, findings)
        all_outcomes.extend(outcomes)

    result = compute_metrics(all_outcomes)
    result.timestamp = datetime.now(timezone.utc).isoformat()
    commit, branch = _git_info()
    result.git_commit = commit
    result.git_branch = branch
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run security scanner quality benchmark')
    parser.add_argument('--corpus', default=os.path.join(os.path.dirname(__file__), 'corpus'),
                        help='Path to corpus directory')
    parser.add_argument('--save', action='store_true', help='Save results to benchmarks/results/')
    parser.add_argument('--compare-latest', action='store_true', help='Compare with latest previous run')
    parser.add_argument('--json-only', action='store_true', help='Output JSON only')
    args = parser.parse_args()

    result = run_benchmark(args.corpus)

    if args.json_only:
        from benchmark_report import result_to_json
        print(json.dumps(result_to_json(result), indent=2))
    else:
        from benchmark_report import print_terminal_report
        print_terminal_report(result)

    if args.save:
        from historical_tracker import save_snapshot
        results_dir = os.path.join(os.path.dirname(__file__), 'results')
        save_snapshot(result, results_dir)
        print(f"\nSnapshot saved to {results_dir}/")

    if args.compare_latest:
        from historical_tracker import load_latest_snapshot, compare_snapshots
        results_dir = os.path.join(os.path.dirname(__file__), 'results')
        prev = load_latest_snapshot(results_dir)
        if prev:
            comparison = compare_snapshots(result, prev)
            from benchmark_report import print_comparison
            print_comparison(comparison)
