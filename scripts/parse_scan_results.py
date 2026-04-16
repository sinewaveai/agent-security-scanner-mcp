#!/usr/bin/env python3
"""
Parse security scanner JSON output and emit counts as:
<total>\t<critical>\t<warning>

Exits non-zero when output is malformed or schema-invalid (fail-closed).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _count_severity(data: dict, level: str) -> int:
    level = level.upper()
    count = 0

    issues = data.get("issues", [])
    if isinstance(issues, list):
        for item in issues:
            if not isinstance(item, dict):
                continue
            if str(item.get("severity", "")).upper() == level:
                count += 1
            nested = item.get("issues", [])
            if isinstance(nested, list):
                for nested_item in nested:
                    if isinstance(nested_item, dict) and str(nested_item.get("severity", "")).upper() == level:
                        count += 1

    files = data.get("files", [])
    if isinstance(files, list):
        for file_item in files:
            if not isinstance(file_item, dict):
                continue
            nested = file_item.get("issues", [])
            if isinstance(nested, list):
                for nested_item in nested:
                    if isinstance(nested_item, dict) and str(nested_item.get("severity", "")).upper() == level:
                        count += 1

    return count


def parse_counts(path: Path) -> tuple[int, int, int]:
    if not path.exists() or path.stat().st_size == 0:
        raise ValueError("security scanner produced no JSON output")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid JSON output: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("scanner output must be a JSON object")

    if data.get("error"):
        raise ValueError(f"scanner returned error: {data.get('error')}")

    if not any(
        key in data
        for key in ("issues_count", "total", "issues", "files", "by_severity", "grade")
    ):
        raise ValueError("scanner output schema not recognized")

    total = data.get("issues_count", data.get("total", 0))
    try:
        total_int = int(total)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid total count: {total}") from exc

    critical = _count_severity(data, "ERROR")
    warning = _count_severity(data, "WARNING")

    return total_int, critical, warning


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: parse_scan_results.py <scan-results.json>", file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    try:
        total, critical, warning = parse_counts(input_path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"{total}\t{critical}\t{warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
