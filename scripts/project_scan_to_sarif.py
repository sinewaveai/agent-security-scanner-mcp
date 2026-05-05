#!/usr/bin/env python3
"""
Convert scan-project JSON output to SARIF 2.1.0.

Supports both:
- Current flat schema: { issues: [{ file, line, ruleId, severity, message }, ...] }
- Legacy nested schema: { files: [{ file, issues: [...] }, ...] }
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def _base_sarif() -> dict:
    return {
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security-scanner-mcp",
                        "version": "3.3.0",
                        "informationUri": "https://github.com/sinewaveai/agent-security-scanner-mcp",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }


def _sarif_level(severity: str | None) -> str:
    sev = (severity or "").upper()
    if sev == "ERROR":
        return "error"
    if sev == "WARNING":
        return "warning"
    return "note"


def _normalize_line(line_value) -> int:
    try:
        line = int(line_value)
        return max(1, line)
    except Exception:  # noqa: BLE001
        return 1


def _append_issue(results: list, issue: dict, fallback_file: str = "") -> None:
    if not isinstance(issue, dict):
        return
    rule_id = issue.get("ruleId", "unknown")
    message = issue.get("message", "Security issue detected")
    file_path = issue.get("file") or issue.get("filePath") or fallback_file or ""
    start_line = _normalize_line(issue.get("line", 1))

    results.append(
        {
            "ruleId": rule_id,
            "level": _sarif_level(issue.get("severity")),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": start_line},
                    }
                }
            ],
        }
    )


def convert(project_scan: dict) -> dict:
    sarif = _base_sarif()
    run = sarif["runs"][0]
    results = run["results"]

    # Preferred path: current flat schema.
    issues = project_scan.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            _append_issue(results, issue)

    # Backward compatibility: legacy nested files schema.
    files = project_scan.get("files", [])
    if isinstance(files, list):
        for file_item in files:
            if not isinstance(file_item, dict):
                continue
            file_path = file_item.get("file", "")
            nested = file_item.get("issues", [])
            if isinstance(nested, list):
                for issue in nested:
                    _append_issue(results, issue, fallback_file=file_path)

    # Add a minimal rule catalog for discovered rules.
    seen_rules = set()
    for result in results:
        rid = result.get("ruleId")
        if rid and rid not in seen_rules:
            seen_rules.add(rid)
            run["tool"]["driver"]["rules"].append(
                {"id": rid, "name": rid, "shortDescription": {"text": rid}}
            )

    return sarif


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: project_scan_to_sarif.py <project-scan.json> <results.sarif>", file=sys.stderr)
        return 2

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    sarif = _base_sarif()

    try:
        data = json.loads(in_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            sarif = convert(data)
        else:
            print("project scan JSON must be an object; writing empty SARIF", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: failed to parse project scan JSON ({exc}); writing empty SARIF", file=sys.stderr)

    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
