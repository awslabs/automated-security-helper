# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.table import Table

from automated_security_helper.core.enums import AshExitCode
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.command_safe_stream import json_commands_broken
from automated_security_helper.utils.console import ash_console, echo
from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    compare_findings,
    comparable_findings,
    coverage_warnings,
)
from automated_security_helper.utils.scan_results_file import (
    ScanResultsRefused,
    parse_full_scan_results,
    read_regular_file,
)
from automated_security_helper.utils.terminal_text import (
    raw_controls_on_one_line,
    shown_on_one_line,
)


class DiffFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def _refuse(reason: str, path: Path | None = None) -> NoReturn:
    source = f" in {path}" if path is not None else ""
    echo(shown_on_one_line(f"Error comparing scan results{source}: {reason}"), err=True)
    raise typer.Exit(AshExitCode.SCAN_ERRORS)


def _load_results(path: Path) -> AshAggregatedResults:
    try:
        return parse_full_scan_results(read_regular_file(path))
    except ScanResultsRefused as exc:
        _refuse(exc.reason, path)


def _finding_row(finding: FlatVulnerability) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "severity": finding.severity.upper(),
        "is_suppressed": finding.is_suppressed,
    }


def _result_payload(
    baseline: AshAggregatedResults, current: AshAggregatedResults
) -> dict[str, Any]:
    try:
        before_findings, after_findings = comparable_findings(baseline, current)
    except ComparabilityRefusal as exc:
        _refuse(str(exc))
    diff = compare_findings(before_findings, after_findings)
    return {
        "new": [_finding_row(finding) for finding in diff.new],
        "absent_after": [_finding_row(finding) for finding in diff.absent_after],
        "moved": [
            {"before": _finding_row(before), "after": _finding_row(after)}
            for before, after in diff.moved
        ],
        "severity_changed": [
            {**_finding_row(after), "before_severity": before.severity.upper()}
            for before, after in diff.severity_changed
        ],
        "suppression_changed": [
            {**_finding_row(after), "before_is_suppressed": before.is_suppressed}
            for before, after in diff.suppression_changed
        ],
        "warnings": coverage_warnings(baseline, current),
    }


def _print_text(payload: dict[str, Any]) -> None:
    groups = {
        "new": "New",
        "absent_after": "Absent after",
        "moved": "Moved",
        "severity_changed": "Severity changed",
        "suppression_changed": "Suppression changed",
    }
    echo(" | ".join(f"{label}: {len(payload[key])}" for key, label in groups.items()))
    for warning in payload["warnings"]:
        echo(f"Warning: {warning}")
    if payload["absent_after"]:
        echo("Absent after means not observed, not confirmed fixed.")
    if not any(payload[key] for key in groups):
        return

    table = Table("Change", "Scanner / rule", "Location", "Severity", "Suppressed")
    for key, label in groups.items():
        for row in payload[key]:
            if key == "moved":
                row = row["after"]
            location = row["file_path"] or "-"
            if row["line_start"] is not None:
                location += f":{row['line_start']}"
            severity = row["severity"]
            if key == "severity_changed":
                severity = f"{row['before_severity']} -> {severity}"
            suppressed = "yes" if row["is_suppressed"] else "no"
            if key == "suppression_changed":
                previous = "yes" if row["before_is_suppressed"] else "no"
                suppressed = f"{previous} -> {suppressed}"
            table.add_row(
                label,
                raw_controls_on_one_line(f"{row['scanner']} / {row['rule_id'] or '-'}"),
                raw_controls_on_one_line(location),
                raw_controls_on_one_line(severity),
                suppressed,
            )
    ash_console(markup=False, highlight=False).print(table)


def diff_command(
    before: Annotated[
        Path, typer.Argument(help="Baseline ASH scan results JSON file.")
    ],
    after: Annotated[Path, typer.Argument(help="Current ASH scan results JSON file.")],
    output_format: Annotated[
        DiffFormat, typer.Option("--format", help="Output format (text or json).")
    ] = DiffFormat.TEXT,
) -> None:
    """Compare the findings in two saved ASH scans without running a scan."""
    baseline = _load_results(before)
    current = _load_results(after)
    payload = _result_payload(baseline, current)
    if output_format == DiffFormat.JSON:
        document = json_commands_broken(
            json.dumps(payload, indent=2, ensure_ascii=True)
        )
        ash_console(markup=False, highlight=False).print(document, soft_wrap=True)
    else:
        _print_text(payload)
