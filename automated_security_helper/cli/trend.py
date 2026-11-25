# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash trend``: new, fixed and carried findings over a series of saved scans.

``ash diff`` compares two results files; this command reads N of them (or the
run history a scan recorded under its output directory) and prints, for each
boundary between consecutive runs, how many findings are new, carried and fixed
per scanner and severity, which findings have been carried longest, and which
boundaries are not like for like. It runs no scan and writes nothing.

The series itself is :mod:`automated_security_helper.utils.finding_trend`; this
module only reads the inputs, refuses what cannot be a series, and renders.

One source per invocation: explicit results files, or ``--history``. Mixing the
two is refused so that the provenance of every point is obvious.
"""

import json
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.table import Table

from automated_security_helper.utils.command_safe_stream import json_commands_broken
from automated_security_helper.utils.console import ash_console, echo
from automated_security_helper.utils.finding_trend import (
    TrendRefusal,
    TrendRun,
    build_trend,
    run_from_results,
    runs_from_history,
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

#: How many carried findings the text output lists; the JSON output lists all.
TEXT_STREAK_LIMIT = 10


class TrendFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def _refuse(reason: str, path: Path | None = None) -> NoReturn:
    source = f" in {path}" if path is not None else ""
    echo(shown_on_one_line(f"Error computing trend{source}: {reason}"), err=True)
    raise typer.Exit(1)


def _runs_from_files(files: list[Path]) -> list[TrendRun]:
    runs: list[TrendRun] = []
    for path in files:
        try:
            results = parse_full_scan_results(read_regular_file(path))
        except ScanResultsRefused as exc:
            _refuse(exc.reason, path)
        try:
            runs.append(run_from_results(results, str(path)))
        except TrendRefusal as exc:
            _refuse(str(exc))
    # Report ids embed the UTC start second, so ordering by them is chronological
    # whatever order the shell expanded the files in. Without an id on every run
    # the order given is kept.
    if all(run.report_id for run in runs):
        runs.sort(key=lambda run: run.report_id or "")
    return runs


def _payload(runs: list[TrendRun]) -> dict[str, Any]:
    try:
        return build_trend(runs).to_dict()
    except TrendRefusal as exc:
        _refuse(str(exc))


def _location(row: dict[str, Any]) -> str:
    location = row["file_path"] or "-"
    if row["line_start"] is not None:
        location += f":{row['line_start']}"
    return location


def _print_text(payload: dict[str, Any]) -> None:
    runs = payload["runs"]
    echo(f"Runs: {len(runs)} (oldest first)")
    for index, run in enumerate(runs):
        echo(
            shown_on_one_line(f"  {index}: {run['label']} ({run['findings']} findings)")
        )

    totals: dict[tuple[int, str], int] = {}
    for entry in payload["series"]:
        key = (entry["run"], entry["status"])
        totals[key] = totals.get(key, 0) + entry["count"]
    for boundary in payload["boundaries"]:
        k = boundary["run"]
        echo(
            f"Run {k}: "
            + " | ".join(
                f"{status.capitalize()}: {totals.get((k, status), 0)}"
                for status in ("new", "carried", "fixed")
            )
        )
        for warning in boundary["coverage_warnings"]:
            echo(f"Warning (run {k}): {warning}")
        if boundary["scanners_added"]:
            echo(
                shown_on_one_line(
                    f"Scanners added (run {k}): {', '.join(boundary['scanners_added'])}"
                )
            )
        if boundary["scanners_removed"]:
            echo(
                shown_on_one_line(
                    f"Scanners removed (run {k}): "
                    f"{', '.join(boundary['scanners_removed'])}"
                )
            )
        if not boundary["like_for_like"]:
            echo(
                f"Run {k} is not like for like with the run before it; "
                "its fixed and new counts do not measure progress."
            )
    echo("Fixed means not observed, not confirmed fixed.")

    if payload["series"]:
        table = Table("Run", "Scanner", "Severity", "New", "Carried", "Fixed")
        cells: dict[tuple[int, str | None, str], dict[str, int]] = {}
        for entry in payload["series"]:
            cell = (entry["run"], entry["scanner"], entry["severity"])
            cells.setdefault(cell, {})[entry["status"]] = entry["count"]
        for (run, scanner, severity), counts in sorted(
            cells.items(), key=lambda item: (item[0][0], item[0][1] or "", item[0][2])
        ):
            table.add_row(
                str(run),
                raw_controls_on_one_line(scanner or "-"),
                raw_controls_on_one_line(severity),
                str(counts.get("new", 0)),
                str(counts.get("carried", 0)),
                str(counts.get("fixed", 0)),
            )
        ash_console(markup=False, highlight=False).print(table)

    streaks = payload["streaks"]
    if streaks:
        echo(
            f"Longest carried findings (top {min(len(streaks), TEXT_STREAK_LIMIT)} "
            f"of {len(streaks)}):"
        )
        table = Table("Scanner / rule", "Location", "Severity", "Runs", "Open since")
        for row in streaks[:TEXT_STREAK_LIMIT]:
            since = row["open_since"]
            if row["left_censored"]:
                since += " (or earlier)"
            table.add_row(
                raw_controls_on_one_line(f"{row['scanner']} / {row['rule_id'] or '-'}"),
                raw_controls_on_one_line(_location(row)),
                raw_controls_on_one_line(row["severity"]),
                str(row["streak_runs"]),
                raw_controls_on_one_line(since),
            )
        ash_console(markup=False, highlight=False).print(table)

    changes = payload["changes"]
    if changes:
        echo(f"Changes while carried: {len(changes)}")
        table = Table("Run", "Change", "Scanner / rule", "Location", "From", "To")
        for row in changes:
            table.add_row(
                str(row["run"]),
                row["kind"],
                raw_controls_on_one_line(f"{row['scanner']} / {row['rule_id'] or '-'}"),
                raw_controls_on_one_line(_location({**row, "line_start": None})),
                raw_controls_on_one_line(str(row["from"])),
                raw_controls_on_one_line(str(row["to"])),
            )
        ash_console(markup=False, highlight=False).print(table)


def trend_command(
    files: Annotated[
        list[Path] | None,
        typer.Argument(
            help=(
                "ASH scan results JSON files, one per run. They are put in "
                "chronological order by report id. At least two."
            ),
        ),
    ] = None,
    history: Annotated[
        Path | None,
        typer.Option(
            "--history",
            help=(
                "Read the run history recorded under this scan output directory "
                "(global_settings.history.enabled) instead of results files."
            ),
        ),
    ] = None,
    output_format: Annotated[
        TrendFormat, typer.Option("--format", help="Output format (text or json).")
    ] = TrendFormat.TEXT,
) -> None:
    """Show new, carried and fixed findings over a series of saved ASH scans."""
    if files and history is not None:
        _refuse("give results files or --history, not both")
    if history is not None:
        runs = runs_from_history(history)
        if not runs:
            _refuse(f"no readable run records under {history}/history")
    elif files:
        runs = _runs_from_files(list(files))
    else:
        _refuse("give at least two results files, or --history DIR")
    payload = _payload(runs)
    if output_format == TrendFormat.JSON:
        document = json_commands_broken(
            json.dumps(payload, indent=2, ensure_ascii=True)
        )
        ash_console(markup=False, highlight=False).print(document, soft_wrap=True)
    else:
        _print_text(payload)
