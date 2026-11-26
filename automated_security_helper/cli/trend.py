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

Beside the trend itself (``finding_trend.Trend.to_dict``) the JSON payload says
how this command built the series: ``ordered_by`` is ``"report_id"`` when the
runs were put in chronological order by their timestamped report ids (always
so for ``--history``, whose records are named by them) and ``"given"`` when a
file names no such id and the order given was kept; ``unreadable_records`` is
how many recorded runs were skipped as unreadable, since a boundary that spans
one is not between consecutive runs; and ``history_cut`` names the older
records left out because they are not part of one series with the newest. The
text output states each of these too.
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
    longest_compatible_suffix,
    run_from_results,
    runs_and_recorded_from_history,
)
from automated_security_helper.utils.scan_history import (
    run_order_key,
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


def _runs_from_files(files: list[Path]) -> tuple[list[TrendRun], str]:
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
    # ASH's report ids embed the UTC start second, so ordering by them is
    # chronological whatever order the shell expanded the files in. The key is
    # the history's own (stamp, token) one, never the raw string: a prefix
    # difference would sort by prefix first, and a hand-written id anywhere.
    # Unless every run names such an id, the order given is kept, and the
    # output says which of the two happened (``ordered_by``).
    keys = [run_order_key(run.report_id) for run in runs]
    sortable = [(key, run) for key, run in zip(keys, runs) if key is not None]
    if len(sortable) == len(runs):
        runs = [run for _, run in sorted(sortable, key=lambda pair: pair[0])]
        return runs, "report_id"
    return runs, "given"


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


def _shown_change_value(value: Any) -> str:
    """A change's from/to as ``ash diff`` words it: booleans are yes/no."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _print_text(payload: dict[str, Any]) -> None:
    runs = payload["runs"]
    if payload.get("ordered_by") == "given":
        echo(
            f"Runs: {len(runs)} (in the order given: not every file names a "
            "sortable report id)"
        )
    else:
        echo(f"Runs: {len(runs)} (oldest first)")
    for index, run in enumerate(runs):
        echo(
            shown_on_one_line(f"  {index}: {run['label']} ({run['findings']} findings)")
        )
    if payload.get("unreadable_records"):
        echo(
            f"Warning: {payload['unreadable_records']} recorded run(s) were "
            "unreadable and are not in this series; a boundary that spans one "
            "is not between consecutive runs."
        )
    if payload.get("history_cut"):
        echo(
            shown_on_one_line(
                f"Warning: {len(payload['history_cut'])} older record(s) are not "
                "part of one series with the newest and were left out: "
                f"{', '.join(payload['history_cut'])}"
            )
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
                for status in ("new", "carried", "fixed", "unobserved")
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
    echo(
        "Fixed means the scanner evaluated the run and did not report it; "
        "unobserved means its scanner did not run there."
    )

    if payload["series"]:
        table = Table(
            "Run", "Scanner", "Severity", "New", "Carried", "Fixed", "Unobserved"
        )
        cells: dict[tuple[int, str | None, str], dict[str, int]] = {}
        for entry in payload["series"]:
            cell = (entry["run"], entry["scanner"], entry["severity"])
            counts = cells.setdefault(cell, {})
            counts[entry["status"]] = counts.get(entry["status"], 0) + entry["count"]
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
                str(counts.get("unobserved", 0)),
            )
        ash_console(markup=False, highlight=False).print(table)

    _print_streaks(payload["streaks"], "Longest carried findings")
    _print_streaks(
        payload.get("suppressed_streaks") or [],
        "Longest carried suppressed findings (accepted, listed apart)",
    )

    changes = payload["changes"]
    if changes:
        # Capped like the streak tables; the JSON lists all. The rows are
        # sorted by (run, kind, scanner, rule, location, id), so "first" is
        # the earliest boundaries.
        if len(changes) > TEXT_STREAK_LIMIT:
            echo(
                f"Changes while carried (first {TEXT_STREAK_LIMIT} of "
                f"{len(changes)}; the JSON output lists all):"
            )
        else:
            echo(f"Changes while carried: {len(changes)}")
        table = Table("Run", "Change", "Scanner / rule", "Location", "From", "To")
        for row in changes[:TEXT_STREAK_LIMIT]:
            table.add_row(
                str(row["run"]),
                row["kind"],
                raw_controls_on_one_line(f"{row['scanner']} / {row['rule_id'] or '-'}"),
                raw_controls_on_one_line(_location({**row, "line_start": None})),
                raw_controls_on_one_line(_shown_change_value(row["from"])),
                raw_controls_on_one_line(_shown_change_value(row["to"])),
            )
        ash_console(markup=False, highlight=False).print(table)


def _print_streaks(streaks: list[dict[str, Any]], title: str) -> None:
    if not streaks:
        return
    echo(f"{title} (top {min(len(streaks), TEXT_STREAK_LIMIT)} of {len(streaks)}):")
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


def trend_command(
    files: Annotated[
        list[Path] | None,
        typer.Argument(
            help=(
                "ASH scan results JSON files, one per run. When every file names "
                "one of ASH's timestamped report ids they are put in "
                "chronological order by it; otherwise they are kept in the "
                "order given, which the output says. At least two."
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
    unreadable = 0
    cut: list[str] = []
    if history is not None:
        # One pass: the names counted and the records read are the same set.
        runs, recorded = runs_and_recorded_from_history(history)
        if not runs:
            if not recorded:
                _refuse(f"no run records under {history}/history")
            _refuse(
                f"none of the {recorded} run records under {history}/history "
                "are readable"
            )
        unreadable = recorded - len(runs)
        # One bad record (a duplicate id, a foreign project) used to refuse the
        # whole history; the series is cut to the longest suffix ending at the
        # newest record instead, and the cut is reported.
        runs, cut = longest_compatible_suffix(runs)
        if len(runs) < 2 and cut:
            # Raw values: _refuse shows the whole reason as one
            # shown_on_one_line call, so escaping the cut here would show
            # its escapes a second time.
            _refuse(
                f"only {len(runs)} of the recorded runs form one series ending "
                f"at the newest record ({len(cut)} left out: "
                f"{', '.join(cut)})"
            )
        if len(runs) < 2:
            # Nothing was cut: one readable record is simply not a series.
            _refuse("a trend needs at least two runs")
        ordered_by = "report_id"
    elif files:
        runs, ordered_by = _runs_from_files(list(files))
    else:
        _refuse("give at least two results files, or --history DIR")
    payload = _payload(runs)
    # How this command built the series, beside the trend itself; the module
    # docstring documents the three keys.
    payload["ordered_by"] = ordered_by
    payload["unreadable_records"] = unreadable
    payload["history_cut"] = cut
    if output_format == TrendFormat.JSON:
        document = json_commands_broken(
            json.dumps(payload, indent=2, ensure_ascii=True)
        )
        ash_console(markup=False, highlight=False).print(document, soft_wrap=True)
    else:
        _print_text(payload)
