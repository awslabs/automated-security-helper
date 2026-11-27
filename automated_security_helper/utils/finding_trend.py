# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""New, fixed and carried findings over a series of runs: the core of ``ash trend``.

``ash diff`` compares two results files. This module chains that comparison over
N runs and keeps the time axis: for each boundary between two consecutive runs,
per scanner and severity, how many findings are new, fixed and carried, which
findings have been carried longest, where severity or suppression changed, and
which boundaries are not like for like.

What it reuses, and does not redo
---------------------------------
Pairing a finding with the same finding in the next run is
:func:`~automated_security_helper.utils.finding_diff.match_findings`, called as is
on each consecutive pair. It is the part that took care (ids that agree, findings
that moved lines, the ambiguity rules for suppressions), and a second matcher would
drift from ``ash diff``. A run record's rows (``utils.scan_history``) carry the
identity ingredients that matcher reads, and :class:`_Row` presents them under the
names it reads them by. Comparability is
:func:`~automated_security_helper.utils.finding_diff.check_comparable` and
:func:`~automated_security_helper.utils.finding_diff.check_same_project`, so a
series refuses what a diff refuses.

Statuses at a boundary
----------------------
For the boundary *into* run ``k`` (k >= 1), comparing run ``k-1`` with run ``k``:

* ``new``: in run ``k`` and not paired with a finding of run ``k-1``;
* ``carried``: in run ``k`` and paired (exactly, or moved to other lines);
* ``fixed``: in run ``k-1``, paired with nothing in run ``k``, and of a scanner
  run ``k`` evaluated: the scanner looked and did not find it;
* ``unobserved``: in run ``k-1``, paired with nothing in run ``k``, and of a
  scanner absent from run ``k``'s ``evaluated_scanners``: nothing looked, so a
  scanner outage is not presented as progress, in the structured counts as in
  the boundary's warnings.

A finding that goes away and comes back is ``fixed`` (or ``unobserved``) and
then ``new`` again: its streak starts over. Run 0 has no boundary; its findings
are counted in the run's own totals. A streak is marked ``left_censored`` when
the finding may have been open before its ``open_since_run``: the streak begins
at the series' first run, or at a run whose predecessor did not evaluate the
finding's scanner (the streak the outage cut is censored, not resumed).

Suppression is part of the series' key: each series entry says whether its
findings are suppressed, and the carried-longest list is split into ``streaks``
(unsuppressed in the last run) and ``suppressed_streaks``, so an accepted,
suppressed finding neither ranks among the live streaks nor hides from the data.

Coverage honesty
----------------
A boundary carries the same coverage warnings ``ash diff`` prints
(:func:`coverage_warnings_from_records` mirrors
:func:`~automated_security_helper.utils.finding_diff.coverage_warnings` over the
markers a run record keeps; a test holds the two equal) and the scanners that
entered or left the expected set. A step in which a scanner disappeared and twenty
findings are "fixed" is labeled ``like_for_like: false`` with the reason, never
presented as progress.

Engine
------
The counts and streak lengths are frame operations (the series is one long frame
grouped by run, scanner, severity and status; a streak is a group over its track).
Text goes through :func:`~automated_security_helper.utils.frame_text.wire`, as in
the matcher, so a path or scanner name holding a lone surrogate survives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Sequence, cast

import polars as pl

from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    check_comparable,
    check_same_project,
    match_findings,
)
from automated_security_helper.utils.frame_text import ranks, unwire, wire
from automated_security_helper.utils.scan_history import (
    read_history_counted,
    run_record_body,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

#: Written into the trend's JSON; a consumer reads it before anything else.
#: 2 added the ``unobserved`` status, ``suppressed`` on each series entry,
#: ``suppressed_streaks`` beside ``streaks``, sorted ``changes`` whose severity
#: values are normalized, and ``left_censored`` for a streak that begins at a
#: scanner outage.
TREND_VERSION = 2

STATUSES = ("new", "carried", "fixed", "unobserved")

_SERIES_SCHEMA = {
    "run": pl.Int64,
    "scanner": pl.String,
    "severity": pl.String,
    "status": pl.String,
    "suppressed": pl.Boolean,
    "track": pl.Int64,
}


class TrendRefusal(ComparabilityRefusal):
    """The runs cannot be put in a series; the text says why."""


@dataclass(frozen=True)
class TrendRun:
    """One run of a series: where it came from and its run record."""

    label: str
    source: str  # "file" for an explicit results file, "history" for a record
    record: dict[str, Any]

    @property
    def report_id(self) -> str | None:
        value = self.record.get("report_id")
        return value if isinstance(value, str) else None


def run_from_results(results: "AshAggregatedResults", label: str) -> TrendRun:
    """A series point from one results file; refuses a scan no comparison can use.

    The refusal names *label* (the file), as the diff CLI's does.
    """
    try:
        check_comparable(results)
    except ComparabilityRefusal as exc:
        raise TrendRefusal(f"{label}: {exc}") from exc
    return TrendRun(label, "file", run_record_body(results))


def run_from_record(record: dict[str, Any], label: str) -> TrendRun:
    """A series point from a run record the history holds."""
    return TrendRun(label, "history", record)


def runs_from_history(output_dir: Any) -> list[TrendRun]:
    """Every readable record of ``<output_dir>/history``, oldest first."""
    return runs_and_recorded_from_history(output_dir)[0]


def runs_and_recorded_from_history(output_dir: Any) -> tuple[list[TrendRun], int]:
    """:func:`runs_from_history` and the number of record names seen, in one pass."""
    records, recorded = read_history_counted(output_dir)
    return (
        [run_from_record(record, str(record["report_id"])) for record in records],
        recorded,
    )


class _Row:
    """A record's finding row, with the attributes ``match_findings`` reads.

    It is the stored row under the names of ``FlatVulnerability``: ``fallback_key``
    takes ``canonical(identity_base)`` itself, so the stored canonical string is
    parsed back to the mapping it came from (``canonical`` of that mapping is the
    string again).
    """

    __slots__ = (
        "index",
        "id",
        "scanner",
        "rule_id",
        "severity",
        "is_suppressed",
        "file_path",
        "line_start",
        "line_end",
        "identity",
        "has_fingerprint_identity",
        "identity_base",
        "identity_message",
        "source_report",
        "result_kind",
    )

    def __init__(self, index: int, row: dict[str, Any]) -> None:
        self.index = index
        self.id = row.get("id")
        self.scanner = row.get("scanner")
        self.rule_id = row.get("rule_id")
        self.severity = row.get("severity")
        self.is_suppressed = bool(row.get("is_suppressed"))
        self.file_path = row.get("file_path")
        self.line_start = row.get("line_start")
        self.line_end = row.get("line_end")
        self.identity = object() if row.get("has_identity") else None
        self.has_fingerprint_identity = bool(row.get("has_fingerprint_identity"))
        base = row.get("identity_base")
        self.identity_base = json.loads(base) if isinstance(base, str) else None
        self.identity_message = row.get("identity_message")
        self.source_report = row.get("source_report")
        self.result_kind = row.get("result_kind")


def _rows(run: TrendRun) -> list[_Row]:
    from automated_security_helper.utils.sarif_utils import NON_FINDING_KINDS

    rows = [_Row(i, row) for i, row in enumerate(run.record["findings"])]
    if len({row.id for row in rows}) != len(rows):
        raise TrendRefusal(f"{run.label}: run contains duplicate finding IDs")
    # A row whose result states no finding is in no count. A record written
    # before result_kind existed names none, so its rows read as findings. Each
    # row keeps its ``index``, its place in the record.
    return [row for row in rows if row.result_kind not in NON_FINDING_KINDS]


def _severity(value: str | None) -> str:
    return (value or "").upper() or "UNKNOWN"


def coverage_warnings_from_records(
    earlier: dict[str, Any],
    later: dict[str, Any],
    labels: tuple[str, str] = ("Baseline", "Current"),
) -> list[str]:
    """``finding_diff.coverage_warnings`` over two run records' coverage markers."""
    a, b = earlier["coverage"], later["coverage"]
    warnings = []
    if set(a["expected_scanners"]) != set(b["expected_scanners"]) or set(
        a["evaluated_scanners"]
    ) != set(b["evaluated_scanners"]):
        warnings.append("Scanner coverage differs between scans.")
    if a["ignore_file_exclusions"] != b["ignore_file_exclusions"]:
        warnings.append("Recorded ignore-file exclusions differ between scans.")
    for label, coverage in zip(labels, (a, b)):
        missing = set(coverage["expected_scanners"]) - set(
            coverage["evaluated_scanners"]
        )
        if missing or coverage["incomplete"]:
            warnings.append(f"{label} scan has incomplete scanner coverage.")
        elif (
            not coverage["expected_scanners"]
            or not coverage["scanner_results_recorded"]
        ):
            warnings.append(
                f"{label} scan does not record enough scanner coverage to establish comparability."
            )
        if coverage["inputs_not_scanned"]:
            warnings.append(f"{label} scan records inputs that were not scanned.")
    return warnings


def _check_series(runs: Sequence[TrendRun]) -> None:
    if len(runs) < 2:
        raise TrendRefusal("a trend needs at least two runs")
    if len({run.source for run in runs}) > 1:
        raise TrendRefusal(
            "do not mix recorded history with explicit results files in one trend"
        )
    seen: dict[str, str] = {}
    for run in runs:
        rid = run.report_id
        if rid is None:
            continue
        if rid in seen:
            raise TrendRefusal(
                f"{run.label}: the same run as {seen[rid]} (report id {rid})"
            )
        seen[rid] = run.label
    first = runs[0]
    for run in runs[1:]:
        try:
            check_same_project(_project_view(first), _project_view(run))
        except ComparabilityRefusal as exc:
            raise TrendRefusal(f"{run.label}: {exc}") from exc


def longest_compatible_suffix(
    runs: Sequence[TrendRun],
) -> tuple[list[TrendRun], list[str]]:
    """The longest suffix of *runs* one series can hold, and the labels cut.

    *runs* are oldest first; the suffix ends at the newest run. A duplicate
    report id or a foreign-project record refuses a whole series
    (:func:`build_trend`), so over a recorded history one bad record blocked
    every trend. Walking from the newest run backwards, a run that repeats a
    kept run's id or is not the newest run's project ends the walk; it and
    everything older are cut, and their labels come back for the caller to
    report. The caller decides whether what is left is still a series (it can
    be shorter than two runs).
    """
    runs = list(runs)
    if not runs:
        return [], []
    newest = runs[-1]
    kept = [newest]
    seen = {newest.report_id} if newest.report_id is not None else set()
    for run in reversed(runs[:-1]):
        rid = run.report_id
        if rid is not None and rid in seen:
            break
        # Against every kept run, not the newest alone: a newest with no project
        # name accepts any, and the pair it let through was refused by
        # _check_series against the oldest kept run, the refusal the cut exists
        # to remove.
        try:
            for kept_run in kept:
                check_same_project(_project_view(kept_run), _project_view(run))
        except ComparabilityRefusal:
            break
        if rid is not None:
            seen.add(rid)
        kept.append(run)
    kept.reverse()
    return kept, [run.label for run in runs[: len(runs) - len(kept)]]


def _project_view(run: TrendRun) -> Any:
    """What ``check_same_project`` reads, from a record."""
    return SimpleNamespace(
        metadata=SimpleNamespace(
            project_name=run.record.get("project_name"),
            workspace_project=run.record.get("workspace_project"),
        )
    )


@dataclass
class Trend:
    """The result of :func:`build_trend`; :meth:`to_dict` is its JSON form."""

    runs: list[dict[str, Any]]
    boundaries: list[dict[str, Any]]
    series: list[dict[str, Any]]
    streaks: list[dict[str, Any]]
    suppressed_streaks: list[dict[str, Any]] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trend_version": TREND_VERSION,
            "runs": self.runs,
            "boundaries": self.boundaries,
            "series": self.series,
            "streaks": self.streaks,
            "suppressed_streaks": self.suppressed_streaks,
            "changes": self.changes,
        }


def build_trend(runs: Sequence[TrendRun]) -> Trend:
    """The trend over *runs*, oldest first, in the order given.

    Raises :class:`TrendRefusal` for fewer than two runs, a run listed twice,
    runs of different projects, a mix of history and files, or a run holding
    duplicate finding ids.
    """
    runs = list(runs)
    _check_series(runs)
    rows = [_rows(run) for run in runs]

    # Track: one number per finding lineage. A finding paired into the next run
    # keeps its track (so a finding that moved lines is one streak); a new finding
    # starts one.
    track_of: list[dict[int, int]] = [{} for _ in runs]
    next_track = 0
    for row in rows[0]:
        track_of[0][row.index] = next_track
        next_track += 1

    boundaries: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    series_rows: list[tuple[int, str | None, str, str, bool, int]] = []
    for k in range(1, len(runs)):
        # The matcher reads only the attributes _Row carries; its pairs are our rows.
        match: Any = match_findings(cast(Any, rows[k - 1]), cast(Any, rows[k]))
        paired = match.exact + match.moved
        for before, after in paired:
            track_of[k][after.index] = track_of[k - 1][before.index]
            series_rows.append(
                (
                    k,
                    wire(after.scanner),
                    _severity(after.severity),
                    "carried",
                    after.is_suppressed,
                    track_of[k][after.index],
                )
            )
            if _severity(before.severity) != _severity(after.severity):
                # Normalized, as the comparison that found the change reads
                # them: a consumer of ("high", "HIGH") saw a change whose from
                # and to were equal under the compare that reported it.
                changes.append(
                    _change(
                        k,
                        "severity",
                        before,
                        after,
                        _severity(before.severity),
                        _severity(after.severity),
                    )
                )
            if before.is_suppressed != after.is_suppressed:
                changes.append(
                    _change(
                        k,
                        "suppression",
                        before,
                        after,
                        before.is_suppressed,
                        after.is_suppressed,
                    )
                )
        for after in match.new:
            track_of[k][after.index] = next_track
            series_rows.append(
                (
                    k,
                    wire(after.scanner),
                    _severity(after.severity),
                    "new",
                    after.is_suppressed,
                    next_track,
                )
            )
            next_track += 1
        # A row the later run did not pair is "fixed" only when the later run's
        # scanner coverage could have seen it: with its scanner absent from
        # evaluated_scanners nothing looked, and the row is "unobserved".
        evaluated_later = set(runs[k].record["coverage"]["evaluated_scanners"])
        for before in match.absent:
            observed = before.scanner is None or before.scanner in evaluated_later
            series_rows.append(
                (
                    k,
                    wire(before.scanner),
                    _severity(before.severity),
                    "fixed" if observed else "unobserved",
                    before.is_suppressed,
                    track_of[k - 1][before.index],
                )
            )
        boundaries.append(_boundary(k, runs[k - 1], runs[k]))

    # The matcher's iteration order is no part of the contract: sorted, so two
    # runs over one series list the same changes in the same order.
    changes = _sorted_changes(changes)
    series = _series(series_rows)
    streaks, suppressed_streaks = _streaks(runs, rows, track_of)
    return Trend(
        runs=[_run_entry(run, run_rows) for run, run_rows in zip(runs, rows)],
        boundaries=boundaries,
        series=series,
        streaks=streaks,
        suppressed_streaks=suppressed_streaks,
        changes=changes,
    )


def _changes_schema() -> dict[str, Any]:
    """The declared columns of the frame :func:`_sorted_changes` sorts."""
    return {
        "position": pl.Int64,
        "run": pl.Int64,
        "kind": pl.String,
        "scanner": pl.String,
        "rule": pl.String,
        "file": pl.String,
        "id": pl.String,
    }


def _changes_frame(changes: list[dict[str, Any]]) -> pl.DataFrame:
    """One row per change, in order, as :func:`_changes_schema`."""
    return pl.DataFrame(
        {
            "position": list(range(len(changes))),
            "run": [change["run"] for change in changes],
            "kind": [wire(change["kind"]) for change in changes],
            "scanner": [wire(change["scanner"] or "") for change in changes],
            "rule": [wire(change["rule_id"] or "") for change in changes],
            "file": [wire(change["file_path"] or "") for change in changes],
            "id": [wire(change["finding_id"] or "") for change in changes],
        },
        schema=_changes_schema(),
    )


def _sorted_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """*changes* by run, kind, scanner, rule, path and finding id, ties in given order.

    A missing text sorts as the empty one. The position is the last key, so
    changes that tie on every key stay in the order they were found.
    """
    frame = _changes_frame(changes)
    order = frame.sort(
        ["run", "kind", "scanner", "rule", "file", "id", "position"],
        maintain_order=True,
    )["position"]
    return [changes[position] for position in order]


def _change(
    k: int, kind: str, before: _Row, after: _Row, old: Any, new: Any
) -> dict[str, Any]:
    return {
        "run": k,
        "kind": kind,
        "finding_id": after.id,
        "scanner": after.scanner,
        "rule_id": after.rule_id,
        "file_path": after.file_path,
        "from": old,
        "to": new,
    }


def _run_entry(run: TrendRun, rows: list[_Row]) -> dict[str, Any]:
    record = run.record
    return {
        "label": run.label,
        "report_id": run.report_id,
        "generated_at": record.get("generated_at"),
        "tool_version": record.get("tool_version"),
        "findings": len(rows),
    }


def _boundary(k: int, earlier: TrendRun, later: TrendRun) -> dict[str, Any]:
    warnings = coverage_warnings_from_records(
        earlier.record, later.record, ("Earlier", "Later")
    )
    before = set(earlier.record["coverage"]["expected_scanners"])
    after = set(later.record["coverage"]["expected_scanners"])
    return {
        "run": k,
        "from_label": earlier.label,
        "to_label": later.label,
        "like_for_like": not warnings,
        "coverage_warnings": warnings,
        "scanners_added": sorted(after - before),
        "scanners_removed": sorted(before - after),
    }


def _series(
    rows: list[tuple[int, str | None, str, str, bool, int]],
) -> list[dict[str, Any]]:
    frame = pl.DataFrame(
        rows,
        schema=_SERIES_SCHEMA,
        orient="row",
    )
    counted = (
        frame.group_by(["run", "scanner", "severity", "status", "suppressed"])
        .agg(pl.len().alias("count"))
        .sort(["run", "scanner", "severity", "status", "suppressed"])
    )
    return [
        {
            "run": run,
            "scanner": unwire(scanner) if scanner is not None else None,
            "severity": severity,
            "status": status,
            "suppressed": suppressed,
            "count": count,
        }
        for run, scanner, severity, status, suppressed, count in counted.iter_rows()
    ]


def _status_schema() -> dict[str, Any]:
    """The declared columns of the frame :func:`status_totals` groups."""
    return {"run": pl.Int64, "status": pl.String, "count": pl.Int64}


def _status_frame(series: Sequence[dict[str, Any]]) -> pl.DataFrame:
    """One row per series entry, in order, as :func:`_status_schema`."""
    return pl.DataFrame(
        {
            "run": [entry["run"] for entry in series],
            "status": [wire(entry["status"]) for entry in series],
            "count": [entry["count"] for entry in series],
        },
        schema=_status_schema(),
    )


def status_totals(series: Sequence[dict[str, Any]]) -> dict[tuple[int, str], int]:
    """How many findings each status holds at each run, over a series' entries.

    Keyed by ``(run, status)``; a pair the series does not hold is absent.
    """
    frame = _status_frame(series)
    totals = frame.group_by(["run", "status"]).agg(pl.col("count").sum())
    return {(run, unwire(status)): count for run, status, count in totals.iter_rows()}


def _cell_schema() -> dict[str, Any]:
    """The declared columns of the frame :func:`cell_counts` groups."""
    return {
        "run": pl.Int64,
        "scanner": pl.String,
        "severity": pl.String,
        "status": pl.String,
        "count": pl.Int64,
    }


def _cell_frame(series: Sequence[dict[str, Any]]) -> pl.DataFrame:
    """One row per series entry, in order, as :func:`_cell_schema`."""
    return pl.DataFrame(
        {
            "run": [entry["run"] for entry in series],
            "scanner": [wire(entry["scanner"]) for entry in series],
            "severity": [wire(entry["severity"]) for entry in series],
            "status": [wire(entry["status"]) for entry in series],
            "count": [entry["count"] for entry in series],
        },
        schema=_cell_schema(),
    )


def cell_counts(
    series: Sequence[dict[str, Any]],
) -> list[tuple[int, str | None, str, dict[str, int]]]:
    """One row per (run, scanner, severity) cell of a series, with a count per status.

    Rows are ``(run, scanner, severity, counts)``, ``counts`` holding every
    status of :data:`STATUSES` (0 for one the cell has none of), ordered by run,
    scanner (a missing one sorting as the empty text) and severity. Cells that
    tie, a missing scanner and an empty one, stay in the order the series first
    holds them.
    """
    frame = _cell_frame(series)
    cells = (
        frame.group_by(["run", "scanner", "severity"], maintain_order=True)
        .agg(
            [
                pl.col("count")
                .filter(pl.col("status") == wire(status))
                .sum()
                .fill_null(0)
                .alias(status)
                for status in STATUSES
            ]
        )
        .with_columns(pl.col("scanner").fill_null("").alias("scanner_key"))
        .sort(["run", "scanner_key", "severity"], maintain_order=True)
    )
    return [
        (
            run,
            unwire(scanner) if scanner is not None else None,
            unwire(severity),
            dict(zip(STATUSES, counts)),
        )
        for run, scanner, severity, *counts in cells.select(
            ["run", "scanner", "severity", *STATUSES]
        ).iter_rows()
    ]


def _presence_schema() -> dict[str, Any]:
    """The declared columns of the (run, track) presence frame of :func:`_streaks`."""
    return {"run": pl.Int64, "track": pl.Int64}


def _presence_frame(track_of: list[dict[int, int]]) -> pl.DataFrame:
    """One row per finding track present in each run, as :func:`_presence_schema`."""
    pairs = [
        (k, track) for k, tracks in enumerate(track_of) for track in tracks.values()
    ]
    return pl.DataFrame(
        {
            "run": [k for k, _ in pairs],
            "track": [track for _, track in pairs],
        },
        schema=_presence_schema(),
    )


def _candidates_schema() -> dict[str, Any]:
    """The declared columns of the last run's candidate frame of :func:`_streaks`."""
    return {
        "position": pl.Int64,
        "track": pl.Int64,
        "scanner": pl.String,
        "scanner_key": pl.String,
        "rule_key": pl.String,
        "file_key": pl.String,
        "line_key": pl.Int64,
        "id_key": pl.String,
    }


def _candidates_frame(
    rows: list[_Row],
    tracks: dict[int, int],
    line_keys: list[int],
    line_rank: dict[int, int],
) -> pl.DataFrame:
    """One row per finding of the last run, as :func:`_candidates_schema`.

    *tracks* maps a finding's index to its track; *line_rank* maps each of
    *line_keys* (one per row) to the rank the frame holds.
    """
    return pl.DataFrame(
        {
            "position": list(range(len(rows))),
            "track": [tracks[row.index] for row in rows],
            "scanner": [wire(row.scanner) for row in rows],
            "scanner_key": [wire(row.scanner or "") for row in rows],
            "rule_key": [wire(row.rule_id or "") for row in rows],
            "file_key": [wire(row.file_path or "") for row in rows],
            "line_key": [line_rank[line_key] for line_key in line_keys],
            "id_key": [wire(row.id or "") for row in rows],
        },
        schema=_candidates_schema(),
    )


def _evaluated_schema() -> dict[str, Any]:
    """The declared columns of the evaluated-scanner frame of :func:`_streaks`."""
    return {"run": pl.Int64, "scanner": pl.String, "evaluated": pl.Boolean}


def _evaluated_frame(runs: list[TrendRun]) -> pl.DataFrame:
    """One row per scanner each run evaluated, as :func:`_evaluated_schema`."""
    pairs = [
        (k, wire(name))
        for k, run in enumerate(runs)
        for name in set(run.record["coverage"]["evaluated_scanners"])
    ]
    return pl.DataFrame(
        {
            "run": [k for k, _ in pairs],
            "scanner": [name for _, name in pairs],
            "evaluated": [True for _ in pairs],
        },
        schema=_evaluated_schema(),
    )


def _streaks(
    runs: list[TrendRun], rows: list[list[_Row]], track_of: list[dict[int, int]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Findings open in the last run that were open before it, longest first.

    Two lists: the unsuppressed streaks, and apart from them the streaks whose
    finding is suppressed in the last run, so an accepted finding never ranks
    among the live ones. ``left_censored`` is True when the streak may reach
    further back than ``open_since_run``: it begins at the series' first run,
    or at a run whose predecessor did not evaluate the finding's scanner.
    """
    presence = _presence_frame(track_of)
    spans = presence.group_by("track").agg(
        pl.len().alias("runs"),
        pl.col("run").min().alias("first"),
        pl.col("run").max().alias("last"),
    )
    last = len(runs) - 1
    open_now = spans.filter((pl.col("last") == last) & (pl.col("runs") > 1))
    # A missing line reads as -1, as it always sorted; the lines enter the frame
    # as ranks, so one past 2**63 stays a line.
    line_keys = [-1 if row.line_start is None else row.line_start for row in rows[last]]
    line_rank = ranks(line_keys)
    candidates = _candidates_frame(rows[last], track_of[last], line_keys, line_rank)
    evaluated = _evaluated_frame(runs)
    # A streak is censored when it starts at the first run, or when the run
    # before it did not evaluate its scanner (a finding with no scanner has none
    # to miss). The join leaves ``evaluated`` null where that run did not.
    found = (
        open_now.join(candidates, on="track", how="inner")
        .with_columns((pl.col("first") - 1).alias("before"))
        .join(
            evaluated,
            left_on=["before", "scanner"],
            right_on=["run", "scanner"],
            how="left",
        )
        .with_columns(
            (
                (pl.col("first") == 0)
                | (pl.col("scanner").is_not_null() & pl.col("evaluated").is_null())
            ).alias("censored")
        )
        .sort(
            [
                "runs",
                "scanner_key",
                "rule_key",
                "file_key",
                "line_key",
                "id_key",
                "position",
            ],
            descending=[True, False, False, False, False, False, False],
            maintain_order=True,
        )
    )
    out: list[dict[str, Any]] = []
    for position, length, first, censored in found.select(
        ["position", "runs", "first", "censored"]
    ).iter_rows():
        row = rows[last][position]
        out.append(
            {
                "finding_id": row.id,
                "scanner": row.scanner,
                "rule_id": row.rule_id,
                "severity": _severity(row.severity),
                "file_path": row.file_path,
                "line_start": row.line_start,
                "is_suppressed": row.is_suppressed,
                "streak_runs": length,
                "open_since_run": first,
                "open_since": runs[first].label,
                "left_censored": censored,
            }
        )
    return (
        [streak for streak in out if not streak["is_suppressed"]],
        [streak for streak in out if streak["is_suppressed"]],
    )
