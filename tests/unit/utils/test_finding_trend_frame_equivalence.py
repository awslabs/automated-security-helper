# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trend's streak order and changes order, held to the code they replaced.

``oracle_streaks`` and ``oracle_sort_changes`` are ``_streaks`` and the changes
sort of ``build_trend`` as they were before their sorts moved onto a frame,
copied unchanged. The streak list is compared with the oracle's on seeded
lineages: ``None`` and empty text in every sort key, a scanner, rule, path and
id holding a lone surrogate, lines that are ``None``, -1, past 2**63 and
negative past -2**63, ties on every key, a last run with no open streak and an
empty last run. The changes order is compared on seeded boundaries whose pairs
are chosen out of order.
"""

import random
from types import SimpleNamespace
from typing import Any

import polars as pl
import pytest

from automated_security_helper.utils import finding_trend
from automated_security_helper.utils.finding_trend import (
    TrendRun,
    _Row,
    _severity,
    build_trend,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------- the oracle


def oracle_streaks(runs, rows, track_of):
    presence = pl.DataFrame(
        [(k, track) for k, tracks in enumerate(track_of) for track in tracks.values()],
        schema={"run": pl.Int64, "track": pl.Int64},
        orient="row",
    )
    spans = presence.group_by("track").agg(
        pl.len().alias("runs"),
        pl.col("run").min().alias("first"),
        pl.col("run").max().alias("last"),
    )
    last = len(runs) - 1
    open_now = spans.filter((pl.col("last") == last) & (pl.col("runs") > 1))
    by_track = {track: (n, first) for track, n, first, _ in open_now.iter_rows()}
    evaluated = [set(run.record["coverage"]["evaluated_scanners"]) for run in runs]
    out: list[dict[str, Any]] = []
    for row in rows[last]:
        found = by_track.get(track_of[last][row.index])
        if found is None:
            continue
        length, first = found
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
                "left_censored": first == 0
                or (
                    row.scanner is not None and row.scanner not in evaluated[first - 1]
                ),
            }
        )
    out.sort(
        key=lambda s: (
            -s["streak_runs"],
            s["scanner"] or "",
            s["rule_id"] or "",
            s["file_path"] or "",
            s["line_start"] if s["line_start"] is not None else -1,
            s["finding_id"] or "",
        )
    )
    return (
        [streak for streak in out if not streak["is_suppressed"]],
        [streak for streak in out if streak["is_suppressed"]],
    )


def oracle_sort_changes(changes):
    changes.sort(
        key=lambda change: (
            change["run"],
            change["kind"],
            change["scanner"] or "",
            change["rule_id"] or "",
            change["file_path"] or "",
            change["finding_id"] or "",
        )
    )
    return changes


# ------------------------------------------------------------------ the seeds

SCANNERS = [None, "", "bandit", "semgrep", "a\udcffb", "é", "Z", "bandit"]
RULES = [None, "", "B101", "B102", "r\udcff", "é"]
FILES = [None, "", "a.py", "b.py", "\udcffx.py", "é.py"]
IDS = [None, "", "dup", "dup", "id-\udcff", "é"]
LINES = [None, None, -1, -1, 0, 5, 5, 2**63, 2**63 + 1, 2**70, -(2**65)]
SEVERITIES = ["HIGH", "high", "LOW", None, "", "medium"]


def seeded_row_dict(rng, index, unique_id, ties=False):
    """A finding row; with *ties* its sort keys come from pools of one or two values."""
    if ties:
        return {
            "id": unique_id if unique_id is not None else "dup",
            "scanner": rng.choice([None, "", "bandit"]),
            "rule_id": rng.choice([None, "B101"]),
            "severity": rng.choice(["HIGH", "LOW"]),
            "is_suppressed": rng.random() < 0.3,
            "file_path": rng.choice([None, "a.py"]),
            "line_start": rng.choice([None, -1, 5]),
            "line_end": None,
        }
    return {
        "id": unique_id if unique_id is not None else rng.choice(IDS),
        "scanner": rng.choice(SCANNERS),
        "rule_id": rng.choice(RULES),
        "severity": rng.choice(SEVERITIES),
        "is_suppressed": rng.random() < 0.3,
        "file_path": rng.choice(FILES),
        "line_start": rng.choice(LINES),
        "line_end": None,
    }


def seeded_lineages(seed):
    """Runs, their rows and the track of each row, as ``build_trend`` holds them."""
    rng = random.Random(seed)
    run_count = rng.randint(2, 6)
    pool = [s for s in SCANNERS if s is not None]
    runs, rows, track_of = [], [], []
    next_track = 0
    previous_tracks: list[int] = []
    for k in range(run_count):
        size = 10 if seed % 3 == 0 else rng.choice([0, 1, 2, 3, 6, 10])
        run_rows = [
            _Row(i, seeded_row_dict(rng, i, None, ties=seed % 3 == 0))
            for i in range(size)
        ]
        offered = list(previous_tracks)
        rng.shuffle(offered)
        tracks: dict[int, int] = {}
        for row in run_rows:
            if k > 0 and offered and rng.random() < (0.9 if seed % 3 == 0 else 0.7):
                tracks[row.index] = offered.pop()
            else:
                tracks[row.index] = next_track
                next_track += 1
        previous_tracks = list(tracks.values())
        record = {
            "coverage": {
                "evaluated_scanners": rng.sample(pool, rng.randint(0, len(pool)))
            }
        }
        runs.append(TrendRun(f"run{k}.json", "file", record))
        rows.append(run_rows)
        track_of.append(tracks)
    return runs, rows, track_of


# ---------------------------------------------------------------------- tests


@pytest.mark.parametrize("seed", range(400))
def test_the_streaks_are_what_the_oracle_lists(seed):
    runs, rows, track_of = seeded_lineages(seed)
    assert finding_trend._streaks(runs, rows, track_of) == oracle_streaks(
        runs, rows, track_of
    )


def test_the_seeded_lineages_reach_the_cases_the_streak_order_depends_on():
    seen = {"streaks": 0, "suppressed": 0, "censored": 0, "uncensored": 0, "tie": 0}
    for seed in range(400):
        runs, rows, track_of = seeded_lineages(seed)
        live, suppressed = oracle_streaks(runs, rows, track_of)
        seen["streaks"] += bool(live)
        seen["suppressed"] += bool(suppressed)
        everything = live + suppressed
        seen["censored"] += any(s["left_censored"] for s in everything)
        seen["uncensored"] += any(not s["left_censored"] for s in everything)

        def key(s):
            return (
                -s["streak_runs"],
                s["scanner"] or "",
                s["rule_id"] or "",
                s["file_path"] or "",
                s["line_start"] if s["line_start"] is not None else -1,
                s["finding_id"] or "",
            )

        keys = [key(s) for s in live]
        seen["tie"] += len(keys) != len(set(keys))
    assert {name: count for name, count in seen.items() if count < 10} == {}


def test_a_run_with_no_findings_at_the_end_has_no_streaks():
    runs, rows, track_of = seeded_lineages(0)
    rows[-1], track_of[-1] = [], {}
    assert finding_trend._streaks(runs, rows, track_of) == ([], [])
    assert oracle_streaks(runs, rows, track_of) == ([], [])


def _record(second, findings, evaluated):
    return {
        "report_id": f"ASH-202601010000{second:02d}-0123456789ab",
        "project_name": "project",
        "findings": findings,
        "coverage": {
            "expected_scanners": ["bandit"],
            "evaluated_scanners": evaluated,
            "ignore_file_exclusions": [],
            "incomplete": False,
            "scanner_results_recorded": True,
            "inputs_not_scanned": [],
        },
    }


def seeded_changing_series(seed, monkeypatch):
    """A series whose matcher pairs rows in a seeded order, and the changes it implies."""
    rng = random.Random(seed)
    run_count = rng.randint(2, 4)
    runs = []
    for k in range(run_count):
        size = 2 if seed % 2 == 0 else rng.choice([0, 2, 4, 8])
        findings = [
            {
                **seeded_row_dict(rng, i, f"id-{k}-{i}", ties=seed % 2 == 0),
                "line_start": 1,
            }
            for i in range(size)
        ]
        # An id of None and one of "" are two ids that tie in the sort's key,
        # as are a scanner, rule and path of None and "".
        for finding, blank in zip(findings, (None, "")):
            if rng.random() < 0.5:
                finding["id"] = blank
        if seed % 2 == 0:
            for finding in findings:
                for field in ("scanner", "rule_id", "file_path"):
                    finding[field] = rng.choice([None, ""])
        runs.append(
            finding_trend.run_from_record(
                _record(k + 1, findings, ["bandit", "semgrep"]), f"r{k}"
            )
        )
    expected: list[dict[str, Any]] = []
    calls = {"k": 0}

    def fake_match(before_rows, after_rows):
        calls["k"] += 1
        k = calls["k"]
        order = list(range(len(after_rows)))
        rng.shuffle(order)
        paired = [
            (before_rows[i], after_rows[j])
            for i, j in zip(
                rng.sample(range(len(before_rows)), len(before_rows)), order
            )
            if rng.random() < 0.8
        ]
        used_before = {id(b) for b, _ in paired}
        used_after = {id(a) for _, a in paired}
        for before, after in paired:
            if _severity(before.severity) != _severity(after.severity):
                expected.append(
                    finding_trend._change(
                        k,
                        "severity",
                        before,
                        after,
                        _severity(before.severity),
                        _severity(after.severity),
                    )
                )
            if before.is_suppressed != after.is_suppressed:
                expected.append(
                    finding_trend._change(
                        k,
                        "suppression",
                        before,
                        after,
                        before.is_suppressed,
                        after.is_suppressed,
                    )
                )
        return SimpleNamespace(
            exact=paired,
            moved=[],
            new=[a for a in after_rows if id(a) not in used_after],
            absent=[b for b in before_rows if id(b) not in used_before],
        )

    monkeypatch.setattr(finding_trend, "match_findings", fake_match)
    return runs, expected


@pytest.mark.parametrize("seed", range(200))
def test_the_changes_come_out_in_the_oracles_order(seed, monkeypatch):
    runs, expected = seeded_changing_series(seed, monkeypatch)
    trend = build_trend(runs)
    assert trend.changes == oracle_sort_changes(expected)


def test_the_seeded_changes_reach_ties_and_both_kinds(monkeypatch):
    kinds, ties = set(), 0
    for seed in range(200):
        runs, expected = seeded_changing_series(seed, monkeypatch)
        build_trend(runs)
        kinds |= {c["kind"] for c in expected}
        keys = [
            (
                c["run"],
                c["kind"],
                c["scanner"] or "",
                c["rule_id"] or "",
                c["file_path"] or "",
                c["finding_id"] or "",
            )
            for c in expected
        ]
        ties += len(keys) != len(set(keys))
    assert kinds == {"severity", "suppression"}
    assert ties >= 10


# ------------------------------------------- the counts the text output reads

STATUSES = finding_trend.STATUSES
SERIES_SCANNERS = [None, "", "bandit", "semgrep", "a\udcffb", "é", "Z"]
SERIES_SEVERITIES = ["HIGH", "LOW", "MEDIUM", "UNKNOWN", "é", "bad\x1bsev"]


def oracle_totals(series):
    totals: dict[tuple[int, str], int] = {}
    for entry in series:
        key = (entry["run"], entry["status"])
        totals[key] = totals.get(key, 0) + entry["count"]
    return totals


def oracle_cells(series):
    cells: dict[tuple[int, str | None, str], dict[str, int]] = {}
    for entry in series:
        cell = (entry["run"], entry["scanner"], entry["severity"])
        counts = cells.setdefault(cell, {})
        counts[entry["status"]] = counts.get(entry["status"], 0) + entry["count"]
    return [
        (run, scanner, severity, {s: counts.get(s, 0) for s in STATUSES})
        for (run, scanner, severity), counts in sorted(
            cells.items(), key=lambda item: (item[0][0], item[0][1] or "", item[0][2])
        )
    ]


def seeded_series(seed):
    """Series entries in the order ``_series`` yields them, over awkward values."""
    rng = random.Random(seed)
    keys = {
        (
            rng.randint(1, 4),
            rng.choice(SERIES_SCANNERS),
            rng.choice(SERIES_SEVERITIES),
            rng.choice(STATUSES),
            rng.random() < 0.5,
        )
        for _ in range(rng.randint(0, 40))
    }
    ordered = sorted(
        keys, key=lambda k: (k[0], k[1] is not None, k[1] or "", k[2], k[3], k[4])
    )
    return [
        {
            "run": run,
            "scanner": scanner,
            "severity": severity,
            "status": status,
            "suppressed": suppressed,
            "count": rng.randint(1, 6),
        }
        for run, scanner, severity, status, suppressed in ordered
    ]


@pytest.mark.parametrize("seed", range(300))
def test_the_status_totals_are_the_oracles(seed):
    series = seeded_series(seed)
    assert finding_trend.status_totals(series) == oracle_totals(series)


@pytest.mark.parametrize("seed", range(300))
def test_the_cell_counts_are_the_oracles(seed):
    series = seeded_series(seed)
    assert finding_trend.cell_counts(series) == oracle_cells(series)


def test_the_seeded_series_reach_the_cases_the_table_order_depends_on():
    blank_tie = zero_cell = lone_surrogate = 0
    for seed in range(300):
        cells = oracle_cells(seeded_series(seed))
        none_cells = {(run, sev) for run, scanner, sev, _ in cells if scanner is None}
        blank_cells = {(run, sev) for run, scanner, sev, _ in cells if scanner == ""}
        blank_tie += bool(none_cells & blank_cells)
        zero_cell += any(0 in counts.values() for *_, counts in cells)
        lone_surrogate += any(s is not None and "\udcff" in s for _, s, _, _ in cells)
    assert min(blank_tie, zero_cell, lone_surrogate) >= 10


def test_an_empty_series_has_no_totals_and_no_cells():
    assert finding_trend.status_totals([]) == {}
    assert finding_trend.cell_counts([]) == []


def _entry(scanner, status, count=1):
    return {
        "run": 1,
        "scanner": scanner,
        "severity": "HIGH",
        "status": status,
        "suppressed": False,
        "count": count,
    }


def test_a_cell_with_one_status_reads_zero_for_the_others():
    series = [_entry("bandit", "fixed", 3)]
    assert finding_trend.cell_counts(series) == [
        (1, "bandit", "HIGH", {"new": 0, "carried": 0, "fixed": 3, "unobserved": 0})
    ]
    assert finding_trend.status_totals(series) == {(1, "fixed"): 3}


def test_a_missing_scanner_and_an_empty_one_keep_the_series_order():
    series = [_entry(None, "new"), _entry("", "fixed")]
    assert [c[1] for c in finding_trend.cell_counts(series)] == [None, ""]
    assert [c[1] for c in oracle_cells(series)] == [None, ""]
