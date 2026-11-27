# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The per-run status totals and the Run, Scanner, Severity table of ``ash trend``.

``oracle_totals`` and ``oracle_table_rows`` are the loops the text output ran
before its counts moved onto the series frame, copied unchanged. The text output
is held to them on the saved three-run fixture and on seeded series: a ``None``
and an empty scanner in one run and severity, a scanner holding a lone
surrogate, suppressed and unsuppressed rows of one cell, statuses a cell does not
have, and ties on every key. No other test pins the table.
"""

import json
import random
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import trend as trend_cli
from automated_security_helper.cli.main import app
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

pytestmark = pytest.mark.unit

STATUSES = ("new", "carried", "fixed", "unobserved")


# ---------------------------------------------------------------- the oracle


def oracle_totals(series):
    totals: dict[tuple[int, str], int] = {}
    for entry in series:
        key = (entry["run"], entry["status"])
        totals[key] = totals.get(key, 0) + entry["count"]
    return totals


def oracle_table_rows(series):
    """The argument tuples the table's ``add_row`` was called with."""
    cells: dict[tuple[int, str | None, str], dict[str, int]] = {}
    for entry in series:
        cell = (entry["run"], entry["scanner"], entry["severity"])
        counts = cells.setdefault(cell, {})
        counts[entry["status"]] = counts.get(entry["status"], 0) + entry["count"]
    rows = []
    for (run, scanner, severity), counts in sorted(
        cells.items(), key=lambda item: (item[0][0], item[0][1] or "", item[0][2])
    ):
        rows.append(
            (
                str(run),
                raw_controls_on_one_line(scanner or "-"),
                raw_controls_on_one_line(severity),
                str(counts.get("new", 0)),
                str(counts.get("carried", 0)),
                str(counts.get("fixed", 0)),
                str(counts.get("unobserved", 0)),
            )
        )
    return rows


def oracle_status_lines(series, boundaries):
    totals = oracle_totals(series)
    return [
        f"Run {boundary['run']}: "
        + " | ".join(
            f"{status.capitalize()}: {totals.get((boundary['run'], status), 0)}"
            for status in STATUSES
        )
        for boundary in boundaries
    ]


# ------------------------------------------------------------------ recording


class RecordingTable:
    """Stands in for ``rich.table.Table``: keeps the columns and the rows added."""

    instances: list["RecordingTable"] = []

    def __init__(self, *columns):
        self.columns = columns
        self.rows = []
        RecordingTable.instances.append(self)

    def add_row(self, *cells):
        self.rows.append(cells)


@pytest.fixture
def recorded(monkeypatch):
    RecordingTable.instances = []
    lines: list[str] = []
    monkeypatch.setattr(trend_cli, "Table", RecordingTable)
    monkeypatch.setattr(
        trend_cli, "echo", lambda text="", err=False, **_: lines.append(text)
    )
    monkeypatch.setattr(
        trend_cli,
        "ash_console",
        lambda **_: SimpleNamespace(print=lambda *_a, **_k: None),
    )
    return lines


def table_with_columns(first_column):
    return [t for t in RecordingTable.instances if t.columns[0] == first_column]


# ------------------------------------------------------------------- fixtures


def _finding(rule, *, severity="HIGH", line=10, path="src/app.py"):
    return {
        "ruleId": rule,
        "message": {"text": "Snippet that must not appear in the trend"},
        "properties": {"issue_severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _results(*findings, second):
    return {
        "metadata": {
            "report_id": f"ASH-202601010000{second:02d}-0123456789ab",
            "project_name": "project",
            "changed_files_only": False,
            "expected_scanners": ["bandit"],
        },
        "scanner_results": {"bandit": {"status": "PASSED"}},
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "bandit"}}, "results": list(findings)}
            ],
        },
    }


def three_runs():
    return [
        _results(_finding("B101"), _finding("B102", severity="LOW", line=20), second=1),
        _results(_finding("B102", severity="LOW", line=20), _finding("B103"), second=2),
        _results(
            _finding("B102", severity="LOW", line=20),
            _finding("B103"),
            _finding("B104", line=40),
            second=3,
        ),
    ]


def run_trend_text(tmp_path, payloads):
    files = []
    for i, payload in enumerate(payloads):
        path = tmp_path / f"run{i}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        files.append(str(path))
    return CliRunner().invoke(app, ["results", "trend", *files])


PINNED_THREE_RUN_ROWS = [
    ("1", "bandit", "HIGH", "1", "0", "1", "0"),
    ("1", "bandit", "LOW", "0", "1", "0", "0"),
    ("2", "bandit", "HIGH", "1", "1", "0", "0"),
    ("2", "bandit", "LOW", "0", "1", "0", "0"),
]

SCANNERS = [None, "", "bandit", "semgrep", "a\udcffb", "é", "Z"]
SEVERITIES = ["HIGH", "LOW", "MEDIUM", "UNKNOWN", "é", "bad\x1bsev"]


def seeded_series(seed):
    """Series entries in the order ``_series`` yields them, over awkward values."""
    rng = random.Random(seed)
    keys = set()
    for _ in range(rng.randint(0, 40)):
        keys.add(
            (
                rng.randint(1, 4),
                rng.choice(SCANNERS),
                rng.choice(SEVERITIES),
                rng.choice(STATUSES),
                rng.random() < 0.5,
            )
        )
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


def payload_for(series):
    runs = sorted({entry["run"] for entry in series} | {1})
    return {
        "runs": [{"label": f"r{i}", "findings": 0} for i in range(max(runs) + 1)],
        "boundaries": [
            {
                "run": k,
                "coverage_warnings": [],
                "scanners_added": [],
                "scanners_removed": [],
                "like_for_like": True,
            }
            for k in runs
        ],
        "series": series,
        "streaks": [],
        "suppressed_streaks": [],
        "changes": [],
    }


# ---------------------------------------------------------------------- tests


def test_the_three_run_totals_and_table_rows_are_pinned(tmp_path, recorded):
    response = run_trend_text(tmp_path, three_runs())
    assert response.exit_code == 0, response.output
    assert [line for line in recorded if line.startswith("Run ")][:2] == [
        "Run 1: New: 1 | Carried: 1 | Fixed: 1 | Unobserved: 0",
        "Run 2: New: 1 | Carried: 2 | Fixed: 0 | Unobserved: 0",
    ]
    (table,) = table_with_columns("Run")[:1]
    assert table.columns == (
        "Run",
        "Scanner",
        "Severity",
        "New",
        "Carried",
        "Fixed",
        "Unobserved",
    )
    assert table.rows == PINNED_THREE_RUN_ROWS


@pytest.mark.parametrize("seed", range(120))
def test_seeded_series_print_what_the_oracle_computes(seed, recorded):
    series = seeded_series(seed)
    payload = payload_for(series)
    trend_cli._print_text(payload)
    assert [line for line in recorded if line.startswith("Run ")] == (
        oracle_status_lines(series, payload["boundaries"])
    )
    tables = table_with_columns("Run")
    if series:
        assert [t.rows for t in tables] == [oracle_table_rows(series)]
    else:
        assert tables == []
