# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` tells an aggregate it read from one it never found.

Whether an aggregate was analyzed was taken from the scanner names that
contributed a field, so an aggregate that parsed and held no results never
counted: the run printed "no aggregate report ... was analyzed" and exited 0 for
the one outcome the command exists to catch, an aggregate that lost every result.
The flag now records that the aggregate was read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils.sarif_field_analysis import analyze_sarif_fields

pytestmark = pytest.mark.unit

_NO_AGGREGATE = "no aggregate report"
_MISSING = "unexpectedly missing from the aggregate report"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _sarif(*results: dict) -> str:
    return json.dumps(
        {"runs": [{"tool": {"driver": {"name": "t"}}, "results": list(results)}]}
    )


def _run(sarif_dir: Path, output_dir: Path, capsys) -> tuple[int, str]:
    exit_code = 0
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit as raised:
        exit_code = raised.exit_code
    return exit_code, re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)


def test_an_aggregate_that_parsed_with_no_results_is_not_a_missing_aggregate(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    _write(sarif_dir / "reports" / "ash.sarif", _sarif())
    _write(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        _sarif({"ruleId": "B101", "level": "error"}),
    )

    exit_code, out = _run(sarif_dir, tmp_path / "out", capsys)

    # Every bandit field is gone from the aggregate: exit 1, not a warning.
    assert exit_code == 1
    assert _MISSING in out
    assert _NO_AGGREGATE not in out


def test_an_aggregate_with_an_empty_runs_list_is_read_too(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    _write(sarif_dir / "reports" / "ash.sarif", json.dumps({"runs": []}))
    _write(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        _sarif({"ruleId": "B101"}),
    )

    exit_code, out = _run(sarif_dir, tmp_path / "out", capsys)

    assert exit_code == 1
    assert _NO_AGGREGATE not in out


def test_no_aggregate_file_still_reads_as_no_aggregate(tmp_path, monkeypatch, capsys):
    """The control: with nothing in reports/ there is nothing to be missing from."""
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    _write(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        _sarif({"ruleId": "B101", "level": "error"}),
    )

    exit_code, out = _run(sarif_dir, tmp_path / "out", capsys)

    assert exit_code == 0
    assert _NO_AGGREGATE in out
    assert _MISSING not in out


def test_an_aggregate_that_could_not_be_read_still_reads_as_not_analyzed(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    _write(sarif_dir / "reports" / "ash.sarif", "{not json")
    _write(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        _sarif({"ruleId": "B101"}),
    )

    exit_code, out = _run(sarif_dir, tmp_path / "out", capsys)

    # The unreadable file fails the run; no field was judged against it.
    assert exit_code == 1
    assert _NO_AGGREGATE in out
    assert _MISSING not in out
    assert "could not be read" in out
