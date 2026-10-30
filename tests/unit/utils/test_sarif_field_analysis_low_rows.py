# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` reads every element, every report once, and
counts scanners without the aggregate.

``_flatten_object`` read only the first element of a list, so a field only a later
element held was missed. A reporter's rendering of the aggregate kept beside it in
``reports/`` (``ash.ghas.sarif``) was analyzed as a scanner named ``ash.ghas``. With
no aggregate analyzed, every scanner field read as unexpectedly missing from it and
the command exited 1 with a judgment about fields. The recursive glob followed a
linked directory in the output tree. The per-scanner Unique Fields column and the
"used by only one scanner" and "used by all scanners" rows counted the aggregate as
a scanner, so a preserved field was never unique and the all-scanners row read 0.
The HTML report counted field paths under a "Total Findings" label and named
``.ash/ash_output`` in its JQ examples whatever directory was analyzed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils import sarif_field_analysis
from automated_security_helper.utils.sarif_field_analysis import (
    _flatten_object,
    analyze_sarif_fields,
)

pytestmark = pytest.mark.unit


def _sarif(result: dict) -> str:
    return json.dumps({"runs": [{"results": [result]}]})


def _run(sarif_dir: Path, output_dir: Path):
    exit_code = 0
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit as raised:
        exit_code = raised.exit_code
    fields = json.loads((output_dir / "sarif_fields.json").read_text(encoding="utf-8"))
    return fields, exit_code


def _plain(capsys) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)


def test_every_list_element_is_flattened():
    from unittest.mock import patch

    result: dict = {}
    with patch(
        "automated_security_helper.utils.sarif_field_analysis.should_include_field",
        return_value=True,
    ):
        _flatten_object(
            {"locations": [{"a": 1}, {"b": {"c": 2}}]}, "runs[].results[]", result
        )

    # Only the first element was read, so "b" was never recorded.
    assert "runs[].results[].locations[].a" in result
    assert "runs[].results[].locations[].b.c" in result


def test_a_report_derived_from_the_aggregate_is_not_a_scanner(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(
        _sarif({"ruleId": "R1"}), encoding="utf-8"
    )
    (sarif_dir / "reports" / "ash.ghas.sarif").write_text(
        _sarif({"ruleId": "R1", "level": "error"}), encoding="utf-8"
    )
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif({"ruleId": "R1"}), encoding="utf-8"
    )

    fields, _ = _run(sarif_dir, tmp_path / "out")

    scanners = {name for scanners in fields.values() for name in scanners}
    assert "ash.ghas" not in scanners
    assert scanners == {"ash", "bandit"}
    assert "derived from the aggregate" in _plain(capsys)


def test_without_an_aggregate_no_field_is_missing_from_it(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif({"ruleId": "R1", "level": "error"}), encoding="utf-8"
    )

    fields, exit_code = _run(sarif_dir, tmp_path / "out")

    # Exited 1 with "unexpectedly missing from the aggregate report" before.
    assert exit_code == 0
    assert set(fields) == {"runs[].results[].ruleId", "runs[].results[].level"}
    out = _plain(capsys)
    assert "no aggregate report" in out
    assert "unexpectedly missing" not in out


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges there")
def test_a_linked_directory_in_the_output_tree_is_not_followed(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leaked.sarif").write_text(_sarif({"ruleId": "LEAKED"}), "utf-8")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(_sarif({"ruleId": "R1"}), "utf-8")
    (sarif_dir / "scanners").mkdir()
    os.symlink(outside, sarif_dir / "scanners" / "linked", target_is_directory=True)

    fields, _ = _run(sarif_dir, tmp_path / "out")

    scanners = {name for scanners in fields.values() for name in scanners}
    assert "linked" not in scanners
    assert "symbolic link" in _plain(capsys)


def test_the_scanner_counts_leave_the_aggregate_out(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "250")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "scanners" / "semgrep").mkdir(parents=True)
    # Both scanners emit ruleId; only bandit emits level; the aggregate keeps all.
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif({"ruleId": "R1", "level": "error"}), encoding="utf-8"
    )
    (sarif_dir / "scanners" / "semgrep" / "semgrep.sarif").write_text(
        _sarif({"ruleId": "R2"}), encoding="utf-8"
    )
    (sarif_dir / "reports" / "ash.sarif").write_text(
        _sarif({"ruleId": "R1", "level": "error"}), encoding="utf-8"
    )

    _run(sarif_dir, tmp_path / "out")

    out = _plain(capsys)
    # ruleId is used by both scanners; level by bandit alone. The aggregate
    # carrying both made "all scanners" read 0 and "only one scanner" read 0.
    assert re.search(r"Fields used by all scanners\s*│\s*1\s*│", out)
    assert re.search(r"Fields used by only one scanner\s*│\s*1\s*│", out)
    bandit = [ln for ln in out.splitlines() if re.match(r"^│\s*bandit\s*│", ln)]
    columns = [c.strip() for c in bandit[0].strip("│").split("│")]
    # Scanner, Total, Unique, Missing (Unexpected), Missing (Intentional), %
    assert columns[1:3] == ["2", "1"]


def test_the_html_report_is_told_the_directory_and_the_unit(tmp_path, monkeypatch):
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(_sarif({"ruleId": "R1"}), "utf-8")
    seen = {}

    def _capture(validation_results, output_path, field_presence, **kwargs):
        seen["results"] = validation_results
        seen["kwargs"] = kwargs

    monkeypatch.setattr(sarif_field_analysis, "generate_html_report", _capture)

    _run(sarif_dir, tmp_path / "out")

    assert seen["kwargs"]["sarif_dir"] == str(sarif_dir)
    assert seen["results"]["summary"]["unit"] == "fields"
    assert seen["results"]["match_statistics"]["ash"]["match_rate"] == 1.0
