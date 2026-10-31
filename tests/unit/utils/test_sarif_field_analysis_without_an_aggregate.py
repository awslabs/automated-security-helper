# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With no aggregate read, no field was checked against one, and the output says so.

The warning said "no field was checked against the aggregate" while the tables beside
it printed every field as unexpectedly missing and 0.0% in the aggregate, and the HTML
marked every field "No" in the missing style. The columns that depend on the aggregate
now read ``n/a`` when none was read.
"""

import html as html_module
import json
import re
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils import sarif_field_analysis
from automated_security_helper.utils.sarif_field_analysis import analyze_sarif_fields

pytestmark = pytest.mark.unit

#: U+2502, the rich table's vertical rule.
BAR = chr(0x2502)


def _write(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"runs": [{"results": [result]}]}), encoding="utf-8")


def _tree(tmp_path: Path, aggregate: dict | None) -> Path:
    sarif_dir = tmp_path / "ash_output"
    _write(
        sarif_dir / "scanners" / "bandit" / "bandit.sarif",
        {"ruleId": "R1", "level": "error"},
    )
    if aggregate is not None:
        _write(sarif_dir / "reports" / "ash.sarif", aggregate)
    return sarif_dir


def _run(sarif_dir: Path, output_dir: Path, capsys, monkeypatch) -> str:
    monkeypatch.setenv("COLUMNS", "250")
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit:
        pass
    return re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)


def _bandit_row(out: str) -> list[str]:
    rows = [ln for ln in out.splitlines() if re.match(rf"^{BAR}\s*bandit\s*{BAR}", ln)]
    assert len(rows) == 1, out
    return [part.strip() for part in rows[0].strip(BAR).split(BAR)]


def test_the_console_table_says_n_a_for_the_aggregate_columns(
    tmp_path, capsys, monkeypatch
):
    out = _run(_tree(tmp_path, None), tmp_path / "out", capsys, monkeypatch)

    # Scanner, Total, Unique, Missing (Unexpected), Missing (Intentional), % in
    # Aggregate: nine fields counted as missing and 0.0% before.
    assert _bandit_row(out)[1:] == ["2", "2", "n/a", "0", "n/a"]


def test_with_an_aggregate_the_columns_are_counts_as_before(
    tmp_path, capsys, monkeypatch
):
    aggregate = {"ruleId": "R1"}
    out = _run(_tree(tmp_path, aggregate), tmp_path / "out", capsys, monkeypatch)

    assert _bandit_row(out)[1:] == ["2", "2", "1", "0", "50.0%"]


def test_the_report_is_told_whether_an_aggregate_was_read(tmp_path, monkeypatch):
    seen = {}

    def _capture(validation_results, output_path, field_presence, **kwargs):
        seen["stats"] = validation_results["match_statistics"]["bandit"]
        seen["kwargs"] = kwargs

    monkeypatch.setattr(sarif_field_analysis, "generate_html_report", _capture)
    monkeypatch.setenv("COLUMNS", "250")

    def run(aggregate):
        try:
            analyze_sarif_fields(
                sarif_dir=str(_tree(tmp_path / str(bool(aggregate)), aggregate)),
                output_dir=str(tmp_path / "out" / str(bool(aggregate))),
            )
        except typer.Exit:
            pass

    run(None)
    assert seen["kwargs"]["aggregate_analyzed"] is False
    assert seen["stats"]["match_rate"] is None
    assert seen["stats"]["field_preservation_rate"] is None

    run({"ruleId": "R1", "level": "error"})
    assert seen["kwargs"]["aggregate_analyzed"] is True
    assert seen["stats"]["match_rate"] == 1.0


def _page(output_dir: Path) -> str:
    report = output_dir / "sarif_validation_report.html"
    return html_module.unescape(report.read_text(encoding="utf-8"))


def test_the_html_says_n_a_where_it_marked_every_field_missing(
    tmp_path, capsys, monkeypatch
):
    _run(_tree(tmp_path, None), tmp_path / "out", capsys, monkeypatch)

    page = _page(tmp_path / "out")
    assert "<td class='missing'>No</td>" not in page
    assert "<td class='informational'>n/a</td>" in page
    assert "Fields in Aggregate: n/a" in page
    # With no aggregate nothing was compared, so the header gives no count of
    # matches ("0/2" read as none of two matched); the table keeps the counts.
    assert "Match Rate: n/a<" in page
    assert "Match Rate: 0/2" not in page


def test_the_html_still_marks_a_field_the_aggregate_lost(tmp_path, capsys, monkeypatch):
    """The control: with an aggregate read, a field it lacks is still missing."""
    _run(_tree(tmp_path, {"ruleId": "R1"}), tmp_path / "out", capsys, monkeypatch)

    page = _page(tmp_path / "out")
    assert "<td class='missing'>No</td>" in page
    assert "<td class='present'>Yes</td>" in page
    assert "Fields in Aggregate: 1 (" in page
