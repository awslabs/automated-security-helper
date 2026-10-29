# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` reads the layout below the directory it was given.

The scanner name and the reports/scanners split were taken from any component of
a file's whole path, so an output directory sitting under an ancestor named
``scanners`` gave every file, the aggregate included, that ancestor's child's
name and listed each file in both groups. Reads go through the guard every other
reader of a scanner's results directory uses, and the writes name the output
directory as their root, so neither follows a link there.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils.sandbox.fs_guard import OutputLinkRefused
from automated_security_helper.utils.sarif_field_analysis import (
    analyze_sarif_fields,
    get_scanner_name_from_path,
)

pytestmark = pytest.mark.unit


def _sarif(rule_id: str = "R1", **extra) -> str:
    return json.dumps(
        {"runs": [{"results": [{"ruleId": rule_id, "level": "error", **extra}]}]}
    )


def _run(sarif_dir: Path, output_dir: Path) -> dict:
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit:
        pass  # exit 1 only signals unexpectedly missing fields
    return json.loads((output_dir / "sarif_fields.json").read_text(encoding="utf-8"))


def test_the_scanner_is_the_directory_under_the_last_scanners_component():
    assert get_scanner_name_from_path("/x/scanners/out/scanners/bandit/r.sarif") == (
        "bandit"
    )
    assert get_scanner_name_from_path("scanners/semgrep/semgrep.sarif") == "semgrep"


def test_an_ancestor_named_scanners_does_not_rename_every_file(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "scanners" / "team" / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(_sarif(), encoding="utf-8")
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif(kind="fail"), encoding="utf-8"
    )

    fields = _run(sarif_dir, tmp_path / "out")

    # Before the fix every file was attributed to "team", the child of the first
    # "scanners" component, and the aggregate's own name was lost.
    assert set(fields["runs[].results[].ruleId"]) == {"ash", "bandit"}
    assert set(fields["runs[].results[].kind"]) == {"bandit"}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges there")
def test_a_sarif_file_that_is_a_link_is_not_followed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "200")
    outside = tmp_path / "outside.sarif"
    outside.write_text(_sarif(rule_id="LEAKED"), encoding="utf-8")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    os.symlink(outside, sarif_dir / "scanners" / "bandit" / "bandit.sarif")

    output_dir = tmp_path / "out"
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit:
        pass

    fields = json.loads((output_dir / "sarif_fields.json").read_text("utf-8"))
    assert fields == {}
    assert "Error processing" in capsys.readouterr().out


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges there")
def test_the_outputs_are_not_written_through_a_link_at_the_output_path(tmp_path):
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(_sarif(), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    linked_output = tmp_path / "out"
    os.symlink(elsewhere, linked_output, target_is_directory=True)

    with pytest.raises(OutputLinkRefused):
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(linked_output))

    assert list(elsewhere.iterdir()) == []
