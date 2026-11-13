# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` fails when a directory of the tree cannot be read.

``os.walk`` skips a directory it cannot list unless it is given an ``onerror``, so
the files below it were left out of the analysis and the run exited 0 over a
partial tree, where a link not followed and an unreadable file already fail it.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils.sarif_field_analysis import (
    _find_sarif_files,
    analyze_sarif_fields,
)

pytestmark = pytest.mark.unit

#: A directory with no permission bits can still be listed by root, and the mode
#: bits mean nothing on Windows.
cannot_deny_listing = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="this user can list a directory whatever its mode",
)


def _sarif(rule_id: str = "R1") -> str:
    return json.dumps({"runs": [{"results": [{"ruleId": rule_id}]}]})


def _tree(tmp_path: Path) -> Path:
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "reports" / "ash.sarif").write_text(_sarif(), encoding="utf-8")
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif(), encoding="utf-8"
    )
    return sarif_dir


def _run(sarif_dir: Path, output_dir: Path, capsys) -> tuple[int, str, dict]:
    exit_code = 0
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit as raised:
        exit_code = raised.exit_code
    out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    fields = json.loads((output_dir / "sarif_fields.json").read_text("utf-8"))
    return exit_code, out, fields


@cannot_deny_listing
def test_an_unreadable_scanner_directory_is_named_and_fails_the_run(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = _tree(tmp_path)
    hidden = sarif_dir / "scanners" / "semgrep"
    hidden.mkdir()
    (hidden / "semgrep.sarif").write_text(_sarif("HIDDEN"), encoding="utf-8")
    hidden.chmod(0)
    try:
        exit_code, out, fields = _run(sarif_dir, tmp_path / "out", capsys)
    finally:
        hidden.chmod(0o755)

    assert exit_code == 1
    assert "semgrep" in out
    assert "could not be read" in out
    # What the directory holds was not read, and the run says so instead of
    # reporting the rest as the whole tree.
    scanners = {name for found in fields.values() for name in found}
    assert scanners == {"ash", "bandit"}


@cannot_deny_listing
def test_the_unreadable_directories_come_back_in_the_list_the_caller_gives(tmp_path):
    sarif_dir = _tree(tmp_path)
    hidden = sarif_dir / "scanners" / "semgrep"
    hidden.mkdir()
    hidden.chmod(0)
    unreadable: list[str] = []
    try:
        files, links = _find_sarif_files(str(sarif_dir), "scanners", True, unreadable)
    finally:
        hidden.chmod(0o755)

    assert [Path(found).name for found in files] == ["bandit.sarif"]
    assert links == []
    assert unreadable == [str(hidden)]


def test_a_directory_that_does_not_exist_is_not_an_unreadable_one(tmp_path):
    """The control: a scan with no ``reports/`` has nothing to read there, which
    is not a failure to read."""
    unreadable: list[str] = []

    files, links = _find_sarif_files(str(tmp_path), "reports", False, unreadable)

    assert (files, links, unreadable) == ([], [], [])


def test_a_tree_with_every_directory_readable_reports_none(tmp_path):
    unreadable: list[str] = []

    files, _ = _find_sarif_files(str(_tree(tmp_path)), "scanners", True, unreadable)

    assert len(files) == 1
    assert unreadable == []
