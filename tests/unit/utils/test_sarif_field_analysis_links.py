# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` walks the output tree without following a link.

``glob.glob(recursive=True)`` followed a linked directory, and the result was
filtered afterwards, so a link to an ancestor was walked until the path was too
long. A linked directory was also skipped with exit 0 while a linked file failed
the run: both are now left out of the analysis and fail it.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils.sarif_field_analysis import analyze_sarif_fields

pytestmark = pytest.mark.unit

#: Only the tests that make a link: the others run on Windows too.
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks need privileges"
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


def test_a_tree_with_no_link_is_read_whole(tmp_path, monkeypatch, capsys):
    """The control for the rows below."""
    monkeypatch.setenv("COLUMNS", "200")

    exit_code, out, fields = _run(_tree(tmp_path), tmp_path / "out", capsys)

    assert exit_code == 0
    assert "Found 2 SARIF files" in out
    assert "symbolic link" not in out
    assert set(fields["runs[].results[].ruleId"]) == {"ash", "bandit"}


@needs_symlinks
def test_a_link_to_an_ancestor_is_not_walked(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = _tree(tmp_path)
    os.symlink(
        os.path.join("..", ".."),
        sarif_dir / "scanners" / "bandit" / "loop",
        target_is_directory=True,
    )
    real_scandir = os.scandir
    walked: list[str] = []

    def _counting_scandir(path="."):
        walked.append(str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _counting_scandir)

    exit_code, out, fields = _run(sarif_dir, tmp_path / "out", capsys)

    monkeypatch.undo()
    # The directories of the tree itself: reports, scanners, scanners/bandit. Before,
    # the walk went into the link and on until the path was too long, a hundred
    # directories and more.
    inside = [path for path in walked if str(sarif_dir) in str(path)]
    assert len(inside) <= 8, inside
    # And the probe saw the walk at all: a walk that does not go through
    # os.scandir would leave this list empty and pass the bound above. It saw the
    # directory that holds the link, and never the link.
    assert str(sarif_dir / "scanners" / "bandit") in inside, inside
    assert not any("loop" in Path(path).parts for path in inside), inside
    assert out.count("Skipping") == 1
    assert set(fields["runs[].results[].ruleId"]) == {"ash", "bandit"}
    # It is a part of the output tree that was not read, so the run fails.
    assert exit_code == 1


@needs_symlinks
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_a_linked_file_and_a_linked_directory_end_the_run_alike(
    tmp_path, monkeypatch, capsys, kind
):
    monkeypatch.setenv("COLUMNS", "200")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leaked.sarif").write_text(_sarif("LEAKED"), encoding="utf-8")
    sarif_dir = _tree(tmp_path)
    if kind == "file":
        # Under a directory of its own: a file read as a scanner "linkedfile"
        # shows in the fields, where one under bandit/ only repeated what
        # bandit.sarif already holds and the check below passed either way.
        (sarif_dir / "scanners" / "linkedfile").mkdir()
        os.symlink(
            outside / "leaked.sarif",
            sarif_dir / "scanners" / "linkedfile" / "x.sarif",
        )
    else:
        os.symlink(outside, sarif_dir / "scanners" / "linked", target_is_directory=True)

    exit_code, out, fields = _run(sarif_dir, tmp_path / "out", capsys)

    assert exit_code == 1
    # What the link points at was not read: no field is attributed to it.
    scanners = {name for found in fields.values() for name in found}
    assert scanners == {"ash", "bandit"}


@needs_symlinks
def test_a_link_in_the_place_of_a_searched_directory_is_not_followed(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ash.sarif").write_text(_sarif("LEAKED"), encoding="utf-8")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        _sarif(), encoding="utf-8"
    )
    os.symlink(outside, sarif_dir / "reports", target_is_directory=True)

    exit_code, out, fields = _run(sarif_dir, tmp_path / "out", capsys)

    assert exit_code == 1
    assert "Found 1 SARIF files" in out
    assert set(fields["runs[].results[].ruleId"]) == {"bandit"}


def test_the_files_come_back_sorted_without_hidden_names_or_other_suffixes(tmp_path):
    from automated_security_helper.utils.sarif_field_analysis import (
        _find_sarif_files,
    )

    sarif_dir = tmp_path / "ash_output"
    for relative in (
        "scanners/s/b.sarif",
        "scanners/s/a.sarif",
        "scanners/s/.hidden.sarif",
        "scanners/s/notes.txt",
        "scanners/.cache/c.sarif",
        "scanners/top.sarif",
    ):
        target = sarif_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{}", encoding="utf-8")

    files, links = _find_sarif_files(str(sarif_dir), "scanners", True)

    assert [Path(found).relative_to(sarif_dir).as_posix() for found in files] == [
        "scanners/s/a.sarif",
        "scanners/s/b.sarif",
        "scanners/top.sarif",
    ]
    assert links == []
    # The reports directory is read one level deep only.
    (sarif_dir / "reports" / "deeper").mkdir(parents=True)
    (sarif_dir / "reports" / "deeper" / "d.sarif").write_text("{}", encoding="utf-8")
    (sarif_dir / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    flat, _ = _find_sarif_files(str(sarif_dir), "reports", False)
    assert [Path(found).name for found in flat] == ["ash.sarif"]
