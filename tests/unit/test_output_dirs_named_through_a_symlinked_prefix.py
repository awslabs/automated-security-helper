# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's output directory is named when the source or the output is spelled through a link.

Were the named output directories found by comparing the source and the output
directory as spelled, then when one of the two is reached through a link above
the tree and the other is not, the output directory would not read as inside the
source, and nothing would name it: ASH's own files in it, ``ash.log`` among them,
would go into the scan set and to every scanner that excludes the named
directories. On macOS that is any path under ``/var``, a link to
``/private/var``, given beside one that is not. Containment is decided with
both sides resolved, and the directory is spelled under the source as it was
given, the spelling every scanner's exclusion is built from.

A link inside the tree still names nothing: ``.ash/ash_output`` committed as a
link to the repository's own ``src`` must not take ``src`` out of the scan,
however the output directory is spelled. A scan into such a directory refuses to
start.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    named_output_dirs,
    output_dirs_to_exclude,
)

pytestmark = [
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
    pytest.mark.usefixtures("no_checkout_above_tmp_path"),
]

SPELLINGS = ("source", "output")


def _layout(tmp_path: Path, spelled_through_link: str) -> tuple[Path, Path]:
    """A tree with its output directory inside, one of the two given via a link.

    ``alias`` is a link to ``real``, above the tree, as ``/var`` is to
    ``/private/var`` on macOS.
    """
    real = tmp_path / "real"
    source = real / "repo"
    output = source / ".ash" / "out"
    output.mkdir(parents=True)
    (output / "ash.log").write_text("log\n", encoding="utf-8")
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    if spelled_through_link == "source":
        return alias / "repo", output
    return source, alias / "repo" / ".ash" / "out"


def _relative(files, source_dir: Path) -> list[str]:
    root = os.path.abspath(source_dir)
    return sorted(Path(os.path.relpath(f, root)).as_posix() for f in files)


@pytest.mark.unit
@pytest.mark.parametrize("spelled_through_link", SPELLINGS)
def test_the_output_dir_is_named_under_the_source_as_given(
    tmp_path, spelled_through_link
):
    source_dir, output_dir = _layout(tmp_path, spelled_through_link)

    named = named_output_dirs(source_dir, output_dir)

    assert named == [Path(os.path.abspath(source_dir)) / ".ash" / "out"], named


@pytest.mark.unit
@pytest.mark.parametrize("spelled_through_link", SPELLINGS)
def test_the_scan_set_leaves_out_ash_output_reached_through_a_symlinked_prefix(
    tmp_path, monkeypatch, spelled_through_link
):
    source_dir, output_dir = _layout(tmp_path, spelled_through_link)
    monkeypatch.chdir(tmp_path)

    files = scan_set(source=str(source_dir), output=str(output_dir))

    assert _relative(files, source_dir) == ["app.py"], files


@pytest.mark.unit
@pytest.mark.parametrize("spelled_through_link", SPELLINGS)
def test_scanners_are_told_to_skip_it(tmp_path, spelled_through_link):
    source_dir, output_dir = _layout(tmp_path, spelled_through_link)

    excluded = output_dirs_to_exclude(source_dir, output_dir)

    assert excluded == [Path(os.path.abspath(source_dir)) / ".ash" / "out"], excluded


def _output_link_to_src(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A tree whose ``.ash/ash_output`` is a link to its own ``src``."""
    real = tmp_path / "real"
    source = real / "repo"
    src = source / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".ash").mkdir()
    (source / ".ash" / "ash_output").symlink_to(
        Path("..") / "src", target_is_directory=True
    )
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    return source, alias, src


@pytest.mark.unit
@pytest.mark.parametrize(
    "output_spelling", ["as the tree", "through the alias", "elsewhere"]
)
def test_an_output_dir_committed_as_a_link_into_the_tree_names_nothing(
    tmp_path, monkeypatch, output_spelling
):
    """However the output directory is spelled, the link's target, ``src``, is
    not named, so its files stay in the scan set."""
    source, alias, _src = _output_link_to_src(tmp_path)
    output_dir = {
        "as the tree": source / ".ash" / "ash_output",
        "through the alias": alias / "repo" / ".ash" / "ash_output",
        "elsewhere": tmp_path / "out",
    }[output_spelling]
    monkeypatch.chdir(tmp_path)

    assert named_output_dirs(source, output_dir) == []
    assert output_dirs_to_exclude(source, output_dir) == []
    files = scan_set(source=str(source), output=str(output_dir))
    assert "src/app.py" in _relative(files, source), files


@pytest.mark.integration
def test_a_scan_into_an_output_dir_committed_as_a_link_into_the_tree_refuses(
    tmp_path, monkeypatch, capsys
):
    """git tracks the output directory itself, as a link: a scan into it would
    clear ``src/reports`` and remove ``src/ash_aggregated_results.json`` through
    the link. The CLI's check, before anything is written, and the
    orchestrator's, which the MCP tools reach directly, both refuse with exit 3,
    and ``src`` is left as it was."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _refuse_committed_output,
    )
    from tests.unit.test_committed_results_paths_are_never_deleted import (
        _confined,
        _initialize,
        _orchestrator,
    )
    from tests.unit.workspace.test_execution import _git

    source, _alias, src = _output_link_to_src(tmp_path)
    (src / "reports").mkdir()
    (src / "reports" / "kept.md").write_text("kept\n", encoding="utf-8")
    (src / "ash_aggregated_results.json").write_text("{}\n", encoding="utf-8")
    _git(source, "init", "-q")
    added = _git(source, "add", "src", ".ash/ash_output")
    assert added.returncode == 0, added.stderr
    output = source / ".ash" / "ash_output"
    monkeypatch.chdir(tmp_path)
    before = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))

    staged = _git(source, "ls-files", "-s", ".ash/ash_output").stdout
    # A control: git tracks the output directory itself, as a link.
    assert staged.startswith("120000 "), staged

    with pytest.raises(SystemExit) as exited:
        _refuse_committed_output(ScanOptions(source_dir=source, output_dir=output))
    assert exited.value.code == 3
    assert "ash_output" in capsys.readouterr().out

    orchestrator = _orchestrator(source, output)
    _confined(
        tmp_path, orchestrator.source_dir, Path(orchestrator.output_dir).resolve()
    )
    with pytest.raises(ASHConfigValidationError):
        _initialize(orchestrator)
    assert sorted(p.relative_to(src).as_posix() for p in src.rglob("*")) == before
