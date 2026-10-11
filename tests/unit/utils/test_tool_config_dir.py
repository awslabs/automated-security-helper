# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where utils/tool_config_dir puts a scanner run's config files, and how it writes them.

tests/unit/config/test_generated_tool_configs_are_outside_the_tree.py runs the
scanners that use it through the scanner executor; these cover the directory's
placement when the temporary directory is inside the scanned tree, and the writes.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.utils.tool_config_dir import (
    active_tool_config_dir,
    tool_config_scope,
    write_tool_config,
)


@pytest.fixture
def tree(tmp_path: Path) -> SimpleNamespace:
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    inside = source / ".ash" / "ash_output"
    inside.mkdir(parents=True)
    outside = tmp_path / "out"
    outside.mkdir()
    return SimpleNamespace(source=source, inside=inside, outside=outside)


def _context(source: Path, output: Path) -> SimpleNamespace:
    return SimpleNamespace(source_dir=source, output_dir=output, config=None)


@pytest.fixture
def temp_inside_the_tree(tree, monkeypatch: pytest.MonkeyPatch) -> Path:
    temp = tree.source / "tmp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    return temp


def test_a_scope_writes_nothing_until_asked(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        assert active_tool_config_dir() is None
    assert active_tool_config_dir() is None


def test_files_of_one_run_share_its_directory(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        first = write_tool_config("a.yaml", "{}\n")
        second = write_tool_config("b.ini", "[bandit]\n")
        assert first.parent == second.parent == active_tool_config_dir()
        assert not in_scanned_tree(first, tree.source)
    assert not first.parent.exists()


def test_the_same_name_twice_keeps_both_contents(tree) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        first = write_tool_config("x.yaml", "first\n")
        second = write_tool_config("x.yaml", "second\n")
        assert first != second and first.name == second.name == "x.yaml"
        assert first.read_text() == "first\n"
        assert second.read_text() == "second\n"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b.yaml", "../x.yaml"])
def test_a_name_that_is_not_a_file_name_is_refused(tree, name: str) -> None:
    with tool_config_scope(_context(tree.source, tree.inside)):
        with pytest.raises(ValueError):
            write_tool_config(name, "{}\n")


def test_a_temporary_directory_inside_the_tree_moves_it_to_the_output_directory(
    tree, temp_inside_the_tree: Path
) -> None:
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
        assert not in_scanned_tree(written, tree.source)
    assert not written.parent.exists()
    assert list(temp_inside_the_tree.iterdir()) == []


def test_with_nowhere_outside_the_tree_it_says_so(
    tree, temp_inside_the_tree: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        with tool_config_scope(_context(tree.source, tree.inside)):
            written = write_tool_config("x.yaml", "{}\n")
            assert written.parent.parent == temp_inside_the_tree
            if os.name != "nt":
                assert (written.parent.stat().st_mode & 0o777) == 0o700
    assert "inside the scanned tree" in caplog.text
    assert not written.parent.exists()
    # Nothing was left behind under the output directory while looking.
    assert list(tree.inside.iterdir()) == []


def test_outside_a_scope_each_file_gets_its_own_directory(tree) -> None:
    context = _context(tree.source, tree.inside)
    first = write_tool_config("x.yaml", "{}\n", context=context)
    second = write_tool_config("x.yaml", "{}\n", context=context)
    assert first.parent != second.parent
    assert not in_scanned_tree(first, tree.source)
