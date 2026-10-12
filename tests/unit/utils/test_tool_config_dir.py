# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where utils/tool_config_dir puts a scanner run's config files, and how it writes them.

tests/unit/config/test_generated_tool_configs_are_outside_the_tree.py runs the
scanners that use it through the scanner executor; these cover the directory's
placement when the temporary directory is inside the scanned tree or is one
another account could change, and the writes.
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


@pytest.fixture(autouse=True)
def _private_umask():
    """The directories the tests make are 0755 whatever the host's umask.

    A umask of 002 would make them group-writable, which the placement rule
    treats as a directory another account could change.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


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


def test_without_a_usable_temporary_directory_the_output_directory_is_used(
    tree, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_temporary_directory() -> str:
        raise FileNotFoundError(2, "No usable temporary directory found")

    monkeypatch.setattr(tempfile, "gettempdir", no_temporary_directory)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert not written.parent.exists()


# A directory another local account can change: it could rename the directory ASH
# made there and put its own in its place before the file is written or read.

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX modes and owners")


def _temp_dir(monkeypatch: pytest.MonkeyPatch, path: Path, mode: int) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    monkeypatch.setattr(tempfile, "tempdir", str(path))
    return path


@posix_only
def test_a_temporary_directory_others_can_write_is_not_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert list(shared.iterdir()) == []


@posix_only
def test_a_directory_above_it_that_others_can_write_is_not_used_either(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    mine = _temp_dir(monkeypatch, tmp_path / "shared" / "mine", 0o700)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == tree.outside
    assert list(mine.iterdir()) == []


@posix_only
def test_a_sticky_temporary_directory_like_tmp_is_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sticky = _temp_dir(monkeypatch, tmp_path / "sticky", 0o1777)
    with tool_config_scope(_context(tree.source, tree.outside)):
        written = write_tool_config("x.yaml", "{}\n")
        assert written.parent.parent == sticky
        assert (written.parent.stat().st_mode & 0o777) == 0o700
    assert list(sticky.iterdir()) == []


@posix_only
def test_with_only_a_shared_temporary_directory_the_output_directory_is_used(
    tree,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The output directory inside the tree beats a directory another account controls."""
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    with caplog.at_level(logging.WARNING):
        with tool_config_scope(_context(tree.source, tree.inside)):
            written = write_tool_config("x.yaml", "{}\n")
            assert written.parent.parent == tree.inside
    assert "inside the scanned tree" in caplog.text
    assert shared.as_posix() in caplog.text
    assert not written.parent.exists()
    assert list(shared.iterdir()) == []


@posix_only
def test_with_no_private_directory_nothing_is_written(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = _temp_dir(monkeypatch, tmp_path / "shared", 0o777)
    os.chmod(tree.outside, 0o777)
    with tool_config_scope(_context(tree.source, tree.outside)):
        with pytest.raises(OSError, match="TMPDIR") as refused:
            write_tool_config("x.yaml", "{}\n")
        assert active_tool_config_dir() is None
    assert shared.as_posix() in str(refused.value)
    assert tree.outside.as_posix() in str(refused.value)
    assert list(shared.iterdir()) == []
    assert list(tree.outside.iterdir()) == []


@posix_only
def test_a_directory_another_account_owns_is_not_used(
    tree, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its owner can rename what is in it whatever its mode says.

    The test account cannot give a directory away, so it is the one that looks
    foreign: with geteuid answering another id, every directory it owns is
    another account's, and neither candidate is used.
    """
    owned = _temp_dir(monkeypatch, tmp_path / "owned", 0o700)
    me = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: me + 1)
    with tool_config_scope(_context(tree.source, tree.outside)):
        with pytest.raises(OSError, match="another account"):
            write_tool_config("x.yaml", "{}\n")
    assert list(owned.iterdir()) == []
    assert list(tree.outside.iterdir()) == []
