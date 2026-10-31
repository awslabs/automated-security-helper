# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four readings of ``output_dir_links``.

- ``linked_output_component`` applies a ``..`` as the kernel does, to the directory
  the components before it lead to with their links followed. Applied lexically,
  an output directory spelled ``/opt/link/../x`` with ``/opt/link`` leading into
  the tree was examined at ``/opt/x``, a path the lookup never uses, and the
  repository link at ``<root>/x``, the directory the lookup reaches, was missed.
  When the two readings name different directories the spelling is refused: the
  writers open the path as written (``os.path.abspath``), so a check that passed
  the directory the lookup reaches would have vetted one directory while the log
  and the results went to another.
- ``is_link`` reads ``os.lstat`` itself and answers False on any ``OSError``;
  ``Path.is_symlink`` let a ``PermissionError`` through on CPython 3.10-3.12.
- ``ignore_output_dir_in_git`` writes nothing when git lists files committed under
  the output directory, since an ignore-everything rule there would hide every
  file a developer adds beside them.
- ``ignore_output_dir_in_git`` answers False, rather than raising, when the write
  fails for a reason other than a link at the name.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import output_dir_links, scan_output_dirs
from automated_security_helper.utils.output_dir_links import (
    OUTPUT_GITIGNORE,
    OutputDirLinkRefused,
    ignore_output_dir_in_git,
    is_link,
    linked_output_component,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.scan_output_dirs import GitIndexAnswer

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _tree(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    root = tree / "repo"
    (root / "sub").mkdir(parents=True)
    (tree / "elsewhere").mkdir()
    (tree / "opt").mkdir()
    return tree, root


@needs_symlinks
def test_a_dotdot_after_an_operator_link_into_the_tree_lands_where_the_lookup_does(
    tmp_path,
):
    tree, root = _tree(tmp_path)
    (tree / "opt" / "link").symlink_to(root / "sub")
    (root / "x").symlink_to(tree / "elsewhere")
    output_dir = tree / "opt" / "link" / ".." / "x"

    found = linked_output_component(root, output_dir)

    assert found is not None
    assert "is a symlink" in found
    assert (root / "x").as_posix() in found
    with pytest.raises(OutputDirLinkRefused):
        refuse_linked_output_dir(root, output_dir)


@needs_symlinks
def test_a_dotdot_after_a_link_that_names_another_directory_as_written_is_refused(
    tmp_path,
):
    """The lookup reaches ``<root>/x``; written out, ``/opt/link/../x`` is
    ``/opt/x``, which is what ASH's writers (``os.path.abspath``) would open. Two
    directories for one spelling: the check vetted one and the log went to the
    other. Such a spelling is refused, naming both, rather than examined at
    either."""
    tree, root = _tree(tmp_path)
    (tree / "opt" / "link").symlink_to(root / "sub")
    (tree / "opt" / "x").mkdir()
    (root / "x").mkdir()
    output_dir = tree / "opt" / "link" / ".." / "x"

    found = linked_output_component(root, output_dir)

    assert found is not None
    assert (root / "x").as_posix() in found
    assert (tree / "opt" / "x").as_posix() in found
    with pytest.raises(OutputDirLinkRefused):
        refuse_linked_output_dir(root, output_dir)


@needs_symlinks
def test_control_a_dotdot_after_a_link_that_names_one_directory_is_accepted(tmp_path):
    """``/alias -> <tree>``, output ``/alias/opt/../out``: as written it is
    ``/alias/out`` and the lookup reaches ``<tree>/out``, one directory under two
    names (macOS's ``/tmp`` is such a link). Nothing to refuse."""
    tree, root = _tree(tmp_path)
    alias = tree / "alias"
    alias.symlink_to(tree)
    (tree / "out").mkdir()
    output_dir = alias / "opt" / ".." / "out"

    assert linked_output_component(root, output_dir) is None


def test_control_a_dotdot_between_plain_directories_is_applied_as_before(tmp_path):
    tree, root = _tree(tmp_path)
    (root / "out").mkdir()
    output_dir = root / "sub" / ".." / "out"

    assert linked_output_component(root, output_dir) is None


def test_is_link_answers_false_when_the_entry_cannot_be_looked_up(
    tmp_path, monkeypatch
):
    real_lstat = os.lstat

    def refused(path, *args, **kwargs):
        if os.fspath(path).endswith("out"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(output_dir_links.os, "lstat", refused)

    assert is_link(tmp_path / "out") is False
    assert linked_output_component(tmp_path, tmp_path / "out") is None


def _answer(names):
    def git_index_below(directory, **_):
        return GitIndexAnswer(
            Path(os.path.abspath(directory)), names=names, repository=Path("/repo")
        )

    return git_index_below


def test_no_ignore_file_is_written_where_the_repository_committed_files(
    tmp_path, monkeypatch
):
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(scan_output_dirs, "git_index_below", _answer(["README.md"]))

    assert ignore_output_dir_in_git(tmp_path, output) is False
    assert not (output / OUTPUT_GITIGNORE).exists()


def test_control_the_ignore_file_is_written_where_nothing_is_committed(
    tmp_path, monkeypatch
):
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(scan_output_dirs, "git_index_below", _answer([]))

    assert ignore_output_dir_in_git(tmp_path, output) is True
    assert (output / OUTPUT_GITIGNORE).read_text(encoding="utf-8").endswith("*\n")


def test_a_write_that_fails_answers_false_rather_than_raising(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(scan_output_dirs, "git_index_below", _answer([]))

    def refused(*args, **kwargs):
        raise PermissionError(13, "Permission denied", str(output))

    monkeypatch.setattr(fs_guard, "open_for_write", refused)

    assert ignore_output_dir_in_git(tmp_path, output) is False


@needs_symlinks
def test_control_a_link_at_the_name_is_still_refused(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    (output / OUTPUT_GITIGNORE).symlink_to(tmp_path / "elsewhere")
    monkeypatch.setattr(scan_output_dirs, "git_index_below", _answer([]))

    with pytest.raises(OutputDirLinkRefused):
        ignore_output_dir_in_git(tmp_path, output)
