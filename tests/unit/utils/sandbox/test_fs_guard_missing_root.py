# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results directory that was never created sweeps as empty.

The post-scan sweep runs over a sandboxed scanner's results directory, which the
scanner itself creates when it writes something. A scanner that wrote nothing
leaves no directory, and os.fwalk raises FileNotFoundError at a root it cannot
open, which the executor's handler graded as the scanner's failure. There is
nothing below a missing directory to remove.
"""

import logging
import os
import sys

import pytest

from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit


def test_a_missing_root_sweeps_as_empty(tmp_path):
    missing = tmp_path / "results"
    assert not missing.exists()

    assert fs_guard.sweep_writable([missing]) == 0

    assert not missing.exists(), "the sweep creates nothing"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_a_missing_root_among_others_does_not_stop_the_sweep(tmp_path):
    """The policy's writable roots are swept in one call; the missing one is
    passed over and the links under the others are still removed."""
    missing = tmp_path / "never-written"
    written = tmp_path / "results"
    written.mkdir()
    (written / "escape").symlink_to(tmp_path)

    removed = fs_guard.sweep_writable([missing, written])

    assert removed == 1
    assert not os.path.lexists(written / "escape")


def test_a_root_that_is_a_regular_file_sweeps_as_empty(tmp_path):
    """The policy's writable roots are directories; a caller that passes a file
    has nothing below it to sweep, and the file is neither opened as a directory
    (a refusal) nor touched."""
    file_root = tmp_path / "root.txt"
    file_root.write_text("kept\n")

    assert fs_guard.sweep_writable([file_root]) == 0

    assert file_root.read_text() == "kept\n"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_a_root_that_is_not_a_directory_is_said_not_refused(tmp_path, caplog):
    """A sandboxed scanner cannot put a file at its own root (that needs write
    on the root's parent, which the policies grant only on the results directory
    itself), so a non-directory root is an operator-side oddity: the sweep says
    so in one WARNING naming the root and goes on, with no refusal, nothing
    removed and no raise, where a silent pass would have hidden it."""
    file_root = tmp_path / "root.txt"
    file_root.write_text("kept\n")
    other = tmp_path / "results"
    other.mkdir()
    (other / "escape").symlink_to(tmp_path)

    with caplog.at_level(logging.WARNING, logger="ash"):
        removed = fs_guard.sweep_writable([file_root, other])

    assert removed == 1, "the next root is still swept"
    assert file_root.read_text() == "kept\n"
    lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("The results directory root")
    ]
    assert len(lines) == 1, [record.getMessage() for record in caplog.records]
    assert str(file_root) in lines[0] and "is not a directory" in lines[0], lines


def test_the_tree_sweep_itself_reads_a_missing_root_as_empty(tmp_path):
    """sweep_writable passes a missing root over before the tree sweep runs;
    the tree sweep, called on its own, reads one as empty too."""
    missing = tmp_path / "results"

    assert fs_guard._sweep_tree(missing) == 0


@pytest.mark.skipif(not hasattr(os, "fwalk"), reason="the os.walk branch is taken")
def test_the_os_walk_fallback_agrees_on_a_missing_root(tmp_path, monkeypatch):
    """Called on the tree sweep directly, so the os.walk branch is reached:
    through sweep_writable the missing root is passed over before it."""
    monkeypatch.delattr(os, "fwalk")
    missing = tmp_path / "results"

    assert fs_guard._sweep_tree(missing) == 0
    assert fs_guard.sweep_writable([missing]) == 0
