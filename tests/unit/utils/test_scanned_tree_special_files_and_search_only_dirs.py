# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of utils/scanned_tree.

A file below a directory the user may search but not list can be read, a name that
is not a regular file is refused before it is opened, a path holding a NUL names no
file, and a link into the tree that names the root in another case is inside it.
"""

import os
import stat
import sys

import pytest

from automated_security_helper.utils import scanned_tree
from automated_security_helper.utils.scanned_tree import (
    REASON_NOT_REGULAR,
    TreeInputRefused,
    open_in_scanned_tree,
    refusal_reason,
    resolves_inside,
)

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the file system objects below are POSIX's"
)


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


class TestADirectoryThatMayOnlyBeSearched:
    @posix_only
    @pytest.mark.skipif(
        not getattr(os, "O_PATH", 0), reason="a directory is named without O_PATH"
    )
    @pytest.mark.skipif(_running_as_root(), reason="root reads every directory")
    def test_a_file_below_it_is_opened(self, tmp_path):
        """Each directory was opened for reading, so mode 0311 refused the walk with
        EACCES, though a plain open of the file below it succeeds."""
        root = tmp_path / "root"
        directory = root / "sub"
        directory.mkdir(parents=True)
        target = directory / "f.txt"
        target.write_text("data", encoding="utf-8")
        directory.chmod(0o311)
        try:
            with open_in_scanned_tree(target, root) as handle:
                assert handle.read() == b"data"
        finally:
            directory.chmod(0o755)


class TestANameThatIsNotARegularFile:
    @posix_only
    def test_a_pipe_is_refused_without_being_opened(self, tmp_path, monkeypatch):
        """The open came first and the check on the descriptor after it, so a device
        node at a candidate path was opened before it was refused."""
        os.mkfifo(tmp_path / "pipe")
        opened = []
        real_open = os.open

        def spy(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(scanned_tree.os, "open", spy)

        with pytest.raises(TreeInputRefused) as refused:
            open_in_scanned_tree(tmp_path / "pipe", tmp_path)

        assert refused.value.reason == REASON_NOT_REGULAR
        assert "pipe" not in opened, opened

    @posix_only
    def test_a_socket_is_a_refusal_not_a_failed_open(self, tmp_path):
        """Opened for reading, a socket fails with ENXIO, a plain OSError, which
        ``refusal_reason`` took for a file that could be read."""
        try:
            os.mknod(tmp_path / "s.sock", stat.S_IFSOCK | 0o600)
        except OSError as error:
            pytest.skip(f"this file system makes no socket node: {error}")

        with pytest.raises(TreeInputRefused) as refused:
            open_in_scanned_tree(tmp_path / "s.sock", tmp_path)

        assert refused.value.reason == REASON_NOT_REGULAR
        assert refusal_reason(tmp_path / "s.sock", tmp_path) == REASON_NOT_REGULAR

    def test_a_regular_file_is_still_opened(self, tmp_path):
        (tmp_path / "f.txt").write_text("data", encoding="utf-8")

        with open_in_scanned_tree(tmp_path / "f.txt", tmp_path) as handle:
            assert handle.read() == b"data"


class TestAPathHoldingANul:
    def test_it_names_no_file(self, tmp_path):
        """``os.open`` raises ``ValueError`` for it, which no caller of this module
        handles, where it handles a missing file."""
        path = tmp_path / "a\0b"

        with pytest.raises(FileNotFoundError):
            open_in_scanned_tree(path, tmp_path)

    def test_it_is_not_a_refusal(self, tmp_path):
        assert refusal_reason(tmp_path / "a\0b", tmp_path) is None


class TestALinkNamingTheRootInAnotherCase:
    @posix_only
    def test_its_target_is_inside(self, tmp_path, monkeypatch):
        """On a case-insensitive volume a link into the tree may resolve to a path
        that spells the root in another case. This stands one in: ``stat`` folds the
        case of the name, as such a volume does, and ``resolves_inside`` has to
        answer by the directory the name reaches."""
        root = tmp_path / "Rootcase"
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "f.txt").write_text("x", encoding="utf-8")
        elsewhere = tmp_path / "ROOTCASE" / "pkg" / "f.txt"
        real_stat = os.stat

        def case_folding_stat(path, *args, **kwargs):
            return real_stat(str(path).replace("ROOTCASE", "Rootcase"), *args, **kwargs)

        monkeypatch.setattr(scanned_tree.os, "stat", case_folding_stat)

        assert resolves_inside(elsewhere, root)

    def test_a_target_outside_is_still_outside(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / "f.txt").write_text("x", encoding="utf-8")

        assert not resolves_inside(tmp_path / "other" / "f.txt", root)

    def test_the_root_itself_is_not_inside_itself(self, tmp_path):
        assert not resolves_inside(tmp_path, tmp_path)
