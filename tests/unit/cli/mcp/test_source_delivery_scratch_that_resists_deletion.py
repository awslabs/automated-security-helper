# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scratch of a source delivery that resists deletion: the tests
``test_source_delivery_deletes_read_only_scratch.py`` does not reach.

Why this file exists
--------------------
``_remove_tree`` clears the read-only bit of what it cannot delete and retries it
once, and only a removal is retried. The other file holds the tests for the tree
that a delete, a re-delivery, a leftover zip staging directory and ``clear_source``
meet. This one holds what stays open after it:

* the directory-mode tests of ``TestTheRealRmtreeOnDirectoryModes`` run the real
  ``shutil.rmtree`` against real directory modes. A file in a directory the owner
  cannot write is not deleted until the directory's mode is cleared too
  (``test_a_directory_without_write_access_does_not_keep_its_files``, the
  parent-directory half of the handler), and a directory the owner cannot open is
  reported to the handler as ``os.open``, which a retry with the path alone would
  turn into a ``TypeError`` that ``suppress(OSError)`` lets out of the delete
  (``test_a_directory_that_cannot_be_opened_does_not_raise_out_of_the_delete``, the
  sentinel for the retry's guard: it goes red if the guard is dropped or widened to
  every reported call). Directories the owner cannot open one inside the other cost
  a pass per level, so
  ``test_directories_the_owner_cannot_open_one_inside_the_other_are_all_deleted``
  nests them to depths 2, 3 and 5.
* ``TestThePassesOfTheDelete`` reads how many passes the delete makes, with a
  ``shutil.rmtree`` double
  (``test_it_stops_at_its_bound_when_every_pass_changes_a_permission``,
  ``test_it_stops_after_two_passes_when_no_pass_changes_a_permission`` and
  ``test_a_chmod_that_changes_no_mode_is_not_progress``, which reads that a call that
  changes no mode is not counted as progress). It also holds
  ``test_make_writable_says_whether_the_mode_changed``, which uses no double: it reads
  the helper's answer on a real directory, with and without a working ``chmod``.
* the cleanup of a zip delivery that ended before it renamed its staging tree into
  place (``TestAZipDeliveryThatEndsWithoutAResult``, the ``finally`` of
  ``set_source_zip_finalize``), and the two git exits the other file does not drive:
  a failed checkout and a clone that timed out
  (``TestAGitDeliveryThatEndsEarlyLeavesNoClone``).

How the tests work
------------------
The delivery tests of the last two classes apply the Windows-semantics pair of
``tests/utils/source_delivery_doubles`` (a read-only file cannot be unlinked until
its bit is cleared), with the read-only bits planted by ``chmod`` on files under
``tmp_path`` and restored at teardown. Against a delete that ignores the error
(``shutil.rmtree(..., ignore_errors=True)``) each leaves the pack file, so the
staging tree or ``source/`` is still there. The three directory-mode tests skip for
root and on Windows, where a mode does not refuse the call. Nothing here runs git:
the clone is a double.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from tests.utils import source_delivery_doubles as doubles

pytestmark = pytest.mark.unit

#: The shared fixtures, bound to this module's namespace so pytest finds them here.
read_only_files = doubles.read_only_files
windows_semantics = doubles.windows_semantics

_SESSION = "scratch-that-resists"

#: What ``_git_executable`` answers, so the argv the doubles read is the same on
#: every machine.
GIT = "/opt/git/bin/git"

#: A directory mode refuses an open or a delete only on POSIX, and not for root.
_POSIX_NOT_ROOT = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="a directory mode refuses an open or a delete only on POSIX, not for root",
)


@pytest.fixture(autouse=True)
def _a_delivery_that_touches_no_other_state(monkeypatch):
    """The recorded sources are process-wide: each test starts with none. Nothing
    waits: a test that refuses a rename would otherwise sleep through every retry."""
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setattr(time, "sleep", lambda seconds: None)


def _plant_a_read_only_pack(tree: Path, read_only) -> Path:
    """Write ``<tree>/.git/objects/pack.pack`` and clear its owner-write bit."""
    pack = tree / ".git" / "objects" / "pack.pack"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text("pack\n")
    return read_only(pack)


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _git_result(returncode: int, stderr: str = "") -> MagicMock:
    result = MagicMock()
    result.returncode = returncode
    result.stdout = ""
    result.stderr = stderr
    return result


def _deliver_from_git(tmp_path: Path, ref=None) -> Path:
    return sd.set_source_git(
        url="https://example.com/foo.git",
        ref=ref,
        workspace_root=tmp_path,
        session_id=_SESSION,
    )


class TestTheRealRmtreeOnDirectoryModes:
    @_POSIX_NOT_ROOT
    def test_a_directory_without_write_access_does_not_keep_its_files(self, tmp_path):
        """A file in a directory the owner cannot write is not deleted until the
        directory's mode is cleared too. Red if the handler clears only the file's
        bit and not its parent directory's."""
        tree = tmp_path / "scratch"
        locked = tree / "locked"
        locked.mkdir(parents=True)
        (locked / "f.txt").write_text("x\n")
        locked.chmod(0o555)
        try:
            assert sd._remove_tree(tree) is True
        finally:
            if locked.exists():
                locked.chmod(0o755)

        assert not tree.exists()

    @_POSIX_NOT_ROOT
    @pytest.mark.parametrize("depth", [2, 3, 5])
    def test_directories_the_owner_cannot_open_one_inside_the_other_are_all_deleted(
        self, tmp_path, depth
    ):
        """``a/`` (mode 000) holding ``b/`` (mode 000): one pass makes ``a/``
        accessible, the next makes ``b/`` accessible, and the one after deletes the
        two. Each level of such directories costs a pass, so a delete that stops after
        two refuses the tree its docstring says it deletes. Fails at depth 2 and more
        on a delete with a fixed number of passes."""
        tree = tmp_path / "scratch"
        chain = [tree]
        for level in range(depth):
            chain.append(chain[-1] / f"d{level}")
        chain[-1].mkdir(parents=True)
        (chain[-1] / "f.txt").write_text("x\n")
        (tree / "plain.txt").write_text("x\n")
        for directory in reversed(chain[1:]):
            directory.chmod(0o000)
        try:
            assert sd._remove_tree(tree) is True
        finally:
            for directory in chain[1:]:
                if directory.exists():
                    directory.chmod(0o700)

        assert not tree.exists()

    @_POSIX_NOT_ROOT
    def test_a_directory_that_cannot_be_opened_does_not_raise_out_of_the_delete(
        self, tmp_path
    ):
        """rmtree reports a failed open to the handler as ``os.open``, which takes
        a flags argument: retrying it with the path alone is a ``TypeError``, and a
        ``TypeError`` is not the ``OSError`` the delete suppresses. The directory is
        made accessible and the answer follows the disk, whatever it is."""
        tree = tmp_path / "scratch"
        closed = tree / "closed"
        closed.mkdir(parents=True)
        (closed / "f.txt").write_text("x\n")
        (tree / "plain.txt").write_text("x\n")
        closed.chmod(0o000)
        try:
            gone = sd._remove_tree(tree)
            assert gone is (not tree.exists())
        finally:
            if closed.exists():
                closed.chmod(0o700)


class TestThePassesOfTheDelete:
    """How long ``_remove_tree`` keeps going. ``shutil.rmtree`` is a double that
    reports one directory the way the real one reports a directory it cannot open
    (``os.open`` and the path), so the count of passes is read directly."""

    @staticmethod
    def _rmtree_that_cannot_open(tree: Path, calls: list, *, mode_each_pass: int):
        """A ``rmtree`` that leaves the tree in place and reports ``tree/stuck``.

        ``mode_each_pass`` is put on ``stuck`` before each report, so a value the
        handler has to change (``0o000``) makes every pass change a permission, and
        one it does not (``0o755``) makes none.
        """
        stuck = tree / "stuck"

        def rmtree(path, ignore_errors=False, onerror=None, **kwargs):
            calls.append(path)
            os.chmod(stuck, mode_each_pass)
            exc_handler = kwargs.get("onexc")
            handler = exc_handler or onerror
            error = PermissionError(errno.EACCES, "cannot open", str(stuck))
            argument = error if exc_handler else (type(error), error, None)
            handler(os.open, str(stuck), argument)

        return rmtree

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="a directory's mode does not change on Windows, so no pass changes one",
    )
    def test_it_stops_at_its_bound_when_every_pass_changes_a_permission(
        self, tmp_path, monkeypatch
    ):
        """A tree that never gets deleted while each pass makes something accessible
        again (something outside puts the mode back) does not loop for ever."""
        tree = tmp_path / "scratch"
        (tree / "stuck").mkdir(parents=True)
        calls: list = []
        monkeypatch.setattr(
            sd,
            "shutil",
            doubles.ModuleWith(
                shutil,
                rmtree=self._rmtree_that_cannot_open(tree, calls, mode_each_pass=0),
            ),
        )

        try:
            assert sd._remove_tree(tree) is False
        finally:
            os.chmod(tree / "stuck", 0o755)

        assert len(calls) == sd._REMOVE_TREE_MAX_PASSES
        assert tree.exists()

    def test_it_stops_after_two_passes_when_no_pass_changes_a_permission(
        self, tmp_path, monkeypatch
    ):
        """Control: with nothing to make accessible, a third pass would meet the
        same refusal, so the delete stops where it did before."""
        tree = tmp_path / "scratch"
        (tree / "stuck").mkdir(parents=True)
        calls: list = []
        monkeypatch.setattr(
            sd,
            "shutil",
            doubles.ModuleWith(
                shutil,
                rmtree=self._rmtree_that_cannot_open(tree, calls, mode_each_pass=0o755),
            ),
        )

        assert sd._remove_tree(tree) is False

        assert len(calls) == 2
        assert tree.exists()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="a directory's mode does not change on Windows, so no pass changes one",
    )
    def test_a_chmod_that_changes_no_mode_is_not_progress(self, tmp_path, monkeypatch):
        """A file system can accept a chmod and change nothing (CIFS mounted without
        permissions, vfat, some FUSE). The delete used to count the call as progress,
        so every pass read as one that made something accessible and it walked the
        tree ``_REMOVE_TREE_MAX_PASSES`` times on the server's event loop. It reads
        the mode again after the chmod, and with no change stops after two passes."""
        tree = tmp_path / "scratch"
        (tree / "stuck").mkdir(parents=True)
        calls: list = []
        monkeypatch.setattr(
            sd,
            "shutil",
            doubles.ModuleWith(
                shutil,
                rmtree=self._rmtree_that_cannot_open(tree, calls, mode_each_pass=0),
            ),
        )
        monkeypatch.setattr(
            sd, "os", doubles.ModuleWith(os, chmod=lambda path, mode: None)
        )

        try:
            assert sd._remove_tree(tree) is False
        finally:
            os.chmod(tree / "stuck", 0o755)

        assert len(calls) == 2, f"{len(calls)} passes over a tree no chmod changes"
        assert tree.exists()

    def test_make_writable_says_whether_the_mode_changed(self, tmp_path, monkeypatch):
        """The answer follows the mode on disk. A directory the owner cannot open is
        changed and the answer is True; one a chmod leaves as it was is False."""
        if sys.platform == "win32":
            pytest.skip("a directory's mode does not change on Windows")
        closed = tmp_path / "closed"
        closed.mkdir()
        closed.chmod(0o000)
        try:
            with monkeypatch.context() as no_chmod:
                no_chmod.setattr(
                    sd, "os", doubles.ModuleWith(os, chmod=lambda path, mode: None)
                )
                assert sd._make_writable(str(closed)) is False
            assert sd._make_writable(str(closed)) is True
            assert sd._make_writable(str(closed)) is False
        finally:
            closed.chmod(0o700)


class TestAZipDeliveryThatEndsWithoutAResult:
    def test_it_deletes_its_staging_tree_though_the_tree_holds_a_read_only_file(
        self, tmp_path, monkeypatch, read_only_files, windows_semantics
    ):
        """The ``finally`` of ``set_source_zip_finalize``: the swap fails with the
        staged tree holding a read-only file, and the tree must not stay for the
        next extraction to write into."""
        payload = _zip_bytes({"app/main.py": "print('new')\n"})
        sd.set_source_zip_chunk(
            upload_id="u1",
            sequence=0,
            data_b64=base64.b64encode(payload).decode("ascii"),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        session_dir = tmp_path / _SESSION
        real_rename = Path.rename

        planted = []

        def rename(path, target):
            if path.name.startswith(sd._STAGING_DIR_PREFIX):
                # The delivery tries a refused rename of the finished tree again,
                # and the pack file is read-only once planted, so it is planted
                # on the first refusal only.
                if not planted:
                    planted.append(_plant_a_read_only_pack(path, read_only_files))
                raise OSError(errno.EBUSY, "device or resource busy")
            return real_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)
        windows_semantics()

        with pytest.raises(OSError, match="busy"):
            sd.set_source_zip_finalize(
                upload_id="u1",
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        assert [
            p.name
            for p in session_dir.iterdir()
            if p.name.startswith(sd._STAGING_DIR_PREFIX)
        ] == []
        assert sd.get_session_source_dir(_SESSION) is None


class TestAGitDeliveryThatEndsEarlyLeavesNoClone:
    def test_a_failed_checkout_leaves_no_source_directory(
        self, tmp_path, read_only_files, windows_semantics
    ):
        def clone_succeeds_checkout_fails(cmd, **kw):
            if "clone" in cmd:
                _plant_a_read_only_pack(Path(cmd[-1]), read_only_files)
                return _git_result(0)
            if "checkout" in cmd:
                return _git_result(1, "did not match any file(s) known to git")
            # fetch is allowed to fail without ending the delivery.
            return _git_result(1)

        windows_semantics()

        with patch.object(sd, "_run_git", side_effect=clone_succeeds_checkout_fails):
            with pytest.raises(RuntimeError, match="git checkout"):
                _deliver_from_git(tmp_path, ref="no-such-ref")

        assert not (tmp_path / _SESSION / "source").exists()
        assert [
            p.name
            for p in (tmp_path / _SESSION).iterdir()
            if p.name.startswith(".source.")
        ] == []
        assert sd.get_session_source_dir(_SESSION) is None

    def test_a_clone_that_times_out_leaves_no_source_directory(
        self, tmp_path, read_only_files, windows_semantics
    ):
        def clone_writes_a_pack_then_times_out(
            url, ref, *, depth, target, env, git=None
        ):
            _plant_a_read_only_pack(target, read_only_files)
            raise sd.GitTimeoutError("git clone did not finish and was stopped")

        windows_semantics()

        with patch.object(sd, "_clone", side_effect=clone_writes_a_pack_then_times_out):
            with pytest.raises(sd.GitTimeoutError):
                _deliver_from_git(tmp_path)

        assert not (tmp_path / _SESSION / "source").exists()
        assert [
            p.name
            for p in (tmp_path / _SESSION).iterdir()
            if p.name.startswith(".source.")
        ] == []
        assert sd.get_session_source_dir(_SESSION) is None
