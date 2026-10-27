# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Source delivery deletes the read-only files a clone leaves, and goes on past
what it cannot delete.

Why this file exists
--------------------
git makes its pack files read-only, and Windows does not delete a read-only
file. ``shutil.rmtree(..., ignore_errors=True)`` then leaves a half-deleted tree
behind. A clone that failed leaves it where the next clone has to go, a leftover
zip staging directory is extracted into and renamed onto ``source/`` with its
stale files in it, and ``clear_source`` leaves part of a workspace the caller was
told is gone. ``_remove_tree`` clears the read-only bit of what it cannot delete
and retries, and a file it still cannot delete (another account owns it) stays
where it is without keeping the rest of the tree from being deleted.

No cell runs git, opens a network connection or needs a particular user. The
Windows rule is stood in for by two doubles (``os.unlink`` refuses a file whose
owner-write bit is clear, and ``shutil.rmtree`` calls its handler the way the
real one does), applied to ``source_delivery``'s own view of the two modules
only, so pytest's cleanup of ``tmp_path`` runs on the real ones. Each cell's
docstring says which wrong behavior it fails on.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from tests.utils import source_delivery_doubles as doubles
from tests.utils.source_delivery_doubles import UNDELETABLE

#: The shared fixture, bound to this module's namespace so pytest finds it here.
windows_semantics = doubles.windows_semantics


@pytest.fixture(autouse=True)
def _delivery_map_is_restored():
    """The session-to-source-dir map is a module global; put it back."""
    saved = dict(sd._SESSION_SOURCE_DIRS)
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    sd._SESSION_SOURCE_DIRS.update(saved)


def _read_only(path: Path) -> Path:
    os.chmod(path, 0o444)
    return path


def _clone_tree_with_a_read_only_pack(root: Path) -> Path:
    """What a finished clone leaves: a tree with a read-only pack file in it."""
    pack = root / ".git" / "objects" / "pack" / "pack.pack"
    pack.parent.mkdir(parents=True)
    pack.write_text("pack\n")
    _read_only(pack)
    return pack


def _zip_bytes(**files: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# The helpers.
# ---------------------------------------------------------------------------


def test_make_writable_gives_the_owner_write_access_to_a_file_and_a_directory(
    tmp_path,
):
    """Fails on a helper that clears nothing, or only the file's bit."""
    file = tmp_path / "pack.pack"
    file.write_text("pack\n")
    _read_only(file)
    directory = tmp_path / "objects"
    directory.mkdir()
    os.chmod(directory, 0o555)
    try:
        sd._make_writable(str(file))
        sd._make_writable(str(directory))

        assert os.stat(file).st_mode & stat.S_IWUSR
        assert os.stat(directory).st_mode & stat.S_IWUSR
    finally:
        os.chmod(directory, 0o755)
        os.chmod(file, 0o644)


def test_make_writable_leaves_a_symlink_and_what_it_points_at_alone(tmp_path):
    """chmod follows a link out of the tree; the helper must not ask it to."""
    outside = tmp_path / "outside.txt"
    outside.write_text("x\n")
    _read_only(outside)
    link = tmp_path / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    try:
        sd._make_writable(str(link))

        assert not os.stat(outside).st_mode & stat.S_IWUSR
    finally:
        os.chmod(outside, 0o644)


def test_a_tree_nothing_resists_is_deleted_and_reported_gone(tmp_path):
    """Control: no double. The answer is read from the disk."""
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "f.txt").write_text("x\n")

    assert sd._remove_tree(tree) is True
    assert not tree.exists()


def test_a_path_that_is_not_there_is_reported_gone(tmp_path):
    assert sd._remove_tree(tmp_path / "never-made") is True


def test_a_tree_with_read_only_files_is_cleared_and_deleted(
    tmp_path, windows_semantics
):
    """Fails on a delete that ignores the error and leaves the pack file."""
    tree = tmp_path / "tree"
    pack = _clone_tree_with_a_read_only_pack(tree)
    windows_semantics()

    assert sd._remove_tree(tree) is True
    assert not os.path.lexists(pack)
    assert not tree.exists()


def test_an_entry_that_cannot_be_deleted_stays_and_the_rest_is_deleted(
    tmp_path, windows_semantics
):
    """The undeletable name sorts first. A handler whose retry raises out of the
    walk would stop there and leave ``readonly.txt``; the rest is deleted."""
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / f"{UNDELETABLE}.txt").write_text("stays\n")
    readonly = tree / "readonly.txt"
    readonly.write_text("goes\n")
    _read_only(readonly)
    windows_semantics()

    assert sd._remove_tree(tree) is False
    assert (tree / f"{UNDELETABLE}.txt").exists()
    assert not readonly.exists()


def test_a_directory_rmtree_cannot_open_is_reported_and_raises_nothing(
    tmp_path, monkeypatch
):
    """rmtree also reports an ``os.open`` that failed. That call takes arguments
    the handler does not have, so it is not retried; retrying it raised a
    TypeError out of the delete."""
    locked = tmp_path / "locked"
    locked.mkdir()

    def rmtree_that_cannot_open(path, ignore_errors=False, onerror=None, **kwargs):
        # The handler arrives as onexc (3.12 and later) or onerror; see
        # doubles.rmtree_calling_windows_unlink.
        exc_handler = kwargs.get("onexc")
        handler = exc_handler or onerror
        error = PermissionError(errno.EACCES, "cannot open", str(path))
        argument = error if exc_handler else (type(error), error, None)
        handler(os.open, str(path), argument)

    monkeypatch.setattr(
        sd, "shutil", doubles.ModuleWith(shutil, rmtree=rmtree_that_cannot_open)
    )

    assert sd._remove_tree(locked) is False
    assert locked.exists()


#: A directory mode refuses an open or a delete only on POSIX, and not for root.
_POSIX_NOT_ROOT = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="a directory mode refuses an open or a delete only on POSIX, not for root",
)


@_POSIX_NOT_ROOT
def test_a_directory_the_owner_cannot_write_is_cleared_and_deleted(tmp_path):
    """No double: the real ``shutil.rmtree`` against real modes. A file and an empty
    directory in a directory the owner cannot write are not deleted until its mode is
    cleared too, which is the handler's parent-directory half."""
    tree = tmp_path / "tree"
    (tree / "empty").mkdir(parents=True)
    (tree / "held.txt").write_text("x\n")
    os.chmod(tree, 0o555)
    try:
        deleted = sd._remove_tree(tree)
    finally:
        if tree.exists():
            os.chmod(tree, 0o755)

    assert deleted is True
    assert not tree.exists()


@_POSIX_NOT_ROOT
def test_a_directory_the_owner_cannot_open_is_made_accessible_and_deleted(tmp_path):
    """No double. ``shutil.rmtree`` reports a directory it cannot open to the handler
    as ``os.open``, which is not retried, so one pass leaves that directory and the
    ones above it. The handler has made it accessible by then, and a second pass
    deletes it. Fails on a delete that stops after one pass."""
    tree = tmp_path / "tree"
    closed = tree / "closed"
    (closed / "empty").mkdir(parents=True)
    (closed / "held.txt").write_text("x\n")
    (tree / "plain.txt").write_text("x\n")
    os.chmod(closed, 0o000)
    try:
        deleted = sd._remove_tree(tree)
    finally:
        if closed.exists():
            os.chmod(closed, 0o700)

    assert deleted is True
    assert not tree.exists()


# ---------------------------------------------------------------------------
# The delivery paths.
# ---------------------------------------------------------------------------


def test_a_failed_clone_removes_the_directory_git_left_with_read_only_files(
    tmp_path, monkeypatch, windows_semantics
):
    """Fails on a clone failure that leaves the clone's staging directory holding the
    pack file: the delivery deletes it, read-only files included."""
    session = "failed-clone"

    def clone_that_fails(cmd, *, env):
        _clone_tree_with_a_read_only_pack(Path(cmd[-1]))
        return subprocess.CompletedProcess(cmd, 128, "", "fatal: early EOF")

    monkeypatch.setattr(sd, "_git_executable", lambda: "git")
    monkeypatch.setattr(sd, "_run_git", clone_that_fails)
    windows_semantics()

    with pytest.raises(sd.GitCommandError, match="git clone failed"):
        sd.set_source_git(
            "https://example.com/foo.git", workspace_root=tmp_path, session_id=session
        )

    assert [
        p.name
        for p in (tmp_path / session).iterdir()
        if p.name == "source" or p.name.startswith(".source.")
    ] == []


def test_a_new_clone_replaces_a_previous_one_whose_pack_files_are_read_only(
    tmp_path, monkeypatch, windows_semantics
):
    """Fails on a re-delivery that cannot delete the previous clone: the old
    ``.git`` is still there beside the new tree."""
    session = "redelivered"
    previous = tmp_path / session / "source"
    _clone_tree_with_a_read_only_pack(previous)
    sd._set_session_source_dir(session, previous)

    def clone_that_works(cmd, *, env):
        target = Path(cmd[-1])
        target.mkdir(parents=True, exist_ok=True)
        (target / "cloned.txt").write_text("new delivery\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sd, "_git_executable", lambda: "git")
    monkeypatch.setattr(sd, "_run_git", clone_that_works)
    windows_semantics()

    target = sd.set_source_git(
        "https://example.com/foo.git", workspace_root=tmp_path, session_id=session
    )

    assert (target / "cloned.txt").read_text() == "new delivery\n"
    assert not (target / ".git").exists()


def test_a_leftover_staging_tree_with_read_only_files_stays_out_of_the_next_zip(
    tmp_path, windows_semantics
):
    """Fails on a delivery that extracts into a leftover staging directory: the
    rename puts the stale file in ``source/``. A delivery has a staging directory of
    its own, and deletes the leftover one (read-only file and all) at its start."""
    session = "zip-leftover"
    stale = tmp_path / session / (sd._STAGING_DIR_PREFIX + "leftover") / "stale.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale\n")
    _read_only(stale)
    payload = _zip_bytes(**{"a.txt": "aa\n"})
    sd.set_source_zip_chunk(
        upload_id="u1",
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=tmp_path,
        session_id=session,
    )
    windows_semantics()

    target = sd.set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=tmp_path,
        session_id=session,
    )

    assert (target / "a.txt").read_text() == "aa\n"
    assert not (target / "stale.txt").exists()
    # Each delivery extracts into a directory of its own, so the leftover can never
    # reach source/ whether or not it was deleted. The deletion is what this test is
    # for, so it is read directly: the leftover, read-only file and all, is gone.
    assert not stale.parent.exists()


def test_clear_source_deletes_a_workspace_that_holds_read_only_files(
    tmp_path, windows_semantics
):
    """Fails on a clear that reports the source gone and leaves the pack file."""
    session = "clear-read-only"
    tree = tmp_path / session / "source"
    _clone_tree_with_a_read_only_pack(tree)
    sd._set_session_source_dir(session, tree)
    windows_semantics()

    sd.clear_source(session, workspace_root=tmp_path)

    assert not (tmp_path / session).exists()
    assert sd.get_session_source_dir(session) is None
