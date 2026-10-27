# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Source delivery reads the answer of ``_remove_tree`` and does not carry on past it.

Why this file exists
--------------------
``_remove_tree`` returns False when something of the tree it was asked to delete is
still on disk. Places in ``source_delivery`` delete scratch: the previous clone, a
clone that failed, a git that could not be started, a git command that timed out, a
failed checkout, what earlier deliveries left beside ``source/``, the zip staging
directory of a delivery that ended early, the tree a zip delivery replaces, and the
session workspace. Each one has to read that answer, because the session's recorded
``source_dir`` is what ``run_ash_scan`` scans when it is given no ``source_dir``, and a
recorded path has to name a complete tree or nothing.

What the code does, by path
---------------------------
* The previous clone is renamed aside (``.source.replaced-<id>``) once the new clone
  is complete (it is made in a staging directory, as a zip extraction is), and so is
  the previous zip tree. It is then renamed again to ``.source.trash-<id>`` and
  deleted under that name, so what cannot be deleted of either stays under the trash
  name, never under the replaced name: a tree that carries the replaced name is whole.
  It never ends a delivery and never leaves a half-deleted tree at ``source/``. A
  previous tree that cannot even be renamed ends the delivery with
  ``SessionWorkspaceError`` and leaves it, and the record, in place.
* What earlier deliveries left beside ``source/`` (``.source.replaced-*``,
  ``.source.trash-*`` and ``.source.incoming*``) is deleted at the start of the next
  delivery, a replaced tree under the trash name. It cannot end that delivery either:
  what cannot be deleted is logged.
* A zip delivery extracts into a staging directory of its own name
  (``.source.incoming-<id>``), so a leftover one is never extracted into.
* A failed clone, fetch or checkout whose staging directory cannot be fully deleted
  raises git's own error (``GitCommandError`` with git's ``error_type``), not a
  workspace error: the step that failed does not delete anything, and the delivery
  deletes its staging directory once, in the ``finally`` that every ending passes
  through. The partial tree is that staging directory, so the previous tree and the
  session's recorded source are untouched, and what could not be deleted stays under
  its scratch name, logged, for the next delivery to delete. A timeout whose cleanup
  leaves something behind is logged the same way, and the timeout is the error
  raised: the error that ended the delivery is the one reported.
* A zip swap renames the previous tree aside, renames the staged tree into place
  and then deletes the old tree on a best-effort basis, so the recorded path names
  the new tree or the previous one, never a half-deleted one. A rename that fails
  puts the previous tree back, and is a ``SessionWorkspaceError``.
* The cleanup of staging after a delivery that ended early cannot replace the
  error that ended it, so it logs what it could not delete. The next delivery
  deletes it.
* ``remove_session_workspace`` (the session-end path) drops the record either way
  and returns whether the workspace is gone. ``clear_source`` is documented to
  leave entries it cannot delete, so it does not raise for them: it logs them.

How the cells work
------------------
``_remove_tree`` is replaced on ``source_delivery`` by a double that answers False
for the paths a cell names and leaves them on disk, and calls the real function for
the rest. Nothing here runs git: ``_run_git`` is a double, and no cell needs a
particular user. Each cell's docstring says which wrong behavior it fails on.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import os
import subprocess
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests

_SESSION = "scratch-it-cannot-delete"

#: What ``_git_executable`` answers, so the argv the doubles read is the same on
#: every machine.
GIT = "/opt/git/bin/git"

URL = "https://example.com/foo.git"


@pytest.fixture(autouse=True)
def _delivery_state_of_one_cell(monkeypatch):
    """The recorded sources are process-wide: each test starts with none. Nothing
    waits: a test that refuses a rename would otherwise sleep through every retry."""
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setattr(time, "sleep", lambda seconds: None)


@pytest.fixture
def refuse_to_delete(monkeypatch):
    """Returns a function that makes ``_remove_tree`` answer False for some paths.

    The function takes a predicate on the path. A path it accepts that is on disk is
    left there and reported as not gone; every other path, one that is not on disk
    included (the real function answers True for it), goes to the real
    ``_remove_tree``.
    """

    real = sd._remove_tree

    def apply(refused) -> None:
        def remove_tree(path) -> bool:
            if refused(Path(path)) and os.path.lexists(path):
                return False
            return real(path)

        monkeypatch.setattr(sd, "_remove_tree", remove_tree)

    return apply


@pytest.fixture
def logged(monkeypatch) -> MagicMock:
    """The module's logger, replaced, so a test can read what was logged."""
    logger = MagicMock()
    monkeypatch.setattr(sd, "_logger", logger)
    return logger


def _warned_once_about(logged: MagicMock, fragment: str) -> None:
    """One warning was logged, and it names ``fragment`` (the scratch that resisted
    deletion), not some other path."""
    assert logged.warning.call_count == 1, logged.warning.call_args_list
    assert fragment in str(logged.warning.call_args), logged.warning.call_args


@pytest.fixture
def isolated_session_registry(monkeypatch):
    """The tools register the session in the process-wide registry and read the
    transport from the environment: a test that drives a tool starts and ends with
    neither."""
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    reset_default_registry_for_tests()
    yield
    reset_default_registry_for_tests()


def _the_session_workspace_or_its_hidden_name(path: Path) -> bool:
    """The session workspace, and the hidden name it is renamed to for the delete.

    ``remove_session_workspace`` renames the workspace aside first and deletes
    that, so a double that refuses the delete has to refuse the hidden name.
    """
    return path.name == _SESSION or path.name.startswith(f".{_SESSION}.deleting-")


def _zip_bytes(**files: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def _upload(tmp_path: Path, payload: bytes, upload_id: str = "u1") -> str:
    """Send ``payload`` as one chunk and return the sha256 to finalize it with."""
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=tmp_path,
        session_id=_SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _a_delivered_tree(tmp_path: Path) -> Path:
    """Record ``<session>/source`` holding ``old.txt`` as the delivered source."""
    previous = tmp_path / _SESSION / "source"
    previous.mkdir(parents=True)
    (previous / "old.txt").write_text("old\n")
    sd._set_session_source_dir(_SESSION, previous)
    return previous


def _finalize(tmp_path: Path, sha256: str) -> Path:
    return sd.set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=sha256,
        workspace_root=tmp_path,
        session_id=_SESSION,
    )


def _deliver_from_git(tmp_path: Path, ref=None) -> Path:
    return sd.set_source_git(
        url=URL, ref=ref, workspace_root=tmp_path, session_id=_SESSION
    )


def _a_replaced_tree(path: Path) -> bool:
    """A tree a delivery renamed aside (``.source.replaced-<id>``), or that it renamed
    again to be deleted (``.source.trash-<id>``): a delete of the first is done under
    the second name."""
    return path.name.startswith((sd._REPLACED_DIR_PREFIX, sd._TRASH_DIR_PREFIX))


def _a_staging_directory(path: Path) -> bool:
    """A zip delivery's staging directory, of any delivery (``.source.incoming-<id>``)."""
    return path.name.startswith(sd._STAGING_DIR_PREFIX)


def _scratch_beside_source(session_dir: Path) -> list:
    """The names a delivery leaves beside ``source/`` and has not deleted."""
    return sorted(
        entry.name
        for entry in session_dir.iterdir()
        if entry.name.startswith(
            (sd._STAGING_DIR_PREFIX, sd._REPLACED_DIR_PREFIX, sd._TRASH_DIR_PREFIX)
        )
    )


# ---------------------------------------------------------------------------
# The zip swap.
# ---------------------------------------------------------------------------


class TestAZipDeliveryThatReplacesATree:
    def test_a_previous_tree_it_cannot_delete_does_not_keep_the_new_one_out(
        self, tmp_path, refuse_to_delete, logged
    ):
        """Fails on a swap that deletes the previous tree in place: when that leaves
        a remnant, the rename of the staged tree onto the path fails and the path
        still names the remnant. The previous tree is renamed aside first, so the
        recorded path names the new tree whatever the delete of the old one does."""
        previous = _a_delivered_tree(tmp_path)
        sha256 = _upload(tmp_path, _zip_bytes(**{"new.txt": "new\n"}))
        refuse_to_delete(_a_replaced_tree)

        target = _finalize(tmp_path, sha256)

        assert target == previous
        assert (target / "new.txt").read_text() == "new\n"
        assert not (target / "old.txt").exists()
        assert sd.get_session_source_dir(_SESSION) == target
        _warned_once_about(logged, sd._TRASH_DIR_PREFIX)

    def test_a_rename_that_fails_leaves_the_previous_tree_in_place(
        self, tmp_path, monkeypatch
    ):
        """Fails on a swap that has already deleted the previous tree when the rename
        of the staged tree onto its path fails: the recorded path then names nothing."""
        previous = _a_delivered_tree(tmp_path)
        sha256 = _upload(tmp_path, _zip_bytes(**{"new.txt": "new\n"}))
        real_rename = Path.rename

        def rename(path, target):
            if _a_staging_directory(path):
                raise OSError(errno.EBUSY, "device or resource busy")
            return real_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)

        with pytest.raises(sd.SessionWorkspaceError, match="busy"):
            _finalize(tmp_path, sha256)

        assert (previous / "old.txt").read_text() == "old\n"
        assert sd.get_session_source_dir(_SESSION) == previous
        assert _scratch_beside_source(tmp_path / _SESSION) == []

    def test_a_restore_that_fails_too_leaves_the_previous_tree_under_its_hidden_name(
        self, tmp_path, monkeypatch
    ):
        """The previous tree was renamed aside, the staged tree cannot take its
        path, and the previous tree cannot be put back either. Nothing is at
        ``source/``, the previous tree stays under the hidden name for the next
        delivery to put back, the record is kept and names the path with nothing at
        it, and no staging directory is left."""
        previous = _a_delivered_tree(tmp_path)
        sha256 = _upload(tmp_path, _zip_bytes(**{"new.txt": "new\n"}))
        real_rename = Path.rename

        def rename(path, target):
            if _a_staging_directory(path) or (
                _a_replaced_tree(path) and Path(target).name == "source"
            ):
                raise OSError(errno.EBUSY, "device or resource busy")
            return real_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)

        with pytest.raises(sd.SessionWorkspaceError, match="busy"):
            _finalize(tmp_path, sha256)

        assert not previous.exists()
        assert sd.get_session_source_dir(_SESSION) == previous
        session_dir = tmp_path / _SESSION
        (aside,) = [p for p in session_dir.iterdir() if _a_replaced_tree(p)]
        assert (aside / "old.txt").read_text() == "old\n"
        assert [p.name for p in session_dir.iterdir() if _a_staging_directory(p)] == []

    def test_a_swap_nothing_resists_leaves_only_the_new_tree(self, tmp_path):
        """Control: no double. The previous tree is gone and nothing is left beside
        the new one."""
        previous = _a_delivered_tree(tmp_path)
        sha256 = _upload(tmp_path, _zip_bytes(**{"new.txt": "new\n"}))

        target = _finalize(tmp_path, sha256)

        assert target == previous
        assert (target / "new.txt").read_text() == "new\n"
        assert not (target / "old.txt").exists()
        session_dir = tmp_path / _SESSION
        assert [p.name for p in session_dir.iterdir() if "replaced" in p.name] == []


class TestAStagingDirectoryAnEarlierDeliveryLeft:
    """A leftover staging directory, or a tree an earlier delivery renamed aside, is
    scratch. A delivery deletes what it can at its start and never extracts into it,
    so one entry that cannot be deleted does not end every later delivery."""

    def _leftover(self, tmp_path: Path, name: str) -> Path:
        stale = tmp_path / _SESSION / name / "stale.txt"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale\n")
        return stale

    @pytest.mark.parametrize(
        "kind", ["a-staging-directory", "the-fixed-name-of-an-earlier-version"]
    )
    def test_a_leftover_that_cannot_be_deleted_does_not_end_the_delivery(
        self, tmp_path, refuse_to_delete, logged, kind
    ):
        """Fails on a delivery that deletes its fixed staging name first and ends when
        that leaves a remnant: the previous delivery's record was dropped and no later
        delivery to the session could succeed. The record names the new tree, the
        stale file is not in it, and what could not be deleted is logged once."""
        name = {
            "a-staging-directory": sd._STAGING_DIR_PREFIX + "left-by-a-delivery",
            "the-fixed-name-of-an-earlier-version": ".source.incoming",
        }[kind]
        _a_delivered_tree(tmp_path)
        stale = self._leftover(tmp_path, name)
        sha256 = _upload(tmp_path, _zip_bytes(**{"a.txt": "aa\n"}))
        refuse_to_delete(lambda path: path.name == name)

        target = _finalize(tmp_path, sha256)

        assert (target / "a.txt").read_text() == "aa\n"
        assert not (target / "stale.txt").exists()
        assert not (target / "old.txt").exists()
        assert sd.get_session_source_dir(_SESSION) == target
        assert stale.exists()
        _warned_once_about(logged, name)

    def test_the_tool_delivers_over_a_leftover_it_cannot_delete(
        self, tmp_path, monkeypatch, refuse_to_delete, isolated_session_registry
    ):
        """Fails on a finalize that answers ``session_workspace_unavailable`` over
        the leftover."""
        from automated_security_helper.cli.mcp_tools import (
            mcp_set_source_zip_finalize,
        )

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
        _a_delivered_tree(tmp_path)
        self._leftover(tmp_path, sd._STAGING_DIR_PREFIX + "left-by-a-delivery")
        sha256 = _upload(tmp_path, _zip_bytes(**{"a.txt": "aa\n"}))
        refuse_to_delete(_a_staging_directory)

        result = mcp_set_source_zip_finalize(
            upload_id="u1", expected_sha256=sha256, session_id=_SESSION
        )

        assert result["success"] is True, result
        assert sd.get_session_source_dir(_SESSION) == tmp_path / _SESSION / "source"

    def test_each_delivery_extracts_into_a_directory_of_its_own(
        self, tmp_path, monkeypatch
    ):
        """Fails on a fixed staging name: a second delivery would meet the first one's
        directory."""
        used: list = []
        real_rename = Path.rename

        def rename(path, target):
            if _a_staging_directory(path):
                used.append(path.name)
            return real_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)

        _finalize(tmp_path, _upload(tmp_path, _zip_bytes(**{"a.txt": "aa\n"})))
        _finalize(tmp_path, _upload(tmp_path, _zip_bytes(**{"b.txt": "bb\n"})))

        assert len(used) == 2
        assert used[0] != used[1]
        assert all(name.startswith(sd._STAGING_DIR_PREFIX) for name in used)

    def test_leftovers_that_can_be_deleted_are_deleted_at_the_start(
        self, tmp_path, logged
    ):
        """A planted leftover of each kind: a staging directory, the fixed name of an
        earlier version, a tree renamed aside, and a plain file with such a name. All of
        them are gone after the next delivery, and the delivery is unaffected."""
        session_dir = tmp_path / _SESSION
        for name in (
            sd._STAGING_DIR_PREFIX + "left-by-a-delivery",
            ".source.incoming",
            sd._REPLACED_DIR_PREFIX + "left-by-a-delivery",
            sd._TRASH_DIR_PREFIX + "left-by-a-delivery",
        ):
            self._leftover(tmp_path, name)
        (session_dir / (sd._REPLACED_DIR_PREFIX + "a-file")).write_text("x\n")
        keep = session_dir / "keep.txt"
        keep.write_text("not scratch\n")
        sha256 = _upload(tmp_path, _zip_bytes(**{"a.txt": "aa\n"}))

        target = _finalize(tmp_path, sha256)

        assert (target / "a.txt").read_text() == "aa\n"
        assert [
            p.name for p in session_dir.iterdir() if p.name.startswith(".source.")
        ] == []
        assert keep.exists()
        logged.warning.assert_not_called()

    def test_a_leftover_tree_that_cannot_be_deleted_is_logged_and_the_delivery_goes_on(
        self, tmp_path, refuse_to_delete, logged
    ):
        """A tree renamed aside by an earlier delivery whose delete left a remnant."""
        remnant = self._leftover(
            tmp_path, sd._REPLACED_DIR_PREFIX + "left-by-a-delivery"
        )
        sha256 = _upload(tmp_path, _zip_bytes(**{"a.txt": "aa\n"}))
        refuse_to_delete(_a_replaced_tree)

        target = _finalize(tmp_path, sha256)

        assert (target / "a.txt").read_text() == "aa\n"
        # The sweep deleted it under the trash name, so what it could not delete is
        # not left under the name a lost previous source is put back from.
        assert not remnant.exists()
        (left,) = [
            p
            for p in (tmp_path / _SESSION).iterdir()
            if p.name.startswith(sd._TRASH_DIR_PREFIX)
        ]
        assert (left / "stale.txt").exists()
        _warned_once_about(logged, left.name)


class TestAZipDeliveryThatEndsEarly:
    def test_staging_it_cannot_delete_is_logged_and_the_refusal_is_kept(
        self, tmp_path, refuse_to_delete, logged
    ):
        """Fails on a cleanup that discards the answer: the staging directory stays
        and nothing says so. The error that ended the delivery is the one raised."""
        sha256 = _upload(tmp_path, b"these bytes are not a zip archive")
        refuse_to_delete(_a_staging_directory)

        with pytest.raises(zipfile.BadZipFile):
            _finalize(tmp_path, sha256)

        # The staging directory that was refused deletion is still beside source/,
        # and the one warning names it.
        left = _scratch_beside_source(tmp_path / _SESSION)
        assert len(left) == 1 and left[0].startswith(sd._STAGING_DIR_PREFIX), left
        _warned_once_about(logged, left[0])


# ---------------------------------------------------------------------------
# The clone.
# ---------------------------------------------------------------------------


def _partial_clone_then(returncode: int, stderr: str = ""):
    """A ``_run_git`` double: ``git clone`` writes a file into the target, then
    answers ``returncode``. The checkout fails, and any other git command (the
    fetch) answers 0, so the checkout that fails is the one of ``FETCH_HEAD``."""

    def run_git(cmd, *, env):
        if "clone" in cmd:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "partial.txt").write_text("partial\n")
            return subprocess.CompletedProcess(cmd, returncode, "", stderr)
        if "checkout" in cmd:
            return subprocess.CompletedProcess(
                cmd, 1, "", "did not match any file(s) known to git"
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run_git


def _a_clone_that_works(cmd, *, env):
    """A ``_run_git`` double: ``git clone`` writes ``cloned.txt`` into the target."""
    if "clone" in cmd:
        target = Path(cmd[-1])
        target.mkdir(parents=True, exist_ok=True)
        (target / "cloned.txt").write_text("new delivery\n")
    return subprocess.CompletedProcess(cmd, 0, "", "")


def _the_previous_tree_stands(tmp_path: Path) -> Path:
    """The delivered tree and the record that names it, whole: a delivery that failed
    before its swap touched neither."""
    previous = tmp_path / _SESSION / "source"
    assert (previous / "old.txt").read_text() == "old\n"
    assert [p.name for p in previous.iterdir()] == ["old.txt"]
    assert sd.get_session_source_dir(_SESSION) == previous
    return previous


class TestAGitDeliveryThatCannotDeleteScratch:
    def test_the_previous_clone_it_cannot_delete_is_moved_aside_and_the_delivery_goes_on(
        self, tmp_path, monkeypatch, refuse_to_delete, logged
    ):
        """Fails on a pre-clean that deletes the previous clone in place and ends the
        delivery when that leaves a remnant: no later delivery to the session could
        succeed, and ``clear_source`` could not fix it. The previous clone is renamed
        aside first, the new clone goes into a fresh ``source/``, and the remnant stays
        under its hidden name, logged."""
        previous = _a_delivered_tree(tmp_path)
        monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)
        refuse_to_delete(_a_replaced_tree)

        target = _deliver_from_git(tmp_path)

        assert target == previous
        assert (target / "cloned.txt").read_text() == "new delivery\n"
        assert not (target / "old.txt").exists()
        assert sd.get_session_source_dir(_SESSION) == target
        remnants = _scratch_beside_source(tmp_path / _SESSION)
        assert len(remnants) == 1
        assert (tmp_path / _SESSION / remnants[0] / "old.txt").exists()
        _warned_once_about(logged, remnants[0])

    def test_a_previous_clone_that_cannot_be_renamed_ends_the_delivery_and_stays(
        self, tmp_path, monkeypatch
    ):
        """The one swap failure that ends a delivery before the new tree is in place:
        nothing moved, so the previous tree is intact at ``source/``, the record that
        names it is kept, and the clone's staging directory is deleted."""
        previous = _a_delivered_tree(tmp_path)
        monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)
        real_rename = Path.rename

        def rename(path, target):
            if path.name == "source":
                raise OSError(errno.EBUSY, "device or resource busy")
            return real_rename(path, target)

        monkeypatch.setattr(Path, "rename", rename)

        with pytest.raises(sd.SessionWorkspaceError, match="busy"):
            _deliver_from_git(tmp_path)

        assert (previous / "old.txt").read_text() == "old\n"
        assert sd.get_session_source_dir(_SESSION) == previous
        assert _scratch_beside_source(tmp_path / _SESSION) == []

    def test_leftovers_of_earlier_deliveries_are_deleted_before_a_clone(
        self, tmp_path, monkeypatch, logged
    ):
        """A planted leftover of each kind, as for a zip delivery."""
        session_dir = tmp_path / _SESSION
        for name in (
            sd._STAGING_DIR_PREFIX + "left-by-a-delivery",
            ".source.incoming",
            sd._REPLACED_DIR_PREFIX + "left-by-a-delivery",
            sd._TRASH_DIR_PREFIX + "left-by-a-delivery",
        ):
            (session_dir / name).mkdir(parents=True)
            (session_dir / name / "stale.txt").write_text("stale\n")
        monkeypatch.setattr(sd, "_run_git", _a_clone_that_works)

        target = _deliver_from_git(tmp_path)

        assert (target / "cloned.txt").exists()
        assert [
            p.name for p in session_dir.iterdir() if p.name.startswith(".source.")
        ] == []
        logged.warning.assert_not_called()

    def test_a_failed_clone_it_cannot_delete_is_reported_with_git_s_message(
        self, tmp_path, monkeypatch, refuse_to_delete, logged
    ):
        """Fails on a cleanup that replaces git's failure with a workspace error, or
        discards what stays: the clone's failure is reported as git's own
        (``GitCommandError``, ``git_clone_failed``), the partial tree stays and is
        logged once. The partial tree is the delivery's staging directory, so the
        previous tree and its record are untouched."""
        _a_delivered_tree(tmp_path)
        monkeypatch.setattr(
            sd, "_run_git", _partial_clone_then(128, "fatal: early EOF")
        )
        refuse_to_delete(_a_staging_directory)

        with pytest.raises(sd.GitCommandError) as raised:
            _deliver_from_git(tmp_path)

        assert raised.value.error_type == sd.GIT_CLONE_FAILED
        assert "git clone failed" in str(raised.value)
        assert "fatal: early EOF" in str(raised.value)
        _the_previous_tree_stands(tmp_path)
        remnants = _scratch_beside_source(tmp_path / _SESSION)
        assert len(remnants) == 1
        assert (tmp_path / _SESSION / remnants[0] / "partial.txt").exists()
        _warned_once_about(logged, remnants[0])

    def test_a_git_that_cannot_be_run_and_a_partial_clone_that_stays_is_reported(
        self, tmp_path, monkeypatch, refuse_to_delete, logged
    ):
        """Fails on the cleanup of a git that could not be started replacing the
        answer: the delivery is reported as a failed clone, the partial tree stays
        in the staging directory, logged once, and the previous tree is untouched."""
        _a_delivered_tree(tmp_path)

        def git_that_cannot_start(cmd, *, env):
            (Path(cmd[-1]) / "partial.txt").write_text("partial\n")
            raise OSError(errno.ENOEXEC, "exec format error")

        monkeypatch.setattr(sd, "_run_git", git_that_cannot_start)
        refuse_to_delete(_a_staging_directory)

        with pytest.raises(sd.GitCommandError) as raised:
            _deliver_from_git(tmp_path)

        assert raised.value.error_type == sd.GIT_CLONE_FAILED
        assert "could not be run" in str(raised.value)
        _the_previous_tree_stands(tmp_path)
        remnants = _scratch_beside_source(tmp_path / _SESSION)
        assert len(remnants) == 1
        _warned_once_about(logged, remnants[0])

    def test_a_failed_checkout_it_cannot_delete_is_reported(
        self, tmp_path, monkeypatch, refuse_to_delete, logged
    ):
        """Fails on a checkout-failure cleanup that replaces git's answer: a ref the
        remote does not have is ``git_checkout_failed`` whether or not the partial
        clone could be deleted."""
        _a_delivered_tree(tmp_path)
        monkeypatch.setattr(sd, "_run_git", _partial_clone_then(0))
        refuse_to_delete(_a_staging_directory)

        with pytest.raises(sd.GitCommandError) as raised:
            _deliver_from_git(tmp_path, ref="no-such-ref")

        assert raised.value.error_type == sd.GIT_CHECKOUT_FAILED
        assert "git checkout" in str(raised.value)
        _the_previous_tree_stands(tmp_path)
        remnants = _scratch_beside_source(tmp_path / _SESSION)
        assert len(remnants) == 1
        _warned_once_about(logged, remnants[0])

    def test_a_timed_out_clone_it_cannot_delete_is_logged_and_the_timeout_raised(
        self, tmp_path, monkeypatch, refuse_to_delete, logged
    ):
        """Fails on a timeout that discards what the cleanup could not delete, and on
        one that replaces the timeout with the cleanup's error: the staging directory
        stays and is logged, and the error that ended the delivery is the one raised."""
        _a_delivered_tree(tmp_path)

        def clone_that_times_out(url, ref, *, depth, target, env, git=None):
            (target / "partial.txt").write_text("partial\n")
            raise sd.GitTimeoutError("git clone did not finish and was stopped")

        monkeypatch.setattr(sd, "_clone", clone_that_times_out)
        refuse_to_delete(_a_staging_directory)

        with pytest.raises(sd.GitTimeoutError, match="did not finish"):
            _deliver_from_git(tmp_path)

        _the_previous_tree_stands(tmp_path)
        left = _scratch_beside_source(tmp_path / _SESSION)
        assert len(left) == 1 and left[0].startswith(sd._STAGING_DIR_PREFIX), left
        _warned_once_about(logged, left[0])

    def test_a_failed_clone_that_is_deleted_reports_git_s_failure(
        self, tmp_path, monkeypatch
    ):
        """Control: no double. The partial tree is gone and the error is git's."""
        monkeypatch.setattr(
            sd, "_run_git", _partial_clone_then(128, "fatal: early EOF")
        )

        with pytest.raises(sd.GitCommandError, match="git clone failed"):
            _deliver_from_git(tmp_path)

        assert not (tmp_path / _SESSION / "source").exists()
        assert _scratch_beside_source(tmp_path / _SESSION) == []


# ---------------------------------------------------------------------------
# The workspace.
# ---------------------------------------------------------------------------


def _a_workspace(tmp_path: Path) -> Path:
    tree = _a_delivered_tree(tmp_path)
    return tree.parent


class TestAWorkspaceThatCannotBeDeleted:
    def test_clear_source_forgets_the_source_and_logs_what_stays(
        self, tmp_path, refuse_to_delete, logged
    ):
        """Fails on a clear that reads nothing of the delete: the entries that stay
        on disk are not logged. ``clear_source`` is documented to leave them, so it
        does not raise."""
        workspace = _a_workspace(tmp_path)
        refuse_to_delete(_the_session_workspace_or_its_hidden_name)

        sd.clear_source(_SESSION, workspace_root=tmp_path)

        assert sd.get_session_source_dir(_SESSION) is None
        # The workspace was renamed aside, so what stays is under the hidden name
        # and the session's own path is free.
        assert not workspace.exists()
        assert list(tmp_path.glob(f".{_SESSION}.deleting-*"))
        _warned_once_about(logged, _SESSION)

    def test_clear_source_of_a_workspace_it_deleted_logs_nothing(
        self, tmp_path, logged
    ):
        """Control: no double."""
        workspace = _a_workspace(tmp_path)

        sd.clear_source(_SESSION, workspace_root=tmp_path)

        assert not workspace.exists()
        assert sd.get_session_source_dir(_SESSION) is None
        logged.warning.assert_not_called()

    def test_the_session_end_path_forgets_the_source_and_returns_false(
        self, tmp_path, refuse_to_delete
    ):
        """The session-end path must finish its other work, so it does not raise:
        it drops the record and returns whether the workspace is gone."""
        _a_workspace(tmp_path)
        refuse_to_delete(_the_session_workspace_or_its_hidden_name)

        gone = sd.remove_session_workspace(_SESSION, workspace_root=tmp_path)

        assert gone is False
        assert sd.get_session_source_dir(_SESSION) is None
        # What the delete could not remove is the hidden tree the workspace was
        # renamed to, and it is still on disk.
        assert len(list(tmp_path.glob(f".{_SESSION}.deleting-*"))) == 1

    def test_the_session_end_path_returns_true_for_a_workspace_it_deleted(
        self, tmp_path
    ):
        """No double: the answer is True and the workspace is gone."""
        workspace = _a_workspace(tmp_path)

        gone = sd.remove_session_workspace(_SESSION, workspace_root=tmp_path)

        assert gone is True
        assert not workspace.exists()
        assert sd.get_session_source_dir(_SESSION) is None
