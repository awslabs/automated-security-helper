# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tree that is refused its rename for a moment is renamed again.

Why this file exists
--------------------
A git clone or a zip extraction is built in a staging directory
(``.source.incoming-<id>``) and renamed onto ``source`` once it is complete, after
the previously delivered tree was renamed aside. On Windows a rename of a directory
can be refused while another program (a virus scanner, a file indexer, a background
``git gc``) still holds a handle on something inside it. That refusal is brief. A
delivery that renamed only once, and then deleted the finished staging directory,
failed with ``session_workspace_unavailable`` and made the client fetch the whole
tree again.

What the code does now
----------------------
``_swap_into_place`` renames each of the three trees it moves (the previous tree
aside, the staging directory into place, and the previous tree back when the
staging directory cannot take its place) up to ``_RENAME_ATTEMPTS`` times,
``_RENAME_WAIT_SECONDS`` apart. The staged tree is not touched between attempts, so
a refusal that passes is followed by a swap that needs no second clone or
extraction. When every attempt to move the previous tree aside is refused the
delivery ends with that tree, and the session's record of it, as they were. When
every attempt to move the staging directory into place is refused the previous tree
is put back, the failure is a ``SessionWorkspaceError`` that names the operating
system's reason, and the staging directory is deleted. When the previous tree cannot
be put back either, the error says so and names where it stays, and a warning is
logged. Git also runs with ``gc.auto=0`` and ``maintenance.auto=false`` (see
``test_set_source_git_host_allowlist.py``), so no background maintenance process is
started inside the staging directory.

How the tests work
------------------
``Path.rename`` is replaced by a double that refuses the rename of one of the trees
a number of times and then lets it through. ``time.sleep`` is replaced by a
recorder, so no test waits. ``_run_git`` is a double that writes ``cloned.txt``
into the clone target; no process starts. The module's logger is replaced by a mock
where a test reads what was logged.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

SESSION = "rename-retry"
URL = "https://example.com/foo.git"
GIT = "/opt/git/bin/git"


@pytest.fixture(autouse=True)
def delivery_state(monkeypatch) -> None:
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})


@pytest.fixture
def waits(monkeypatch) -> List[float]:
    """Every ``time.sleep`` the delivery makes, recorded and not waited for."""
    recorded: List[float] = []
    monkeypatch.setattr(time, "sleep", recorded.append)
    return recorded


def _refuse_the_staging_rename(monkeypatch, times: int) -> Dict[str, int]:
    """Refuse the rename of a staging directory ``times`` times, then allow it.

    Returns the counts: ``calls`` is how many renames of a staging directory were
    tried and ``refused`` how many of them were refused.
    """
    counts = {"calls": 0, "refused": 0}
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith(sd._STAGING_DIR_PREFIX):
            counts["calls"] += 1
            if counts["refused"] < times:
                counts["refused"] += 1
                raise PermissionError(errno.EACCES, "Access is denied")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)
    return counts


def _a_delivered_tree(tmp_path: Path) -> Path:
    """Record ``<session>/source`` holding ``old.txt`` as the delivered source."""
    previous = tmp_path / SESSION / "source"
    previous.mkdir(parents=True)
    (previous / "old.txt").write_text("old\n")
    sd._set_session_source_dir(SESSION, previous)
    return previous


def _a_clone_that_works(clones: List[List[str]]) -> Any:
    """A ``_run_git`` double; ``clones`` collects each clone command it is given."""

    def run_git(cmd, *, env):
        if "clone" in cmd:
            clones.append(list(cmd))
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "cloned.txt").write_text("new delivery\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    return run_git


def _deliver_from_git(tmp_path: Path) -> Path:
    return sd.set_source_git(url=URL, workspace_root=tmp_path, session_id=SESSION)


def _upload_a_zip(tmp_path: Path) -> str:
    """Send a one-file zip as a single chunk; return the sha256 to finalize with."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("new.txt", "new\n")
    payload = buffer.getvalue()
    sd.set_source_zip_chunk(
        upload_id="u1",
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=tmp_path,
        session_id=SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _finalize(tmp_path: Path, sha256: str) -> Path:
    return sd.set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=sha256,
        workspace_root=tmp_path,
        session_id=SESSION,
    )


def _scratch_beside_source(tmp_path: Path) -> List[str]:
    return sorted(
        p.name for p in (tmp_path / SESSION).iterdir() if p.name.startswith(".source.")
    )


def test_a_clone_refused_its_rename_twice_is_delivered(
    tmp_path, monkeypatch, waits
) -> None:
    """Fails on a swap that renames once: the second delivery ends with
    ``session_workspace_unavailable`` and the finished clone is deleted."""
    previous = _a_delivered_tree(tmp_path)
    clones: List[List[str]] = []
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works(clones))
    counts = _refuse_the_staging_rename(monkeypatch, times=2)

    target = _deliver_from_git(tmp_path)

    assert target == previous
    assert (target / "cloned.txt").read_text() == "new delivery\n"
    assert not (target / "old.txt").exists()
    assert sd.get_session_source_dir(SESSION) == target
    assert counts == {"calls": 3, "refused": 2}, counts
    assert len(waits) == 2 and all(0 < wait <= 1.0 for wait in waits), waits
    assert _scratch_beside_source(tmp_path) == []


def test_the_clone_is_not_made_again_when_the_rename_is_retried(
    tmp_path, monkeypatch, waits
) -> None:
    """Fails on a retry that starts the delivery over: git would clone once for each
    refused rename. The staged tree is kept between attempts."""
    _a_delivered_tree(tmp_path)
    clones: List[List[str]] = []
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works(clones))
    _refuse_the_staging_rename(monkeypatch, times=2)

    _deliver_from_git(tmp_path)

    assert len(clones) == 1, clones


def test_an_extraction_refused_its_rename_twice_is_delivered(
    tmp_path, waits, monkeypatch
) -> None:
    """The zip channel shares the swap: a staged extraction is renamed again too."""
    previous = _a_delivered_tree(tmp_path)
    sha256 = _upload_a_zip(tmp_path)
    counts = _refuse_the_staging_rename(monkeypatch, times=2)

    target = _finalize(tmp_path, sha256)

    assert target == previous
    assert (target / "new.txt").read_text() == "new\n"
    assert not (target / "old.txt").exists()
    assert counts == {"calls": 3, "refused": 2}, counts
    assert _scratch_beside_source(tmp_path) == []


def test_a_rename_that_is_always_refused_still_ends_the_delivery_with_the_reason(
    tmp_path, monkeypatch, waits
) -> None:
    """Fails on a retry that never ends or never reports: the delivery ends after
    the bounded number of attempts with the operating system's reason, the previous
    tree is put back and recorded, and the staging directory is deleted."""
    previous = _a_delivered_tree(tmp_path)
    clones: List[List[str]] = []
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works(clones))
    counts = _refuse_the_staging_rename(monkeypatch, times=10**6)

    with pytest.raises(sd.SessionWorkspaceError, match="Access is denied"):
        _deliver_from_git(tmp_path)

    assert counts["calls"] == sd._RENAME_ATTEMPTS, counts
    assert counts["calls"] > 2, "a single refusal must not end the delivery"
    assert len(waits) == sd._RENAME_ATTEMPTS - 1, waits
    assert (previous / "old.txt").read_text() == "old\n"
    assert [p.name for p in previous.iterdir()] == ["old.txt"]
    assert sd.get_session_source_dir(SESSION) == previous
    assert _scratch_beside_source(tmp_path) == []
    assert len(clones) == 1, clones


def _a_refusal_of_the_staging_rename(monkeypatch, error: OSError) -> Dict[str, int]:
    """Refuse every rename of a staging directory with ``error``; count the calls."""
    counts = {"calls": 0}
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith(sd._STAGING_DIR_PREFIX):
            counts["calls"] += 1
            raise error
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)
    return counts


def _a_windows_error(number: int) -> OSError:
    """What Windows raises for a sharing violation (32) or an access denial (5): an
    ``OSError`` that carries ``winerror``, whichever errno it was mapped to."""
    error = OSError(errno.EIO, "a Windows refusal")
    error.winerror = number  # type: ignore[attr-defined]
    return error


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(PermissionError(errno.EACCES, "Access is denied"), id="eacces"),
        pytest.param(OSError(errno.EBUSY, "Device or resource busy"), id="ebusy"),
        pytest.param(_a_windows_error(5), id="winerror-5"),
        pytest.param(_a_windows_error(32), id="winerror-32"),
    ],
)
def test_a_refusal_that_a_wait_can_clear_is_retried(
    tmp_path, monkeypatch, waits, error
) -> None:
    """A program that holds a handle inside the tree (access denied, a sharing
    violation, a busy device) lets go within a fraction of a second: the rename is
    tried the full number of times."""
    _a_delivered_tree(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works([]))
    counts = _a_refusal_of_the_staging_rename(monkeypatch, error)

    with pytest.raises(sd.SessionWorkspaceError):
        _deliver_from_git(tmp_path)

    assert counts["calls"] == sd._RENAME_ATTEMPTS, counts
    assert len(waits) == sd._RENAME_ATTEMPTS - 1, waits


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(FileNotFoundError(errno.ENOENT, "No such file"), id="enoent"),
        pytest.param(FileExistsError(errno.EEXIST, "File exists"), id="eexist"),
        pytest.param(OSError(errno.ENOTEMPTY, "Directory not empty"), id="enotempty"),
        pytest.param(OSError(errno.EXDEV, "Invalid cross-device link"), id="exdev"),
        pytest.param(OSError(errno.EROFS, "Read-only file system"), id="erofs"),
        pytest.param(OSError(errno.ENOSPC, "No space left on device"), id="enospc"),
    ],
)
def test_a_refusal_that_a_wait_cannot_clear_is_not_retried(
    tmp_path, monkeypatch, waits, error
) -> None:
    """Fails on a retry of every ``OSError``: the staging directory is gone, something
    took the place of ``source``, the file system is read-only or full. Waiting does
    not change any of these, and the delivery runs synchronously inside the server's
    event loop, so each wait stalls every other call. One attempt, no wait, and the
    previous tree is put back as before."""
    previous = _a_delivered_tree(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works([]))
    counts = _a_refusal_of_the_staging_rename(monkeypatch, error)

    with pytest.raises(sd.SessionWorkspaceError):
        _deliver_from_git(tmp_path)

    assert counts["calls"] == 1, counts
    assert waits == [], waits
    assert (previous / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == previous


def test_the_wait_between_attempts_is_short() -> None:
    """The retry runs inside a delivery that holds the session, in the server's event
    loop: the waits of one rename together stay under a second, as the comment on
    ``_RENAME_ATTEMPTS`` promises."""
    total = sd._RENAME_WAIT_SECONDS * (sd._RENAME_ATTEMPTS - 1)

    assert 0 < sd._RENAME_WAIT_SECONDS <= 0.5
    assert total < 1.0, total


def test_control_a_rename_that_is_not_refused_waits_for_nothing(
    tmp_path, monkeypatch, waits
) -> None:
    """Control: no double on the rename. The first delivery of a session is renamed
    at once, and the recorded waits are empty."""
    clones: List[List[str]] = []
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works(clones))

    target = _deliver_from_git(tmp_path)

    assert (target / "cloned.txt").read_text() == "new delivery\n"
    assert waits == []
    assert _scratch_beside_source(tmp_path) == []


@pytest.fixture
def logged(monkeypatch) -> MagicMock:
    """The module's logger, replaced, so a test can read what was logged."""
    logger = MagicMock()
    monkeypatch.setattr(sd, "_logger", logger)
    return logger


def _refuse_renames(monkeypatch, **times: int) -> Dict[str, Dict[str, int]]:
    """Refuse the rename of the named trees ``times`` times each, then allow it.

    The keys are ``aside`` (the previous tree to a ``.source.replaced-`` name),
    ``into_place`` (the staging directory onto ``source``) and ``back`` (the
    ``.source.replaced-`` name back onto ``source``). Returns, for each of the three,
    how many renames were ``calls`` and how many of them were ``refused``.
    """
    counts = {
        kind: {"calls": 0, "refused": 0} for kind in ("aside", "into_place", "back")
    }
    real_rename = Path.rename

    def kind_of(path: Path, target: Path) -> str:
        if path.name == "source" and target.name.startswith(sd._REPLACED_DIR_PREFIX):
            return "aside"
        if path.name.startswith(sd._STAGING_DIR_PREFIX):
            return "into_place"
        if path.name.startswith(sd._REPLACED_DIR_PREFIX) and target.name == "source":
            return "back"
        return "other"

    def rename(path, target):
        kind = kind_of(path, Path(target))
        if kind != "other":
            counts[kind]["calls"] += 1
            if counts[kind]["refused"] < times.get(kind, 0):
                counts[kind]["refused"] += 1
                raise PermissionError(errno.EACCES, "Access is denied")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)
    return counts


def test_a_previous_tree_refused_its_rename_aside_twice_is_replaced(
    tmp_path, monkeypatch, waits
) -> None:
    """Fails on a swap that tries the previous tree's rename once: the finished
    clone is deleted and the client fetches the whole tree again, for a refusal that
    passes within a fraction of a second."""
    previous = _a_delivered_tree(tmp_path)
    clones: List[List[str]] = []
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works(clones))
    counts = _refuse_renames(monkeypatch, aside=2)

    target = _deliver_from_git(tmp_path)

    assert target == previous
    assert (target / "cloned.txt").read_text() == "new delivery\n"
    assert not (target / "old.txt").exists()
    assert counts["aside"] == {"calls": 3, "refused": 2}, counts
    assert len(waits) == 2, waits
    assert len(clones) == 1, clones
    assert _scratch_beside_source(tmp_path) == []


def test_a_previous_tree_that_is_always_refused_ends_the_delivery_and_stays(
    tmp_path, monkeypatch, waits
) -> None:
    """Fails on a retry that never ends or never reports: the delivery ends after the
    bounded number of attempts with the operating system's reason. The previous tree
    and its record are as they were, the staging directory is deleted and the uploaded
    zip is kept for the same finalize to be sent again."""
    previous = _a_delivered_tree(tmp_path)
    sha256 = _upload_a_zip(tmp_path)
    counts = _refuse_renames(monkeypatch, aside=10**6)

    with pytest.raises(sd.SessionWorkspaceError, match="Access is denied"):
        _finalize(tmp_path, sha256)

    assert counts["aside"]["calls"] == sd._RENAME_ATTEMPTS, counts
    assert len(waits) == sd._RENAME_ATTEMPTS - 1, waits
    assert counts["into_place"]["calls"] == 0, "the staged tree was never renamed"
    assert [p.name for p in previous.iterdir()] == ["old.txt"]
    assert sd.get_session_source_dir(SESSION) == previous
    assert _scratch_beside_source(tmp_path) == []
    assert sd._final_zip_path(tmp_path / SESSION, "u1").exists()


def test_a_previous_tree_refused_its_return_twice_is_put_back(
    tmp_path, monkeypatch, waits, logged
) -> None:
    """Fails on a put-back that is tried once: a refusal that would have passed
    leaves no tree at ``source`` and a record that names a path nothing created."""
    previous = _a_delivered_tree(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works([]))
    counts = _refuse_renames(monkeypatch, into_place=10**6, back=2)

    with pytest.raises(sd.SessionWorkspaceError) as failed:
        _deliver_from_git(tmp_path)

    assert counts["back"] == {"calls": 3, "refused": 2}, counts
    assert (previous / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == previous
    assert "could not be restored" not in str(failed.value), failed.value
    logged.warning.assert_not_called()
    assert _scratch_beside_source(tmp_path) == []


def test_a_previous_tree_that_cannot_be_put_back_is_named_in_the_error_and_the_log(
    tmp_path, monkeypatch, waits, logged
) -> None:
    """Fails on a put-back failure that is swallowed: the error named only the staged
    rename, and nothing said where the previous source went. It stays under its
    hidden name for the next delivery to put back, the record still names ``source``,
    and the error and one warning name the hidden path."""
    previous = _a_delivered_tree(tmp_path)
    monkeypatch.setattr(sd, "_run_git", _a_clone_that_works([]))
    counts = _refuse_renames(monkeypatch, into_place=10**6, back=10**6)

    with pytest.raises(sd.SessionWorkspaceError) as failed:
        _deliver_from_git(tmp_path)

    session_dir = tmp_path / SESSION
    hidden = sorted(
        p for p in session_dir.iterdir() if p.name.startswith(sd._REPLACED_DIR_PREFIX)
    )
    assert counts["back"]["calls"] == sd._RENAME_ATTEMPTS, counts
    assert len(hidden) == 1, hidden
    assert (hidden[0] / "old.txt").read_text() == "old\n"
    assert not previous.exists()
    assert sd.get_session_source_dir(SESSION) == previous
    message = str(failed.value)
    assert "Access is denied" in message, message
    assert "the previous source could not be restored" in message, message
    assert hidden[0].name in message, message
    assert logged.warning.call_count == 1, logged.warning.call_args_list
    assert hidden[0].name in str(logged.warning.call_args), logged.warning.call_args
    assert [
        p.name
        for p in session_dir.iterdir()
        if p.name.startswith(sd._STAGING_DIR_PREFIX)
    ] == []
