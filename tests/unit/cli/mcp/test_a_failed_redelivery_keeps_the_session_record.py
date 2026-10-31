# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A re-delivery that fails never sends a later scan to the server's working directory.

Why this file exists
--------------------
``run_ash_scan`` with no ``source_dir`` scans the session's recorded source. With
no record it scans the server's working directory on stdio (the documented default
for a local client, where it is the tree the developer means) and answers
``session_source_mismatch`` on a network transport, which names the wrong cause. A
record whose directory is gone is answered ``delivered_source_missing``: re-deliver.

A delivery that failed used to drop the record in three places: the zip swap when
neither tree could be put in place, the pre-clean of a staging directory, and the
pre-clean of the previous clone. A stdio client whose re-delivery failed and which
then scanned without a ``source_dir`` was scanned the server's working directory:
a scan of the wrong tree that reads as a result.

What the code does now
----------------------
The record stays. A re-delivery builds the new tree beside the old one (a git clone
and a zip extraction both go into a staging directory) and swaps it in at the end, so
a delivery that fails before the swap, or whose swap fails before the previous tree
moved, leaves the previous tree and the record that names it in place, and the scan
reads the previous tree. Only a swap that cannot complete (the previous tree was
moved aside, the new tree cannot take its path, and the previous tree cannot be moved
back) leaves the record naming a path with nothing at it. The scan is then refused
with ``delivered_source_missing``, and is pointed neither at half a tree nor at the
server's working directory. Nothing is ever deleted where it stands.

How the tests work
-------------------
``_run_git`` is a double (no process starts), and the renames that fail are doubles
on ``Path.rename``. The scan side is ``_resolve_omitted_source_dir``, the
function ``run_ash_scan`` calls for an omitted ``source_dir``, once for the stdio
session and once for a session id a network client would carry. Each test starts
with a first delivery that succeeded, so the failure is a re-delivery.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_server import _resolve_omitted_source_dir
from automated_security_helper.cli.mcp_tools import (
    mcp_set_source_git,
    mcp_set_source_zip_finalize,
)

pytestmark = pytest.mark.unit

HOST = "git.example.invalid"
URL = f"https://{HOST}/team/repo.git"
GIT = "/opt/git/bin/git"

#: The stdio session, and the id a network client carries.
SESSIONS = [
    pytest.param(DEFAULT_SESSION_ID, id="stdio"),
    pytest.param("http-session-a", id="network"),
]


@pytest.fixture(autouse=True)
def delivery(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", HOST)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sd, "_git_executable", lambda: GIT)
    # A refused rename is tried again after a short wait; the tests do not wait for
    # it. Only that wait is removed: stubbing time.sleep would stop it for every thread.
    monkeypatch.setattr(sd, "_RENAME_WAIT_SECONDS", 0)
    # The record of a delivered tree is kept per process; each test starts empty.
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    yield workspace
    reset_default_registry_for_tests()


#: The commit id the double's ``rev-parse`` answers: a ref-less clone is refused
#: unless its HEAD names a commit, so the double names one.
HEAD_COMMIT = "f" * 40


def _git_that_fails_at(step: str):
    """A ``_run_git`` double: every step works, except ``step``, which fails.

    The delivery runs four git commands: ``clone``, then for a delivery with no
    ref a ``rev-parse`` that must name a commit (an empty clone is refused), and
    for one with a ref a ``fetch`` and a ``checkout``. The double answers each
    by the command word in its argv.
    """

    def run_git(cmd, *, env):
        name = next(
            part for part in cmd if part in ("clone", "fetch", "checkout", "rev-parse")
        )
        if name == "clone":
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            (target / "cloned.txt").write_text("from git\n")
        if name != step:
            # The step the double is told to fail is read before any answer:
            # an earlier shape answered rev-parse with a commit first, so
            # ``_git_that_fails_at("rev-parse")`` never failed and the
            # ref-less clone's refusal was never driven as a failed delivery.
            if name == "rev-parse":
                return subprocess.CompletedProcess(cmd, 0, HEAD_COMMIT + "\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if name == "fetch":
            # A fetch that git fails is tolerated; one that git cannot be started
            # for fails the delivery.
            raise OSError(errno.ENOEXEC, "exec format error")
        return subprocess.CompletedProcess(cmd, 128, "", "fatal: early EOF")

    return run_git


def _zip_payload(**files: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def _deliver_zip(session_id: str, upload_id: str, **files: str) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_set_source_zip_chunk

    payload = _zip_payload(**files)
    chunk = mcp_set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        session_id=session_id,
    )
    assert chunk["success"] is True, chunk
    return mcp_set_source_zip_finalize(
        upload_id=upload_id,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        session_id=session_id,
    )


def _refused_as_missing(session_id: str) -> None:
    resolution = _resolve_omitted_source_dir(session_id)

    assert resolution.source_dir is None, "the scan would read " + str(
        resolution.source_dir
    )
    assert resolution.error is not None
    assert resolution.error["error_type"] == "delivered_source_missing", (
        resolution.error
    )
    assert resolution.error["success"] is False


@pytest.mark.parametrize("session_id", SESSIONS)
@pytest.mark.parametrize("step", ["clone", "fetch", "checkout"])
def test_a_git_redelivery_that_fails_leaves_the_scan_on_the_previous_tree(
    monkeypatch, session_id, step
) -> None:
    """Fails on a record dropped by the failed delivery (stdio then scans the
    server's working directory, and a network session is told its id is unstable),
    and on a previous tree deleted before the clone worked (the scan is then refused
    as missing, and the client's clone is gone for a mistyped ref)."""
    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("none"))
    first = mcp_set_source_git(url=URL, ref="release", session_id=session_id)
    assert first["success"] is True, first
    delivered = _resolve_omitted_source_dir(session_id)
    assert delivered.error is None and delivered.source_dir == first["source_dir"]

    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at(step))
    second = mcp_set_source_git(url=URL, ref="release", session_id=session_id)

    assert second["success"] is False, second
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None, resolution.error
    assert resolution.source_dir == first["source_dir"]
    assert (Path(resolution.source_dir) / "cloned.txt").read_text() == "from git\n"


@pytest.mark.parametrize("session_id", SESSIONS)
def test_a_ref_less_redelivery_whose_clone_has_no_commit_keeps_the_previous_tree(
    monkeypatch, session_id
) -> None:
    """A clone with no ref whose HEAD names no commit is refused, and the refusal
    is a failed delivery like the others: the previous tree and its record stay.
    Red before the double read ``step`` before answering rev-parse: the second
    delivery then succeeded with an empty tree."""
    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("none"))
    first = mcp_set_source_git(url=URL, session_id=session_id)
    assert first["success"] is True, first

    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("rev-parse"))
    second = mcp_set_source_git(url=URL, session_id=session_id)

    assert second["success"] is False, second
    assert "no commit" in second["error"], second
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None, resolution.error
    assert resolution.source_dir == first["source_dir"]
    assert (Path(resolution.source_dir) / "cloned.txt").read_text() == "from git\n"


@pytest.mark.parametrize("session_id", SESSIONS)
def test_a_git_redelivery_whose_partial_clone_cannot_be_deleted_keeps_the_previous_tree(
    monkeypatch, session_id
) -> None:
    """Fails on a previous tree deleted before the clone worked: the failed clone's
    staging directory resists deletion, the tool answers with git's own
    ``git_clone_failed`` and not a workspace error, and the scan still reads the
    previous tree. The leftover is scratch that the next delivery deletes."""
    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("none"))
    first = mcp_set_source_git(url=URL, session_id=session_id)
    assert first["success"] is True, first
    real_remove_tree = sd._remove_tree

    def remove_tree(path):
        staging = Path(path).name.startswith(sd._STAGING_DIR_PREFIX)
        return False if staging else real_remove_tree(path)

    monkeypatch.setattr(sd, "_remove_tree", remove_tree)
    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("clone"))

    second = mcp_set_source_git(url=URL, session_id=session_id)

    assert second["success"] is False, second
    assert second["error_type"] == "git_clone_failed", second
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None, resolution.error
    assert resolution.source_dir == first["source_dir"]


@pytest.mark.parametrize("session_id", SESSIONS)
def test_a_git_swap_that_cannot_complete_is_refused_as_missing(
    monkeypatch, session_id
) -> None:
    """Neither tree can be put in place: the previous one was moved aside, the clone
    cannot take its path, and the previous one cannot be moved back. On Windows an
    open handle under a tree (an indexer, a virus scanner) can block renames. The
    record stays and names a path with nothing at it, so a stdio scan does not read the
    server's working directory, and a later delivery replaces the record."""
    sd._set_session_source_dir("someone-else", Path("elsewhere") / "source")
    monkeypatch.setattr(sd, "_run_git", _git_that_fails_at("none"))
    assert mcp_set_source_git(url=URL, session_id=session_id)["success"] is True
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith((sd._STAGING_DIR_PREFIX, sd._REPLACED_DIR_PREFIX)):
            raise OSError(errno.EBUSY, "device or resource busy")
        return real_rename(path, target)

    # The first call (source -> replaced) goes through; the two that follow fail.
    monkeypatch.setattr(Path, "rename", rename)

    second = mcp_set_source_git(url=URL, session_id=session_id)

    assert second["success"] is False, second
    assert second["error_type"] == "session_workspace_unavailable", second
    recorded = sd.get_session_source_dir(session_id)
    assert recorded is not None, "the failed delivery dropped the session's record"
    assert not recorded.exists(), f"the record names a path that exists: {recorded}"
    _refused_as_missing(session_id)

    # The next delivery works from what the failed one left, and replaces the record.
    monkeypatch.setattr(Path, "rename", real_rename)
    third = mcp_set_source_git(url=URL, session_id=session_id)
    assert third["success"] is True, third
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None
    assert resolution.source_dir == third["source_dir"]


@pytest.mark.parametrize("session_id", SESSIONS)
def test_a_zip_swap_that_cannot_complete_is_refused_as_missing(
    monkeypatch, session_id
) -> None:
    """Neither tree can be put in place: the previous one was moved aside, the staged
    one cannot take its path, and the previous one cannot be moved back. The record
    stays and names a path with nothing at it, whether or not another session holds
    source (a network session was then told its id was unstable, which is the wrong
    cause)."""
    sd._set_session_source_dir("someone-else", Path("elsewhere") / "source")
    first = _deliver_zip(session_id, "u1", **{"old.txt": "old\n"})
    assert first["success"] is True, first
    real_rename = Path.rename

    def rename(path, target):
        if path.name.startswith((sd._STAGING_DIR_PREFIX, sd._REPLACED_DIR_PREFIX)):
            raise OSError(errno.EBUSY, "device or resource busy")
        return real_rename(path, target)

    # The first call (source -> replaced) goes through; the two that follow fail.
    monkeypatch.setattr(Path, "rename", rename)

    second = _deliver_zip(session_id, "u2", **{"new.txt": "new\n"})

    assert second["success"] is False, second
    assert second["error_type"] == "session_workspace_unavailable", second
    _refused_as_missing(session_id)


@pytest.mark.parametrize("session_id", SESSIONS)
def test_a_zip_redelivery_that_fails_before_the_swap_keeps_the_previous_tree(
    session_id,
) -> None:
    """Control: an archive that is refused leaves the previous tree, and the record
    that names it, in place."""
    first = _deliver_zip(session_id, "u1", **{"old.txt": "old\n"})
    assert first["success"] is True, first

    second = mcp_set_source_zip_finalize(
        upload_id="u1", expected_sha256="0" * 64, session_id=session_id
    )

    assert second["success"] is False, second
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None
    assert (Path(resolution.source_dir) / "old.txt").read_text() == "old\n"


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(PermissionError(errno.EACCES, "permission denied"), id="eacces"),
        pytest.param(OSError(errno.EBUSY, "device or resource busy"), id="ebusy"),
        pytest.param(OSError(errno.ENOTEMPTY, "directory not empty"), id="enotempty"),
        pytest.param(FileNotFoundError(errno.ENOENT, "no such file"), id="enoent"),
    ],
)
@pytest.mark.parametrize("move", ["staged-into-place", "previous-aside"])
def test_a_swap_failure_is_one_stable_error_type(monkeypatch, failure, move) -> None:
    """The swap raised whatever OSError the file system chose: ``PermissionError`` was
    answered with its class name, ``OSError`` too, and a ``FileNotFoundError`` with no
    ``error_type`` at all, as if the archive were missing. A client branches on one
    value."""
    session_id = DEFAULT_SESSION_ID
    assert _deliver_zip(session_id, "u1", **{"old.txt": "old\n"})["success"] is True
    real_rename = Path.rename

    def rename(path, target):
        failing = (
            path.name.startswith(sd._STAGING_DIR_PREFIX)
            if move == "staged-into-place"
            else path.name == "source"
        )
        if failing:
            raise failure
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)

    result = _deliver_zip(session_id, "u2", **{"new.txt": "new\n"})

    assert result["success"] is False, result
    assert result["error_type"] == "session_workspace_unavailable", result
    # Whichever move failed, the previous tree is where it was and the record names
    # it: the scan reads it, not the server's working directory and not half a tree.
    resolution = _resolve_omitted_source_dir(session_id)
    assert resolution.error is None
    assert (Path(resolution.source_dir) / "old.txt").read_text() == "old\n"
    assert not (Path(resolution.source_dir) / "new.txt").exists()
