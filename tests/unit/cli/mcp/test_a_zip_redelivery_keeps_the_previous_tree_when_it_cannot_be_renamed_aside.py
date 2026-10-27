# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A zip re-delivery whose previous tree cannot be renamed aside keeps that tree.

What the code does, by path
---------------------------
``set_source_zip_finalize`` extracts into a staging directory and swaps it in: the
previous tree is renamed to a ``.source.replaced-<hex>`` sibling, the staged tree
is renamed to ``source``, and the old tree is deleted.

On Windows a directory with any file held open (an antivirus scanner, an indexer)
refuses the rename for as long as the hold lasts. The swap tries the rename of the
previous tree up to ``_RENAME_ATTEMPTS`` times, ``_RENAME_WAIT_SECONDS`` apart
(``test_a_delivery_retries_the_rename_into_place.py``), because a hold is often let
go within a fraction of a second and a finished extraction is worth that wait. If
the file system refuses every attempt, the delivery ends with
``SessionWorkspaceError``, which the tool reports as
``session_workspace_unavailable``. Nothing is deleted in place: the previous tree
stays at ``source/`` whole, the session's recorded source still names it, the
staging directory is deleted, and the uploaded zip stays on disk, so the same
finalize can be sent again once the hold is gone.

One thing is deliberately not done: the previous tree is not deleted where it
stands. Whatever blocks a rename of a directory usually blocks deleting it too, so
that fallback ended in a half-deleted tree, the new tree thrown away and a record
naming a path nothing created.

A plain ``OSError`` from the swap (the staged tree cannot be renamed into place)
is reported by ``mcp_set_source_zip_finalize`` with ``error_type``
``session_workspace_unavailable``, the stable type of the delivery tools for a
workspace they cannot use, and not left to escape the tool. A ``FileNotFoundError``
from the extraction itself (a file that vanished under it) is not the client's
mistake and not a workspace failure either: it leaves the tool for the server's own
handler, which answers with its class name. Only an upload that never received its
last chunk (``UploadNotFoundError``) is answered with an ``error`` and no
``error_type``, because that one is the client's to fix.

How the tests work
------------------
``Path.rename`` is replaced by a double that refuses the renames a test names and
calls the real one for the rest. Every test is DISARMED: the workspace root is the
test's own tmp_path, and nothing runs git, a scanner or the network.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import time
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import mcp_set_source_zip_finalize

SESSION = "zip-swap"


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    return root


@pytest.fixture(autouse=True)
def slept(monkeypatch) -> list:
    """Every ``time.sleep`` the delivery makes, recorded and not waited for.

    Automatic: a test that refuses a rename without asking for it would wait the
    full 0.8 seconds of the retries for real.
    """
    waits: list = []
    monkeypatch.setattr(time, "sleep", waits.append)
    return waits


def _zip(**files: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def _upload(payload: bytes, upload_id: str) -> str:
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        session_id=SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _deliver(files: dict, upload_id: str) -> Path:
    payload = _zip(**files)
    return sd.set_source_zip_finalize(
        upload_id=upload_id,
        expected_sha256=_upload(payload, upload_id),
        session_id=SESSION,
    )


def _refuse_renames(monkeypatch, refused) -> list:
    """Make ``Path.rename`` raise PermissionError for the (source, target) pairs
    ``refused`` accepts, and record every refusal."""
    real = Path.rename
    seen: list = []

    def rename(self: Path, target):
        if refused(self, Path(target)):
            seen.append((self.name, Path(target).name))
            raise PermissionError(13, "a planted refusal of the rename")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    return seen


def _the_previous_tree_to_a_replaced_name(source: Path, target: Path) -> bool:
    return source.name == "source" and target.name.startswith(".source.replaced-")


def _scratch_beside_source(session_dir: Path) -> list:
    return sorted(
        p.name for p in session_dir.iterdir() if p.name.startswith(".source.")
    )


def test_a_previous_tree_that_cannot_be_renamed_ends_the_delivery_and_stays(
    workspace, monkeypatch, slept
) -> None:
    first = _deliver({"old.txt": "old\n"}, "u1")
    refusals = _refuse_renames(monkeypatch, _the_previous_tree_to_a_replaced_name)

    result = mcp_set_source_zip_finalize(
        upload_id="u2",
        expected_sha256=_upload(_zip(**{"new.txt": "new\n"}), "u2"),
        session_id=SESSION,
    )

    assert result["success"] is False, result
    assert result["error_type"] == sd.SESSION_WORKSPACE_UNAVAILABLE, result
    # The previous tree is whole, the record names it, and the new tree is not in it.
    assert (first / "old.txt").read_text() == "old\n"
    assert not (first / "new.txt").exists()
    assert sd.get_session_source_dir(SESSION) == first
    # Nothing was deleted in place and nothing was left beside source/.
    assert _scratch_beside_source(first.parent) == []
    # Every attempt was made, with a short wait between them and none after the last.
    assert len(refusals) == sd._RENAME_ATTEMPTS, refusals
    assert len(slept) == sd._RENAME_ATTEMPTS - 1, slept


def test_the_same_finalize_can_be_sent_again_once_the_hold_is_gone(
    workspace, monkeypatch, slept
) -> None:
    """The uploaded zip stays on disk after the refusal, so the client's retry works."""
    first = _deliver({"old.txt": "old\n"}, "u1")
    held = {"yes": True}
    _refuse_renames(
        monkeypatch,
        lambda source, target: (
            held["yes"] and _the_previous_tree_to_a_replaced_name(source, target)
        ),
    )
    sha256 = _upload(_zip(**{"new.txt": "new\n"}), "u2")

    refused = mcp_set_source_zip_finalize(
        upload_id="u2", expected_sha256=sha256, session_id=SESSION
    )
    held["yes"] = False
    delivered = mcp_set_source_zip_finalize(
        upload_id="u2", expected_sha256=sha256, session_id=SESSION
    )

    assert refused["success"] is False, refused
    assert delivered["success"] is True, delivered
    assert (first / "new.txt").read_text() == "new\n"
    assert not (first / "old.txt").exists()
    assert sd.get_session_source_dir(SESSION) == first
    assert _scratch_beside_source(first.parent) == []


def test_a_plain_oserror_from_the_swap_is_a_stable_error_type(
    workspace, monkeypatch
) -> None:
    """The staged tree cannot be renamed into place (a first delivery, so there
    is no previous tree): the OSError is reported, not raised through the tool."""
    _refuse_renames(
        monkeypatch,
        lambda source, target: (
            source.name.startswith(sd._STAGING_DIR_PREFIX) and target.name == "source"
        ),
    )

    result = mcp_set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=_upload(_zip(**{"new.txt": "new\n"}), "u1"),
        session_id=SESSION,
    )

    assert result["success"] is False, result
    assert result["error_type"] == sd.SESSION_WORKSPACE_UNAVAILABLE, result
    assert _scratch_beside_source(workspace / SESSION) == []


def test_a_staged_tree_that_cannot_be_moved_into_place_puts_the_previous_tree_back(
    workspace, monkeypatch
) -> None:
    first = _deliver({"old.txt": "old\n"}, "u1")
    _refuse_renames(
        monkeypatch,
        lambda source, target: (
            source.name.startswith(sd._STAGING_DIR_PREFIX) and target.name == "source"
        ),
    )

    result = mcp_set_source_zip_finalize(
        upload_id="u2",
        expected_sha256=_upload(_zip(**{"new.txt": "new\n"}), "u2"),
        session_id=SESSION,
    )

    assert result["success"] is False, result
    assert result["error_type"] == sd.SESSION_WORKSPACE_UNAVAILABLE, result
    assert (first / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == first
    assert _scratch_beside_source(first.parent) == []


def test_a_redelivery_with_a_working_rename_leaves_no_replaced_directory(
    workspace, slept
) -> None:
    """Control: no double. The new tree is in place and nothing is left aside."""
    _deliver({"old.txt": "old\n"}, "u1")

    second = _deliver({"new.txt": "new\n"}, "u2")

    assert (second / "new.txt").is_file()
    assert not (second / "old.txt").exists()
    assert _scratch_beside_source(second.parent) == []
    assert slept == [], slept


def test_a_file_that_vanishes_during_the_extraction_is_not_a_missing_upload(
    workspace, monkeypatch
) -> None:
    """Fails on a ``FileNotFoundError`` from the extraction that is answered like a
    missing upload, with an ``error`` and no ``error_type``: it is a failure on disk,
    so it leaves the tool for the server's handler, and the previous tree stays
    delivered, the staging directory is deleted and the uploaded zip is kept."""
    first = _deliver({"old.txt": "old\n"}, "u1")
    sha256 = _upload(_zip(**{"new.txt": "new\n"}), "u2")

    def extraction_that_loses_a_file(self, path=None, members=None, pwd=None):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(path))

    monkeypatch.setattr(zipfile.ZipFile, "extractall", extraction_that_loses_a_file)

    with pytest.raises(FileNotFoundError) as raised:
        mcp_set_source_zip_finalize(
            upload_id="u2", expected_sha256=sha256, session_id=SESSION
        )

    assert not isinstance(raised.value, sd.UploadNotFoundError), raised.value
    assert (first / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == first
    assert _scratch_beside_source(first.parent) == []


def test_an_upload_that_never_received_its_last_chunk_has_no_error_type(
    workspace,
) -> None:
    """Control: the client's own mistake keeps its answer, an ``error`` and no
    ``error_type``, and a ``FileNotFoundError`` for a caller of the function."""
    with pytest.raises(FileNotFoundError, match="did the last chunk arrive"):
        sd.set_source_zip_finalize(
            upload_id="never-sent", expected_sha256="0" * 64, session_id=SESSION
        )

    result = mcp_set_source_zip_finalize(
        upload_id="never-sent", expected_sha256="0" * 64, session_id=SESSION
    )

    assert result["success"] is False, result
    assert "error_type" not in result, result
    assert "did the last chunk arrive" in result["error"], result
