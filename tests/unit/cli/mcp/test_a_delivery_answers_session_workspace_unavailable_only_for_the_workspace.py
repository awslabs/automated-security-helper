# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``session_workspace_unavailable`` means the session's workspace, and only that.

What the code does, by path
---------------------------
``error_type`` ``session_workspace_unavailable`` is the one value a client branches
on when the server cannot use the session's workspace: a directory of it cannot be
created, or the swap of a delivered tree cannot complete. It is raised as
``SessionWorkspaceError`` at those sites.

``mcp_set_source_zip_finalize`` also caught every other ``OSError`` and answered it
the same way. An error from reading the uploaded archive, or from extracting one of
its members (a member name the client chose can be too long or hold a character the
file system refuses), is not a problem with the workspace, and a client that
retried it as one would never learn that its archive was the cause. Those errors
are no longer mapped: they keep the handling they had before, and the tool's own
handler answers them with the error's class name.

What stays: a workspace directory that cannot be created, whichever delivery tool
asks for it, is answered ``session_workspace_unavailable`` with the path.

Every test is DISARMED: the workspace root is the test's own tmp_path, and nothing
runs git, a scanner or the network.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_tools import (
    mcp_set_source_zip_chunk,
    mcp_set_source_zip_finalize,
)

pytestmark = pytest.mark.unit

SESSION = "zip-oserror"


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    return root


def _zip(**files: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def _upload(payload: bytes, upload_id: str, session_id: str = SESSION) -> str:
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        session_id=session_id,
    )
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("failure", ["reading the archive", "extracting a member"])
def test_an_oserror_that_is_not_about_the_workspace_is_not_answered_as_one(
    monkeypatch, failure
) -> None:
    first = sd.set_source_zip_finalize(
        upload_id="u1",
        expected_sha256=_upload(_zip(**{"old.txt": "old\n"}), "u1"),
        session_id=SESSION,
    )
    expected_sha256 = _upload(_zip(**{"new.txt": "new\n"}), "u2")
    error = OSError(errno.ENAMETOOLONG, "file name too long")
    if failure == "extracting a member":

        def extractall(self, *args, **kwargs):
            raise error

        monkeypatch.setattr(zipfile.ZipFile, "extractall", extractall)
    else:
        real_open = Path.open

        def open_(self: Path, *args, **kwargs):
            if self.suffix == ".zip":
                raise error
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_)

    with pytest.raises(OSError) as raised:
        mcp_set_source_zip_finalize(
            upload_id="u2", expected_sha256=expected_sha256, session_id=SESSION
        )

    assert not isinstance(raised.value, sd.SessionWorkspaceError), raised.value
    assert raised.value.errno == errno.ENAMETOOLONG, raised.value
    # The refused delivery leaves the previous tree, its record and no scratch.
    assert (first / "old.txt").read_text() == "old\n"
    assert sd.get_session_source_dir(SESSION) == first
    assert list(first.parent.glob(".source.incoming-*")) == []


@pytest.mark.parametrize("step", ["chunk", "finalize"])
def test_a_workspace_that_cannot_be_created_is_answered_as_unavailable(
    workspace, step
) -> None:
    """A regular file where the session's directory should be: the directory cannot
    be made, and the tool says so with the path, whichever delivery step asked."""
    blocker = workspace / "blocked-session"
    blocker.write_text("not a directory\n", encoding="utf-8")

    if step == "chunk":
        result = mcp_set_source_zip_chunk(
            upload_id="u1",
            sequence=0,
            data_b64=base64.b64encode(b"PK").decode("ascii"),
            last=True,
            session_id="blocked-session",
        )
    else:
        result = mcp_set_source_zip_finalize(
            upload_id="u1", expected_sha256="0" * 64, session_id="blocked-session"
        )

    assert result["success"] is False, result
    assert result.get("error_type") == sd.SESSION_WORKSPACE_UNAVAILABLE, result
    assert str(blocker) in result["error"], result
