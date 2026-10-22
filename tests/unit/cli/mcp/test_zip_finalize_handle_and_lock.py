# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finalize refuses a zip only after its handle is closed.

A refused zip (over the size limit, or a checksum mismatch) is removed after the
handle that read it is closed. Windows does not delete a file that is open, so an
unlink inside the ``with`` replaces the intended ``ValueError`` with a
``PermissionError`` and leaves the zip on disk. The cells here stand in for that
rule with a recorded double: ``Path.unlink`` raises ``PermissionError`` while a
handle opened on the zip is still open.

Every cell works under ``tmp_path``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

SESSION = "finalize-lock-session"


def _zip_bytes(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _upload(payload: bytes, upload_id: str, root: Path) -> Path:
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=root,
        session_id=SESSION,
    )
    session_dir = sd._session_workspace(root, SESSION)
    return sd._final_zip_path(session_dir, upload_id)


@pytest.fixture(autouse=True)
def _clean(tmp_path):
    yield
    sd.clear_source(SESSION, workspace_root=tmp_path)


@pytest.fixture
def windows_unlink(monkeypatch):
    """Recorded double: ``Path.unlink`` of a zip raises while a handle on it is open."""
    handles: List[object] = []
    real_open = Path.open
    real_unlink = Path.unlink

    def recording_open(self, mode="r", *args, **kwargs):
        handle = real_open(self, mode, *args, **kwargs)
        if self.suffix == ".zip" and "r" in mode and "b" in mode:
            handles.append(handle)
        return handle

    def refusing_unlink(self, missing_ok=False):
        if self.suffix == ".zip" and any(not h.closed for h in handles):
            raise PermissionError(32, "being used by another process", str(self))
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "open", recording_open)
    monkeypatch.setattr(Path, "unlink", refusing_unlink)
    return handles


def test_an_oversize_zip_is_removed_after_its_handle_closes(
    tmp_path, monkeypatch, windows_unlink
) -> None:
    payload = _zip_bytes({"a.txt": b"hi"})
    final = _upload(payload, "big", tmp_path)
    monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 1)

    with pytest.raises(ValueError, match="zip too large"):
        sd.set_source_zip_finalize(
            upload_id="big",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            workspace_root=tmp_path,
            session_id=SESSION,
        )

    assert windows_unlink, "the cell never saw the zip opened"
    assert not final.exists()


def test_a_checksum_mismatch_is_removed_after_its_handle_closes(
    tmp_path, windows_unlink
) -> None:
    final = _upload(_zip_bytes({"a.txt": b"hi"}), "bad", tmp_path)

    with pytest.raises(ValueError, match="sha256 mismatch"):
        sd.set_source_zip_finalize(
            upload_id="bad",
            expected_sha256="0" * 64,
            workspace_root=tmp_path,
            session_id=SESSION,
        )

    assert windows_unlink, "the cell never saw the zip opened"
    assert not final.exists()


def test_a_delivered_zip_is_removed_after_its_handle_closes(
    tmp_path, windows_unlink
) -> None:
    payload = _zip_bytes({"a.txt": b"hi"})
    final = _upload(payload, "ok", tmp_path)

    target = sd.set_source_zip_finalize(
        upload_id="ok",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=tmp_path,
        session_id=SESSION,
    )

    assert (target / "a.txt").read_bytes() == b"hi"
    assert not final.exists()
