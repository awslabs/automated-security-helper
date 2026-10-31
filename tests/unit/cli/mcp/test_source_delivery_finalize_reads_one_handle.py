#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The finalize reads one handle and removes only the zip it read.

``set_source_zip_finalize`` holds the upload's lock only to open the zip and to
remove it, so a chunk of the same upload may assemble a new zip over the path
while the finalize hashes, validates and extracts. Two things follow, and both
were broken: the bytes extracted must be the bytes hashed (one handle, not a
second open of the path), and the removal at the end, or with a refusal, must
delete the path only while it still names the file that was read, so the newer
zip waits for its own finalize instead of vanishing.

Each test swaps a different zip onto the path from inside the member validation,
the point of the finalize at which the archive is open and a chunk's rename is
admitted, and then reads what is left at the path.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import clear_all_session_state

pytestmark = pytest.mark.unit

SESSION = "one-handle-session"
UPLOAD = "upload"


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _upload(payload: bytes, tmp_path: Path) -> str:
    sd.set_source_zip_chunk(
        upload_id=UPLOAD,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=tmp_path,
        session_id=SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _finalize(sha256: str, tmp_path: Path) -> Path:
    return sd.set_source_zip_finalize(
        upload_id=UPLOAD,
        expected_sha256=sha256,
        workspace_root=tmp_path,
        session_id=SESSION,
    )


def _swapping_in(newer: bytes, final: Path):
    """A ``_validate_zip_member`` that first puts ``newer`` at ``final``.

    The swap is a rename of a file written beside the path, the way the last
    chunk of an upload promotes its ``.part``, so the path names a new file.
    """
    original = sd._validate_zip_member
    swapped = {"done": False}

    def validate(name: str) -> None:
        if not swapped["done"]:
            swapped["done"] = True
            staged = final.with_name(final.name + ".newer")
            staged.write_bytes(newer)
            os.replace(staged, final)
        original(name)

    return validate


@pytest.fixture(autouse=True)
def _forget_sessions():
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    clear_all_session_state()


class TestANewerZipOutlivesTheFinalizeThatDidNotReadIt:
    def test_a_zip_assembled_during_a_refused_validation_is_kept(self, tmp_path):
        """Red at the base: the refusal unlinked the path, newer zip and all."""
        hostile = _zip_bytes({"../escape.py": b"x"})
        newer = _zip_bytes({"fine.py": b"print(2)\n"})
        sha256 = _upload(hostile, tmp_path)
        final = sd._final_zip_path(tmp_path / SESSION, UPLOAD)

        with (
            patch.object(
                sd, "_validate_zip_member", side_effect=_swapping_in(newer, final)
            ),
            pytest.raises(ValueError, match="traversal"),
        ):
            _finalize(sha256, tmp_path)

        assert final.read_bytes() == newer

    def test_the_delivered_tree_is_the_hashed_zip_and_a_newer_zip_is_kept(
        self, tmp_path
    ):
        """Red at the base: the end of a delivery unlinked whatever the path named.

        The tree is the archive that was hashed, read from the one handle, not the
        archive a chunk put at the path after the checksum; that archive stays
        for its own finalize.
        """
        hashed = _zip_bytes({"a.py": b"print(1)\n"})
        newer = _zip_bytes({"b.py": b"print(2)\n"})
        sha256 = _upload(hashed, tmp_path)
        final = sd._final_zip_path(tmp_path / SESSION, UPLOAD)

        with patch.object(
            sd, "_validate_zip_member", side_effect=_swapping_in(newer, final)
        ):
            target = _finalize(sha256, tmp_path)

        assert (target / "a.py").exists()
        assert not (target / "b.py").exists()
        assert final.read_bytes() == newer

    def test_the_zip_that_was_read_is_removed_as_before(self, tmp_path):
        """Control: with nothing newer at the path, a refusal and a delivery remove it."""
        hostile = _zip_bytes({"../escape.py": b"x"})
        sha256 = _upload(hostile, tmp_path)
        final = sd._final_zip_path(tmp_path / SESSION, UPLOAD)
        with pytest.raises(ValueError, match="traversal"):
            _finalize(sha256, tmp_path)
        assert not final.exists()

        payload = _zip_bytes({"a.py": b"print(1)\n"})
        sha256 = _upload(payload, tmp_path)
        target = _finalize(sha256, tmp_path)
        assert (target / "a.py").exists()
        assert not final.exists()
