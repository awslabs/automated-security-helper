# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of the image delivery tools: the other half of the source channels.

Covers set_source_image, set_source_image_archive_chunk and
set_source_image_archive_finalize, each with the refusals a client can trigger and
the ``invalid_session_id`` result every session-scoped tool has. The saved image is
a tiny tar built in memory with fixed entry times, so its bytes and the sha256 the
mismatch message quotes are the same on every run. Nothing is fetched and nothing
scans: a reference is stored, an archive is moved, and ``clear_source`` forgets
both.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_server
from tests.snapshot.mcp.mcp_snapshot_support import make_ctx, record

pytestmark = pytest.mark.unit

_BAD_SESSION = {"mcp-session-id": "../escape"}
_SESSION = {"mcp-session-id": "session-image"}
_REF = "registry.example.com/team/app@sha256:" + "ab" * 32


async def _call(tool: str, *args, headers=None, **kwargs) -> Dict[str, Any]:
    ctx = make_ctx(headers)
    result = await getattr(mcp_server, tool)(ctx, *args, **kwargs)
    return record(tool, result, ctx)


def _saved_image() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        body = b"[]"
        info = tarfile.TarInfo("manifest.json")
        info.size = len(body)
        info.mtime = 1767323046
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        tar.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_set_source_image(snapshot):
    stored = await _call("set_source_image", image_ref=_REF, headers=_SESSION)
    tag_only = await _call(
        "set_source_image", image_ref="alpine:3.20", headers=_SESSION
    )
    empty = await _call("set_source_image", image_ref="   ", headers=_SESSION)
    option_like = await _call(
        "set_source_image", image_ref="--insecure", headers=_SESSION
    )
    spaced = await _call("set_source_image", image_ref="alpine 3.20", headers=_SESSION)
    invalid_session = await _call(
        "set_source_image", image_ref=_REF, headers=_BAD_SESSION
    )
    await _call("clear_source", headers=_SESSION)

    assert stored == snapshot(name="stored")
    assert tag_only == snapshot(name="tag_only_replaces_the_subject")
    assert empty == snapshot(name="empty_ref")
    assert option_like == snapshot(name="option_like_ref")
    assert spaced == snapshot(name="ref_with_whitespace")
    assert invalid_session == snapshot(name="invalid_session_id")


@pytest.mark.asyncio
async def test_image_archive_upload_and_finalize(snapshot):
    payload = _saved_image()
    half = len(payload) // 2
    chunks = [payload[:half], payload[half:]]
    digest = hashlib.sha256(payload).hexdigest()

    first = await _call(
        "set_source_image_archive_chunk",
        upload_id="image-1",
        sequence=0,
        data_b64=base64.b64encode(chunks[0]).decode(),
        last=False,
        headers=_SESSION,
    )
    out_of_order = await _call(
        "set_source_image_archive_chunk",
        upload_id="image-1",
        sequence=5,
        data_b64=base64.b64encode(chunks[1]).decode(),
        last=True,
        headers=_SESSION,
    )
    last = await _call(
        "set_source_image_archive_chunk",
        upload_id="image-1",
        sequence=1,
        data_b64=base64.b64encode(chunks[1]).decode(),
        last=True,
        headers=_SESSION,
    )
    bad_base64 = await _call(
        "set_source_image_archive_chunk",
        upload_id="image-2",
        sequence=0,
        data_b64="abc",
        last=True,
        headers=_SESSION,
    )
    await _call(
        "set_source_image_archive_chunk",
        upload_id="image-3",
        sequence=0,
        data_b64=base64.b64encode(payload).decode(),
        last=True,
        headers=_SESSION,
    )
    wrong_digest = await _call(
        "set_source_image_archive_finalize",
        upload_id="image-3",
        expected_sha256="0" * 64,
        headers=_SESSION,
    )
    finalized = await _call(
        "set_source_image_archive_finalize",
        upload_id="image-1",
        expected_sha256=digest,
        headers=_SESSION,
    )
    unknown_upload = await _call(
        "set_source_image_archive_finalize",
        upload_id="never-uploaded",
        expected_sha256=digest,
        headers=_SESSION,
    )
    not_a_tar = b"this is not a saved image, only text\n" * 20
    await _call(
        "set_source_image_archive_chunk",
        upload_id="image-4",
        sequence=0,
        data_b64=base64.b64encode(not_a_tar).decode(),
        last=True,
        headers=_SESSION,
    )
    refused_shape = await _call(
        "set_source_image_archive_finalize",
        upload_id="image-4",
        expected_sha256=hashlib.sha256(not_a_tar).hexdigest(),
        headers=_SESSION,
    )
    cleared = await _call("clear_source", headers=_SESSION)

    invalid = {
        "set_source_image_archive_chunk": await _call(
            "set_source_image_archive_chunk",
            upload_id="u",
            sequence=0,
            data_b64="",
            last=True,
            headers=_BAD_SESSION,
        ),
        "set_source_image_archive_finalize": await _call(
            "set_source_image_archive_finalize",
            upload_id="u",
            expected_sha256=digest,
            headers=_BAD_SESSION,
        ),
    }

    assert first == snapshot(name="chunk_0")
    assert out_of_order == snapshot(name="chunk_out_of_order")
    assert last == snapshot(name="chunk_1_last")
    assert bad_base64 == snapshot(name="chunk_invalid_base64")
    assert wrong_digest == snapshot(name="finalize_sha256_mismatch")
    assert finalized == snapshot(name="finalize")
    assert unknown_upload == snapshot(name="finalize_unknown_upload")
    assert refused_shape == snapshot(name="finalize_not_a_tar")
    assert cleared == snapshot(name="clear_source_forgets_the_image")
    for tool, result in invalid.items():
        assert result == snapshot(name=f"{tool}_invalid_session_id")
