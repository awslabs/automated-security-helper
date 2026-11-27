# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP image scan runs in a directory that holds only its output.

The scan's anchoring directory is the scan target and the config-confinement
boundary, so anchoring at the session's workspace put the delivered tree, the
uploads, the image archives and the materialized profile inside both. It is a
dedicated empty directory under the session instead, and a delivered archive
that is no longer on disk is refused before anything starts.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from unittest.mock import AsyncMock, patch

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp import source_delivery as sd
from tests.snapshot.mcp.mcp_snapshot_support import make_ctx

pytestmark = pytest.mark.unit

_SESSION = "session-image-anchor"
IMAGE_REF = "registry.example.com/team/app@sha256:" + "a" * 64


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(sd, "resolve_workspace_root", lambda: tmp_path)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
    # The operator's registry allowlist admits nothing by default; these rows
    # are about the scan's anchoring, not the gate.
    monkeypatch.setenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", "registry.example.com")
    yield tmp_path
    sd._drop_session_source_dir(_SESSION)
    # The locator too: left behind, it points a LATER test's session at this
    # test's deleted tmp_path (the registry is module-level state).
    sd._drop_session_image_locator(_SESSION)


def _tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return buf.getvalue()


async def _run():
    ctx = make_ctx({"mcp-session-id": _SESSION})
    scan = AsyncMock(return_value={"success": True, "scan_id": "scan-1"})
    with patch.object(mcp_server, "mcp_scan_directory", scan):
        result = await mcp_server.run_ash_scan(ctx)
    return result, scan


@pytest.mark.asyncio
async def test_a_reference_scan_is_anchored_at_a_dedicated_empty_directory(workspace):
    sd.set_source_image(IMAGE_REF, session_id=_SESSION)
    # Things a session workspace holds that the scan must not see.
    session_dir = workspace / _SESSION
    (session_dir / "source").mkdir(parents=True, exist_ok=True)
    (session_dir / "source" / "old.py").write_text("x = 1\n")

    result, scan = await _run()

    assert result.get("success") is True, result
    anchor = scan.call_args.kwargs["directory_path"]
    assert anchor == str(session_dir / "image-scan")
    assert not any((session_dir / "image-scan").iterdir())
    assert scan.call_args.kwargs["asset"].image.ref == IMAGE_REF


@pytest.mark.asyncio
async def test_a_delivered_archive_that_is_gone_is_refused_before_the_scan(workspace):
    payload = _tar_bytes()
    sd.set_source_image_archive_chunk(
        upload_id="up",
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=workspace,
        session_id=_SESSION,
    )
    archive = sd.set_source_image_archive_finalize(
        upload_id="up",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=workspace,
        session_id=_SESSION,
    )
    archive.unlink()

    result, scan = await _run()

    assert result["success"] is False
    assert result["error_type"] == "delivered_image_missing"
    scan.assert_not_called()


@pytest.mark.asyncio
async def test_a_delivered_archive_that_is_present_is_scanned(workspace):
    payload = _tar_bytes()
    sd.set_source_image_archive_chunk(
        upload_id="up",
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=workspace,
        session_id=_SESSION,
    )
    sd.set_source_image_archive_finalize(
        upload_id="up",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=workspace,
        session_id=_SESSION,
    )

    result, scan = await _run()

    assert result.get("success") is True, result
    scan.assert_called_once()
