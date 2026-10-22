# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An sse message names one session, read the way the SDK reads it.

A message POST carries its session in the ``session_id`` query parameter of the
endpoint URL. The SDK routes a message whose query repeats the parameter by the
last value. ASH gives such a call no session identity, so the session a call acts
for is always the session whose stream receives its result.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.cli.mcp import build_sse_app
from tests.utils.mcp_transport_harness import (
    AsgiSseConnection,
    LOOPBACK_PORT,
)


@pytest.fixture(autouse=True)
def workspace(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    for name in (
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_TRANSPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    return root


def _zip() -> Dict[str, object]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    data = buffer.getvalue()
    return {"data": data, "sha": hashlib.sha256(data).hexdigest()}


@pytest.mark.parametrize("order", ["other-first", "own-first"])
def test_a_repeated_session_id_names_no_session(workspace, order) -> None:
    async def _run():
        app = build_sse_app(mount_path="/sse", host="127.0.0.1", port=LOOPBACK_PORT)
        upload = _zip()
        async with AsgiSseConnection(app) as owner, AsgiSseConnection(app) as other:
            chunk = await owner.call_tool(
                "set_source_zip_chunk",
                {
                    "upload_id": "u1",
                    "sequence": 0,
                    "data_b64": base64.b64encode(upload["data"]).decode(),
                    "last": True,
                },
            )
            final = await owner.call_tool(
                "set_source_zip_finalize",
                {"upload_id": "u1", "expected_sha256": upload["sha"]},
            )
            assert chunk.get("success") is True and final.get("success") is True
            owner_id = owner.message_path.split("session_id=")[1]
            other_id = other.message_path.split("session_id=")[1]
            first, second = (
                (owner_id, other_id) if order == "other-first" else (other_id, owner_id)
            )
            # The SDK delivers the result to the stream of the last value, so
            # the call is made on whichever connection that is.
            caller = other if order == "other-first" else owner
            caller.message_path = (
                f"{caller.message_path.split('?')[0]}"
                f"?session_id={first}&session_id={second}"
            )
            result = await caller.call_tool("clear_source", {})
            return owner_id, Path(final["source_dir"]), result

    owner_id, source_dir, result = asyncio.run(_run())

    assert result.get("success") is False, result
    assert result.get("error_type") == "session_identity_required", result
    assert result.get("session_id") != owner_id, result
