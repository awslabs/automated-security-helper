# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stdio server's exit removes the default workspace only when it is the last one.

Every stdio server of one user resolves the same ``<workspace root>/__default__``
(the root depends only on ``ASH_MCP_WORKSPACE_ROOT``, ``XDG_CACHE_HOME`` and
``HOME``): two IDE windows, or two agents, share it. A server removes it on exit
only when no other live stdio server shares the root, so the tree and bound
profile of a server still running stay in place. A server that died without
exiting cleanly does not count as live.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Dict

import pytest

from automated_security_helper.cli.mcp import sessions
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, KillAfter


def _zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    return buffer.getvalue()


def _server(root: Path, stderr) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items() if not k.startswith("ASH_MCP_")}
    env["ASH_MCP_WORKSPACE_ROOT"] = str(root)
    return subprocess.Popen(
        [sys.executable, "-m", "automated_security_helper.cli.main", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr,
        env=env,
        text=True,
    )


def _call(proc: subprocess.Popen, request_id: int, method: str, params: Dict) -> Dict:
    proc.stdin.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        + "\n"
    )
    proc.stdin.flush()
    for line in proc.stdout:
        message = json.loads(line)
        if message.get("id") == request_id:
            return message
    raise AssertionError(f"the server closed stdout before answering {method}")


def _initialize(proc: subprocess.Popen) -> None:
    _call(
        proc,
        1,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ash-test", "version": "0"},
        },
    )
    proc.stdin.write(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
    )
    proc.stdin.flush()


def _close(proc: subprocess.Popen) -> int:
    proc.stdin.close()
    return proc.wait(timeout=120)


@pytest.mark.e2e
def test_a_second_stdio_server_exiting_leaves_the_first_ones_tree(tmp_path) -> None:
    root = tmp_path / "ws"
    data = _zip()
    second = None
    with (tmp_path / "stderr").open("w") as stderr:
        first = _server(root, stderr)
        watchdog = threading.Timer(240, first.kill)
        watchdog.start()
        try:
            _initialize(first)
            _call(
                first,
                2,
                "tools/call",
                {
                    "name": "set_source_zip_chunk",
                    "arguments": {
                        "upload_id": "u1",
                        "sequence": 0,
                        "data_b64": base64.b64encode(data).decode(),
                        "last": True,
                    },
                },
            )
            _call(
                first,
                3,
                "tools/call",
                {
                    "name": "set_source_zip_finalize",
                    "arguments": {
                        "upload_id": "u1",
                        "expected_sha256": hashlib.sha256(data).hexdigest(),
                    },
                },
            )
            tree = root / "__default__" / "source"
            assert tree.is_dir()

            second = _server(root, stderr)
            # The watchdog above kills only the first server; reading the second
            # one's stdout blocks the same way.
            with KillAfter(second, "the second stdio server"):
                _initialize(second)
                assert _close(second) == 0

            still_there = tree.is_dir()
            assert _close(first) == 0
        finally:
            watchdog.cancel()
            for proc in (first, second):
                if proc is not None and proc.returncode is None:
                    proc.kill()
                    proc.wait(timeout=CHILD_TIMEOUT_SECONDS)

    assert still_there, "a sibling stdio server's exit removed this server's tree"
    assert not (root / "__default__").exists(), "the last server's exit left the tree"


@pytest.mark.unit
def test_a_server_that_died_does_not_keep_the_tree(tmp_path, monkeypatch) -> None:
    root = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    (root / "__default__" / "source").mkdir(parents=True)

    stale = sessions.StdioServerPresence()
    stale.__enter__()
    stale.abandon_for_tests()  # its process "died": the lock is gone, the entry stays

    with sessions.StdioServerPresence():
        pass

    assert not (root / "__default__").exists()


@pytest.mark.unit
def test_presence_entries_never_count_as_session_workspaces(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    with sessions.StdioServerPresence():
        removed = sessions.sweep_stale_workspaces(0.0, now=10**12)

    assert removed == []
