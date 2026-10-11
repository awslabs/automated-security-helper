# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session's delivered tree does not change under a scan of that session.

A scan of a session holds the session's scan lock while it reads
``<workspace root>/<session id>/source``. ``clear_source`` removed that tree
without taking the lock, so a client could empty the directory a running scan
was reading, which can make the scan report clean for code it never examined;
re-delivering with ``set_source_git`` or ``set_source_zip_finalize`` replaced it
the same way. Each is now refused while the lock is held, with
``error_type: source_delivery_busy``, and works again once the scan is done.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import (
    get_default_registry,
    reset_default_registry_for_tests,
)

SESSION = "scanning-session"


@pytest.fixture(autouse=True)
def delivered(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    reset_default_registry_for_tests()
    data = _zip()
    sd.set_source_zip_chunk(
        "first", 0, base64.b64encode(data).decode(), True, session_id=SESSION
    )
    source = sd.set_source_zip_finalize(
        "first", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )
    yield source
    sd.clear_source(SESSION)
    reset_default_registry_for_tests()


def _zip(body: str = "print('hello')\n") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", body)
    return buffer.getvalue()


@pytest.fixture
def scan_running():
    lock = get_default_registry().get_or_create(SESSION).lock
    lock.acquire()  # stands in for a running scan of the session
    yield
    lock.release()


def test_clear_source_is_refused_while_the_sessions_scan_runs(
    delivered, scan_running
) -> None:
    result = mcp_tools.mcp_clear_source(session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert (delivered / "app.py").is_file(), "the tree was removed under the scan"


def test_a_new_zip_is_refused_while_the_sessions_scan_runs(
    delivered, scan_running
) -> None:
    data = _zip("print('replaced')\n")
    sd.set_source_zip_chunk(
        "second", 0, base64.b64encode(data).decode(), True, session_id=SESSION
    )

    result = mcp_tools.mcp_set_source_zip_finalize(
        upload_id="second",
        expected_sha256=hashlib.sha256(data).hexdigest(),
        session_id=SESSION,
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert "hello" in (delivered / "app.py").read_text()


def test_a_clone_is_refused_while_the_sessions_scan_runs(
    delivered, scan_running, monkeypatch
) -> None:
    monkeypatch.setattr(
        sd.subprocess, "run", lambda *a, **k: pytest.fail("git ran during the scan")
    )

    result = mcp_tools.mcp_set_source_git(
        url="https://git.example.invalid/team/repo.git", session_id=SESSION
    )

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert (delivered / "app.py").is_file()


def test_clear_source_works_once_the_scan_is_done(delivered) -> None:
    result = mcp_tools.mcp_clear_source(session_id=SESSION)

    assert result.get("success") is True, result
    assert not delivered.exists()
