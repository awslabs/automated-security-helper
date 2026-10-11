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

The scan takes that lock on a worker thread, after ``run_ash_scan`` has already
returned the scan id. A change, or the session ending, in that window went
through, so the session claims its scan before the id is returned; and a scan
is refused while a change to the tree is in progress.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import (
    end_session,
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


def _stub_scan(monkeypatch, record: dict) -> None:
    def run_ash_scan(**kwargs):
        record["tree_present"] = (Path(kwargs["source_dir"]) / "app.py").is_file()

    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_scan.run_ash_scan",
        run_ash_scan,
    )


async def _other_tasks_done() -> None:
    current = asyncio.current_task()
    await asyncio.gather(*(t for t in asyncio.all_tasks() if t is not current))


def test_a_change_is_refused_between_a_scan_starting_and_running(
    delivered, monkeypatch
) -> None:
    scanned: dict = {}
    _stub_scan(monkeypatch, scanned)

    async def main():
        started = await mcp_tools.mcp_scan_directory(str(delivered), session_id=SESSION)
        refused = mcp_tools.mcp_clear_source(session_id=SESSION)
        await _other_tasks_done()
        return started, refused

    started, refused = asyncio.run(main())

    assert started.get("success") is True, started
    assert refused.get("error_type") == "source_delivery_busy", refused
    assert scanned.get("tree_present") is True, "the scan read a removed tree"
    assert mcp_tools.mcp_clear_source(session_id=SESSION).get("success") is True


def test_a_session_ending_before_its_scan_runs_keeps_the_tree_for_it(
    delivered, monkeypatch
) -> None:
    scanned: dict = {}
    _stub_scan(monkeypatch, scanned)

    async def main() -> bool:
        await mcp_tools.mcp_scan_directory(str(delivered), session_id=SESSION)
        ended_now = end_session(SESSION)
        await _other_tasks_done()
        return ended_now

    ended_now = asyncio.run(main())

    assert ended_now is False
    assert scanned.get("tree_present") is True, "the scan read a removed tree"
    assert not delivered.exists(), "the tree outlived the scan of an ended session"


def test_a_scan_is_refused_while_the_sessions_tree_is_changing(
    delivered, monkeypatch
) -> None:
    scanned: dict = {}
    _stub_scan(monkeypatch, scanned)

    async def main():
        with sd._no_scan_running(SESSION):
            return await mcp_tools.mcp_scan_directory(
                str(delivered), session_id=SESSION
            )

    result = asyncio.run(main())

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert scanned == {}, "a scan ran"


def test_run_ash_scan_reports_that_refusal_as_busy(tmp_path, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
    from tests.utils.mcp_transport_harness import stdio_tool_calls

    target = tmp_path / "project"
    target.mkdir()
    (target / "app.py").write_text("print('hello')\n", encoding="utf-8")
    scanned: dict = {}
    _stub_scan(monkeypatch, scanned)

    async def main():
        with sd._no_scan_running(DEFAULT_SESSION_ID):
            (result,) = await stdio_tool_calls(
                [("run_ash_scan", {"source_dir": str(target)})]
            )
        return result

    result = asyncio.run(main())

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert scanned == {}, "a scan ran"
