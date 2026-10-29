# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A change to a session's tree is refused while a scan of it runs in another server.

The busy gate of a delivery or a clear (``source_delivery._no_scan_running``)
takes the session's change, which excludes the scans of this process alone. A
scan in another server sharing the workspace root holds a locked entry under
``<root>/.ash-mcp-scans/<session id>/`` instead (``sessions.ScanPresence``): a
replica behind a load balancer scanning the same session, or a sibling stdio
server of the same user scanning ``__default__``, the one workspace every stdio
server of that user shares. The gate reads that entry too, so the tree is not
replaced or removed under a scan the gate cannot otherwise see.

The stdio session took part in none of this: ``ScanPresence`` registered nothing
for a reserved id, and ``end_session`` removed the reserved workspace without a
look at the registry. A stdio scan holds a presence entry like any other now,
and ending the stdio session waits for a sibling server's scan as it does for
a replica's.

Another server is stood in for by a second open handle on the same entry in this
process: the advisory lock is per open file, so a registry read in the same
process meets the held lock as another process would.
"""

from __future__ import annotations

import errno
import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

REPLICATED = "replicated-session"


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    sessions.reset_default_registry_for_tests()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions._ended_while_scanning.clear()
    saved = dict(sd._SESSION_SOURCE_DIRS)
    sd._SESSION_SOURCE_DIRS.clear()
    yield workspace
    sd._SESSION_SOURCE_DIRS.clear()
    sd._SESSION_SOURCE_DIRS.update(saved)
    sessions._ended_while_scanning.clear()
    sessions.reset_guard_refusal_warning_for_tests()
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def _sandbox(root: Path, session_id: str) -> Path:
    sandbox = mark_session_workspace(root / session_id)
    (sandbox / "source").mkdir()
    (sandbox / "source" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    sd._set_session_source_dir(session_id, sandbox / "source")
    return sandbox


def test_a_stdio_scan_holds_a_presence_entry_for_sibling_servers(root) -> None:
    _sandbox(root, DEFAULT_SESSION_ID)

    with sessions.ScanPresence(DEFAULT_SESSION_ID) as presence:
        registered = presence._entry is not None
        held = sessions.a_scan_in_another_server_holds(DEFAULT_SESSION_ID)
    released = sessions.a_scan_in_another_server_holds(DEFAULT_SESSION_ID)

    assert registered, "the stdio scan registered nothing"
    assert (held, released) == (True, False)


def test_clear_source_is_refused_while_a_sibling_servers_stdio_scan_runs(
    root,
) -> None:
    sandbox = _sandbox(root, DEFAULT_SESSION_ID)

    with sessions.ScanPresence(DEFAULT_SESSION_ID):
        result = mcp_tools.mcp_clear_source(session_id=DEFAULT_SESSION_ID)
        kept = (sandbox / "source" / "app.py").is_file()
    after = mcp_tools.mcp_clear_source(session_id=DEFAULT_SESSION_ID)

    assert result.get("success") is False, result
    assert result.get("error_type") == "source_delivery_busy", result
    assert "another server" in result.get("error", ""), result
    assert kept, "the tree was removed under the sibling server's scan"
    assert after.get("success") is True, after
    assert not (sandbox / "source").exists()


@pytest.mark.parametrize(
    "removes_workspace", [True, False], ids=["a-clear", "a-delivery"]
)
def test_a_change_is_refused_while_a_replicas_scan_of_the_session_runs(
    root, removes_workspace
) -> None:
    _sandbox(root, REPLICATED)

    with sessions.ScanPresence(REPLICATED):
        with pytest.raises(sd.SourceDeliveryBusyError, match="another server"):
            with sd._no_scan_running(REPLICATED, removes_workspace=removes_workspace):
                pytest.fail("the change began under the replica's scan")
        # The refused change holds nothing: a scan of this process may start.
        session = sessions.get_default_registry().session_for(REPLICATED)
        assert session.try_claim_scan(), "the refused change kept the session"
        session.release_scan()
    with sd._no_scan_running(REPLICATED, removes_workspace=removes_workspace):
        pass  # the change goes on once the scan elsewhere is over


def test_a_change_proceeds_when_no_scan_runs_anywhere(root) -> None:
    _sandbox(root, REPLICATED)
    ran = False

    with sd._no_scan_running(REPLICATED):
        ran = True

    assert ran


def test_an_entry_a_dead_server_left_does_not_refuse_the_change(root) -> None:
    _sandbox(root, REPLICATED)
    holder = root / sessions.SCAN_PRESENCE_DIR / REPLICATED
    holder.mkdir(parents=True)
    (holder / "12345-gone").write_bytes(b"")
    ran = False

    with sd._no_scan_running(REPLICATED):
        ran = True

    assert ran
    assert not (holder / "12345-gone").exists(), "the dead scan's entry was kept"


def test_a_session_with_no_workspace_takes_no_presence_guard(root, monkeypatch) -> None:
    """The first delivery into a fresh root creates the workspace itself. A gate
    that took the guard first would create the registry under a root that may
    not exist yet, and warn when it cannot."""

    def never(_root):
        pytest.fail("the guard was taken for a session with no workspace")

    monkeypatch.setattr(sessions, "_scan_presence_guard", never)

    with sd._no_scan_running("fresh"):
        pass

    assert not (root / sessions.SCAN_PRESENCE_DIR).exists()


def test_a_refused_guard_lets_the_change_go_on_and_warns_once(
    root, monkeypatch, ash_log
) -> None:
    """A root whose registry is refused has no registered scans to read (a scan
    there runs unregistered), so the change goes on as it did before the
    registry existed, and the process-wide latch says so once."""
    _sandbox(root, REPLICATED)

    def refused(_root):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(sessions, "_scan_presence_guard", refused)
    ran = False

    with sd._no_scan_running(REPLICATED):
        ran = True
    with sd._no_scan_running(REPLICATED):
        pass

    assert ran
    warned = [
        r.getMessage()
        for r in ash_log
        if "Could not take the scan presence lock" in r.getMessage()
    ]
    assert len(warned) == 1, warned
    assert (
        f"while checking for a scan of session {REPLICATED!r} in another server"
        in warned[0]
    ), warned[0]


def test_ending_the_stdio_session_waits_for_a_sibling_servers_scan(root) -> None:
    sandbox = _sandbox(root, DEFAULT_SESSION_ID)

    with sessions.ScanPresence(DEFAULT_SESSION_ID):
        ended_now = sessions.end_session(DEFAULT_SESSION_ID)
        kept = (sandbox / "source" / "app.py").is_file()
    ended_after = sessions.end_session(DEFAULT_SESSION_ID)

    assert ended_now is False
    assert kept, "the stdio workspace was removed under the sibling server's scan"
    assert ended_after is True
    assert not sandbox.exists()
