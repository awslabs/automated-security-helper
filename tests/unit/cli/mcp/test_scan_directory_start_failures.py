# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_directory`` answers a failed pre-scan check with a refusal, and holds nothing on failure.

Three places let an exception leave the tool where the client expects a dict:

* the client-rules denial check read the session's rules outside any guard, so a
  rules lookup that failed escaped the tool;
* the check for a config source outside the session's grant caught only the
  not-permitted error, so any other failure while reading the candidates escaped;
* the session's scan claim and its count were taken before the ``try`` that
  releases them, so a failure between the claim and the ``try`` left the session
  claimed, and ``clear_source`` was refused as busy from then on.

The ``delivered`` fixture releases no claim: a test that takes one releases it,
and the fixture fails a test that leaves one held.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.sessions import (
    get_default_registry,
    reset_default_registry_for_tests,
)
from automated_security_helper.config import config_sources

pytestmark = pytest.mark.unit

SESSION = "start-failures-session"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "scan-root"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state(None)
    reset_default_registry_for_tests()
    yield
    clear_profile_registry()
    clear_session_state(None)
    reset_default_registry_for_tests()


@pytest.fixture
def delivered() -> Path:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")
    data = buffer.getvalue()
    sd.set_source_zip_chunk(
        "first", 0, base64.b64encode(data).decode(), True, session_id=SESSION
    )
    source = sd.set_source_zip_finalize(
        "first", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )
    yield source
    # A test claims only what it takes and releases it itself. A claim still held
    # here is a leak, and it must fail the test as this assertion's message.
    # The assertion runs before the cleanup: ``clear_source`` takes the session's
    # change lock (``_while_no_scan_runs``), so on a leaked claim it raises its
    # busy refusal, and run first it would bury the message that names the leak.
    session = get_default_registry().session_for(SESSION)
    # try_begin_change answers None when the change began, and the reason it was
    # refused otherwise.
    idle = session.try_begin_change() is None
    if idle:
        session.end_change()
    try:
        assert idle, "the test left a scan claim held on the session"
    finally:
        sd.clear_source(SESSION)


def _scan(source: Path) -> Dict[str, Any]:
    return asyncio.run(mcp_tools.mcp_scan_directory(str(source), session_id=SESSION))


def test_a_session_rules_lookup_that_fails_refuses_the_denial_check(
    delivered: Path,
) -> None:
    with patch.object(
        mcp_tools, "_session_client_rules", side_effect=RuntimeError("rules gone")
    ):
        denial = mcp_tools._client_config_denial(
            None, delivered, SESSION, "scan_directory"
        )

    assert denial is not None
    assert denial["success"] is False, denial
    assert denial["error_type"] == "config_policy_unreadable", denial
    assert "rules gone" in denial["error"], denial


def test_a_scan_is_refused_when_the_session_rules_lookup_fails(
    delivered: Path,
) -> None:
    with (
        patch.object(
            mcp_tools, "_session_client_rules", side_effect=RuntimeError("rules gone")
        ),
        patch.object(mcp_tools, "_run_scan_async") as started,
    ):
        result = _scan(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "config_policy_unreadable", result
    assert not started.called


def test_a_candidate_check_that_fails_refuses_the_discovered_config(
    delivered: Path,
) -> None:
    with patch.object(
        config_sources, "check_discovery_candidates", side_effect=OSError("unreadable")
    ):
        refusal = mcp_tools._discovered_config_refusal(delivered, SESSION)

    assert refusal is not None
    assert str(delivered.as_posix()) in str(refusal)


def test_a_scan_is_refused_when_the_candidate_check_fails(delivered: Path) -> None:
    with (
        patch.object(
            config_sources,
            "check_discovery_candidates",
            side_effect=OSError("unreadable"),
        ),
        patch.object(mcp_tools, "_run_scan_async") as started,
    ):
        result = _scan(delivered)

    assert result["success"] is False, result
    assert result["error_type"] == "config_check_failed", result
    assert not started.called


class _ContextShape:
    """The attribute set of a real ``Context``, so a missing attribute raises.

    A bare ``MagicMock`` answers every name, which hides a send on a method the
    real context does not have.
    """

    headers: Dict[str, Any] = {}

    async def debug(self, message: str) -> None: ...

    async def info(self, message: str) -> None: ...

    async def warning(self, message: str) -> None: ...

    async def error(self, message: str) -> None: ...

    async def report_progress(self, progress, total=None, message=None) -> None: ...


def test_run_ash_scan_returns_a_failed_candidate_check_under_its_own_type(
    delivered: Path,
) -> None:
    from automated_security_helper.cli import mcp_server
    from unittest.mock import AsyncMock, MagicMock

    ctx = MagicMock(spec=_ContextShape)
    ctx.headers = {"mcp-session-id": SESSION}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())

    with (
        patch.object(
            config_sources,
            "check_discovery_candidates",
            side_effect=OSError("unreadable"),
        ),
        patch.object(mcp_tools, "_run_scan_async") as started,
    ):
        result = asyncio.run(mcp_server.run_ash_scan(ctx, source_dir=str(delivered)))

    assert result["success"] is False, result
    assert result["error_type"] == "config_check_failed", result
    assert not started.called


def test_control_a_candidate_outside_the_grant_is_still_refused_as_before(
    delivered: Path,
) -> None:
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )

    with patch.object(
        config_sources,
        "check_discovery_candidates",
        side_effect=ASHConfigInputNotPermittedError("base outside"),
    ):
        refusal = mcp_tools._discovered_config_refusal(delivered, SESSION)

    assert refusal is not None
    assert "base outside" in str(refusal)


def test_a_failure_between_the_claim_and_the_release_leaves_no_claim(
    delivered: Path,
) -> None:
    from automated_security_helper.cli.mcp import sessions

    with (
        patch.object(
            sessions, "per_session_scan_limit", side_effect=RuntimeError("limit gone")
        ),
        patch.object(mcp_tools, "_run_scan_async") as started,
    ):
        try:
            result = _scan(delivered)
        except RuntimeError:
            result = None

    cleared = mcp_tools.mcp_clear_source(session_id=SESSION)
    assert cleared.get("success") is True, cleared
    assert result is not None, "the failure left the tool as an exception"
    assert result["success"] is False, result
    assert not started.called


def test_control_a_scan_refused_at_its_limit_releases_only_its_own_claim(
    delivered: Path,
) -> None:
    from automated_security_helper.cli.mcp import sessions

    session = get_default_registry().session_for(SESSION)
    # Another scan of the session: claimed, and counted against the limit.
    assert session.try_claim_scan()
    assert session.try_start_scan(None)
    try:
        with (
            patch.object(sessions, "per_session_scan_limit", return_value=1),
            patch.object(mcp_tools, "_run_scan_async") as started,
        ):
            result = _scan(delivered)

        assert result["success"] is False, result
        assert result["error_type"] == "session_scan_limit", result
        assert not started.called
        # The other scan's claim is still held: the refused call released one
        # claim, its own, and no more.
        assert session.try_begin_change() == sessions.CHANGE_REFUSED_BY_SCAN
    finally:
        session.release_scan()
        session.scan_returned()
