# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's session-scoped lookups, and what a refusal tells another session.

``tests/unit/cli/mcp/test_scan_registry_is_session_scoped.py`` drives the MCP
tools over the transport. These pin the registry underneath them: every lookup
that takes a ``session_id`` answers for that session's scans only, an unscoped
lookup still sees everything (the scan runners use it), the statistics a listing
reports count only the caller's scans, the busy-directory refusal names the
running scan's id, and how a stopping scan ended, only to the session that owns
it, and the max_concurrent_scans refusal names the limit and not how many scans
are running.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_tools import mcp_list_active_scans
from automated_security_helper.core.resource_management import (
    scan_registry as scan_registry_module,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    DEFAULT_SCAN_SESSION,
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def registry(monkeypatch) -> ScanRegistry:
    fresh = ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


def _register(registry: ScanRegistry, root: Path, name: str, session: str) -> str:
    target = root / name
    target.mkdir()
    return registry.register_scan(
        directory_path=str(target),
        output_directory=str(target),
        session_id=session,
    )


def test_scoped_lookups_answer_for_the_owner_only(registry, tmp_path) -> None:
    scan_id = _register(registry, tmp_path, "a", "session-a")

    assert registry.get_scan(scan_id, session_id="session-a") is not None
    assert registry.get_scan(scan_id, session_id="session-b") is None
    assert registry.get_scan(scan_id) is not None, "the unscoped lookup sees it"
    assert [s["scan_id"] for s in registry.list_scans(session_id="session-b")] == []
    assert registry.cancel_scan(scan_id, session_id="session-b") is False
    assert registry.get_scan(scan_id).status == MCScanStatus.PENDING
    with pytest.raises(MCPResourceError, match="not found in registry"):
        registry.check_scan_progress(scan_id, session_id="session-b")


def test_a_scan_registered_without_a_session_belongs_to_the_default_session(
    registry, tmp_path
) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(target)
    )

    assert registry.get_scan(scan_id, session_id=DEFAULT_SCAN_SESSION) is not None
    assert registry.get_scan(scan_id, session_id="session-a") is None


def test_the_listing_statistics_count_only_the_callers_scans(
    registry, tmp_path
) -> None:
    _register(registry, tmp_path, "a1", "session-a")
    _register(registry, tmp_path, "a2", "session-a")
    _register(registry, tmp_path, "b1", "session-b")

    listing = asyncio.run(mcp_list_active_scans(session_id="session-b"))

    assert listing["stats"]["total_scans"] == 1, listing["stats"]
    assert listing["stats"]["active_scans"] == 1, listing["stats"]
    assert listing["stats"]["status_counts"]["pending"] == 1, listing["stats"]


def test_a_busy_directory_refusal_names_the_scan_only_to_its_owner(
    registry, tmp_path
) -> None:
    target = tmp_path / "shared"
    target.mkdir()
    owner_scan = registry.register_scan(
        directory_path=str(target), output_directory=str(target), session_id="owner"
    )

    with pytest.raises(MCPResourceError) as other:
        registry.register_scan(
            directory_path=str(target), output_directory=str(target), session_id="other"
        )
    with pytest.raises(MCPResourceError) as same:
        registry.register_scan(
            directory_path=str(target), output_directory=str(target), session_id="owner"
        )

    assert owner_scan not in str(other.value) and owner_scan not in str(
        other.value.context
    ), other.value.context
    assert same.value.context.get("scan_id") == owner_scan, same.value.context


def test_a_stopping_scan_refusal_tells_only_its_owner_how_it_ended(
    registry, tmp_path
) -> None:
    """A cancelled scan still stopping keeps its directory busy.

    The refusal says "still stopping (cancelled)" only to the session that owns
    the scan; any other session is told only that the directory already has an
    active scan, which is all it needs to know. Telling it the scan is stopping
    rather than running would say that someone closed it. Like the scan id, the
    status is for the owner.
    """
    target = tmp_path / "stopping"
    target.mkdir()
    owner_scan = registry.register_scan(
        directory_path=str(target), output_directory=str(target), session_id="owner"
    )
    entry = registry.get_scan(owner_scan)
    entry.has_runner = True
    registry.cancel_scan(owner_scan, session_id="owner")
    assert entry.occupies_its_directory() and not entry.is_active()

    with pytest.raises(MCPResourceError) as other:
        registry.register_scan(
            directory_path=str(target), output_directory=str(target), session_id="other"
        )
    with pytest.raises(MCPResourceError) as same:
        registry.register_scan(
            directory_path=str(target), output_directory=str(target), session_id="owner"
        )

    assert "already has an active scan" in str(other.value), other.value
    assert "stopping" not in str(other.value), other.value
    assert "scan_id" not in other.value.context, other.value.context
    assert MCScanStatus.CANCELLED.value not in str(other.value), other.value
    assert MCScanStatus.CANCELLED.value not in str(other.value.context), (
        other.value.context
    )
    assert "still stopping" in str(same.value), same.value
    assert MCScanStatus.CANCELLED.value in str(same.value), same.value


def test_a_limit_refusal_tells_no_session_how_many_scans_are_running(
    registry, tmp_path
) -> None:
    """The max_concurrent_scans refusal names the limit, and not the count.

    The refusal names the server-wide limit and not a count of running scans, so
    no session learns how many scans the others run. The limit is server-wide,
    and the refused session needs to know it reached it; how many scans the
    other sessions run is theirs. Three are registered without a limit,
    so the count is above the limit of two and the two numbers differ.
    """
    for name in ("a1", "a2", "a3"):
        _register(registry, tmp_path, name, "session-a")
    target = tmp_path / "b1"
    target.mkdir()

    with pytest.raises(MCPResourceError) as refused:
        registry.register_scan(
            directory_path=str(target),
            output_directory=str(target),
            session_id="session-b",
            max_active=2,
        )

    message = str(refused.value)
    assert "max_concurrent_scans limit of 2" in message, message
    assert re.search(r"\b3\b", message) is None, message
    assert set(refused.value.context) == {
        "directory_path",
        "max_concurrent_scans",
        "error_category",
        "suggestions",
    }, refused.value.context
    assert refused.value.context["max_concurrent_scans"] == 2, refused.value.context
    assert registry.list_scans(directory_path=str(target)) == [], (
        "the refused scan was registered"
    )


def test_the_progress_monitor_reads_the_scan_in_the_session_that_started_it(
    registry, tmp_path
) -> None:
    """run_ash_scan's monitor polls the scan it started, so it asks as its session."""
    from unittest.mock import AsyncMock, MagicMock

    from automated_security_helper.cli.mcp.progress_monitor import (
        _fetch_initial_scan_info,
    )

    scan_id = _register(registry, tmp_path, "monitored", "session-a")
    ctx = MagicMock()
    ctx.error = AsyncMock()

    found = asyncio.run(_fetch_initial_scan_info(ctx, scan_id, "session-a"))
    unscoped = asyncio.run(_fetch_initial_scan_info(ctx, scan_id))

    assert found is not None, ctx.error.call_args_list
    assert unscoped is None, "the default session must not see session-a's scan"
