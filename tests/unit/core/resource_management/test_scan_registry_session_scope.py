# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's session-scoped lookups, and what a refusal tells another session.

``tests/unit/cli/mcp/test_scan_registry_is_session_scoped.py`` drives the MCP
tools over the transport. These pin the registry underneath them: every lookup
that takes a ``session_id`` answers for that session's scans only, an unscoped
lookup still sees everything (the scan runners use it), the statistics a listing
reports count only the caller's scans, and the busy-directory refusal names the
running scan's id only to the session that owns it.
"""

from __future__ import annotations

import asyncio
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
