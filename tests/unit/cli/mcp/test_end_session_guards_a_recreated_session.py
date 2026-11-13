# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``end_session`` sees a session a scan recreated after the registry forgot it.

The registry forgets idle sessions once its map is large, so the entry for an id
can be missing while a scan of that id is about to claim it. ``end_session`` has to
take the session it removes through the registry's own lookup, the one that makes
the entry, so that a claim made right after the lookup is seen by the change guard
and the delivered tree is left alone until the scan returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry, end_session

pytestmark = pytest.mark.unit


@pytest.fixture
def registry(tmp_path: Path, monkeypatch) -> MCPSessionRegistry:
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    sessions.reset_default_registry_for_tests()
    yield sessions.get_default_registry()
    sessions.reset_default_registry_for_tests()
    sessions._ended_while_scanning.clear()


def _a_scan_claims_right_after_the_first_lookup(
    registry: MCPSessionRegistry, monkeypatch, session_id: str
) -> list:
    """Make a scan claim ``session_id`` as soon as the first lookup of it returns."""

    claimed: list = []
    fired = {"done": False}

    def after_lookup(method):
        def wrapper(self, requested):
            found = method(self, requested)
            if requested == session_id and not fired["done"]:
                fired["done"] = True
                scan_session = self.session_for(session_id)
                assert scan_session.try_claim_scan()
                claimed.append(scan_session)
            return found

        return wrapper

    monkeypatch.setattr(MCPSessionRegistry, "get", after_lookup(MCPSessionRegistry.get))
    monkeypatch.setattr(
        MCPSessionRegistry, "session_for", after_lookup(MCPSessionRegistry.session_for)
    )
    return claimed


def test_an_evicted_id_a_scan_recreates_is_not_removed_while_it_holds_a_claim(
    registry, monkeypatch
) -> None:
    assert "evicted" not in registry
    claimed = _a_scan_claims_right_after_the_first_lookup(
        registry, monkeypatch, "evicted"
    )

    removed_now = end_session("evicted")

    assert claimed, "the scan never claimed the session"
    assert removed_now is False
    assert registry.get("evicted") is claimed[0]
    assert "evicted" in sessions._ended_while_scanning


def test_the_removal_runs_once_the_scan_returns(registry, monkeypatch) -> None:
    claimed = _a_scan_claims_right_after_the_first_lookup(
        registry, monkeypatch, "evicted"
    )
    assert end_session("evicted") is False

    claimed[0].release_scan()
    sessions.finish_ended_session("evicted")

    assert "evicted" not in registry
    assert "evicted" not in sessions._ended_while_scanning


def test_ending_a_session_that_never_existed_is_a_no_op(registry) -> None:
    assert end_session("never-existed") is True

    assert "never-existed" not in registry
    assert "never-existed" not in sessions._ended_while_scanning


def test_ending_an_id_that_cannot_name_a_session_does_not_raise(registry) -> None:
    assert end_session("../escape") is True
    assert len(registry) == 0
