# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``disconnect`` drops every record the server holds for the session's id.

Idle eviction leaves the profile binding (``profile_registry``) and the
delivered-source record (``source_delivery``) in place, so a client that merely
went idle keeps them. Disconnect is the end of the session, so it clears both,
for the disconnected id and for that id only -- ``clear_all_session_state()``
clears every session's binding, and disconnect must never take that arm. An id
with no binding has no state at all (``get_session_state`` returns None), so a
dropped binding reads as None.

All files are under ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery
from automated_security_helper.cli.mcp.profile_registry import (
    bind_session_config,
    clear_all_session_state,
    get_session_state,
)
from automated_security_helper.cli.mcp.sessions import MCPSessionRegistry
from automated_security_helper.config.ash_config import AshConfig

_SESSION_IDS = ("gone", "stays", "never-seen")


@pytest.fixture(autouse=True)
def _isolate_records():
    """Scrub the process-wide binding and delivered-source stores around a test.

    ``clear_session_state`` takes the id it drops, so the scrub of every session
    is ``clear_all_session_state``. The delivered-source ids are dropped before
    the test as well, so a record another test left cannot be read here.
    """
    clear_all_session_state()
    for session_id in _SESSION_IDS:
        source_delivery._drop_session_source_dir(session_id)
    yield
    clear_all_session_state()
    for session_id in _SESSION_IDS:
        source_delivery._drop_session_source_dir(session_id)


@pytest.fixture
def registry(tmp_path: Path) -> MCPSessionRegistry:
    return MCPSessionRegistry(workspace_parent=tmp_path / "sessions")


def _bind_and_deliver(session_id: str, tmp_path: Path) -> Path:
    bind_session_config(
        session_id, config=AshConfig(project_name="t"), profile_name="chosen"
    )
    source = tmp_path / f"{session_id}-source"
    source.mkdir(exist_ok=True)
    source_delivery._set_session_source_dir(session_id, source)
    return source


def test_disconnect_clears_the_profile_binding_and_the_source_record(
    registry: MCPSessionRegistry, tmp_path: Path
) -> None:
    _bind_and_deliver("gone", tmp_path)
    workspace = registry.get_or_create("gone").workspace_root

    registry.disconnect("gone")

    assert get_session_state("gone") is None
    assert source_delivery.get_session_source_dir("gone") is None
    assert not workspace.exists()


def test_disconnect_clears_only_the_disconnected_ids_records(
    registry: MCPSessionRegistry, tmp_path: Path
) -> None:
    """The id is always passed through: no disconnect clears another session's state."""
    _bind_and_deliver("gone", tmp_path)
    stays_source = _bind_and_deliver("stays", tmp_path)
    registry.get_or_create("gone")
    registry.get_or_create("stays")

    registry.disconnect("gone")

    assert get_session_state("stays").profile_name == "chosen"
    assert get_session_state("stays").bound_config is not None
    assert source_delivery.get_session_source_dir("stays") == stays_source
    assert get_session_state("gone") is None


def test_disconnect_of_an_unknown_id_leaves_every_other_sessions_records(
    registry: MCPSessionRegistry, tmp_path: Path
) -> None:
    """Control: an id with nothing at all is a no-op for the other ids too."""
    stays_source = _bind_and_deliver("stays", tmp_path)

    registry.disconnect("never-seen")

    assert get_session_state("stays").profile_name == "chosen"
    assert source_delivery.get_session_source_dir("stays") == stays_source
