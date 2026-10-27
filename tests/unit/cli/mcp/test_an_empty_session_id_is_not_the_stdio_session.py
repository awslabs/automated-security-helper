# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only an explicit ``None`` names the stdio session; an empty string is an id.

``DEFAULT_SESSION_ID`` is the session a caller with no id gets. An accessor that
maps every falsy id to it (``session_id or DEFAULT_SESSION_ID``) reads an empty
string as the stdio session too, so a call for the id "" would bind, read,
materialize into or hold the stdio session's state. Each site below reads
``DEFAULT_SESSION_ID if session_id is None else session_id``.

The accessors that were already covered are in ``test_clear_session_state_scope``.
This file holds one cell per remaining site: ``bind_session_config``,
``resolve_session_config_path``, ``resolve_session_trusted_config_path``,
``session_profile_entry``, ``materialize_session_config``,
``materialize_session_binding`` and ``sessions.writing_session_state``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import profile_registry, sessions
from automated_security_helper.cli.mcp.sandbox import CLIENT_CONFIG_DIR_NAME
from automated_security_helper.config.ash_config import AshConfig


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    profile_registry.clear_all_session_state()
    yield workspace
    profile_registry.clear_all_session_state()
    sessions.reset_default_registry_for_tests()


def _bind_stdio(**paths: str) -> None:
    profile_registry.bind_session_config(
        None, config=AshConfig(), profile_name="stdio-profile", **paths
    )


def test_binding_an_empty_id_does_not_bind_the_stdio_session() -> None:
    state = profile_registry.bind_session_config(
        "", config=AshConfig(), profile_name="strict"
    )

    assert state.session_id == ""
    assert not profile_registry.session_has_binding(None), (
        "binding an empty id bound the stdio session"
    )
    assert profile_registry.session_has_binding(""), (
        "the binding is not readable under the id it was made for"
    )


def test_the_config_path_of_an_empty_id_is_not_the_stdio_sessions(tmp_path) -> None:
    config_file = tmp_path / "stdio.yaml"
    config_file.write_text("{}\n", encoding="utf-8")
    _bind_stdio(config_path=str(config_file))

    assert profile_registry.resolve_session_config_path("") is None
    assert profile_registry.resolve_session_config_path(None) == str(config_file)


def test_the_trusted_path_of_an_empty_id_is_not_the_stdio_sessions(tmp_path) -> None:
    trusted_file = tmp_path / "trusted.yaml"
    trusted_file.write_text("{}\n", encoding="utf-8")
    _bind_stdio(trusted_config_path=str(trusted_file))

    assert profile_registry.resolve_session_trusted_config_path("") is None
    assert profile_registry.resolve_session_trusted_config_path(None) == str(
        trusted_file
    )


def test_the_profile_entry_of_an_empty_id_is_not_the_stdio_sessions() -> None:
    """The stdio session's bound profile is not registered, so reading it fails
    closed; an empty id has no binding and reads None."""
    _bind_stdio()

    assert profile_registry.session_profile_entry("") is None
    with pytest.raises(profile_registry.ProfileRegistryError):
        profile_registry.session_profile_entry(None)


def test_materializing_for_an_empty_id_writes_nothing_for_the_stdio_session(
    root,
) -> None:
    """An empty id has no session sandbox, so the write is refused, and the
    stdio session's workspace is not created."""
    with pytest.raises(RuntimeError):
        profile_registry.materialize_session_config("", AshConfig())

    assert not (root / profile_registry.DEFAULT_SESSION_ID).exists()


def test_a_binding_for_an_empty_id_leaves_the_stdio_sessions_client_copy(
    root,
) -> None:
    client_copy = (
        root
        / profile_registry.DEFAULT_SESSION_ID
        / CLIENT_CONFIG_DIR_NAME
        / profile_registry.SESSION_CONFIG_FILENAME
    )
    client_copy.parent.mkdir(parents=True)
    client_copy.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        profile_registry.materialize_session_binding("", AshConfig())

    assert client_copy.is_file(), "the stdio session's client copy was removed"


def test_holding_an_empty_id_does_not_hold_the_stdio_session() -> None:
    registry = sessions.get_default_registry()

    with sessions.writing_session_state(""):
        assert profile_registry.DEFAULT_SESSION_ID not in registry, (
            "an empty id took the stdio session's write hold"
        )

    with sessions.writing_session_state(None):
        assert profile_registry.DEFAULT_SESSION_ID in registry
