# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The caller with no server-issued session owns no session state, in either layer.

``UNIDENTIFIED_SESSION_ID`` stands for a remote caller the server did not issue
a session to. The session registry will not hand it a session, and the profile
registry will not materialize a config for it. Each layer refuses on its own, so
a caller that reaches one of them without going through the other still gets no
directory, and nothing is created under the workspace root.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions
from automated_security_helper.cli.mcp.profile_registry import (
    clear_session_state,
    materialize_session_config,
)
from automated_security_helper.cli.mcp.session_identity import UNIDENTIFIED_SESSION_ID
from automated_security_helper.config.ash_config import AshConfig


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    clear_session_state()


def test_the_session_registry_gives_the_unidentified_caller_no_session(root) -> None:
    registry = sessions.get_default_registry()

    with pytest.raises(ValueError, match="no session the server issued"):
        registry.session_for(UNIDENTIFIED_SESSION_ID)

    assert registry.get(UNIDENTIFIED_SESSION_ID) is None
    assert list(root.iterdir()) == []


def test_the_session_registry_still_gives_an_issued_session_one(root) -> None:
    registry = sessions.get_default_registry()

    session = registry.session_for("issued-1")

    assert session.id == "issued-1"
    assert registry.get("issued-1") is session


def test_the_profile_registry_writes_no_config_for_the_unidentified_caller(
    root,
) -> None:
    with pytest.raises(RuntimeError, match="no session the server issued"):
        materialize_session_config(UNIDENTIFIED_SESSION_ID, AshConfig())

    assert list(root.iterdir()) == []


def test_the_profile_registry_still_writes_a_config_for_an_issued_session(
    root,
) -> None:
    path = materialize_session_config("issued-1", AshConfig())

    assert Path(path).is_file()
    assert Path(path).resolve().is_relative_to(root.resolve())
