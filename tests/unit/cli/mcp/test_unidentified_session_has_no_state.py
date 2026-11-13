# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The caller with no server-issued session owns no session state, in either layer.

``UNIDENTIFIED_SESSION_ID`` stands for a remote caller the server did not issue
a session to. The session registry will not hand it a session, and the profile
registry will not materialize a config for it. Each layer refuses on its own, so
a caller that reaches one of them without going through the other still gets no
directory, and nothing is created under the workspace root.

The TTL sweep honors both layers too. A directory under the root that carries
this name is reserved, so the sweep leaves it alone; and when the reservation
is not what stops it, the session registry's refusal is, and the sweep goes on
to the next entry instead of raising.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import session_identity, sessions
from automated_security_helper.cli.mcp.profile_registry import (
    clear_session_state,
    materialize_session_config,
)
from automated_security_helper.cli.mcp.session_identity import UNIDENTIFIED_SESSION_ID
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

STALE_REAL_SESSIONS = ["stale-real-1", "stale-real-2", "stale-real-3"]


@pytest.fixture(autouse=True)
def root(tmp_path, monkeypatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    sessions.reset_default_registry_for_tests()
    yield workspace
    sessions.reset_default_registry_for_tests()
    clear_session_state(None)


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


def _marked_workspaces(root: Path) -> None:
    """The unidentified name and three real sessions, all marked and all unused."""
    mark_session_workspace(root / UNIDENTIFIED_SESSION_ID)
    for name in STALE_REAL_SESSIONS:
        mark_session_workspace(root / name)


def _sweep_everything_unused() -> list:
    """A sweep that finds every marked workspace stale, wherever it sits in the root."""
    return sessions.sweep_stale_workspaces(3600, now=time.time() + 7200)


def test_the_sweep_leaves_a_directory_named_for_the_unidentified_caller(root) -> None:
    _marked_workspaces(root)

    removed = _sweep_everything_unused()

    assert sorted(removed) == STALE_REAL_SESSIONS
    assert (root / UNIDENTIFIED_SESSION_ID).is_dir()
    assert not any((root / name).exists() for name in STALE_REAL_SESSIONS)


def test_the_sweep_goes_on_past_a_name_the_session_registry_refuses(
    root, monkeypatch
) -> None:
    _marked_workspaces(root)
    # Nothing is reserved here, so the registry's own refusal of the name is
    # what the sweep meets at that entry.
    monkeypatch.setattr(session_identity, "is_reserved_session_id", lambda _id: False)

    removed = _sweep_everything_unused()

    assert sorted(removed) == STALE_REAL_SESSIONS
    assert (root / UNIDENTIFIED_SESSION_ID).is_dir()
    assert not any((root / name).exists() for name in STALE_REAL_SESSIONS)
