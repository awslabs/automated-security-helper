# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A named config is set aside for the stdio session only when the caller is the stdio session.

``client_named_config_is_untrusted`` sets aside the profile files the server
writes in the calling session's ``config/`` directory. The calling session was
read as ``session_id or DEFAULT_SESSION_ID``, so a call for the id "" was judged
by the stdio session's sandbox, and the stdio session's own profile file read as
set aside for that caller. An empty string is a session of its own
(profile_registry's reading, pinned by
test_an_empty_session_id_is_not_the_stdio_session.py) with no sandbox of its own,
so nothing is set aside for it; only None is the stdio session here too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    SESSION_CONFIG_FILENAME,
)
from automated_security_helper.cli.mcp.sandbox import (
    CONFIG_DIR_NAME,
    client_named_config_is_untrusted,
)
from automated_security_helper.cli.mcp.session_paths import mark_session_workspace

pytestmark = pytest.mark.unit


@pytest.fixture
def stdio_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The profile file the server wrote for the stdio session."""
    root = tmp_path / "workspaces"
    root.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    config_dir = mark_session_workspace(root / DEFAULT_SESSION_ID) / CONFIG_DIR_NAME
    config_dir.mkdir()
    profile = config_dir / SESSION_CONFIG_FILENAME
    profile.write_text("project_name: x\n", encoding="utf-8")
    return profile


def test_the_stdio_sessions_own_profile_is_set_aside_for_it(stdio_profile) -> None:
    assert client_named_config_is_untrusted(stdio_profile, session_id=None) is False


def test_an_empty_session_id_is_not_judged_by_the_stdio_sandbox(stdio_profile) -> None:
    assert client_named_config_is_untrusted(stdio_profile, session_id="") is True


def test_another_session_is_not_judged_by_the_stdio_sandbox_either(
    stdio_profile,
) -> None:
    assert client_named_config_is_untrusted(stdio_profile, session_id="other") is True
