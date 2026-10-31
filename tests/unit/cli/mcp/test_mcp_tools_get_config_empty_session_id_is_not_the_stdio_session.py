# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config judges a named file for its own session's delivered tree, never stdio's by accident.

With a named config and no search_dir, get_config judges the file for the
target a scan of this session would take: the session's delivered source, or
the working directory. The session was read as ``session_id or
DEFAULT_SESSION_ID``, so an empty-string session id fell back to the stdio
session and the answer was judged for the stdio client's delivered tree. An
empty string is a session of its own (profile_registry's reading, pinned by
test_an_empty_session_id_is_not_the_stdio_session.py), so only None is the
stdio session here too.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_get_config

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "scan-root"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    saved = dict(sd._SESSION_SOURCE_DIRS)
    sd._SESSION_SOURCE_DIRS.clear()
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    sd._SESSION_SOURCE_DIRS.update(saved)
    clear_profile_registry()
    clear_all_session_state()


def _named_config(tmp_path: Path) -> Path:
    repo = tmp_path / "scan-root" / "repo"
    repo.mkdir(parents=True)
    config = repo / ".ash.yaml"
    config.write_text("project_name: x\n", encoding="utf-8")
    return config


def _recording(monkeypatch) -> List[str]:
    asked: List[str] = []
    real = sd.get_session_source_dir

    def recorded(session_id: str):
        asked.append(session_id)
        return real(session_id)

    monkeypatch.setattr(sd, "get_session_source_dir", recorded)
    return asked


def test_an_empty_session_id_is_not_judged_for_the_stdio_delivery(
    tmp_path, monkeypatch
) -> None:
    stdio_tree = tmp_path / "workspaces" / DEFAULT_SESSION_ID / "source"
    stdio_tree.mkdir(parents=True)
    sd._set_session_source_dir(DEFAULT_SESSION_ID, stdio_tree)
    asked = _recording(monkeypatch)

    mcp_get_config(config_path=str(_named_config(tmp_path)), session_id="")

    assert asked, "the answer never asked which tree the session delivered"
    assert DEFAULT_SESSION_ID not in asked, asked
    assert "" in asked, asked


def test_no_session_id_is_the_stdio_session(tmp_path, monkeypatch) -> None:
    asked = _recording(monkeypatch)

    mcp_get_config(config_path=str(_named_config(tmp_path)), session_id=None)

    assert asked == [DEFAULT_SESSION_ID], asked
