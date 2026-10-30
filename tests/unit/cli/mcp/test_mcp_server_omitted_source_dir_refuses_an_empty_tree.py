# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""run_ash_scan with no usable source_dir never scans a tree that holds nothing.

Two gaps in the no-argument form. A delivered tree that was on disk but empty
passed the existence check and was scanned, and an empty tree scans clean: the
false negative the refusal of a gone tree exists to prevent. And an empty
string for ``source_dir`` is not None, so it skipped the omitted-form
resolution and the scan ran on the server's working directory, which the
omitted form exists to refuse. An empty tree is now refused as a gone one is,
and a blank ``source_dir`` is the omitted form.

A third gap followed: the check took any entry in the listing for a tree to
scan, so a tree of empty directories, or a bare ``.git`` directory left where a
checkout never landed, was scanned and reported clean. The check now walks to
the first regular file, ``.git`` aside, and a tree with none is refused too.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp_server import (
    _OmittedSourceResolution,
    _resolve_omitted_source_dir,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_session_registry(monkeypatch):
    # A header-less ctx is the stdio session only while no HTTP transport is
    # set in the environment; with one set, the blank source_dir case is refused
    # before the branch it pins, for a reason that is not this file's.
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    saved = dict(sd._SESSION_SOURCE_DIRS)
    sd._SESSION_SOURCE_DIRS.clear()
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    sd._SESSION_SOURCE_DIRS.update(saved)


def test_an_empty_delivered_tree_is_refused(tmp_path) -> None:
    delivered = tmp_path / "session-a" / "source"
    delivered.mkdir(parents=True)
    sd._set_session_source_dir("session-a", delivered)

    resolution = _resolve_omitted_source_dir("session-a")

    assert resolution.source_dir is None, "an empty tree was handed to the scan"
    assert resolution.error is not None
    assert resolution.error["error_type"] == "delivered_source_missing"
    assert "Deliver it again" in resolution.error["error"]


def test_a_tree_of_empty_directories_is_refused(tmp_path) -> None:
    """Red at the base: a directory entry counted as something to scan."""
    delivered = tmp_path / "session-c" / "source"
    (delivered / "src" / "pkg").mkdir(parents=True)
    (delivered / "docs").mkdir()
    sd._set_session_source_dir("session-c", delivered)

    resolution = _resolve_omitted_source_dir("session-c")

    assert resolution.source_dir is None, "a tree with no file was handed to the scan"
    assert resolution.error is not None
    assert resolution.error["error_type"] == "delivered_source_missing"


def test_a_tree_holding_only_a_git_directory_is_refused(tmp_path) -> None:
    """Red at the base: a clone whose checkout never landed left ``.git`` alone,
    and that entry counted."""
    delivered = tmp_path / "session-d" / "source"
    (delivered / ".git" / "objects").mkdir(parents=True)
    (delivered / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    sd._set_session_source_dir("session-d", delivered)

    resolution = _resolve_omitted_source_dir("session-d")

    assert resolution.source_dir is None, "a bare .git was handed to the scan"
    assert resolution.error is not None
    assert resolution.error["error_type"] == "delivered_source_missing"


def test_a_file_below_an_empty_top_level_is_used(tmp_path) -> None:
    delivered = tmp_path / "session-e" / "source"
    (delivered / "src" / "pkg").mkdir(parents=True)
    (delivered / "src" / "pkg" / "app.py").write_text("x = 1\n", encoding="utf-8")
    sd._set_session_source_dir("session-e", delivered)

    resolution = _resolve_omitted_source_dir("session-e")

    assert resolution.error is None
    assert resolution.source_dir == str(delivered)


def test_a_delivered_tree_with_a_file_is_used(tmp_path) -> None:
    delivered = tmp_path / "session-b" / "source"
    delivered.mkdir(parents=True)
    (delivered / "app.py").write_text("x = 1\n", encoding="utf-8")
    sd._set_session_source_dir("session-b", delivered)

    resolution = _resolve_omitted_source_dir("session-b")

    assert resolution.error is None
    assert resolution.source_dir == str(delivered)


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_source_dir_is_the_omitted_form(monkeypatch, blank: str) -> None:
    from automated_security_helper.cli import mcp_server

    refusal = _OmittedSourceResolution(
        error={
            "success": False,
            "error": "nothing delivered",
            "error_type": "delivered_source_missing",
        }
    )
    resolver = MagicMock(return_value=refusal)
    monkeypatch.setattr(mcp_server, "_resolve_omitted_source_dir", resolver)
    started = AsyncMock()
    monkeypatch.setattr(mcp_server, "mcp_scan_directory", started)
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())

    result = asyncio.run(mcp_server.run_ash_scan(ctx, source_dir=blank))

    assert resolver.call_count == 1, "a blank source_dir skipped the omitted form"
    assert result.get("error_type") == "delivered_source_missing", result
    assert not started.called, "the scan ran on the server's working directory"
