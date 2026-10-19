# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config that no longer loads leaves the per-session scan limit at its default.

The limit is read from ``ASH_CONFIG`` for every scan, so an operator's file can
be changed or broken while the server runs. A file that does not load must not
fail the scan being started, and must not lift the limit: the caller gets the
default of 2, the same as with no config at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import sessions

REMOTE_SESSION = "issued-session-1"


@pytest.fixture(autouse=True)
def network_caller(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    sessions.reset_default_registry_for_tests()
    yield
    sessions.reset_default_registry_for_tests()


def _config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "operator.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_limit_comes_from_a_config_that_loads(tmp_path, monkeypatch) -> None:
    config = _config(
        tmp_path,
        "project_name: operator\n"
        "mcp-resource-management:\n"
        "  max_concurrent_scans_per_session: 5\n",
    )
    monkeypatch.setenv("ASH_CONFIG", str(config))

    assert sessions.per_session_scan_limit(REMOTE_SESSION) == 5


def test_no_config_gives_the_default_limit() -> None:
    assert sessions.per_session_scan_limit(REMOTE_SESSION) == 2


def test_a_malformed_config_leaves_the_default_limit(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(
        "ASH_CONFIG", str(_config(tmp_path, "project_name: {unclosed\n"))
    )

    assert sessions.per_session_scan_limit(REMOTE_SESSION) == 2


def test_a_missing_config_file_leaves_the_default_limit(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "gone.yaml"))

    assert sessions.per_session_scan_limit(REMOTE_SESSION) == 2
