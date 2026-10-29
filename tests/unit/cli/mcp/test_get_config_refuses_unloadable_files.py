# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP ``get_config`` answers a config file that does not load with an error.

Resolution refuses the file, as it does for a scan, and the tool returns that as
a structured response (``success`` False, ``error_category`` ``invalid_format``)
naming the file, rather than raising for the server's generic handler to turn
into "Error getting config" with a logged traceback, or answering with the
defaults.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config

pytestmark = pytest.mark.unit

BAD_YAML = "project_name: demo\nscanners: [bandit\n"


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _assert_error_response(result, name: str) -> None:
    assert result["success"] is False, result
    assert result["operation"] == "get_config"
    assert result["error_category"] == "invalid_format"
    assert name in result["error"]
    assert "scanners" not in result


def test_a_named_file_that_does_not_parse(tmp_path):
    path = tmp_path / "ash.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")

    _assert_error_response(mcp_get_config(config_path=str(path)), "ash.yaml")


def test_a_discovered_file_that_does_not_parse(tmp_path):
    (tmp_path / ".ash").mkdir()
    (tmp_path / ".ash" / ".ash.yaml").write_text(BAD_YAML, encoding="utf-8")

    _assert_error_response(mcp_get_config(search_dir=str(tmp_path)), ".ash.yaml")


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_discovery_that_cannot_read_the_only_source(tmp_path, raw):
    """Discovery refuses an unreadable pyproject.toml; that is a response too."""
    (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

    result = mcp_get_config(search_dir=str(tmp_path), raw=raw)

    assert result["success"] is False, result
    assert result["operation"] == "get_config"
    assert result["error_category"] == "file_not_found"
    assert "pyproject.toml" in result["error"]


@pytest.mark.parametrize("raw", [False, True], ids=["resolved", "raw"])
def test_a_discovered_dangling_link_is_reported_as_not_found(tmp_path, raw):
    (tmp_path / ".ash").mkdir()
    (tmp_path / ".ash" / ".ash.yaml").symlink_to(tmp_path / "not-checked-out.yaml")

    result = mcp_get_config(search_dir=str(tmp_path), raw=raw)

    assert result["success"] is False, result
    assert result["error_category"] == "file_not_found"
    assert ".ash.yaml" in result["error"]


def test_a_raw_read_of_a_file_that_does_not_parse(tmp_path):
    path = tmp_path / "ash.yaml"
    path.write_text(BAD_YAML, encoding="utf-8")

    result = mcp_get_config(config_path=str(path), raw=True)

    _assert_error_response(result, "ash.yaml")


def test_control_a_file_that_loads_is_returned(tmp_path):
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: demo\n", encoding="utf-8")

    result = mcp_get_config(config_path=str(path))

    assert result["project_name"] == "demo"
