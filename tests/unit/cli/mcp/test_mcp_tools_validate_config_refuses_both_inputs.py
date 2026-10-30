# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_config`` given both inputs refuses, instead of answering for one of them.

The tool documents ``config_content`` and ``config_path`` as mutually exclusive.
Given both, it validated the content alone and answered as if for the request,
so a caller read one input's result under the other's name. It now refuses
before anything is read, in the shape of its missing-input refusal.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _local_caller(monkeypatch, tmp_path):
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))


def test_both_inputs_are_refused_as_conflicting(tmp_path) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config = tmp_path / "ash.yaml"
    config.write_text("project_name: on-disk\n", encoding="utf-8")

    result = mcp_validate_config(
        config_content="project_name: in-the-request\n", config_path=str(config)
    )

    assert result["valid"] is False, result
    assert [e["type"] for e in result["errors"]] == ["conflicting_input"], result
    assert "not both" in result["errors"][0]["message"], result
    assert result["warnings"] == [], result


def test_one_input_alone_still_validates(tmp_path) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    config = tmp_path / "ash.yaml"
    config.write_text("project_name: on-disk\n", encoding="utf-8")

    by_path = mcp_validate_config(config_path=str(config))
    by_content = mcp_validate_config(config_content="project_name: in-the-request\n")

    assert by_path["valid"] is True, by_path
    assert by_content["valid"] is True, by_content
