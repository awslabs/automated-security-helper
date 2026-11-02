# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Raw ``get_config`` answers a mapping, or refuses the file as unusable.

The tool documents a dict, and the wire carries one: a config file whose top
level is a list or a scalar came back as that list or scalar, a response no
client of the tool reads. Such a file is one the loader cannot use, so it is
refused as every other unusable config is, with exit code 3 and a reason that
names the kind of value at the top level, never the value itself.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _local_caller(monkeypatch, tmp_path):
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))


def _raw(path) -> Any:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    return mcp_get_config(config_path=str(path), raw=True)


@pytest.mark.parametrize(
    "name,text,kind",
    [
        ("list.yaml", "- a\n- b\n", "a list"),
        ("list.json", "[1, 2]\n", "a list"),
        ("scalar.yaml", "just a word\n", "a string"),
    ],
)
def test_a_non_mapping_top_level_is_refused_as_a_config(
    tmp_path, name: str, text: str, kind: str
) -> None:
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    response = _raw(config)

    assert isinstance(response, dict), response
    assert response.get("success") is False, response
    assert response["exit_code"] == 3, response
    assert kind in response["error"], response
    assert "mapping" in response["error"], response
    # The value is the file's own: described by kind, never quoted.
    assert "just a word" not in response["error"], response


def test_a_mapping_is_still_answered_as_written(tmp_path) -> None:
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    response: Dict[str, Any] = _raw(config)

    assert response == {"project_name": "demo"}, response


def test_an_empty_file_is_an_empty_configuration(tmp_path) -> None:
    config = tmp_path / "empty.yaml"
    config.write_text("", encoding="utf-8")

    assert _raw(config) == {}
