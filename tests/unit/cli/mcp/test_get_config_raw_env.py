# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config(raw=True) returns a config file as written, environment references included.

Why this file exists
--------------------
``yaml.safe_load`` has no constructor for ``!ENV``. Read with it, an operator
config that uses ``!ENV``, which ASH's own loader supports, would fail with
``ConstructorError: could not determine a constructor for the tag '!ENV'``, and
raw mode would be unusable for exactly the configs that keep values out of the
file. ASH's loader, for its part, resolves every string starting with ``${``, so
a TOML config read through it would hand the client values read from the
server's environment.

Raw mode parses the file without reading the environment. It never
returns a value from the environment, for an operator's file or a client's. (A
client's file that uses ``!ENV`` may instead be refused with
``config_env_not_resolved`` where the server refuses such files; either way, no
environment value.)

Each value ASH's loader would take from the environment comes back as the string
``!ENV `` followed by the reference as written: an ``!ENV`` scalar, a plain YAML
scalar shaped like ``${VAR:default}`` (the loader resolves those implicitly), and
a TOML string starting with ``${``. A quoted YAML string that only looks like a
reference is a literal the loader keeps, and comes back as written, without the
prefix. Raw mode first returned all of these as the bare reference, so a client
could not tell ``!ENV ${VAR:d}`` from the literal ``"${VAR:d}"``.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config

pytestmark = pytest.mark.unit

SENTINEL = "value-from-the-servers-environment"


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.setenv("ASH_TEST_TOKEN", SENTINEL)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def _assert_never_resolved(result) -> None:
    assert SENTINEL not in json.dumps(result, default=str), (
        "raw mode returned a value read from the server's environment"
    )


def test_an_env_tag_in_an_operator_yaml(tmp_path):
    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  severity_threshold: !ENV ${ASH_TEST_THRESHOLD:HIGH}\n"
        "  token: !ENV ${ASH_TEST_TOKEN:unset}\n",
        encoding="utf-8",
    )

    result = mcp_get_config(config_path=str(config), raw=True)

    assert result == {
        "project_name": "demo",
        "global_settings": {
            "severity_threshold": "!ENV ${ASH_TEST_THRESHOLD:HIGH}",
            "token": "!ENV ${ASH_TEST_TOKEN:unset}",
        },
    }
    _assert_never_resolved(result)


def test_a_plain_reference_in_an_operator_yaml(tmp_path):
    """ASH's loader resolves a bare ${VAR} scalar too; raw mode says so."""
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: ${ASH_TEST_TOKEN:unset}\n", encoding="utf-8")

    result = mcp_get_config(config_path=str(config), raw=True)

    assert result == {"project_name": "!ENV ${ASH_TEST_TOKEN:unset}"}
    _assert_never_resolved(result)


@pytest.mark.parametrize(
    "written", ['"${ASH_TEST_TOKEN:unset}"', "'${ASH_TEST_TOKEN:unset}'"]
)
def test_a_quoted_literal_is_told_apart_from_a_reference(tmp_path, written):
    """The loader keeps a quoted string as it is; raw mode returns it so."""
    from automated_security_helper.config.config_sources import read_config_file

    config = tmp_path / ".ash.yaml"
    config.write_text(
        f"project_name: {written}\n"
        "global_settings:\n"
        "  severity_threshold: !ENV ${ASH_TEST_TOKEN:unset}\n",
        encoding="utf-8",
    )

    result = mcp_get_config(config_path=str(config), raw=True)

    assert result["project_name"] == "${ASH_TEST_TOKEN:unset}"
    assert result["global_settings"]["severity_threshold"] == (
        "!ENV ${ASH_TEST_TOKEN:unset}"
    )
    # The rule raw mode follows is the loader's: it keeps the literal.
    assert read_config_file(config)["project_name"] == "${ASH_TEST_TOKEN:unset}"


@pytest.mark.parametrize(
    "name,text",
    [
        (".ash.toml", 'project_name = "${ASH_TEST_TOKEN:unset}"\n'),
        ("pyproject.toml", '[tool.ash]\nproject_name = "${ASH_TEST_TOKEN:unset}"\n'),
    ],
    ids=["ash-toml", "pyproject"],
)
def test_a_reference_in_an_operator_toml(tmp_path, name, text):
    config = tmp_path / name
    config.write_text(text, encoding="utf-8")

    result = mcp_get_config(config_path=str(config), raw=True)

    assert result == {"project_name": "!ENV ${ASH_TEST_TOKEN:unset}"}
    _assert_never_resolved(result)


def test_the_resolved_config_reads_the_environment(tmp_path, monkeypatch):
    """Raw mode aside, the resolved config is what a scan would use.

    The configuration the tool resolves, which is the one a scan uses, takes the
    environment's value: LOW with the variable set, the file's default HIGH
    without it. What the client sees of it is the reference the value was read
    through, at its place, however short, and the default as it is. Raw mode
    shows the reference as written instead.
    """
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "global_settings:\n  severity_threshold: !ENV ${ASH_TEST_THRESHOLD:HIGH}\n",
        encoding="utf-8",
    )

    def in_effect() -> str:
        # Resolved as mcp_get_config resolves a named file.
        resolved = resolve_config(
            config_path=config, source_dir=default_confinement_root(config)
        )
        return resolved.global_settings.severity_threshold

    monkeypatch.setenv("ASH_TEST_THRESHOLD", "LOW")
    assert in_effect() == "LOW"
    result = mcp_get_config(config_path=str(config))
    assert (
        result["global_settings"]["severity_threshold"]
        == "<from ${ASH_TEST_THRESHOLD:HIGH}>"
    ), result

    monkeypatch.delenv("ASH_TEST_THRESHOLD")
    assert in_effect() == "HIGH"
    result = mcp_get_config(config_path=str(config))
    assert result["global_settings"]["severity_threshold"] == "HIGH", result


def test_a_config_a_client_delivered(tmp_path, monkeypatch):
    workspace = tmp_path / "workspaces"
    delivered = workspace / "session-a" / "source"
    delivered.mkdir(parents=True)
    config = delivered / ".ash.yaml"
    config.write_text("project_name: !ENV ${ASH_TEST_TOKEN:unset}\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))

    result = mcp_get_config(config_path=str(config), raw=True, session_id="session-a")

    _assert_never_resolved(result)
    if result.get("success") is False:
        assert result["error_type"] == "config_env_not_resolved", result
    else:
        assert result == {"project_name": "!ENV ${ASH_TEST_TOKEN:unset}"}
