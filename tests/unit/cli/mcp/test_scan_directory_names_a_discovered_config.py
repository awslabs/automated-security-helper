# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP scan_directory refuses a discovered config that cannot be used, and names it.

With no ``config_path``, the scan discovers the target's config. One that does
not parse or does not validate used to start the scan, which then ended with
exit 3 and no word of the file. The tool now checks the discovered file as it
checks a named one (``sandbox.check_config_input``): before any scan starts it
answers with the refusal, naming the file, in the text that repeats none of a
client's or a repository's values. Every case here puts a marker on the line
the parser stops at, or in the value that does not validate, and checks the
marker is in neither the response nor the log.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)

CANARY = "CANARY-VALUE-5e2b"

#: (file name under the target, content). A defect of each kind discovery can
#: select a file with: a YAML, JSON and TOML name, under .ash/ and at the root.
BROKEN = [
    pytest.param(".ash/.ash.yaml", f"project_name: *{CANARY}\n", id="yaml-alias"),
    pytest.param(".ash.yml", f"project_name: [{CANARY}\n  : :\n", id="yaml-unparsable"),
    pytest.param(
        "ash.yaml",
        f"global_settings:\n  ignore_paths:\n    - path: [{CANARY}]\n      reason: r\n",
        id="yaml-invalid",
    ),
    pytest.param(".ash.json", '{"project_name": [' + f'"{CANARY}"' + "}", id="json"),
    pytest.param(".ashrc.toml", f'project_name = ["{CANARY}"\n', id="toml"),
    pytest.param("ashrc.yaml", b"project_name: \xff\xfe\n", id="not-utf8"),
]


@pytest.fixture
def target(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    return scan


def _scan(target: Path):
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(mcp_scan_directory(directory_path=str(target)))
    return result, started.called


def _write(path: Path, content) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize(("name", "content"), BROKEN)
def test_a_discovered_config_that_cannot_be_used_is_refused_and_named(
    target, caplog, name, content
):
    _write(target / name, content)

    with caplog.at_level(logging.DEBUG):
        result, started = _scan(target)

    assert started is False, result
    assert result["success"] is False, result
    assert result.get("error_category") == "invalid_format", result
    assert Path(name).name in result["error"], result
    assert CANARY not in repr(result)
    assert CANARY not in caplog.text
    assert not (target / ".ash" / "ash_output").exists()


@pytest.mark.parametrize("named", [False, True], ids=["discovered", "named"])
def test_a_config_that_is_a_link_to_itself_is_refused_and_named(target, named):
    """A response, not an exception out of the tool: Path.resolve raises
    RuntimeError for such a link on Python 3.12 and older."""
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    config = target / ".ash.yaml"
    config.symlink_to(config.name)

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_scan_directory(
                directory_path=str(target),
                config_path=str(config) if named else None,
            )
        )

    assert started.called is False, result
    assert result["success"] is False, result
    assert ".ash.yaml" in result["error"], result


UNSET_VARIABLE = "ASH_TEST_UNSET_VARIABLE_5e2b"


@pytest.mark.parametrize(
    ("name", "content"),
    [
        pytest.param(
            ".ash/.ash.yaml",
            f"project_name: !ENV ${{{UNSET_VARIABLE}}}\n",
            id="yaml-explicit",
        ),
        pytest.param(
            ".ash.yml", f"project_name: ${{{UNSET_VARIABLE}}}\n", id="yaml-implicit"
        ),
        pytest.param(
            ".ashrc.toml", f'project_name = "${{{UNSET_VARIABLE}}}"\n', id="toml"
        ),
        pytest.param(
            "pyproject.toml",
            f'[tool.ash]\nproject_name = "${{{UNSET_VARIABLE}}}"\n',
            id="pyproject",
        ),
    ],
)
def test_a_discovered_config_reading_an_unset_variable_is_refused_and_named(
    target, monkeypatch, name, content
):
    """A value read from a variable that is not set, with no default, is one the
    file cannot supply: refused before the scan, naming the file and the variable."""
    monkeypatch.delenv(UNSET_VARIABLE, raising=False)
    _write(target / name, content)

    result, started = _scan(target)

    assert started is False, result
    assert result["success"] is False, result
    assert Path(name).name in result["error"], result
    assert UNSET_VARIABLE in result["error"], result
    assert not (target / ".ash" / "ash_output").exists()


def test_a_discovered_pyproject_that_declares_ash_but_does_not_parse(target, caplog):
    """Discovery refuses it, as the scan's own discovery does, naming the file."""
    _write(target / "pyproject.toml", f'[tool.ash]\nproject_name = "{CANARY}\n')

    with caplog.at_level(logging.DEBUG):
        result, started = _scan(target)

    assert started is False, result
    assert result["success"] is False, result
    assert result.get("error_category") == "invalid_format", result
    assert "pyproject.toml" in result["error"], result
    assert CANARY not in repr(result)


def test_control_a_usable_discovered_config_starts_the_scan(target):
    _write(target / ".ash" / ".ash.yaml", "project_name: fine\n")

    result, started = _scan(target)

    assert result["success"] is True, result
    assert started is True


def test_control_a_pyproject_without_an_ash_table_is_not_a_config(target):
    """Not a config source, so not refused, even when it is not valid TOML."""
    _write(target / "pyproject.toml", "[project\nname = 'x'\n")

    result, started = _scan(target)

    assert result["success"] is True, result
    assert started is True
