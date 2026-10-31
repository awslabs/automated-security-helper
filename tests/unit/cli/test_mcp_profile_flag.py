# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash mcp --profile`` reaches the profile registry.

``mcp_command`` declares ``--profile`` and registers each ``NAME=path`` it gets,
but ``ash mcp`` is the typer wrapper in ``cli/main.py``, which declares every
option again and forwards it. The wrapper did not declare ``--profile``, so the
documented ``ash mcp --profile default=/etc/ash/default.yaml`` failed with ``No
such option`` while tests calling ``mcp_command`` directly passed. These tests
go through the wrapper, and the last one checks that the two option sets stay
the same, so the next option added to one and not the other fails here too.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    get_profile_registry,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolate(monkeypatch) -> None:
    """An empty registry, no real server, and no environment change left behind.

    ``mcp_command`` sets ``ASH_LOG_TO_STDERR`` for the process; setting it here
    first makes monkeypatch restore it afterwards.
    """
    monkeypatch.setenv("ASH_LOG_TO_STDERR", "1")
    clear_profile_registry()
    yield
    clear_profile_registry()


@pytest.fixture
def server_start(monkeypatch) -> dict:
    """Stand in for the stdio server, recording the registry it would serve."""
    seen: dict = {}

    def _fake_run() -> None:
        seen["registry"] = get_profile_registry()

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.run_mcp_server", _fake_run
    )
    return seen


def _profile(tmp_path: Path, name: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(f"project_name: {name}\n", encoding="utf-8")
    return path


def test_each_profile_is_registered_before_the_server_starts(
    tmp_path: Path, server_start: dict
) -> None:
    default = _profile(tmp_path, "default")
    strict = _profile(tmp_path, "strict")

    result = CliRunner().invoke(
        ash_app,
        [
            "mcp",
            "--quiet",
            "--profile",
            f"default={default}",
            "--profile",
            f"strict={strict}",
        ],
    )

    assert result.exit_code == 0, result.output
    registry = server_start["registry"]
    assert sorted(registry) == ["default", "strict"]
    assert registry["default"].path == default
    assert registry["strict"].path == strict
    assert registry["strict"].config.project_name == "strict"


def test_a_profile_that_does_not_load_stops_startup(
    tmp_path: Path, server_start: dict
) -> None:
    """The spec reaches validation: a missing file exits 3 and no server starts."""
    result = CliRunner().invoke(
        ash_app,
        ["mcp", "--quiet", "--profile", f"default={tmp_path / 'absent.yaml'}"],
    )

    assert result.exit_code == 3, result.output
    assert "registry" not in server_start
    assert get_profile_registry() == {}


def test_a_profile_inside_a_scanned_checkout_stops_startup(
    tmp_path: Path, server_start: dict, monkeypatch
) -> None:
    """A profile kept in a git checkout under a granted scan root is refused at
    registration (its owner could rewrite it before the scan), so the server
    exits 3 and never starts."""
    allowed = tmp_path / "allowed"
    checkout = allowed / "checkout"
    (checkout / ".git").mkdir(parents=True)
    profile = _profile(checkout, "default")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(allowed))

    result = CliRunner().invoke(
        ash_app, ["mcp", "--quiet", "--profile", f"default={profile}"]
    )

    assert result.exit_code == 3, result.output
    assert "registry" not in server_start
    assert get_profile_registry() == {}


def test_without_profile_nothing_is_registered(server_start: dict) -> None:
    result = CliRunner().invoke(ash_app, ["mcp", "--quiet"])

    assert result.exit_code == 0, result.output
    assert server_start["registry"] == {}


def test_the_wrapper_declares_every_option_mcp_command_does() -> None:
    """Every ``mcp_command`` parameter is an ``ash mcp`` option, and no other.

    Compared by parameter name: the wrapper spells some boolean flags
    differently (``--verbose/--no-verbose`` against ``--verbose``/``-v``), which
    is a separate question from whether the option reaches ``mcp_command`` at all.
    """
    # add_completion=False: a one-command app otherwise gains typer's
    # --install-completion and --show-completion, which are not mcp_command's.
    direct = typer.Typer(add_completion=False)
    direct.command()(mcp_command)
    expected = {param.name for param in typer.main.get_command(direct).params}

    group = typer.main.get_command(ash_app)
    wrapper = group.commands["mcp"]  # type: ignore[attr-defined]
    declared = {param.name for param in wrapper.params}

    assert declared == expected
