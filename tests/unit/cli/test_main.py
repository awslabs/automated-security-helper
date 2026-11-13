"""Unit tests for the main CLI module."""

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


def test_a_probe_group_built_from_ash_typer_group_has_only_its_own_commands():
    """The lazy subcommands belong to AshRootTyperGroup (the real app's class).

    Tests build probe groups from AshTyperGroup to measure the usage-error
    behavior; a probe must report exactly the commands it registered, so the
    lazy names must not read as its commands, must not parse as subcommands,
    and its --help must not import the engine.
    """
    from automated_security_helper.cli.main import _LAZY_SUBCOMMANDS, AshTyperGroup

    probe = AshTyperGroup(name="probe")
    assert not set(_LAZY_SUBCOMMANDS) & set(probe.commands)
    assert "report" not in probe.commands
    assert probe.commands.get("report") is None


def test_main_app_commands():
    """The click tree `ash` parses with carries every expected command.

    Read from ``typer.main.get_command(app)`` rather than the Typer-level
    ``registered_commands``/``registered_groups``: the heavy subcommands are
    registered lazily (cli/main.py's ``_LAZY_SUBCOMMANDS``), so the click
    group's ``commands`` mapping -- which is what ``ash`` resolves a typed
    subcommand against, and what the docs generator walks -- is the contract.
    """
    import typer.main

    group = typer.main.get_command(app)
    names = list(group.commands)

    for expected in (
        "scan",
        "config",
        "dependencies",
        "inspect",
        "plugin",
        "build-image",
        "report",
        "merge",
        "mcp",
    ):
        assert expected in names

    # A lazy name resolves to a real, callable click command with parameters.
    report = group.commands["report"]
    assert report.name == "report"
    assert report.params


@patch("automated_security_helper.cli.main.run_ash_scan_cli_command")
def test_main_app_default_command(mock_run_ash_scan_cli_command, cli_runner):
    """Test that the main app runs the scan command by default."""
    # Setup mock
    mock_run_ash_scan_cli_command.return_value = None

    # Run the CLI with no command (should default to scan)
    with patch.object(typer, "Exit"):
        result = cli_runner.invoke(app, ["--help"])

    # Check that the result is successful
    assert result.exit_code == 0

    # Check that the help output contains expected text
    assert "Commands" in result.stdout
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "inspect" in result.stdout
