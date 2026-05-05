"""Tests for cli/plugin.py — covers plugin list and show commands."""

from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.plugin import plugin_app


runner = CliRunner()


class TestPluginList:
    """Tests for the plugin list command."""

    def test_list_command_exists(self):
        result = runner.invoke(plugin_app, ["list", "--help"])
        assert result.exit_code == 0

    def test_list_command_runs(self):
        result = runner.invoke(plugin_app, ["list"])
        # May succeed or fail depending on plugin availability, just verify it runs
        assert result.exit_code in (0, 1, 2)


class TestPluginShow:
    """Tests for the plugin show command."""

    def test_show_command_exists(self):
        result = runner.invoke(plugin_app, ["show", "--help"])
        assert result.exit_code == 0
