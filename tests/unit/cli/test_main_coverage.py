"""Tests for cli/main.py — covers app registration, mcp_wrapper, get_genai_guide, reset_logging."""

import logging
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app, reset_logging_config, run_app


runner = CliRunner()


class TestResetLoggingConfig:
    """Tests for reset_logging_config."""

    def test_removes_ashs_handlers_from_root_logger(self):
        from automated_security_helper.utils.log import ash_handler

        root = logging.getLogger()
        handler = ash_handler(logging.StreamHandler())
        root.addHandler(handler)
        reset_logging_config()
        assert handler not in root.handlers

    def test_removes_ashs_handlers_from_ash_logger(self):
        from automated_security_helper.utils.log import ash_handler

        ash_logger = logging.getLogger("ash")
        handler = ash_handler(logging.StreamHandler())
        ash_logger.addHandler(handler)
        reset_logging_config()
        assert handler not in ash_logger.handlers

    def test_keeps_a_handler_ash_did_not_add(self):
        """An application that embeds ASH may have its own handlers on these."""
        root, ash_logger = logging.getLogger(), logging.getLogger("ash")
        on_root, on_ash = logging.StreamHandler(), logging.StreamHandler()
        root.addHandler(on_root)
        ash_logger.addHandler(on_ash)
        try:
            reset_logging_config()
            assert on_root in root.handlers
            assert on_ash in ash_logger.handlers
        finally:
            root.removeHandler(on_root)
            ash_logger.removeHandler(on_ash)

    def test_disables_ash_propagation(self):
        reset_logging_config()
        ash_logger = logging.getLogger("ash")
        assert ash_logger.propagate is False


class TestRunApp:
    """Tests for run_app."""

    def test_calls_app(self):
        with patch("automated_security_helper.cli.main.app") as mock_app:
            mock_app.side_effect = SystemExit(0)
            with pytest.raises(SystemExit):
                run_app()
            mock_app.assert_called_once()


class TestMcpWrapper:
    """Tests for the mcp command wrapper."""

    def test_mcp_command_help(self):
        result = runner.invoke(app, ["mcp", "--help"])
        assert result.exit_code == 0
        assert "MCP" in result.output or "mcp" in result.output.lower()


class TestGetGenaiGuide:
    """Tests for get-genai-guide command."""

    def test_from_local_file(self, tmp_path):
        """From a checkout the command writes the docs page, byte for byte.

        It reads no network in this case, so nothing can time out: the old
        allowance for exit 1 and 2 only hid a failed write.
        """
        guide_path = (
            Path(__file__).parent.parent.parent.parent
            / "docs"
            / "content"
            / "docs"
            / "genai-steering-guide.md"
        )

        output_path = tmp_path / "guide.md"
        result = runner.invoke(app, ["get-genai-guide", "--output", str(output_path)])

        assert result.exit_code == 0, result.output
        assert output_path.read_bytes() == guide_path.read_bytes()

    def test_from_github(self, tmp_path):
        output_path = tmp_path / "guide.md"
        mock_response = MagicMock()
        mock_response.text = "# Guide from GitHub"
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            result = runner.invoke(
                app,
                ["get-genai-guide", "--output", str(output_path), "--from-github"],
            )
            assert result.exit_code == 0
            assert output_path.exists()

    def test_it_offers_no_section_the_guide_dropped(self, tmp_path):
        """Neither the help nor the message after a download offers the
        "Severity Discrepancies" section, which the guide does not have.

        Every report grades a finding the same way, so the guide does not say
        Markdown and JSON can disagree, and the command must not promise to
        explain how to handle that.
        """
        guide = (
            Path(__file__).parents[3]
            / "docs"
            / "content"
            / "docs"
            / "genai-steering-guide.md"
        ).read_text(encoding="utf-8")
        assert "discrepanc" not in guide.lower()
        output_path = tmp_path / "guide.md"

        with patch("requests.get", side_effect=AssertionError("network")):
            shown = runner.invoke(app, ["get-genai-guide", "--help"])
            downloaded = runner.invoke(
                app, ["get-genai-guide", "--output", str(output_path)]
            )

        assert shown.exit_code == 0
        assert downloaded.exit_code == 0, downloaded.output
        assert output_path.read_text(encoding="utf-8") == guide
        assert "discrepanc" not in shown.output.lower()
        assert "discrepanc" not in downloaded.output.lower()

    def test_github_fetch_failure(self, tmp_path):
        import requests

        output_path = tmp_path / "guide.md"

        with patch("requests.get", side_effect=requests.RequestException("timeout")):
            # Mock local file not existing
            with patch("pathlib.Path.exists", return_value=False):
                result = runner.invoke(
                    app,
                    [
                        "get-genai-guide",
                        "--output",
                        str(output_path),
                        "--from-github",
                    ],
                )
                assert result.exit_code == 1


class TestAppStructure:
    """Tests for app command registration."""

    def test_help_shows_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "config" in result.output
        assert "report" in result.output

    def test_config_subcommand(self):
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0

    def test_inspect_subcommand(self):
        result = runner.invoke(app, ["inspect", "--help"])
        assert result.exit_code == 0

    def test_dependencies_subcommand(self):
        result = runner.invoke(app, ["dependencies", "--help"])
        assert result.exit_code == 0
