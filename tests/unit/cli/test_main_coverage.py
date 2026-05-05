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

    def test_removes_handlers_from_root_logger(self):
        root = logging.getLogger()
        handler = logging.StreamHandler()
        root.addHandler(handler)
        reset_logging_config()
        assert handler not in root.handlers

    def test_removes_handlers_from_ash_logger(self):
        ash_logger = logging.getLogger("ash")
        handler = logging.StreamHandler()
        ash_logger.addHandler(handler)
        reset_logging_config()
        assert handler not in ash_logger.handlers

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
        guide_content = "# GenAI Guide\nTest content"
        guide_path = (
            Path(__file__).parent.parent.parent.parent
            / "docs"
            / "content"
            / "docs"
            / "genai-steering-guide.md"
        )

        output_path = tmp_path / "guide.md"
        result = runner.invoke(
            app, ["get-genai-guide", "--output", str(output_path)]
        )
        # If guide file exists locally, it should succeed
        if guide_path.exists():
            assert result.exit_code == 0
            assert output_path.exists()
        # Otherwise it will try GitHub (which may timeout in tests)

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

    def test_github_fetch_failure(self, tmp_path):
        import requests

        output_path = tmp_path / "guide.md"

        with patch(
            "requests.get", side_effect=requests.RequestException("timeout")
        ):
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
