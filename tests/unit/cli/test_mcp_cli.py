# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the MCP CLI command wrapper (automated_security_helper/cli/mcp.py).

Tests cover validate_log_options, validate_command_options, validate_mcp_dependencies,
and the mcp_command Typer callback including error handling paths.
"""

from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ASHValidationError, ScannerError
from automated_security_helper.cli.mcp import (
    validate_log_options,
    validate_command_options,
    validate_mcp_dependencies,
    mcp_command,
)


# ---------------------------------------------------------------------------
# Tests for validate_log_options
# ---------------------------------------------------------------------------


class TestValidateLogOptions:
    def test_debug_flag_overrides_everything(self):
        result = validate_log_options(verbose=True, debug=True, log_level=AshLogLevel.ERROR)
        assert result == AshLogLevel.DEBUG

    def test_verbose_flag_when_debug_false(self):
        result = validate_log_options(verbose=True, debug=False, log_level=AshLogLevel.ERROR)
        assert result == AshLogLevel.VERBOSE

    def test_returns_explicit_log_level_when_no_flags(self):
        result = validate_log_options(verbose=False, debug=False, log_level=AshLogLevel.TRACE)
        assert result == AshLogLevel.TRACE

    def test_default_info_level(self):
        result = validate_log_options(verbose=False, debug=False, log_level=AshLogLevel.INFO)
        assert result == AshLogLevel.INFO


# ---------------------------------------------------------------------------
# Tests for validate_command_options
# ---------------------------------------------------------------------------


class TestValidateCommandOptions:
    def test_quiet_with_verbose_raises(self):
        with pytest.raises(ASHValidationError):
            validate_command_options(verbose=True, debug=False, quiet=True)

    def test_quiet_with_debug_raises(self):
        with pytest.raises(ASHValidationError):
            validate_command_options(verbose=False, debug=True, quiet=True)

    def test_quiet_with_both_raises(self):
        with pytest.raises(ASHValidationError):
            validate_command_options(verbose=True, debug=True, quiet=True)

    def test_quiet_alone_passes(self):
        # Should not raise
        validate_command_options(verbose=False, debug=False, quiet=True)

    def test_verbose_without_quiet_passes(self):
        validate_command_options(verbose=True, debug=False, quiet=False)

    def test_all_false_passes(self):
        validate_command_options(verbose=False, debug=False, quiet=False)


# ---------------------------------------------------------------------------
# Tests for validate_mcp_dependencies
# ---------------------------------------------------------------------------


class TestValidateMcpDependencies:
    @patch("automated_security_helper.cli.mcp.FastMCP", new=object())
    @patch("automated_security_helper.cli.mcp.Context", new=object())
    def test_returns_true_when_both_available(self):
        assert validate_mcp_dependencies() is True

    @patch("automated_security_helper.cli.mcp.FastMCP", new=None)
    @patch("automated_security_helper.cli.mcp.Context", new=object())
    def test_returns_false_when_fastmcp_missing(self):
        assert validate_mcp_dependencies() is False

    @patch("automated_security_helper.cli.mcp.FastMCP", new=object())
    @patch("automated_security_helper.cli.mcp.Context", new=None)
    def test_returns_false_when_context_missing(self):
        assert validate_mcp_dependencies() is False

    @patch("automated_security_helper.cli.mcp.FastMCP", new=None)
    @patch("automated_security_helper.cli.mcp.Context", new=None)
    def test_returns_false_when_both_missing(self):
        assert validate_mcp_dependencies() is False


# ---------------------------------------------------------------------------
# Tests for mcp_command
# ---------------------------------------------------------------------------


@pytest.fixture
def typer_ctx():
    """Create a mock typer.Context."""
    ctx = MagicMock(spec=typer.Context)
    ctx.resilient_parsing = False
    return ctx


class TestMcpCommand:
    def test_resilient_parsing_returns_early(self, typer_ctx):
        typer_ctx.resilient_parsing = True
        # Should return None without side effects
        result = mcp_command(typer_ctx)
        assert result is None

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=False)
    def test_missing_deps_exits_with_code_1(self, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx)
        assert exc_info.value.exit_code == 1

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch("automated_security_helper.cli.mcp_server.run_mcp_server")
    def test_successful_server_start(self, mock_run, _mock_deps, typer_ctx):
        mcp_command(typer_ctx, quiet=True)
        mock_run.assert_called_once()

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch("automated_security_helper.cli.mcp_server.run_mcp_server")
    def test_not_quiet_prints_startup_message(self, mock_run, _mock_deps, typer_ctx):
        # Should not raise; exercises the print branch when quiet=False
        mcp_command(typer_ctx, quiet=False)
        mock_run.assert_called_once()

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=KeyboardInterrupt,
    )
    def test_keyboard_interrupt_exits_0(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=True)
        assert exc_info.value.exit_code == 0

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=KeyboardInterrupt,
    )
    def test_keyboard_interrupt_not_quiet(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=False)
        assert exc_info.value.exit_code == 0

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=ScannerError("scanner broke"),
    )
    def test_scanner_error_exits_2(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=True)
        assert exc_info.value.exit_code == 2

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=ScannerError("scanner broke"),
    )
    def test_scanner_error_not_quiet(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=False)
        assert exc_info.value.exit_code == 2

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=ASHValidationError("bad config"),
    )
    def test_validation_error_exits_3(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=True)
        assert exc_info.value.exit_code == 3

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=ASHValidationError("bad config"),
    )
    def test_validation_error_not_quiet(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=False)
        assert exc_info.value.exit_code == 3

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=RuntimeError("unexpected"),
    )
    def test_generic_exception_exits_1(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=True)
        assert exc_info.value.exit_code == 1

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        side_effect=RuntimeError("unexpected"),
    )
    def test_generic_exception_not_quiet(self, _mock_run, _mock_deps, typer_ctx):
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, quiet=False)
        assert exc_info.value.exit_code == 1

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch("automated_security_helper.cli.mcp_server.run_mcp_server")
    def test_quiet_with_verbose_raises_exit_3(self, _mock_run, _mock_deps, typer_ctx):
        """Options validation failure (quiet + verbose) raises Exit(3)."""
        with pytest.raises(typer.Exit) as exc_info:
            mcp_command(typer_ctx, verbose=True, quiet=True)
        assert exc_info.value.exit_code == 3

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch("automated_security_helper.cli.mcp_server.run_mcp_server")
    def test_debug_sets_log_level(self, mock_run, _mock_deps, typer_ctx):
        """Debug flag is passed through log level resolution."""
        mcp_command(typer_ctx, debug=True, quiet=False)
        mock_run.assert_called_once()

    @patch("automated_security_helper.cli.mcp.validate_mcp_dependencies", return_value=True)
    @patch("automated_security_helper.cli.mcp_server.run_mcp_server")
    def test_verbose_sets_log_level(self, mock_run, _mock_deps, typer_ctx):
        """Verbose flag is passed through log level resolution."""
        mcp_command(typer_ctx, verbose=True, quiet=False)
        mock_run.assert_called_once()
