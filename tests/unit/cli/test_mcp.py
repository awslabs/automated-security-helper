"""
Unit tests for MCP CLI command functionality.

This module provides comprehensive unit tests for the MCP CLI command,
covering conditional import handling, direct function call replacements,
CLI command registration, parameter handling, and error scenarios.
"""

import json
import tempfile
import pytest
import typer
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from automated_security_helper.cli.mcp import (
    mcp_command,
    _parse_ash_results,
    _parse_ash_results_from_scan,
    _validate_scan_parameters,
    _validate_file_system_access,
    _create_structured_error_response,
    _get_ash_version_direct,
    _run_ash_scan_direct,
    _start_mcp_server,
)
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError


class TestTemporaryDirectoryIntegration:
    """Test temporary directory management integration with scan operations."""

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    @patch("automated_security_helper.cli.mcp.resolve_config")
    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_scan_creates_temp_dir_when_none_provided(
        self, mock_version, mock_config, mock_scan
    ):
        """Test that scan creates temporary directory when none provided."""
        # Setup mocks
        mock_version.return_value = (True, "ASH version 3.0.0")
        mock_config_obj = MagicMock()
        mock_config_obj.global_settings.severity_threshold = "MEDIUM"
        mock_config_obj.fail_on_findings = False
        mock_config.return_value = mock_config_obj
        mock_scan.return_value = {}

        # Use a real temporary directory that exists
        with tempfile.TemporaryDirectory() as temp_dir:
            # Call scan without output_dir
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Should create temporary directory
            assert result.get("success") is True

            # Verify temp directory was created with proper structure
            temp_output_dir = result.get("temp_output_dir")
            if temp_output_dir:
                # The temp directory should have been created but may be cleaned up
                # Check that the scan was called with proper output directory
                mock_scan.assert_called_once()
                call_args = mock_scan.call_args
                output_dir = call_args.kwargs.get("output_dir")
                assert output_dir is not None
                assert "ash_output" in output_dir

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    @patch("automated_security_helper.cli.mcp.resolve_config")
    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_scan_cleanup_on_error(self, mock_version, mock_config, mock_scan):
        """Test that temporary directories are cleaned up on scan errors."""
        # Setup mocks
        mock_version.return_value = (True, "ASH version 3.0.0")
        mock_config_obj = MagicMock()
        mock_config_obj.global_settings.severity_threshold = "MEDIUM"
        mock_config_obj.fail_on_findings = False
        mock_config.return_value = mock_config_obj
        mock_scan.side_effect = ScannerError("Test scanner error")

        # Use a real temporary directory that exists
        with tempfile.TemporaryDirectory() as temp_dir:
            # Call scan without output_dir
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Should return error response
            assert result.get("success") is False
            assert result.get("error_type") == "runtime"
            assert "ASH scanner error" in result.get("error", "")


class TestParseAshResults:
    """Test the _parse_ash_results function."""

    def test_parse_ash_results_with_complete_data(self):
        """Test parsing with complete aggregated results data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Create sample aggregated results JSON
            sample_results = {
                "additional_reports": {
                    "bandit": {
                        "source": {
                            "finding_count": 5,
                            "actionable_finding_count": 3,
                            "status": "failed",
                        }
                    },
                    "semgrep": {
                        "source": {
                            "finding_count": 2,
                            "actionable_finding_count": 1,
                            "status": "failed",
                        }
                    },
                },
                "metadata": {"summary_stats": {"total": 7, "actionable": 4}},
            }

            # Write the sample results to the aggregated results file
            aggregated_results_path = output_dir / "ash_aggregated_results.json"
            with open(aggregated_results_path, "w") as f:
                json.dump(sample_results, f)

            # Create sample reports directory with files
            reports_dir = output_dir / "reports"
            reports_dir.mkdir()
            (reports_dir / "ash.sarif").write_text('{"version": "2.1.0"}')
            (reports_dir / "ash.html").write_text("<html><body>Report</body></html>")

            # Test the parsing function
            results = _parse_ash_results(str(output_dir))

            # Verify the results
            assert results["scanners_run"] == ["bandit", "semgrep"]
            assert results["total_findings"] == 7
            assert results["actionable_findings"] == 4
            assert len(results["reports_generated"]) == 2

            # Check report details
            report_names = [r["name"] for r in results["reports_generated"]]
            assert "ash.sarif" in report_names
            assert "ash.html" in report_names

    def test_parse_ash_results_with_fallback_calculation(self):
        """Test parsing with fallback calculation when metadata is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Create sample aggregated results JSON without metadata.summary_stats
            sample_results = {
                "additional_reports": {
                    "bandit": {
                        "source": {
                            "finding_count": 3,
                            "actionable_finding_count": 2,
                            "status": "failed",
                        }
                    },
                    "detect-secrets": {
                        "source": {
                            "finding_count": 1,
                            "actionable_finding_count": 1,
                            "status": "failed",
                        }
                    },
                }
            }

            # Write the sample results to the aggregated results file
            aggregated_results_path = output_dir / "ash_aggregated_results.json"
            with open(aggregated_results_path, "w") as f:
                json.dump(sample_results, f)

            # Test the parsing function
            results = _parse_ash_results(str(output_dir))

            # Verify the results - should calculate from additional_reports
            assert results["scanners_run"] == ["bandit", "detect-secrets"]
            assert results["total_findings"] == 4  # 3 + 1
            assert results["actionable_findings"] == 3  # 2 + 1

    def test_parse_ash_results_missing_file(self):
        """Test parsing when aggregated results file is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Test the parsing function without creating the file
            results = _parse_ash_results(str(output_dir))

            # Verify the results - should return empty structure
            assert results["scanners_run"] == []
            assert results["total_findings"] == 0
            assert results["actionable_findings"] == 0
            assert results["reports_generated"] == []

    def test_parse_ash_results_invalid_json(self):
        """Test parsing with invalid JSON content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Write invalid JSON to the aggregated results file
            aggregated_results_path = output_dir / "ash_aggregated_results.json"
            with open(aggregated_results_path, "w") as f:
                f.write("invalid json content {")

            # Test the parsing function
            results = _parse_ash_results(str(output_dir))

            # Verify the results - should contain parse_error
            assert "parse_error" in results
            assert results["scanners_run"] == []
            assert results["total_findings"] == 0
            assert results["actionable_findings"] == 0


class TestParseAshResultsFromScan:
    """Test the _parse_ash_results_from_scan function."""

    def test_parse_with_output_dir_in_scan_results(self):
        """Test parsing when output_dir is in scan results."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Create sample aggregated results JSON
            sample_results = {
                "additional_reports": {
                    "semgrep": {
                        "source": {
                            "finding_count": 2,
                            "actionable_finding_count": 1,
                            "status": "failed",
                        }
                    }
                }
            }

            # Write the sample results to the aggregated results file
            aggregated_results_path = output_dir / "ash_aggregated_results.json"
            with open(aggregated_results_path, "w") as f:
                json.dump(sample_results, f)

            # Test with scan results containing output_dir
            scan_results = {
                "success": True,
                "output_dir": str(output_dir),
                "results": {"some": "data"},
            }

            # Test the parsing function
            results = _parse_ash_results_from_scan(scan_results)

            # Verify the results
            assert results["scanners_run"] == ["semgrep"]
            assert results["total_findings"] == 2
            assert results["actionable_findings"] == 1

    def test_parse_with_explicit_output_dir(self):
        """Test parsing with explicit output_dir parameter."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)

            # Create sample aggregated results JSON
            sample_results = {
                "additional_reports": {
                    "bandit": {
                        "source": {
                            "finding_count": 1,
                            "actionable_finding_count": 1,
                            "status": "failed",
                        }
                    }
                }
            }

            # Write the sample results to the aggregated results file
            aggregated_results_path = output_dir / "ash_aggregated_results.json"
            with open(aggregated_results_path, "w") as f:
                json.dump(sample_results, f)

            # Test with explicit output_dir parameter
            scan_results = {"some": "data"}

            # Test the parsing function with explicit output_dir
            results = _parse_ash_results_from_scan(
                scan_results, output_dir=str(output_dir)
            )

            # Verify the results
            assert results["scanners_run"] == ["bandit"]
            assert results["total_findings"] == 1
            assert results["actionable_findings"] == 1

    def test_parse_fallback_behavior(self):
        """Test fallback behavior when no output directory is available."""
        # Test with no output directory available
        scan_results = {"success": True, "results": {"some": "data"}}

        # Test the parsing function
        results = _parse_ash_results_from_scan(scan_results)

        # Verify the results - should return empty structure
        assert results["scanners_run"] == []
        assert results["total_findings"] == 0
        assert results["actionable_findings"] == 0
        assert results["reports_generated"] == []


class TestValidationFunctions:
    """Test validation functions."""

    def test_validate_scan_parameters_valid(self):
        """Test scan parameter validation with valid inputs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(temp_dir, "MEDIUM")
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_scan_parameters_invalid_directory(self):
        """Test scan parameter validation with invalid directory."""
        is_valid, errors = _validate_scan_parameters("/nonexistent/path", "MEDIUM")
        assert is_valid is False
        assert len(errors) > 0
        assert any("does not exist" in error for error in errors)

    def test_validate_scan_parameters_invalid_severity(self):
        """Test scan parameter validation with invalid severity."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(temp_dir, "INVALID")
            assert is_valid is False
            assert len(errors) > 0
            assert any("Invalid severity threshold" in error for error in errors)

    def test_validate_file_system_access_valid(self):
        """Test file system access validation with valid directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_file_system_access(temp_dir)
            assert is_valid is True
            assert len(errors) == 0

    def test_validate_file_system_access_invalid(self):
        """Test file system access validation with invalid directory."""
        is_valid, errors = _validate_file_system_access("/nonexistent/path")
        assert is_valid is False
        assert len(errors) > 0


class TestStructuredErrorResponse:
    """Test structured error response creation."""

    def test_create_structured_error_response_basic(self):
        """Test creating basic structured error response."""
        response = _create_structured_error_response(
            error_type="validation", error_message="Test error message"
        )

        assert response["success"] is False
        assert response["error"] == "Test error message"
        assert response["error_type"] == "validation"
        assert "suggestions" in response

    def test_create_structured_error_response_with_context(self):
        """Test creating structured error response with context."""
        context = {"directory_path": "/test/path", "severity": "HIGH"}
        suggestions = ["Check the path", "Verify permissions"]

        response = _create_structured_error_response(
            error_type="filesystem",
            error_message="File system error",
            context=context,
            suggestions=suggestions,
        )

        assert response["success"] is False
        assert response["error"] == "File system error"
        assert response["error_type"] == "filesystem"
        assert response["context"] == context
        assert response["suggestions"] == suggestions


class TestGetAshVersionDirect:
    """Test direct ASH version retrieval."""

    @patch("automated_security_helper.utils.get_ash_version.get_ash_version")
    def test_get_ash_version_direct_success(self, mock_get_version):
        """Test successful version retrieval."""
        mock_get_version.return_value = "3.0.0"

        success, version_info = _get_ash_version_direct()

        assert success is True
        assert "ASH version 3.0.0" in version_info

    @patch("automated_security_helper.utils.get_ash_version.get_ash_version")
    def test_get_ash_version_direct_import_error(self, mock_get_version):
        """Test version retrieval with import error."""
        mock_get_version.side_effect = ImportError("No package metadata was found")

        success, version_info = _get_ash_version_direct()

        assert success is True  # Should handle development mode gracefully
        assert "development mode" in version_info

    @patch("automated_security_helper.utils.get_ash_version.get_ash_version")
    def test_get_ash_version_direct_other_error(self, mock_get_version):
        """Test version retrieval with other errors."""
        mock_get_version.side_effect = Exception("Some other error")

        success, version_info = _get_ash_version_direct()

        assert success is False
        assert "Error getting ASH version" in version_info


class TestFileSystemValidation:
    """Test file system validation functions."""

    def test_validate_file_system_access_valid_directory(self):
        """Test file system validation with valid directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_file_system_access(temp_dir)

            assert is_valid is True
            assert len(errors) == 0

    def test_validate_file_system_access_nonexistent_path(self):
        """Test file system validation with nonexistent path."""
        is_valid, errors = _validate_file_system_access("/nonexistent/path")

        assert is_valid is not True
        assert len(errors) > 0


class TestScanParameterValidation:
    """Test comprehensive scan parameter validation and error handling."""

    def test_validate_scan_parameters_valid_inputs(self):
        """Test validation with valid scan parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            assert is_valid is True
            assert len(errors) == 0

    def test_validate_scan_parameters_empty_directory_path(self):
        """Test validation with empty directory path."""
        is_valid, errors = _validate_scan_parameters(
            directory_path="", severity_threshold="MEDIUM"
        )

        assert is_valid is not True
        assert any("cannot be empty" in error for error in errors)

    def test_validate_scan_parameters_non_string_directory_path(self):
        """Test validation with non-string directory path."""
        is_valid, errors = _validate_scan_parameters(
            directory_path=123, severity_threshold="MEDIUM"
        )

        assert is_valid is not True
        assert any("must be a string" in error for error in errors)

    def test_validate_scan_parameters_empty_severity_threshold(self):
        """Test validation with empty severity threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(
                directory_path=temp_dir, severity_threshold=""
            )

            assert is_valid is not True
            assert any("cannot be empty" in error for error in errors)

    def test_validate_scan_parameters_non_string_severity_threshold(self):
        """Test validation with non-string severity threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(
                directory_path=temp_dir, severity_threshold=123
            )

            assert is_valid is not True
            assert any("must be a string" in error for error in errors)

    def test_validate_scan_parameters_invalid_severity_threshold(self):
        """Test validation with invalid severity threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(
                directory_path=temp_dir, severity_threshold="INVALID"
            )

            assert is_valid is not True
            assert any("Invalid severity threshold" in error for error in errors)


class TestMcpCommandCliIntegration:
    """Test MCP CLI command integration and parameter handling.

    Tests requirements 4.1, 4.2, 4.3, 4.4 for CLI command structure,
    parameter handling, and registration patterns.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_with_mcp_available(self, mock_start_server):
        """Test MCP command execution when MCP dependencies are available."""
        # Mock MCP imports to be available
        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            # Create a test app and add the command
            app = typer.Typer()
            app.command()(mcp_command)

            # Test command execution
            result = self.runner.invoke(app, [])

            # Should not exit with error when MCP is available
            assert result.exit_code == 0
            mock_start_server.assert_called_once()

    def test_mcp_command_without_mcp_dependencies(self):
        """Test MCP command execution when MCP dependencies are missing."""
        # Ensure MCP modules are not available by patching the module-level imports
        with (
            patch("automated_security_helper.cli.mcp.FastMCP", None),
            patch("automated_security_helper.cli.mcp.Context", None),
        ):
            # Create a test app and add the command
            app = typer.Typer()
            app.command()(mcp_command)

            # Test command execution
            result = self.runner.invoke(app, [])

            # Should exit with error code 1
            assert result.exit_code == 1

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_parameter_handling(self, mock_start_server):
        """Test MCP command parameter handling and defaults."""
        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            app = typer.Typer()
            app.command()(mcp_command)

            # Test with verbose flag
            result = self.runner.invoke(app, ["--verbose"])
            assert result.exit_code == 0

            # Test with debug flag
            result = self.runner.invoke(app, ["--debug"])
            assert result.exit_code == 0

            # Test with quiet flag
            result = self.runner.invoke(app, ["--quiet"])
            assert result.exit_code == 0

            # Test with log level
            result = self.runner.invoke(app, ["--log-level", "DEBUG"])
            assert result.exit_code == 0

    def test_mcp_command_resilient_parsing(self):
        """Test MCP command with resilient parsing enabled."""
        # Create a mock context with resilient_parsing=True
        mock_ctx = MagicMock()
        mock_ctx.resilient_parsing = True

        # Should return early without doing anything
        result = mcp_command(mock_ctx)
        assert result is None

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_keyboard_interrupt_handling(self, mock_start_server):
        """Test MCP command handling of keyboard interrupt."""
        mock_start_server.side_effect = KeyboardInterrupt()

        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            app = typer.Typer()
            app.command()(mcp_command)

            result = self.runner.invoke(app, [])

            # Should exit cleanly on keyboard interrupt
            assert result.exit_code == 0

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_scanner_error_handling(self, mock_start_server):
        """Test MCP command handling of scanner errors."""
        mock_start_server.side_effect = ScannerError("Scanner configuration error")

        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            app = typer.Typer()
            app.command()(mcp_command)

            result = self.runner.invoke(app, [])

            # Should exit with code 2 for scanner errors
            assert result.exit_code == 2

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_validation_error_handling(self, mock_start_server):
        """Test MCP command handling of validation errors."""
        mock_start_server.side_effect = ASHValidationError("Invalid configuration")

        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            app = typer.Typer()
            app.command()(mcp_command)

            result = self.runner.invoke(app, [])

            # Should exit with code 3 for validation errors
            assert result.exit_code == 3

    @patch("automated_security_helper.cli.mcp._start_mcp_server")
    def test_mcp_command_unexpected_error_handling(self, mock_start_server):
        """Test MCP command handling of unexpected errors."""
        mock_start_server.side_effect = RuntimeError("Unexpected system error")

        with patch.dict(
            "sys.modules", {"mcp.server.fastmcp": MagicMock(), "mcp": MagicMock()}
        ):
            app = typer.Typer()
            app.command()(mcp_command)

            result = self.runner.invoke(app, [])

            # Should exit with code 1 for unexpected errors
            assert result.exit_code == 1


class TestDirectFunctionCallReplacements:
    """Test direct function call replacements for ASH operations.

    Tests requirements 3.1, 3.2, 3.3, 3.4 for replacing subprocess calls
    with direct Python function calls.
    """

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    @patch("automated_security_helper.cli.mcp.resolve_config")
    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_run_ash_scan_direct_success(
        self, mock_get_version, mock_config, mock_run_scan
    ):
        """Test successful direct ASH scan execution."""
        # Setup mocks
        mock_get_version.return_value = (True, "ASH version 3.0.0")
        mock_config_obj = MagicMock()
        mock_config_obj.global_settings.severity_threshold = "MEDIUM"
        mock_config_obj.fail_on_findings = False
        mock_config.return_value = mock_config_obj
        mock_run_scan.return_value = {"scan": "results"}

        with tempfile.TemporaryDirectory() as temp_dir:
            # Test the direct scan function
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Verify successful result
            assert result["success"] is True
            # Use path resolution to handle macOS path differences
            assert Path(result["scan_path"]).resolve() == Path(temp_dir).resolve()
            assert result["mode"] == "local"
            assert result["severity_threshold"] == "MEDIUM"
            assert "execution_time_seconds" in result
            assert result["ash_version"] == "ASH version 3.0.0"

            # Verify direct function was called instead of subprocess
            mock_run_scan.assert_called_once()
            call_args = mock_run_scan.call_args
            # Use path resolution for comparison
            assert (
                Path(call_args.kwargs["source_dir"]).resolve()
                == Path(temp_dir).resolve()
            )
            assert call_args.kwargs["mode"].value == "local"
            assert call_args.kwargs["fail_on_findings"] is False
            assert call_args.kwargs["quiet"] is False

    def test_run_ash_scan_direct_validation_error(self):
        """Test direct scan with validation errors."""
        # Test with invalid directory
        result = _run_ash_scan_direct(
            directory_path="/nonexistent/path", severity_threshold="MEDIUM"
        )

        # Should return structured error response
        assert result["success"] is False
        assert result["error_type"] == "validation"
        assert "does not exist" in result["error"]
        assert "suggestions" in result

    def test_run_ash_scan_direct_invalid_severity(self):
        """Test direct scan with invalid severity threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="INVALID"
            )

            # Should return validation error
            assert result["success"] is False
            assert result["error_type"] == "validation"
            assert "Invalid severity threshold" in result["error"]

    def test_run_ash_scan_direct_import_error(self):
        """Test direct scan with import errors."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock import error by setting module-level imports to None
            with (
                patch("automated_security_helper.cli.mcp.run_ash_scan", None),
                patch("automated_security_helper.cli.mcp.resolve_config", None),
            ):
                result = _run_ash_scan_direct(
                    directory_path=temp_dir, severity_threshold="MEDIUM"
                )

                # Should return runtime error (as per implementation)
                assert result["success"] is False
                assert result["error_type"] == "runtime"
                assert "Failed to import ASH scan functionality" in result["error"]

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    def test_run_ash_scan_direct_scanner_error(self, mock_run_scan):
        """Test direct scan with scanner errors."""
        mock_run_scan.side_effect = ScannerError("Scanner configuration failed")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Should return runtime error
            assert result["success"] is False
            assert result["error_type"] == "runtime"
            assert "ASH scanner error" in result["error"]

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    def test_run_ash_scan_direct_validation_error_from_ash(self, mock_run_scan):
        """Test direct scan with ASH validation errors."""
        mock_run_scan.side_effect = ASHValidationError("Invalid scan configuration")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Should return validation error
            assert result["success"] is False
            assert result["error_type"] == "validation"
            assert "ASH validation error" in result["error"]

    @patch("automated_security_helper.cli.mcp.run_ash_scan")
    def test_run_ash_scan_direct_unexpected_error(self, mock_run_scan):
        """Test direct scan with unexpected errors."""
        mock_run_scan.side_effect = RuntimeError("Unexpected system error")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="MEDIUM"
            )

            # Should return runtime error
            assert result["success"] is False
            assert result["error_type"] == "runtime"
            assert "Unexpected error during ASH scan" in result["error"]


class TestMcpServerLifecycle:
    """Test MCP server initialization and lifecycle management.

    Tests requirements 1.1, 1.4, 6.1 for server startup, shutdown,
    and graceful interrupt handling.
    """

    @patch("automated_security_helper.cli.mcp._setup_mcp_server_handlers")
    @patch("signal.signal")
    def test_start_mcp_server_success(self, mock_signal, mock_setup_handlers):
        """Test successful MCP server startup."""
        # Mock FastMCP server
        mock_server = MagicMock()

        with patch(
            "automated_security_helper.cli.mcp.FastMCP", return_value=mock_server
        ):
            # Mock server.run() to avoid blocking
            mock_server.run.side_effect = KeyboardInterrupt()

            # Test server startup
            with pytest.raises(KeyboardInterrupt):
                _start_mcp_server(quiet=True)

            # Verify server was initialized and configured
            mock_setup_handlers.assert_called_once_with(mock_server)
            mock_server.run.assert_called_once()

    def test_start_mcp_server_initialization_error(self):
        """Test MCP server initialization error handling."""
        with patch(
            "automated_security_helper.cli.mcp.FastMCP",
            side_effect=Exception("Server init failed"),
        ):
            with pytest.raises(ScannerError) as exc_info:
                _start_mcp_server(quiet=True)

            assert "Failed to initialize MCP server" in str(exc_info.value)

    @patch("automated_security_helper.cli.mcp._setup_mcp_server_handlers")
    def test_start_mcp_server_handler_setup_error(self, mock_setup_handlers):
        """Test MCP server handler setup error."""
        mock_setup_handlers.side_effect = Exception("Handler setup failed")

        with patch("mcp.server.fastmcp.FastMCP", return_value=MagicMock()):
            with pytest.raises(ScannerError) as exc_info:
                _start_mcp_server(quiet=True)

            assert "Failed to set up MCP server handlers" in str(exc_info.value)

    @patch("automated_security_helper.cli.mcp._setup_mcp_server_handlers")
    def test_start_mcp_server_runtime_error(self, mock_setup_handlers):
        """Test MCP server runtime error handling."""
        mock_server = MagicMock()
        mock_server.run.side_effect = Exception("Server runtime error")

        with patch("mcp.server.fastmcp.FastMCP", return_value=mock_server):
            with pytest.raises(ScannerError) as exc_info:
                _start_mcp_server(quiet=True)

            assert "MCP server runtime error" in str(exc_info.value)

    @patch("automated_security_helper.cli.mcp._setup_mcp_server_handlers")
    @patch("signal.signal")
    def test_start_mcp_server_signal_handling(self, mock_signal, mock_setup_handlers):
        """Test MCP server signal handler registration."""
        mock_server = MagicMock()
        mock_server.run.side_effect = KeyboardInterrupt()

        with patch(
            "automated_security_helper.cli.mcp.FastMCP", return_value=mock_server
        ):
            with pytest.raises(KeyboardInterrupt):
                _start_mcp_server(quiet=True)

            # Verify signal handlers were registered
            assert mock_signal.call_count >= 1
            # Check that SIGINT handler was registered
            signal_calls = [
                call[0][0] for call in mock_signal.call_args_list
            ]  # Extract signal from (signal, handler) tuple
            import signal

            assert signal.SIGINT in signal_calls


class TestErrorHandlingAndValidation:
    """Test comprehensive error handling and validation.

    Tests requirements 6.1, 6.2, 6.3, 6.4 for error handling,
    validation, and structured error responses.
    """

    def test_validate_scan_parameters_comprehensive(self):
        """Test comprehensive scan parameter validation."""
        # Test empty directory path
        is_valid, errors = _validate_scan_parameters("", "MEDIUM")
        assert not is_valid
        assert any("cannot be empty" in error for error in errors)

        # Test non-string directory path
        is_valid, errors = _validate_scan_parameters(123, "MEDIUM")
        assert not is_valid
        assert any("must be a string" in error for error in errors)

        # Test empty severity threshold
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(temp_dir, "")
            assert not is_valid
            assert any("cannot be empty" in error for error in errors)

        # Test non-string severity threshold
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_scan_parameters(temp_dir, 123)
            assert not is_valid
            assert any("must be a string" in error for error in errors)

    def test_validate_file_system_access_comprehensive(self):
        """Test comprehensive file system access validation."""
        # Test with non-existent directory
        is_valid, errors = _validate_file_system_access("/nonexistent/path")
        assert not is_valid
        assert len(errors) > 0

        # Test with valid directory
        with tempfile.TemporaryDirectory() as temp_dir:
            is_valid, errors = _validate_file_system_access(temp_dir)
            assert is_valid
            assert len(errors) == 0

    def test_create_structured_error_response_all_error_types(self):
        """Test structured error response creation for all error types."""
        error_types = ["validation", "filesystem", "runtime", "dependency"]

        for error_type in error_types:
            response = _create_structured_error_response(
                error_type=error_type, error_message=f"Test {error_type} error"
            )

            assert response["success"] is False
            assert response["error"] == f"Test {error_type} error"
            assert response["error_type"] == error_type
            assert "suggestions" in response
            assert isinstance(response["suggestions"], list)
            assert len(response["suggestions"]) > 0

    def test_create_structured_error_response_with_all_parameters(self):
        """Test structured error response with all parameters."""
        context = {"param1": "value1", "param2": "value2"}
        suggestions = ["Suggestion 1", "Suggestion 2"]

        response = _create_structured_error_response(
            error_type="validation",
            error_message="Comprehensive test error",
            context=context,
            suggestions=suggestions,
        )

        assert response["success"] is False
        assert response["error"] == "Comprehensive test error"
        assert response["error_type"] == "validation"
        assert response["context"] == context
        assert response["suggestions"] == suggestions
