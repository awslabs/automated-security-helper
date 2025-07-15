"""
Integration tests for MCP CLI command end-to-end functionality.

This module provides comprehensive integration tests for the MCP CLI command,
covering complete server startup, tool execution, scan workflows, server lifecycle,
and functionality parity with the original standalone script.

Tests requirements 1.1, 1.3, 1.4, 5.1, 5.2, 5.3, 5.4, 5.5 from the spec.
"""

import json
import signal
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.cli.mcp import (
    _start_mcp_server,
    _get_ash_version_direct,
    _run_ash_scan_direct,
    _parse_ash_results,
)


class TestMcpServerLifecycle:
    """Test MCP server lifecycle management and graceful shutdown."""

    @pytest.fixture
    def mock_mcp_dependencies(self):
        """Mock MCP dependencies for testing."""
        mock_fastmcp = MagicMock()
        mock_context = MagicMock()

        # Mock the FastMCP server
        mock_server = MagicMock()
        mock_server.run = MagicMock()
        mock_fastmcp.return_value = mock_server

        with patch.dict(
            "sys.modules",
            {
                "mcp": MagicMock(),
                "mcp.server": MagicMock(),
                "mcp.server.fastmcp": MagicMock(
                    FastMCP=mock_fastmcp, Context=mock_context
                ),
            },
        ):
            yield {
                "FastMCP": mock_fastmcp,
                "Context": mock_context,
                "server": mock_server,
            }

    def test_mcp_server_startup_success(self, mock_mcp_dependencies):
        """Test successful MCP server startup and initialization.

        Tests requirement 1.1: MCP server starts with ASH security scanning capabilities.
        """
        mock_server = mock_mcp_dependencies["server"]

        # Mock server.run to avoid blocking
        mock_server.run.side_effect = KeyboardInterrupt()

        # Test server startup
        with pytest.raises(KeyboardInterrupt):
            _start_mcp_server(quiet=True)

        # Verify server was initialized with correct name
        mock_mcp_dependencies["FastMCP"].assert_called_once_with("ASH Security Scanner")

        # Verify server.run was called
        mock_server.run.assert_called_once()

    def test_mcp_server_graceful_shutdown(self, mock_mcp_dependencies):
        """Test graceful MCP server shutdown on interrupt.

        Tests requirement 1.4: Graceful shutdown and exit on Ctrl+C.
        """
        mock_server = mock_mcp_dependencies["server"]

        # Mock server.run to simulate KeyboardInterrupt
        mock_server.run.side_effect = KeyboardInterrupt()

        # Test graceful shutdown
        with pytest.raises(KeyboardInterrupt):
            _start_mcp_server(quiet=True)

        # Verify server was properly initialized before shutdown
        mock_mcp_dependencies["FastMCP"].assert_called_once()
        mock_server.run.assert_called_once()

    def test_mcp_server_error_handling(self, mock_mcp_dependencies):
        """Test MCP server error handling during startup.

        Tests requirement 6.1: Server encounters error during startup.
        """
        # Mock FastMCP to raise an exception during initialization
        mock_mcp_dependencies["FastMCP"].side_effect = Exception("Server init failed")

        # Test error handling
        with pytest.raises(ScannerError, match="Failed to initialize MCP server"):
            _start_mcp_server(quiet=True)

    def test_mcp_server_runtime_error_handling(self, mock_mcp_dependencies):
        """Test MCP server runtime error handling.

        Tests requirement 6.1: Server runtime errors are handled properly.
        """
        mock_server = mock_mcp_dependencies["server"]

        # Mock server.run to raise a runtime exception
        mock_server.run.side_effect = Exception("Runtime error")

        # Test runtime error handling
        with pytest.raises(ScannerError, match="MCP server runtime error"):
            _start_mcp_server(quiet=True)

    @patch("automated_security_helper.cli.mcp._resource_manager")
    def test_resource_cleanup_on_shutdown(
        self, mock_resource_manager, mock_mcp_dependencies
    ):
        """Test that temporary resources are cleaned up on shutdown.

        Tests requirement 6.4: Clean up temporary resources on termination.
        """
        mock_server = mock_mcp_dependencies["server"]
        mock_server.run.side_effect = KeyboardInterrupt()

        # Test shutdown with resource cleanup
        with pytest.raises(KeyboardInterrupt):
            _start_mcp_server(quiet=True)

        # Verify cleanup was called
        mock_resource_manager.cleanup.assert_called()

    @patch("signal.signal")
    def test_signal_handler_registration(self, mock_signal, mock_mcp_dependencies):
        """Test that signal handlers are properly registered.

        Tests requirement 1.4: Graceful interrupt handling.
        """
        mock_server = mock_mcp_dependencies["server"]
        mock_server.run.side_effect = KeyboardInterrupt()

        # Test signal handler registration
        with pytest.raises(KeyboardInterrupt):
            _start_mcp_server(quiet=True)

        # Verify signal handlers were registered
        assert mock_signal.call_count >= 1
        # Check that SIGINT handler was registered
        signal_calls = [call[0] for call in mock_signal.call_args_list]
        assert signal.SIGINT in signal_calls


class TestMcpToolExecution:
    """Test MCP tool execution with real ASH integration."""

    @pytest.fixture
    def mock_mcp_server(self):
        """Create a mock MCP server for tool testing."""
        mock_server = MagicMock()
        mock_context = MagicMock()

        # Mock async context methods
        async def mock_report_progress(current, total, message):
            pass

        mock_context.report_progress = mock_report_progress
        mock_context.info = MagicMock()

        return mock_server, mock_context

    @pytest.fixture
    def sample_scan_directory(self):
        """Create a sample directory with scannable files for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a Python file with a potential security issue
            python_file = Path(temp_dir) / "test.py"
            python_file.write_text("""
import subprocess
import os

# Potential security issue - shell injection
def run_command(user_input):
    subprocess.call(f"echo {user_input}", shell=True)

# Another potential issue - hardcoded password
password = "hardcoded_password_123"

if __name__ == "__main__":
    run_command("test")
""")

            # Create a requirements.txt file
            requirements_file = Path(temp_dir) / "requirements.txt"
            requirements_file.write_text("requests==2.25.1\nflask==1.1.4\n")

            yield temp_dir

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    @patch("automated_security_helper.cli.mcp._run_ash_scan_direct")
    async def test_scan_directory_tool_success(
        self, mock_run_scan, mock_get_version, mock_mcp_server, sample_scan_directory
    ):
        """Test successful scan_directory tool execution.

        Tests requirement 5.2: scan_directory tool with identical interface.
        """
        mock_server, mock_context = mock_mcp_server

        # Mock successful version check
        mock_get_version.return_value = (True, "ASH version 3.0.0")

        # Mock successful scan
        mock_scan_result = {
            "success": True,
            "exit_code": 0,
            "execution_time_seconds": 5.2,
            "ash_version": "ASH version 3.0.0",
            "output_dir": "/.ash/ash_output",
            "results": {"scanners": {"bandit": {"findings": 2}}},
        }
        mock_run_scan.return_value = mock_scan_result

        # Set up the MCP server with handlers
        with patch(
            "automated_security_helper.cli.mcp._parse_ash_results_from_scan"
        ) as mock_parse:
            mock_parse.return_value = {
                "scanners_run": ["bandit"],
                "total_findings": 2,
                "actionable_findings": 1,
                "reports_generated": [],
            }

            # Import and set up the tool function
            from automated_security_helper.cli.mcp import _setup_mcp_tools

            # Mock the tool decorator
            tool_functions = {}

            def mock_tool_decorator():
                def decorator(func):
                    tool_functions[func.__name__] = func
                    return func

                return decorator

            mock_server.tool = mock_tool_decorator

            # Set up tools
            _setup_mcp_tools(mock_server, type("Context", (), {}))

            # Execute the scan_directory tool
            result = await tool_functions["scan_directory"](
                directory_path=sample_scan_directory,
                severity_threshold="MEDIUM",
                ctx=mock_context,
            )

            # Verify the result
            assert result["success"] is True
            assert result["scan_path"] == sample_scan_directory
            assert result["mode"] == "local"
            assert result["severity_threshold"] == "MEDIUM"
            assert "findings_summary" in result
            assert "execution_time_seconds" in result
            assert "ash_version" in result

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    async def test_scan_directory_tool_validation_error(
        self,
        mock_get_version,
        mock_mcp_server,
    ):
        """Test scan_directory tool with validation errors.

        Tests requirement 6.2: Structured error responses for scan operation failures.
        """
        mock_server, mock_context = mock_mcp_server

        # Mock successful version check
        mock_get_version.return_value = (True, "ASH version 3.0.0")

        # Import and set up the tool function
        from automated_security_helper.cli.mcp import _setup_mcp_tools

        # Mock the tool decorator
        tool_functions = {}

        def mock_tool_decorator():
            def decorator(func):
                tool_functions[func.__name__] = func
                return func

            return decorator

        mock_server.tool = mock_tool_decorator

        # Set up tools
        _setup_mcp_tools(mock_server, type("Context", (), {}))

        # Execute the scan_directory tool with invalid parameters
        result = await tool_functions["scan_directory"](
            directory_path="/nonexistent/path",
            severity_threshold="INVALID",
            ctx=mock_context,
        )

        # Verify structured error response
        assert result["success"] is False
        assert result["error_type"] == "validation"
        assert "suggestions" in result
        assert "context" in result

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_check_installation_tool_success(self, mock_get_version, mock_mcp_server):
        """Test successful check_installation tool execution.

        Tests requirement 5.2: check_installation tool with identical interface.
        """
        mock_server, mock_context = mock_mcp_server

        # Mock successful version check
        mock_get_version.return_value = (True, "ASH version 3.0.0")

        # Import and set up the tool function
        from automated_security_helper.cli.mcp import _setup_mcp_tools

        # Mock the tool decorator
        tool_functions = {}

        def mock_tool_decorator():
            def decorator(func):
                tool_functions[func.__name__] = func
                return func

            return decorator

        mock_server.tool = mock_tool_decorator

        # Set up tools
        _setup_mcp_tools(mock_server, type("Context", (), {}))

        # Execute the check_installation tool
        result = tool_functions["check_installation"]()

        # Verify the result
        assert result["installed"] is True
        assert result["version_info"] == "ASH version 3.0.0"
        assert result["mode_supported"] == "local"
        assert result["ready_to_scan"] is True
        assert "additional_checks" in result

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_check_installation_tool_not_installed(
        self, mock_get_version, mock_mcp_server
    ):
        """Test check_installation tool when ASH is not installed.

        Tests requirement 6.2: Structured error responses for failures.
        """
        mock_server, mock_context = mock_mcp_server

        # Mock failed version check
        mock_get_version.return_value = (False, "ASH not found")

        # Import and set up the tool function
        from automated_security_helper.cli.mcp import _setup_mcp_tools

        # Mock the tool decorator
        tool_functions = {}

        def mock_tool_decorator():
            def decorator(func):
                tool_functions[func.__name__] = func
                return func

            return decorator

        mock_server.tool = mock_tool_decorator

        # Set up tools
        _setup_mcp_tools(mock_server, type("Context", (), {}))

        # Execute the check_installation tool
        result = tool_functions["check_installation"]()

        # Verify the result
        assert result["installed"] is False
        assert result["error"] == "ASH not found"
        assert result["ready_to_scan"] is False


class TestMcpResourcesAndPrompts:
    """Test MCP resources and prompts functionality."""

    @pytest.fixture
    def mock_mcp_server(self):
        """Create a mock MCP server for resource testing."""
        mock_server = MagicMock()
        return mock_server

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_ash_status_resource_installed(self, mock_get_version, mock_mcp_server):
        """Test ash://status resource when ASH is installed.

        Tests requirement 5.1: ash://status resource with direct version checking.
        """
        # Mock successful version check
        mock_get_version.return_value = (True, "ASH version 3.0.0")

        # Import and set up the resource function
        from automated_security_helper.cli.mcp import _setup_mcp_resources

        # Mock the resource decorator
        resource_functions = {}

        def mock_resource_decorator(uri):
            def decorator(func):
                resource_functions[uri] = func
                return func

            return decorator

        mock_mcp_server.resource = mock_resource_decorator

        # Set up resources
        _setup_mcp_resources(mock_mcp_server)

        # Execute the ash://status resource
        result = resource_functions["ash://status"]()

        # Verify the result
        assert "ASH Status: ✅ READY" in result
        assert "ASH version 3.0.0" in result
        assert "Local mode includes these scanners:" in result

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_ash_status_resource_not_installed(self, mock_get_version, mock_mcp_server):
        """Test ash://status resource when ASH is not installed.

        Tests requirement 5.1: ash://status resource with error handling.
        """
        # Mock failed version check
        mock_get_version.return_value = (False, "ASH not found")

        # Import and set up the resource function
        from automated_security_helper.cli.mcp import _setup_mcp_resources

        # Mock the resource decorator
        resource_functions = {}

        def mock_resource_decorator(uri):
            def decorator(func):
                resource_functions[uri] = func
                return func

            return decorator

        mock_mcp_server.resource = mock_resource_decorator

        # Set up resources
        _setup_mcp_resources(mock_mcp_server)

        # Execute the ash://status resource
        result = resource_functions["ash://status"]()

        # Verify the result
        assert "ASH Status: ❌ NOT AVAILABLE" in result
        assert "ASH not found" in result
        assert "To install ASH, run:" in result

    def test_ash_help_resource(self, mock_mcp_server):
        """Test ash://help resource content.

        Tests requirement 5.3: ash://help resource with identical content.
        """
        # Import and set up the resource function
        from automated_security_helper.cli.mcp import _setup_mcp_resources

        # Mock the resource decorator
        resource_functions = {}

        def mock_resource_decorator(uri):
            def decorator(func):
                resource_functions[uri] = func
                return func

            return decorator

        mock_mcp_server.resource = mock_resource_decorator

        # Set up resources
        _setup_mcp_resources(mock_mcp_server)

        # Execute the ash://help resource
        result = resource_functions["ash://help"]()

        # Verify the result contains expected content
        assert "ASH (Automated Security Helper) Usage Guide" in result
        assert "What ASH Scans For:" in result
        assert "Supported File Types:" in result
        assert "Local Mode Benefits:" in result
        assert "Best Practices:" in result

    def test_analyze_security_findings_prompt(self, mock_mcp_server):
        """Test analyze_security_findings prompt functionality.

        Tests requirement 5.4: analyze_security_findings prompt with identical functionality.
        """
        # Import and set up the prompt function
        from automated_security_helper.cli.mcp import _setup_mcp_prompts

        # Mock the prompt decorator
        prompt_functions = {}

        def mock_prompt_decorator():
            def decorator(func):
                prompt_functions[func.__name__] = func
                return func

            return decorator

        mock_mcp_server.prompt = mock_prompt_decorator

        # Set up prompts
        _setup_mcp_prompts(mock_mcp_server)

        # Execute the analyze_security_findings prompt
        sample_results = '{"findings": [{"severity": "HIGH", "type": "security"}]}'
        result = prompt_functions["analyze_security_findings"](sample_results)

        # Verify the result contains expected prompt structure
        assert "Please analyze these ASH security scan results" in result
        assert "Summary" in result
        assert "Key Findings" in result
        assert "Risk Assessment" in result
        assert "Recommendations" in result
        assert "Next Steps" in result
        assert sample_results in result


class TestMcpScanWorkflow:
    """Test complete MCP scan workflow with real ASH integration."""

    @pytest.fixture
    def sample_project_directory(self):
        """Create a sample project directory for end-to-end testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = Path(temp_dir)

            # Create Python files with various security issues
            (project_dir / "app.py").write_text("""
import os
import subprocess
import hashlib

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

def execute_command(user_input):
    # Shell injection vulnerability
    os.system(f"echo {user_input}")

def weak_hash(data):
    # Weak cryptographic hash
    return hashlib.md5(data.encode()).hexdigest()

if __name__ == "__main__":
    execute_command("test")
""")

            # Create a Dockerfile with potential issues
            (project_dir / "Dockerfile").write_text("""
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
WORKDIR /app
USER root
EXPOSE 8080
CMD ["python", "app.py"]
""")

            # Create a requirements file
            (project_dir / "requirements.txt").write_text("""
flask==1.0.0
requests==2.20.0
pyyaml==3.13
""")

            yield str(project_dir)

    @patch("automated_security_helper.interactions.run_ash_scan.run_ash_scan")
    @patch("automated_security_helper.utils.get_ash_version.get_ash_version")
    def test_end_to_end_scan_workflow(
        self, mock_get_version, mock_run_scan, sample_project_directory
    ):
        """Test complete end-to-end scan workflow through MCP.

        Tests requirement 1.3: Complete scan workflow through MCP with real ASH integration.
        """
        # Mock ASH version
        mock_get_version.return_value = "3.0.0"

        # Create mock scan results
        mock_scan_results = {
            "scanners": {
                "bandit": {"status": "completed", "findings": 3},
                "semgrep": {"status": "completed", "findings": 2},
                "detect-secrets": {"status": "completed", "findings": 1},
            },
            "summary": {"total_findings": 6, "actionable_findings": 4},
        }
        mock_run_scan.return_value = mock_scan_results

        # Create temporary output directory
        with tempfile.TemporaryDirectory() as output_dir:
            # Create mock aggregated results file
            aggregated_results = {
                "additional_reports": {
                    "bandit": {
                        "source": {
                            "finding_count": 3,
                            "actionable_finding_count": 2,
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
                    "detect-secrets": {
                        "source": {
                            "finding_count": 1,
                            "actionable_finding_count": 1,
                            "status": "failed",
                        }
                    },
                },
                "metadata": {"summary_stats": {"total": 6, "actionable": 4}},
            }

            # Write aggregated results to output directory
            results_file = Path(output_dir) / "ash_aggregated_results.json"
            with open(results_file, "w") as f:
                json.dump(aggregated_results, f)

            # Test the direct scan function
            result = _run_ash_scan_direct(
                directory_path=sample_project_directory,
                severity_threshold="MEDIUM",
                output_dir=output_dir,
            )

            # Verify scan was executed
            assert result["success"] is True
            assert result["scan_path"] == sample_project_directory
            assert result["mode"] == "local"
            assert result["severity_threshold"] == "MEDIUM"

            # Verify ASH scan was called with correct parameters
            mock_run_scan.assert_called_once()
            call_args = mock_run_scan.call_args
            assert call_args.kwargs["source_dir"] == sample_project_directory
            assert call_args.kwargs["mode"].value == "local"
            assert call_args.kwargs["fail_on_findings"] is False
            assert call_args.kwargs["quiet"] is True

    def test_result_parsing_functionality(self, sample_project_directory):
        """Test result parsing functionality matches original script.

        Tests requirement 5.5: Result parsing with identical logic and output format.
        """
        with tempfile.TemporaryDirectory() as output_dir:
            # Create comprehensive mock aggregated results
            aggregated_results = {
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
                            "finding_count": 3,
                            "actionable_finding_count": 2,
                            "status": "failed",
                        }
                    },
                    "detect-secrets": {
                        "source": {
                            "finding_count": 2,
                            "actionable_finding_count": 2,
                            "status": "failed",
                        }
                    },
                    "checkov": {
                        "source": {
                            "finding_count": 1,
                            "actionable_finding_count": 0,
                            "status": "passed",
                        }
                    },
                },
                "metadata": {"summary_stats": {"total": 11, "actionable": 7}},
            }

            # Write aggregated results
            results_file = Path(output_dir) / "ash_aggregated_results.json"
            with open(results_file, "w") as f:
                json.dump(aggregated_results, f)

            # Create mock report files
            reports_dir = Path(output_dir) / "reports"
            reports_dir.mkdir()
            (reports_dir / "ash.sarif").write_text('{"version": "2.1.0"}')
            (reports_dir / "ash.html").write_text("<html><body>Report</body></html>")
            (reports_dir / "ash.json").write_text('{"findings": []}')

            # Test result parsing
            results = _parse_ash_results(output_dir)

            # Verify parsed results match expected format
            assert results["scanners_run"] == [
                "bandit",
                "semgrep",
                "detect-secrets",
                "checkov",
            ]
            assert results["total_findings"] == 11
            assert results["actionable_findings"] == 7
            assert len(results["reports_generated"]) == 3

            # Verify report details
            report_names = [r["name"] for r in results["reports_generated"]]
            assert "ash.sarif" in report_names
            assert "ash.html" in report_names
            assert "ash.json" in report_names


class TestFunctionalityParity:
    """Test functionality parity with original standalone script."""

    def test_mcp_server_name_consistency(self):
        """Test that MCP server uses the same name as original script.

        Tests requirement 5.1: Same FastMCP server name "ASH Security Scanner".
        """
        with patch("mcp.server.fastmcp.FastMCP") as mock_fastmcp:
            mock_server = MagicMock()
            mock_server.run.side_effect = KeyboardInterrupt()
            mock_fastmcp.return_value = mock_server

            with patch.dict(
                "sys.modules",
                {
                    "mcp": MagicMock(),
                    "mcp.server": MagicMock(),
                    "mcp.server.fastmcp": MagicMock(FastMCP=mock_fastmcp),
                },
            ):
                try:
                    _start_mcp_server(quiet=True)
                except KeyboardInterrupt:
                    pass

                # Verify server was initialized with correct name
                mock_fastmcp.assert_called_once_with("ASH Security Scanner")

    @patch("automated_security_helper.cli.mcp._get_ash_version_direct")
    def test_tool_interface_consistency(self, mock_get_version):
        """Test that MCP tools maintain identical interfaces.

        Tests requirement 5.2: Tools with identical interfaces.
        """
        mock_get_version.return_value = (True, "ASH version 3.0.0")

        # Test scan_directory tool interface
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _run_ash_scan_direct(
                directory_path=temp_dir, severity_threshold="HIGH"
            )

            # Verify response structure matches expected format
            expected_keys = [
                "success",
                "scan_path",
                "mode",
                "severity_threshold",
                "execution_time_seconds",
                "ash_version",
            ]

            for key in expected_keys:
                assert key in result, f"Missing key: {key}"

    def test_error_response_structure_consistency(self):
        """Test that error responses maintain consistent structure.

        Tests requirement 6.2: Structured error responses for failures.
        """
        # Test validation error structure
        result = _run_ash_scan_direct(
            directory_path="/nonexistent/path", severity_threshold="INVALID"
        )

        # Verify error response structure
        assert result["success"] is False
        assert "error" in result
        assert "error_type" in result
        assert "suggestions" in result
        assert "context" in result

        # Verify error type is appropriate
        assert result["error_type"] == "validation"

    @patch("automated_security_helper.utils.get_ash_version.get_ash_version")
    def test_version_checking_consistency(self, mock_get_version):
        """Test that version checking maintains consistency.

        Tests requirement 3.1: Direct version checking instead of subprocess.
        """
        mock_get_version.return_value = "3.0.0"

        success, version_info = _get_ash_version_direct()

        # Verify direct function call was used
        mock_get_version.assert_called_once()

        # Verify response format
        assert success is True
        assert "ASH version 3.0.0" in version_info


# Integration test markers for pytest
pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,  # These tests may take longer due to MCP server operations
]
