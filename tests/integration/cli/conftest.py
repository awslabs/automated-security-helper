"""
Configuration for MCP CLI integration tests.

This module provides pytest configuration and fixtures specifically
for MCP CLI integration tests.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


@pytest.fixture(scope="session")
def integration_test_config():
    """Configuration for integration tests."""
    return {
        "timeout": 30,  # Maximum test timeout in seconds
        "temp_dir_prefix": "ash_mcp_integration_test_",
        "mock_mcp_available": True,  # Whether to mock MCP as available
    }


@pytest.fixture
def mock_mcp_environment():
    """Mock MCP environment for integration tests."""
    # Mock MCP modules to be available
    mock_mcp = MagicMock()
    mock_fastmcp = MagicMock()
    mock_context = MagicMock()

    # Create a mock FastMCP server
    mock_server = MagicMock()
    mock_server.run = MagicMock()
    mock_fastmcp.return_value = mock_server

    # Mock async methods for context
    async def mock_report_progress(current, total, message):
        pass

    mock_context.report_progress = mock_report_progress
    mock_context.info = MagicMock()

    modules_to_mock = {
        "mcp": mock_mcp,
        "mcp.server": MagicMock(),
        "mcp.server.fastmcp": MagicMock(FastMCP=mock_fastmcp, Context=mock_context),
    }

    with patch.dict("sys.modules", modules_to_mock):
        yield {
            "mcp": mock_mcp,
            "FastMCP": mock_fastmcp,
            "Context": mock_context,
            "server": mock_server,
        }


@pytest.fixture
def temp_scan_directory():
    """Create a temporary directory with sample files for scanning."""
    with tempfile.TemporaryDirectory(prefix="ash_mcp_test_scan_") as temp_dir:
        scan_dir = Path(temp_dir)

        # Create a Python file with potential security issues
        python_file = scan_dir / "sample.py"
        python_file.write_text(
            """
import os
import subprocess

# Potential security issue - hardcoded secret
SECRET_KEY = "sk-1234567890abcdef"

def run_command(user_input):
    # Shell injection vulnerability
    os.system(f"echo {user_input}")

def another_function():
    # Another potential issue
    subprocess.call("ls -la", shell=True)

if __name__ == "__main__":
    run_command("test")
"""
        )

        # Create a requirements.txt file
        requirements_file = scan_dir / "requirements.txt"
        requirements_file.write_text(
            """
requests==2.25.1
flask==1.1.4
pyyaml==3.13
"""
        )

        # Create a simple Dockerfile
        dockerfile = scan_dir / "Dockerfile"
        dockerfile.write_text(
            """
FROM ubuntu:latest
RUN apt-get update
COPY . /app
WORKDIR /app
USER root
CMD ["python", "sample.py"]
"""
        )

        yield str(scan_dir)


@pytest.fixture
def mock_ash_scan_results():
    """Mock ASH scan results for testing."""
    return {
        "success": True,
        "exit_code": 0,
        "execution_time_seconds": 3.5,
        "ash_version": f"ASH version {__import__('automated_security_helper.utils.version_management', fromlist=['get_version']).get_version()}",
        "output_dir": "/.ash/mock_ash_output",
        "results": {
            "scanners": {
                "bandit": {
                    "status": "completed",
                    "findings": 2,
                    "actionable_findings": 1,
                },
                "semgrep": {
                    "status": "completed",
                    "findings": 1,
                    "actionable_findings": 1,
                },
                "detect-secrets": {
                    "status": "completed",
                    "findings": 1,
                    "actionable_findings": 1,
                },
            }
        },
    }


@pytest.fixture
def mock_aggregated_results():
    """Mock aggregated results JSON structure."""
    return {
        "additional_reports": {
            "bandit": {
                "source": {
                    "finding_count": 2,
                    "actionable_finding_count": 1,
                    "status": "failed",
                }
            },
            "semgrep": {
                "source": {
                    "finding_count": 1,
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
        "metadata": {"summary_stats": {"total": 4, "actionable": 3}},
    }


@pytest.fixture
def temp_output_directory(mock_aggregated_results):
    """Create a temporary output directory with mock ASH results."""
    with tempfile.TemporaryDirectory(prefix="ash_mcp_test_output_") as temp_dir:
        output_dir = Path(temp_dir)

        # Create aggregated results file
        results_file = output_dir / "ash_aggregated_results.json"
        import json

        with open(results_file, "w") as f:
            json.dump(mock_aggregated_results, f)

        # Create reports directory with sample files
        reports_dir = output_dir / "reports"
        reports_dir.mkdir()

        (reports_dir / "ash.sarif").write_text('{"version": "2.1.0", "runs": []}')
        (reports_dir / "ash.html").write_text(
            "<html><body><h1>ASH Report</h1></body></html>"
        )
        (reports_dir / "ash.json").write_text(
            '{"findings": [], "summary": {"total": 4}}'
        )

        yield str(output_dir)


# Pytest markers for integration tests
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "mcp: mark test as MCP-specific")


# Test collection configuration
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add integration marker to all tests in this directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add slow marker to tests that might take longer
        if any(
            keyword in item.name.lower()
            for keyword in ["workflow", "lifecycle", "end_to_end"]
        ):
            item.add_marker(pytest.mark.slow)

        # Add mcp marker to MCP-specific tests
        if "mcp" in item.name.lower():
            item.add_marker(pytest.mark.mcp)
