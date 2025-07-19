"""
Test runner for MCP integration tests.

This module provides a simple test runner to validate MCP integration tests
can be executed properly and to demonstrate the testing capabilities.
"""

import pytest
import sys
from pathlib import Path


def run_mcp_integration_tests():
    """Run MCP integration tests with appropriate configuration."""

    # Get the test file path
    test_file = Path(__file__).parent / "test_mcp_integration.py"

    # Configure pytest arguments
    pytest_args = [
        str(test_file),
        "-v",  # Verbose output
        "--tb=short",  # Short traceback format
        "-x",  # Stop on first failure
        "--disable-warnings",  # Disable warnings for cleaner output
    ]

    # Add integration test markers
    pytest_args.extend(["-m", "integration"])

    print("Running MCP CLI Integration Tests...")
    print("=" * 50)

    # Run the tests
    exit_code = pytest.main(pytest_args)

    if exit_code == 0:
        print("\n" + "=" * 50)
        print("✅ All MCP integration tests passed!")
    else:
        print("\n" + "=" * 50)
        print("❌ Some MCP integration tests failed.")
        print("Check the output above for details.")

    return exit_code


if __name__ == "__main__":
    sys.exit(run_mcp_integration_tests())
