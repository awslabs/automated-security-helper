"""Scanner fixtures for ASH tests."""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from tests.utils.mocks import create_mock_scanner_plugin, create_mock_sarif_report


@pytest.fixture
def mock_scanner_plugin():
    """Create a mock scanner plugin for testing."""
    return create_mock_scanner_plugin()


@pytest.fixture
def mock_scanner_with_findings():
    """Create a mock scanner plugin that returns findings."""
    from tests.utils.mocks import create_mock_finding

    findings = [
        create_mock_finding(rule_id="MOCK-001", message="First mock finding"),
        create_mock_finding(
            rule_id="MOCK-002",
            message="Second mock finding",
            file_path="src/other.py",
            start_line=20,
            end_line=25,
        ),
    ]

    sarif_report = create_mock_sarif_report(findings)
    return create_mock_scanner_plugin(scan_result=sarif_report)


@pytest.fixture
def scanner_test_files(tmp_path):
    """Create test files for scanner testing."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    # Create a test Python file with potential security issues
    test_file = source_dir / "example.py"
    test_file.write_text("""
import os

def unsafe_function():
    # This should trigger a security finding
    os.system("echo 'Hello, World!'")  # nosec

    # This should also trigger a finding
    eval("2 + 2")  # nosec
""")

    return source_dir


@pytest.fixture
def bandit_scanner_context(tmp_path):
    """Create a context for testing the Bandit scanner."""
    from automated_security_helper.scanners.ash_default.bandit_scanner import (
        BanditScannerConfig,
    )

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # Create a test Python file with potential security issues
    test_file = source_dir / "example.py"
    test_file.write_text("""
import os
import subprocess
import pickle

def unsafe_function():
    # OS command injection vulnerability
    user_input = "user_input"
    os.system(f"echo {user_input}")  # nosec

    # Unsafe deserialization
    with open("data.pkl", "rb") as f:
        data = pickle.load(f)  # nosec

    # Eval injection
    expr = "2 + 2"
    result = eval(expr)  # nosec

    return result
""")

    config = AshConfig(
        project_name="test-project",
        scanners={"bandit": BanditScannerConfig(enabled=True)},
    )

    context = PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)

    return {
        "context": context,
        "source_dir": source_dir,
        "output_dir": output_dir,
        "test_file": test_file,
    }


@pytest.fixture
def semgrep_scanner_context(tmp_path):
    """Create a context for testing the Semgrep scanner."""
    from automated_security_helper.config.scanner_types import SemgrepScannerConfig

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # Create a test Python file with potential security issues
    test_file = source_dir / "example.py"
    test_file.write_text("""
import os
import subprocess
import hashlib

def unsafe_function():
    # Weak hash algorithm
    h = hashlib.md5()
    h.update(b"data")

    # Command injection
    cmd = input("Enter command: ")
    os.system(cmd)

    return h.hexdigest()
""")

    config = AshConfig(
        project_name="test-project",
        scanners={"semgrep": SemgrepScannerConfig(enabled=True)},
    )

    context = PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)

    return {
        "context": context,
        "source_dir": source_dir,
        "output_dir": output_dir,
        "test_file": test_file,
    }
