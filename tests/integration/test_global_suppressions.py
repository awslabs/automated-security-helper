"""Integration tests for global suppressions feature."""

import pytest
import tempfile
from pathlib import Path
import yaml
import json

from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.enums import ExecutionStrategy


@pytest.fixture
def temp_source_dir():
    """Create a temporary source directory with test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        source_dir = Path(temp_dir)

        # Create a test Python file with a potential security issue
        test_file = source_dir / "example.py"
        test_file.write_text("""
import os

def unsafe_function():
    # This should trigger a security finding
    os.system("echo 'Hello, World!'")  # nosec

    # This should also trigger a finding
    eval("2 + 2")  # nosec
""")

        yield source_dir


@pytest.fixture
def temp_output_dir():
    """Create a temporary output directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        yield output_dir


@pytest.fixture
def temp_config_file(temp_source_dir):
    """Create a temporary ASH config file with suppressions."""
    config_file = temp_source_dir / ".ash.yaml"

    config_data = {
        "project_name": "test-project",
        "fail_on_findings": True,
        "global_settings": {
            "severity_threshold": "MEDIUM",
            "suppressions": [
                {
                    "rule_id": "B605",  # Bandit rule for os.system
                    "file_path": "example.py",
                    "reason": "Test suppression for os.system",
                }
            ],
        },
        "scanners": {"bandit": {"enabled": True}},
        "reporters": {"sarif": {"enabled": True}},
    }

    with open(config_file, "w") as f:
        yaml.dump(config_data, f)

    yield config_file


def test_global_suppressions_integration(
    temp_source_dir, temp_output_dir, temp_config_file
):
    """Test that global suppressions are applied correctly in a full scan."""
    # Create orchestrator with the test configuration
    orchestrator = ASHScanOrchestrator(
        source_dir=temp_source_dir,
        output_dir=temp_output_dir,
        config_path=temp_config_file,
        strategy=ExecutionStrategy.SEQUENTIAL,  # Use sequential for predictable test results
        enabled_scanners=["bandit"],  # Only run bandit scanner
        show_progress=False,
        verbose=True,
    )

    # Execute scan
    results = orchestrator.execute_scan(phases=["convert", "scan", "report"])

    # Check that results were generated
    assert results is not None

    # Check that the SARIF report was generated
    sarif_file = temp_output_dir / "reports" / "ash.sarif"
    assert sarif_file.exists()

    # Load the SARIF report
    with open(sarif_file, "r") as f:
        sarif_data = json.load(f)

    # Find the results for the bandit scanner
    bandit_results = None
    for run in sarif_data.get("runs", []):
        if run.get("tool", {}).get("driver", {}).get("name") == "bandit":
            bandit_results = run.get("results", [])
            break

    assert bandit_results is not None

    # Check that the os.system finding was suppressed
    os_system_finding = None
    eval_finding = None

    for result in bandit_results:
        if "os.system" in result.get("message", {}).get("text", ""):
            os_system_finding = result
        elif "eval" in result.get("message", {}).get("text", ""):
            eval_finding = result

    # Check that both findings were detected
    assert os_system_finding is not None, "os.system finding not detected"
    assert eval_finding is not None, "eval finding not detected"

    # Check that the os.system finding was suppressed
    assert "suppressions" in os_system_finding
    assert len(os_system_finding["suppressions"]) > 0
    assert (
        "Test suppression for os.system"
        in os_system_finding["suppressions"][0]["justification"]
    )

    # Check that the eval finding was not suppressed
    assert "suppressions" not in eval_finding or len(eval_finding["suppressions"]) == 0


def test_ignore_suppressions_flag_integration(
    temp_source_dir, temp_output_dir, temp_config_file
):
    """Test that the ignore_suppressions flag works correctly."""
    # Create orchestrator with the test configuration and ignore_suppressions flag
    orchestrator = ASHScanOrchestrator(
        source_dir=temp_source_dir,
        output_dir=temp_output_dir,
        config_path=temp_config_file,
        strategy=ExecutionStrategy.SEQUENTIAL,  # Use sequential for predictable test results
        enabled_scanners=["bandit"],  # Only run bandit scanner
        show_progress=False,
        verbose=True,
        ignore_suppressions=True,  # Enable ignore_suppressions flag
    )

    # Execute scan
    results = orchestrator.execute_scan(phases=["convert", "scan", "report"])

    # Check that results were generated
    assert results is not None

    # Check that the SARIF report was generated
    sarif_file = temp_output_dir / "reports" / "ash.sarif"
    assert sarif_file.exists()

    # Load the SARIF report
    with open(sarif_file, "r") as f:
        sarif_data = json.load(f)

    # Find the results for the bandit scanner
    bandit_results = None
    for run in sarif_data.get("runs", []):
        if run.get("tool", {}).get("driver", {}).get("name") == "bandit":
            bandit_results = run.get("results", [])
            break

    assert bandit_results is not None

    # Check that the os.system finding was not suppressed due to ignore_suppressions flag
    os_system_finding = None
    for result in bandit_results:
        if "os.system" in result.get("message", {}).get("text", ""):
            os_system_finding = result
            break

    assert os_system_finding is not None
    assert (
        "suppressions" not in os_system_finding
        or len(os_system_finding["suppressions"]) == 0
    )
