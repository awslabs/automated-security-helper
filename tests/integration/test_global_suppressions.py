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
        # No `# nosec` on either line. Both carried one, which is bandit's inline
        # suppression marker, so bandit reported nothing and the aggregated SARIF held
        # no results at all -- while the comments beside them claimed the lines should
        # trigger findings. This test exists to check that ASH's *config-level*
        # suppressions mark a finding suppressed, which requires the finding to exist
        # in the first place.
        test_file.write_text("""
import os

def unsafe_function():
    # This should trigger a security finding
    os.system("echo 'Hello, World!'")

    # This should also trigger a finding
    eval("2 + 2")
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
                    # `path`, not `file_path`: AshSuppression extends
                    # IgnorePathWithReason, which declares `path` as required. The
                    # old key was not the field at all, so this config never
                    # validated -- invisible while the bare constructor made the
                    # test die before configuration was read.
                    "path": "example.py",
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
    # ``create`` rather than the bare constructor. ASHScanOrchestrator assigns
    # self.execution_engine in ``initialize()``, not ``__init__``, and
    # ``execute_scan`` refuses to run without it -- so the bare constructor, which
    # the class docstring reserves for "tests that need an uninitialized
    # instance", was the wrong choice for a test that wants a full scan. This
    # failed from the day it was written; #494 only replaced an obscure
    # AttributeError with an explicit guard naming the cause.
    orchestrator = ASHScanOrchestrator.create(
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

    # Find the results for the bandit scanner.
    #
    # Attribution is per RESULT, not per run. The aggregated report carries a single
    # run whose driver is "AWS Labs - Automated Security Helper", and each result
    # names its scanner in properties.scanner_name -- the precedence documented by
    # flat_vulnerability._extract_scanner_name_from_result. Looking for a run whose
    # driver is named "bandit" therefore matched nothing and left bandit_results as
    # None, which is what this assertion caught once the scan got far enough to
    # produce a report at all.
    bandit_results = [
        result
        for run in sarif_data.get("runs", [])
        for result in run.get("results", [])
        if result.get("properties", {}).get("scanner_name") == "bandit"
    ]

    assert bandit_results, (
        "no result was attributed to bandit; scanner_name values present: "
        f"{sorted({r.get('properties', {}).get('scanner_name') for run in sarif_data.get('runs', []) for r in run.get('results', [])})}"
    )

    # Check that the os.system finding was suppressed
    os_system_finding = None
    eval_finding = None

    # Matched on ruleId, not on message text. Bandit's B605 message reads "Starting
    # a process with a shell: ..." and never contains the string "os.system", so the
    # text match found nothing and both findings read as undetected. The rule id is
    # also what the suppression under test targets -- temp_config_file suppresses
    # rule_id B605 -- so keying on it checks the same identity the product does.
    # B307 is bandit's rule for eval. The scan also emits B607 on the os.system line
    # (partial executable path), which neither assertion is about.
    for result in bandit_results:
        if result.get("ruleId") == "B605":
            os_system_finding = result
        elif result.get("ruleId") == "B307":
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
    # ``create`` for the same reason as above: initialize() is what builds the
    # execution engine, and execute_scan requires it.
    orchestrator = ASHScanOrchestrator.create(
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

    # Find the results for the bandit scanner.
    #
    # Attribution is per RESULT, not per run. The aggregated report carries a single
    # run whose driver is "AWS Labs - Automated Security Helper", and each result
    # names its scanner in properties.scanner_name -- the precedence documented by
    # flat_vulnerability._extract_scanner_name_from_result. Looking for a run whose
    # driver is named "bandit" therefore matched nothing and left bandit_results as
    # None, which is what this assertion caught once the scan got far enough to
    # produce a report at all.
    bandit_results = [
        result
        for run in sarif_data.get("runs", [])
        for result in run.get("results", [])
        if result.get("properties", {}).get("scanner_name") == "bandit"
    ]

    assert bandit_results, (
        "no result was attributed to bandit; scanner_name values present: "
        f"{sorted({r.get('properties', {}).get('scanner_name') for run in sarif_data.get('runs', []) for r in run.get('results', [])})}"
    )

    # Check that the os.system finding was not suppressed due to ignore_suppressions flag
    os_system_finding = None
    # ruleId rather than message text, for the reason given in the test above.
    for result in bandit_results:
        if result.get("ruleId") == "B605":
            os_system_finding = result
            break

    assert os_system_finding is not None
    assert (
        "suppressions" not in os_system_finding
        or len(os_system_finding["suppressions"]) == 0
    )
