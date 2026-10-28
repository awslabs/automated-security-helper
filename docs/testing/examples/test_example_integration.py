"""Example integration tests for ASH components.

This module demonstrates best practices for writing integration tests that verify
interactions between multiple components.
"""

import json
import pytest
from pathlib import Path

# Import the components being tested
# In a real test, you would import the actual components
# For this example, we'll define mock classes


class ExampleScanner:
    """Example scanner class for demonstration purposes."""

    def __init__(self, config=None):
        self.name = "example"
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.findings = []

    def scan_file(self, file_path):
        """Scan a file for security issues."""
        file_path = Path(file_path)
        content = file_path.read_text()
        findings = []

        if "import pickle" in content:
            findings.append(
                {
                    "file_path": str(file_path),
                    "line": content.find("import pickle") + 1,
                    "message": "Unsafe pickle usage detected",
                    "severity": "HIGH",
                    "rule_id": "EX001",
                }
            )

        self.findings = findings
        return ScanResult(findings)


class ScanResult:
    """Example scan result class for demonstration purposes."""

    def __init__(self, findings):
        self.findings = findings


class ExampleReporter:
    """Example reporter class for demonstration purposes."""

    def __init__(self, config=None):
        self.name = "example"
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    def generate_report(self, scan_result):
        """Generate a report from scan results."""
        report = {"version": "1.0.0", "scanner": "example", "findings": []}

        for finding in scan_result.findings:
            report["findings"].append(
                {
                    "file": finding["file_path"],
                    "line": finding["line"],
                    "message": finding["message"],
                    "severity": finding["severity"],
                    "rule_id": finding["rule_id"],
                }
            )

        return report


class ExampleSuppressor:
    """Example suppression handler class for demonstration purposes."""

    def __init__(self, config=None):
        self.name = "example"
        self.config = config or {}
        self.suppressions = self.config.get("suppressions", [])

    def should_suppress(self, finding):
        """Check if a finding should be suppressed."""
        for suppression in self.suppressions:
            if suppression.get("rule_id") == finding["rule_id"]:
                if (
                    suppression.get("file_path") is None
                    or suppression.get("file_path") == finding["file_path"]
                ):
                    return True
        return False

    def apply_suppressions(self, scan_result):
        """Apply suppressions to scan results."""
        filtered_findings = []
        for finding in scan_result.findings:
            if not self.should_suppress(finding):
                filtered_findings.append(finding)

        return ScanResult(filtered_findings)


# Fixtures for the tests
@pytest.fixture
def example_scanner():
    """Create an instance of ExampleScanner for testing."""
    return ExampleScanner()


@pytest.fixture
def example_reporter():
    """Create an instance of ExampleReporter for testing."""
    return ExampleReporter()


@pytest.fixture
def example_suppressor(suppression_config=None):
    """Create an instance of ExampleSuppressor for testing."""
    config = {"suppressions": suppression_config or []}
    return ExampleSuppressor(config)


@pytest.fixture
def temp_python_file(ash_temp_path):
    """Create a temporary Python file for testing."""
    file_path = ash_temp_path / "test.py"
    return file_path


# Integration tests for scanner and reporter
@pytest.mark.integration
class TestScannerReporterIntegration:
    """Integration tests for scanner and reporter components."""

    def test_scan_and_report_with_no_issues(
        self, example_scanner, example_reporter, temp_python_file
    ):
        """Test scanning and reporting with no security issues."""
        # Arrange
        temp_python_file.write_text("print('Hello, world!')")

        # Act
        scan_result = example_scanner.scan_file(temp_python_file)
        report = example_reporter.generate_report(scan_result)

        # Assert
        assert len(report["findings"]) == 0

    def test_scan_and_report_with_issues(
        self, example_scanner, example_reporter, temp_python_file
    ):
        """Test scanning and reporting with security issues."""
        # Arrange
        temp_python_file.write_text("import pickle\npickle.loads(b'')")

        # Act
        scan_result = example_scanner.scan_file(temp_python_file)
        report = example_reporter.generate_report(scan_result)

        # Assert
        assert len(report["findings"]) == 1
        assert report["findings"][0]["file"] == str(temp_python_file)
        assert report["findings"][0]["message"] == "Unsafe pickle usage detected"
        assert report["findings"][0]["severity"] == "HIGH"
        assert report["findings"][0]["rule_id"] == "EX001"


# Integration tests for scanner, suppressor, and reporter
@pytest.mark.integration
class TestScannerSuppressorReporterIntegration:
    """Integration tests for scanner, suppressor, and reporter components."""

    def test_scan_suppress_and_report(
        self, example_scanner, example_reporter, temp_python_file
    ):
        """Test scanning, suppressing, and reporting."""
        # Arrange
        temp_python_file.write_text("import pickle\npickle.loads(b'')")
        suppression_config = [{"rule_id": "EX001", "file_path": str(temp_python_file)}]
        suppressor = ExampleSuppressor({"suppressions": suppression_config})

        # Act
        scan_result = example_scanner.scan_file(temp_python_file)
        filtered_result = suppressor.apply_suppressions(scan_result)
        report = example_reporter.generate_report(filtered_result)

        # Assert
        assert len(scan_result.findings) == 1  # Original scan found an issue
        assert len(filtered_result.findings) == 0  # Issue was suppressed
        assert len(report["findings"]) == 0  # Report shows no issues

    def test_scan_suppress_and_report_with_partial_suppression(
        self, example_scanner, example_reporter, ash_temp_path
    ):
        """Test scanning, suppressing, and reporting with partial suppression."""
        # Arrange
        file1 = ash_temp_path / "test1.py"
        file2 = ash_temp_path / "test2.py"
        file1.write_text("import pickle\npickle.loads(b'')")
        file2.write_text("import pickle\npickle.loads(b'')")

        suppression_config = [
            {"rule_id": "EX001", "file_path": str(file1)}  # Only suppress in file1
        ]
        suppressor = ExampleSuppressor({"suppressions": suppression_config})

        # Act
        scan_result1 = example_scanner.scan_file(file1)
        scan_result2 = example_scanner.scan_file(file2)

        # Combine findings
        combined_findings = scan_result1.findings + scan_result2.findings
        combined_result = ScanResult(combined_findings)

        filtered_result = suppressor.apply_suppressions(combined_result)
        report = example_reporter.generate_report(filtered_result)

        # Assert
        assert len(combined_result.findings) == 2  # Original scan found two issues
        assert len(filtered_result.findings) == 1  # One issue was suppressed
        assert len(report["findings"]) == 1  # Report shows one issue
        assert report["findings"][0]["file"] == str(
            file2
        )  # The issue in file2 was not suppressed


# Example of using the integration test utilities
@pytest.mark.integration
def test_with_integration_test_environment(ash_temp_path):
    """Test using the integration test environment utility."""
    # Import the utility
    # In a real test, you would import from tests.utils.integration_test_utils
    # For this example, we'll define a simplified version

    class IntegrationTestEnvironment:
        def __init__(self):
            self.base_dir = Path(f"{ash_temp_path}/test")
            self.project_dir = self.base_dir / "project"
            self.config_dir = self.project_dir / ".ash"
            self.output_dir = self.project_dir / ".ash" / "ash_output"

        def create_file(self, relative_path, content):
            file_path = self.project_dir / relative_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            return file_path

        def create_config_file(self, config_data):
            self.config_dir.mkdir(parents=True, exist_ok=True)
            config_file = self.config_dir / ".ash.json"
            config_file.write_text(json.dumps(config_data))
            return config_file

        def run_ash(self, args):
            # Simulate running the ASH command
            # In a real test, this would actually run the command
            return {"returncode": 0, "stdout": "Success", "stderr": ""}

    # Define a context manager for the environment
    class ContextManager:
        def __enter__(self):
            self.env = IntegrationTestEnvironment()
            return self.env

        def __exit__(self, exc_type, exc_val, exc_tb):
            # Clean up would happen here
            pass

    # Use the context manager in a test
    with ContextManager() as env:
        # Set up the test environment
        env.create_config_file({"scanners": {"example": {"enabled": True}}})
        env.create_file("src/main.py", "import pickle\npickle.loads(b'')")

        # Run the command being tested
        result = env.run_ash(["scan"])

        # Verify the results
        assert result["returncode"] == 0


# Example of using the component interaction tester
@pytest.mark.integration
def test_with_component_interaction_tester(ash_temp_path):
    """Test using the component interaction tester utility."""
    # Import the utility
    # In a real test, you would import from tests.utils.integration_test_utils
    # For this example, we'll define a simplified version

    class ComponentInteractionTester:
        def __init__(self):
            self.components = {}
            self.interactions = []

        def register_component(self, name, component_class, **kwargs):
            component = component_class(**kwargs)
            self.components[name] = component
            return component

        def record_interaction(self, source, target, method, args, kwargs, result):
            self.interactions.append(
                {
                    "source": source,
                    "target": target,
                    "method": method,
                    "args": args,
                    "kwargs": kwargs,
                    "result": result,
                }
            )

        def verify_interaction(self, source, target, method):
            for interaction in self.interactions:
                if (
                    interaction["source"] == source
                    and interaction["target"] == target
                    and interaction["method"] == method
                ):
                    return True
            return False

    # Define a context manager for the tester
    class ContextManager:
        def __enter__(self):
            self.tester = ComponentInteractionTester()
            return self.tester

        def __exit__(self, exc_type, exc_val, exc_tb):
            # Clean up would happen here
            pass

    # Use the context manager in a test
    with ContextManager() as tester:
        # Register components
        scanner = tester.register_component("scanner", ExampleScanner)
        reporter = tester.register_component("reporter", ExampleReporter)

        # Create a test file
        file_path = Path(f"{ash_temp_path}/test.py")
        file_path.write_text("import pickle\npickle.loads(b'')")

        # Execute the interaction
        scan_result = scanner.scan_file(file_path)
        tester.record_interaction(
            "scanner", "scanner", "scan_file", [file_path], {}, scan_result
        )

        report = reporter.generate_report(scan_result)
        tester.record_interaction(
            "reporter", "reporter", "generate_report", [scan_result], {}, report
        )

        # Verify the interaction
        assert tester.verify_interaction("scanner", "scanner", "scan_file")
        assert tester.verify_interaction("reporter", "reporter", "generate_report")
