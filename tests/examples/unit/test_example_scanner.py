"""Example unit tests for a scanner component.

This module demonstrates best practices for writing unit tests for scanner components.
"""

import json
import pytest
from pathlib import Path
import subprocess


# Import the component being tested
# In a real test, you would import the actual component
# For this example, we'll define a mock class
class ExampleScanner:
    """Example scanner class for demonstration purposes."""

    def __init__(self, config=None):
        self.name = "example"
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.findings = []

    def is_enabled(self):
        """Check if the scanner is enabled."""
        return self.enabled

    def scan_file(self, file_path):
        """Scan a file for security issues.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult object with findings
        """
        if not isinstance(file_path, (str, Path)):
            raise TypeError("file_path must be a string or Path object")

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # In a real scanner, this would call an external tool or analyze the file
        # For this example, we'll simulate finding issues in Python files with "import pickle"
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


# Fixtures for the tests
@pytest.fixture
def example_scanner():
    """Create an instance of ExampleScanner for testing."""
    return ExampleScanner()


@pytest.fixture
def temp_python_file(ash_temp_path):
    """Create a temporary Python file for testing."""
    file_path = ash_temp_path / "test.py"
    return file_path


# Unit tests for ExampleScanner
@pytest.mark.unit
class TestExampleScanner:
    """Unit tests for the ExampleScanner class."""

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        # Arrange & Act
        scanner = ExampleScanner()

        # Assert
        assert scanner.name == "example"
        assert scanner.is_enabled()
        assert scanner.findings == []

    def test_initialization_with_config(self):
        """Test that the scanner initializes correctly with a config."""
        # Arrange
        config = {"enabled": False}

        # Act
        scanner = ExampleScanner(config)

        # Assert
        assert scanner.name == "example"
        assert not scanner.is_enabled()

    def test_scan_file_with_no_issues(self, example_scanner, temp_python_file):
        """Test scanning a file with no security issues."""
        # Arrange
        temp_python_file.write_text("print('Hello, world!')")

        # Act
        result = example_scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == 0
        assert example_scanner.findings == []

    def test_scan_file_with_issues(self, example_scanner, temp_python_file):
        """Test scanning a file with security issues."""
        # Arrange
        temp_python_file.write_text("import pickle\npickle.loads(b'')")

        # Act
        result = example_scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == 1
        assert result.findings[0]["file_path"] == str(temp_python_file)
        assert result.findings[0]["message"] == "Unsafe pickle usage detected"
        assert result.findings[0]["severity"] == "HIGH"
        assert result.findings[0]["rule_id"] == "EX001"

    @pytest.mark.parametrize(
        "file_content,expected_findings",
        [
            ("print('Hello, world!')", 0),  # No issues
            ("import pickle\npickle.loads(b'')", 1),  # Unsafe pickle usage
            ("import os\nos.system('ls')", 0),  # No issues for this scanner
        ],
    )
    def test_scan_file_with_different_content(
        self, example_scanner, temp_python_file, file_content, expected_findings
    ):
        """Test scanning files with different content."""
        # Arrange
        temp_python_file.write_text(file_content)

        # Act
        result = example_scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == expected_findings

    def test_scan_file_with_invalid_path_type(self, example_scanner):
        """Test scanning with an invalid path type."""
        # Arrange & Act & Assert
        with pytest.raises(TypeError):
            example_scanner.scan_file(123)

    def test_scan_file_with_nonexistent_file(self, example_scanner):
        """Test scanning a nonexistent file."""
        # Arrange & Act & Assert
        with pytest.raises(FileNotFoundError):
            example_scanner.scan_file("/nonexistent/file.py")


# Example of using mocks in unit tests
@pytest.mark.unit
class TestExampleScannerWithMocks:
    """Unit tests for ExampleScanner using mocks."""

    def test_scan_file_with_mocked_read_text(
        self, example_scanner, temp_python_file, mocker
    ):
        """Test scanning a file with a mocked read_text method."""
        # Arrange
        temp_python_file.write_text(
            "print('Hello, world!')"
        )  # This content will be ignored due to the mock
        mock_read_text = mocker.patch.object(Path, "read_text")
        mock_read_text.return_value = "import pickle\npickle.loads(b'')"

        # Act
        result = example_scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == 1
        assert result.findings[0]["message"] == "Unsafe pickle usage detected"
        mock_read_text.assert_called_once()

    def test_scan_file_with_mocked_exists(
        self, example_scanner, temp_python_file, mocker
    ):
        """Test scanning a file with a mocked exists method."""
        # Arrange
        mock_exists = mocker.patch.object(Path, "exists")
        mock_exists.return_value = False

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            example_scanner.scan_file(temp_python_file)
        mock_exists.assert_called_once()


# Example of a more complex test with subprocess mocking
@pytest.mark.unit
def test_scanner_with_subprocess_mock(mocker):
    """Test a scanner that uses subprocess with mocking."""
    # This is an example of how you might test a scanner that calls an external tool

    # Arrange
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=["example-tool", "-r", "test.py"],
        returncode=0,
        stdout=json.dumps(
            {
                "results": [
                    {
                        "filename": "test.py",
                        "line": 1,
                        "issue_text": "Unsafe code detected",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_cwe": "CWE-123",
                        "test_id": "EX001",
                    }
                ]
            }
        ),
        stderr="",
    )

    # Define a scanner class that uses subprocess
    class SubprocessScanner:
        def scan_file(self, file_path):
            result = subprocess.run(
                ["example-tool", "-r", str(file_path)], capture_output=True, text=True
            )
            data = json.loads(result.stdout)
            return data["results"]

    # Act
    scanner = SubprocessScanner()
    results = scanner.scan_file("test.py")

    # Assert
    assert len(results) == 1
    assert results[0]["filename"] == "test.py"
    assert results[0]["issue_text"] == "Unsafe code detected"
    assert results[0]["issue_severity"] == "HIGH"
    mock_run.assert_called_once_with(
        ["example-tool", "-r", "test.py"], capture_output=True, text=True
    )


# Example of testing with custom assertions
@pytest.mark.unit
def test_scanner_with_custom_assertions(example_scanner, temp_python_file):
    """Test a scanner using custom assertions."""

    # Define a custom assertion function
    def assert_has_finding(
        findings, file_path=None, message=None, severity=None, rule_id=None
    ):
        """Assert that findings contain a finding matching the given criteria."""
        for finding in findings:
            matches = True
            if file_path is not None and finding["file_path"] != file_path:
                matches = False
            if message is not None and message not in finding["message"]:
                matches = False
            if severity is not None and finding["severity"] != severity:
                matches = False
            if rule_id is not None and finding["rule_id"] != rule_id:
                matches = False
            if matches:
                return  # Found a matching finding

        # If we get here, no matching finding was found
        criteria = []
        if file_path is not None:
            criteria.append(f"file_path={file_path}")
        if message is not None:
            criteria.append(f"message containing '{message}'")
        if severity is not None:
            criteria.append(f"severity={severity}")
        if rule_id is not None:
            criteria.append(f"rule_id={rule_id}")

        pytest.fail(f"No finding matching criteria: {', '.join(criteria)}")

    # Arrange
    temp_python_file.write_text("import pickle\npickle.loads(b'')")

    # Act
    result = example_scanner.scan_file(temp_python_file)

    # Assert using custom assertion
    assert_has_finding(
        result.findings,
        file_path=str(temp_python_file),
        message="Unsafe pickle usage",
        severity="HIGH",
        rule_id="EX001",
    )
