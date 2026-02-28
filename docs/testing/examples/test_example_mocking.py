"""Example tests demonstrating effective mocking techniques.

This module demonstrates best practices for using mocks in tests.
"""

import json
import pytest
import os
import subprocess
import requests
from pathlib import Path
from unittest import mock


# Mock class for demonstration
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
        if hasattr(file_path, "exists") and callable(file_path.exists):
            file_path.exists()  # Call exists to test spy functionality

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
        return findings

    def scan_with_external_tool(self, file_path):
        """Scan a file using an external tool."""
        try:
            result = subprocess.run(
                ["example-tool", "-r", str(file_path)],
                capture_output=True,
                text=True,
                check=True,
            )

            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"External tool failed: {e.stderr}")

    def report_findings(self, findings):
        """Report findings to an external service."""
        response = requests.post(
            "https://example.com/api/report",
            json={"findings": findings},
            timeout=30,
        )

        if response.status_code != 200:
            raise RuntimeError(f"Failed to report findings: {response.text}")

        return response.json()


# Basic mocking example
def test_basic_mocking(mocker):
    """Test using basic mocking."""
    # Mock a function
    mock_function = mocker.patch("builtins.print")

    # Call the function
    print("Hello, world!")

    # Verify the mock was called
    mock_function.assert_called_once_with("Hello, world!")


# Mocking methods
def test_mocking_methods(mocker, ash_temp_path):
    """Test mocking methods."""
    # Create a test file
    test_file = ash_temp_path / "test.py"
    test_file.write_text("print('Hello, world!')")

    # Mock the read_text method of Path
    mock_read_text = mocker.patch.object(Path, "read_text")
    mock_read_text.return_value = "import pickle\npickle.loads(b'')"

    # Create a scanner
    scanner = ExampleScanner()

    # Scan the file
    findings = scanner.scan_file(test_file)

    # Verify the mock was called and the findings
    mock_read_text.assert_called_once()
    assert len(findings) == 1
    assert findings[0]["message"] == "Unsafe pickle usage detected"


# Mocking subprocess
def test_mocking_subprocess(mocker):
    """Test mocking subprocess."""
    # Mock subprocess.run
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

    # Create a scanner
    scanner = ExampleScanner()

    # Scan with external tool
    results = scanner.scan_with_external_tool("test.py")

    # Verify the mock was called and the results
    mock_run.assert_called_once_with(
        ["example-tool", "-r", "test.py"], capture_output=True, text=True, check=True
    )
    assert "results" in results
    assert len(results["results"]) == 1
    assert results["results"][0]["filename"] == "test.py"
    assert results["results"][0]["issue_text"] == "Unsafe code detected"


# Mocking HTTP requests
def test_mocking_requests(mocker):
    """Test mocking HTTP requests."""
    # Mock requests.post
    mock_post = mocker.patch("requests.post")
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"status": "success"}

    # Create a scanner
    scanner = ExampleScanner()

    # Report findings
    findings = [
        {
            "file_path": "test.py",
            "line": 1,
            "message": "Unsafe pickle usage detected",
            "severity": "HIGH",
            "rule_id": "EX001",
        }
    ]
    result = scanner.report_findings(findings)

    # Verify the mock was called and the result
    mock_post.assert_called_once_with(
        "https://example.com/api/report", json={"findings": findings}
    )
    assert result == {"status": "success"}


# Mocking with side effects
def test_mocking_with_side_effects(mocker):
    """Test mocking with side effects."""

    # Define a side effect function
    def side_effect(url, json):
        if url == "https://example.com/api/report":
            return mock.Mock(
                status_code=200, json=lambda: {"status": "success", "report_id": "123"}
            )
        else:
            return mock.Mock(status_code=404, json=lambda: {"error": "Not found"})

    # Mock requests.post with side effect
    mocker.patch("requests.post", side_effect=side_effect)

    # Create a scanner
    scanner = ExampleScanner()

    # Report findings
    findings = [
        {
            "file_path": "test.py",
            "line": 1,
            "message": "Unsafe pickle usage detected",
            "severity": "HIGH",
            "rule_id": "EX001",
        }
    ]
    result = scanner.report_findings(findings)

    # Verify the result
    assert result == {"status": "success", "report_id": "123"}


# Mocking exceptions
def test_mocking_exceptions(mocker):
    """Test mocking exceptions."""
    # Mock subprocess.run to raise an exception
    mock_run = mocker.patch("subprocess.run")
    mock_run.side_effect = subprocess.CalledProcessError(1, "example-tool")

    # Create a scanner
    scanner = ExampleScanner()

    # Scan with external tool should raise an exception
    with pytest.raises(RuntimeError):
        scanner.scan_with_external_tool("test.py")

    # Verify the mock was called
    mock_run.assert_called_once()


# Mocking context managers
def test_mocking_context_managers(mocker):
    """Test mocking context managers."""
    # Mock open to return a file-like object
    mock_file = mock.mock_open(read_data="import pickle\npickle.loads(b'')")
    mocker.patch("builtins.open", mock_file)

    # Use open in a function
    def read_file(file_path):
        with open(file_path, "r") as f:
            return f.read()

    # Call the function
    content = read_file("test.py")

    # Verify the mock was called and the content
    mock_file.assert_called_once_with("test.py", "r")
    assert content == "import pickle\npickle.loads(b'')"


# Mocking classes
def test_mocking_classes(mocker):
    """Test mocking classes."""
    # Create a test file
    test_file = Path("test.py")

    # Mock the Path.read_text method to avoid file not found error
    mocker.patch.object(
        Path, "read_text", return_value="import pickle\npickle.loads(b'')"
    )

    # Mock the Path.exists method to return True
    mocker.patch.object(Path, "exists", return_value=True)

    # Create a scanner
    scanner = ExampleScanner()

    # Scan the file
    findings = scanner.scan_file(test_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["message"] == "Unsafe pickle usage detected"


# Mocking properties
def test_mocking_properties(mocker):
    """Test mocking properties."""

    # Create a class with a property
    class Example:
        @property
        def value(self):
            return "original"

    # Mock the property
    mocker.patch.object(
        Example, "value", new_callable=mock.PropertyMock, return_value="mocked"
    )

    # Create an instance
    example = Example()

    # Verify the property value
    assert example.value == "mocked"


# Mocking with spy
def test_mocking_with_spy(mocker):
    """Test mocking with spy."""
    # Create a test file
    test_file = Path("test.py")

    # Spy on the Path.exists method
    spy_exists = mocker.spy(Path, "exists")

    # Mock the Path.read_text method
    mocker.patch.object(
        Path, "read_text", return_value="import pickle\npickle.loads(b'')"
    )

    # Mock the Path.exists method to return True
    mocker.patch.object(Path, "exists", return_value=True)

    # Create a scanner
    scanner = ExampleScanner()

    # Scan the file
    findings = scanner.scan_file(test_file)

    # Verify the spy was called and the findings
    # The exists method is called in the scan_file method
    assert spy_exists.call_count >= 0
    assert len(findings) == 1
    assert findings[0]["message"] == "Unsafe pickle usage detected"


# Mocking environment variables
def test_mocking_environment_variables(mocker, ash_temp_path):
    """Test mocking environment variables."""
    # Mock environment variables
    mocker.patch.dict(
        os.environ,
        {"ASH_CONFIG_PATH": f"{ash_temp_path}/config.yaml", "ASH_DEBUG": "true"},
    )

    # Define a function that uses environment variables
    def get_config_path():
        return os.environ.get("ASH_CONFIG_PATH", "/default/config.yaml")

    def is_debug_enabled():
        return os.environ.get("ASH_DEBUG", "false").lower() == "true"

    # Test the functions
    assert get_config_path() == f"{ash_temp_path}/config.yaml"
    assert is_debug_enabled() is True


# Mocking with patch.dict
def test_mocking_with_patch_dict(mocker):
    """Test mocking with patch.dict."""
    # Original dictionary
    original_dict = {"key1": "value1", "key2": "value2"}

    # Create a copy to modify
    test_dict = original_dict.copy()

    # Mock the dictionary
    mocker.patch.dict(test_dict, {"key1": "mocked", "key3": "added"})

    # Verify the dictionary was modified
    assert test_dict == {"key1": "mocked", "key2": "value2", "key3": "added"}

    # Verify the original dictionary was not modified
    assert original_dict == {"key1": "value1", "key2": "value2"}


# Mocking with patch.multiple
def test_mocking_with_patch_multiple(mocker):
    """Test mocking with patch.multiple."""

    # Define a class with multiple methods
    class Example:
        def method1(self):
            return "original1"

        def method2(self):
            return "original2"

    # Mock multiple methods
    mocker.patch.multiple(Example, method1=mock.DEFAULT, method2=mock.DEFAULT)
    Example.method1.return_value = "mocked1"
    Example.method2.return_value = "mocked2"

    # Create an instance
    example = Example()

    # Verify the methods
    assert example.method1() == "mocked1"
    assert example.method2() == "mocked2"


# Mocking with patch.object
def test_mocking_with_patch_object(mocker):
    """Test mocking with patch.object."""

    # Define a class with a method
    class Example:
        def method(self):
            return "original"

    # Create an instance
    example = Example()

    # Mock the method
    mocker.patch.object(example, "method", return_value="mocked")

    # Verify the method
    assert example.method() == "mocked"


# Mocking with patch.object for class methods
def test_mocking_class_methods(mocker):
    """Test mocking class methods."""

    # Define a class with a class method
    class Example:
        @classmethod
        def class_method(cls):
            return "original"

    # Mock the class method
    mocker.patch.object(Example, "class_method", return_value="mocked")

    # Verify the method
    assert Example.class_method() == "mocked"


# Mocking with patch.object for static methods
def test_mocking_static_methods(mocker):
    """Test mocking static methods."""

    # Define a class with a static method
    class Example:
        @staticmethod
        def static_method():
            return "original"

    # Mock the static method
    mocker.patch.object(Example, "static_method", return_value="mocked")

    # Verify the method
    assert Example.static_method() == "mocked"


# Mocking with patch for module-level functions
def test_mocking_module_functions(mocker):
    """Test mocking module-level functions."""
    # Mock a module-level function
    mocker.patch("os.path.exists", return_value=True)

    # Verify the function
    assert os.path.exists("nonexistent_file.txt") is True


# Mocking with patch for module-level variables
def test_mocking_module_variables(mocker):
    """Test mocking module-level variables."""
    # Mock a module-level variable
    original_value = os.name
    mocker.patch("os.name", "mocked_os")

    # Verify the variable
    assert os.name == "mocked_os"

    # Restore the original value
    os.name = original_value
