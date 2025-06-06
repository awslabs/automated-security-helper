"""Example tests for complex scenarios.

This module demonstrates best practices for writing tests for complex scenarios
that involve multiple components, external services, and advanced testing techniques.
"""

import json
import pytest
import os
import tempfile
from pathlib import Path
import threading
import http.server
import socketserver
import time
import urllib


# Mock classes for demonstration purposes
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


# Example of a complex test with multiple components and mocks
@pytest.mark.integration
def test_complex_scenario_with_multiple_components(tmp_path, mocker):
    """Test a complex scenario with multiple components and mocks."""
    # Arrange
    # Create test files
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    file1 = src_dir / "main.py"
    file2 = src_dir / "utils.py"

    file1.write_text(
        "import pickle\nfrom utils import helper\n\ndef main():\n    data = pickle.loads(b'')\n    helper(data)"
    )
    file2.write_text("def helper(data):\n    return data")

    # Create configuration
    config = {
        "scanners": {"example": {"enabled": True, "options": {"severity": "HIGH"}}},
        "reporters": {
            "example": {"enabled": True, "output_file": str(tmp_path / "report.json")}
        },
    }

    # Mock external service call
    mock_api_call = mocker.patch("requests.post")
    mock_api_call.return_value.status_code = 200
    mock_api_call.return_value.json.return_value = {"status": "success"}

    # Create components
    scanner = ExampleScanner(config["scanners"]["example"])
    reporter = ExampleReporter(config["reporters"]["example"])

    # Act
    # Scan files
    findings = []
    for file_path in [file1, file2]:
        result = scanner.scan_file(file_path)
        findings.extend(result.findings)

    # Generate report
    combined_result = ScanResult(findings)
    report = reporter.generate_report(combined_result)

    # Write report to file
    output_file = Path(config["reporters"]["example"]["output_file"])
    with open(output_file, "w") as f:
        json.dump(report, f)

    # Assert
    # Verify findings
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(file1)
    assert findings[0]["message"] == "Unsafe pickle usage detected"

    # Verify report file was created
    assert output_file.exists()

    # Verify report content
    with open(output_file, "r") as f:
        saved_report = json.load(f)

    assert saved_report["version"] == "1.0.0"
    assert saved_report["scanner"] == "example"
    assert len(saved_report["findings"]) == 1
    assert saved_report["findings"][0]["file"] == str(file1)
    assert saved_report["findings"][0]["message"] == "Unsafe pickle usage detected"


# Example of a test with a mock HTTP server
@pytest.mark.integration
def test_with_mock_http_server(tmp_path):
    """Test with a mock HTTP server."""

    # Set up a mock HTTP server
    class MockHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/test.json":
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"key": "value"}).encode())
            else:
                self.send_response(404)
                self.end_headers()

    # Find an available port
    with socketserver.TCPServer(("", 0), None) as s:
        port = s.server_address[1]

    # Start the server in a separate thread
    server = socketserver.TCPServer(("", port), MockHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    try:
        # Wait for the server to start
        time.sleep(0.1)

        # Define a function that uses the HTTP server
        def fetch_json(url):
            import urllib.request

            with urllib.request.urlopen(url) as response:
                return json.loads(response.read().decode())

        # Test the function
        result = fetch_json(f"http://localhost:{port}/test.json")
        assert result == {"key": "value"}

        # Test with a non-existent path
        with pytest.raises(urllib.error.HTTPError):
            fetch_json(f"http://localhost:{port}/nonexistent.json")

    finally:
        # Shut down the server
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)


# Example of a test with environment variables
@pytest.mark.integration
def test_with_environment_variables(mocker):
    """Test with environment variables."""
    # Mock environment variables
    mocker.patch.dict(
        os.environ, {"ASH_CONFIG_PATH": "/tmp/config.yaml", "ASH_DEBUG": "true"}
    )

    # Define a function that uses environment variables
    def get_config_path():
        return os.environ.get("ASH_CONFIG_PATH", "/default/config.yaml")

    def is_debug_enabled():
        return os.environ.get("ASH_DEBUG", "false").lower() == "true"

    # Test the functions
    assert get_config_path() == "/tmp/config.yaml"
    assert is_debug_enabled() is True

    # Test with a missing environment variable
    mocker.patch.dict(os.environ, {"ASH_CONFIG_PATH": "/tmp/config.yaml"}, clear=True)
    assert get_config_path() == "/tmp/config.yaml"
    assert is_debug_enabled() is False


# Example of a test with temporary files and directories
@pytest.mark.integration
def test_with_temp_files_and_dirs():
    """Test with temporary files and directories."""
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)

        # Create a temporary file
        temp_file = temp_dir_path / "test.py"
        temp_file.write_text("import pickle\npickle.loads(b'')")

        # Use the temporary file
        scanner = ExampleScanner()
        result = scanner.scan_file(temp_file)

        # Verify the result
        assert len(result.findings) == 1
        assert result.findings[0]["file_path"] == str(temp_file)
        assert result.findings[0]["message"] == "Unsafe pickle usage detected"

    # The temporary directory and file are automatically cleaned up
    assert not temp_dir_path.exists()


# Example of a test with a context manager for resource management
@pytest.mark.integration
def test_with_resource_management():
    """Test with a context manager for resource management."""

    # Define a context manager for resource management
    class TempFileManager:
        def __init__(self, content):
            self.content = content
            self.file_path = None

        def __enter__(self):
            fd, self.file_path = tempfile.mkstemp(suffix=".py")
            os.close(fd)
            with open(self.file_path, "w") as f:
                f.write(self.content)
            return self.file_path

        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.file_path and os.path.exists(self.file_path):
                os.unlink(self.file_path)

    # Use the context manager in a test
    with TempFileManager("import pickle\npickle.loads(b'')") as file_path:
        # Use the temporary file
        scanner = ExampleScanner()
        result = scanner.scan_file(file_path)

        # Verify the result
        assert len(result.findings) == 1
        assert result.findings[0]["file_path"] == file_path
        assert result.findings[0]["message"] == "Unsafe pickle usage detected"

    # The temporary file is automatically cleaned up
    assert not os.path.exists(file_path)


# Example of a test with parameterized fixtures
@pytest.mark.integration
@pytest.mark.parametrize(
    "file_content,expected_findings",
    [
        ("print('Hello, world!')", 0),
        ("import pickle\npickle.loads(b'')", 1),
        ("import os\nos.system('ls')", 0),
    ],
)
def test_with_parameterized_fixtures(file_content, expected_findings, tmp_path):
    """Test with parameterized fixtures."""
    # Create a test file
    test_file = tmp_path / "test.py"
    test_file.write_text(file_content)

    # Scan the file
    scanner = ExampleScanner()
    result = scanner.scan_file(test_file)

    # Verify the result
    assert len(result.findings) == expected_findings

    if expected_findings > 0:
        assert result.findings[0]["file_path"] == str(test_file)
        if "import pickle" in file_content:
            assert result.findings[0]["message"] == "Unsafe pickle usage detected"


# Example of a test with custom test data
@pytest.mark.integration
def test_with_custom_test_data(tmp_path):
    """Test with custom test data."""
    # Define test data
    test_data = [
        {
            "file_name": "safe.py",
            "content": "print('Hello, world!')",
            "expected_findings": 0,
        },
        {
            "file_name": "unsafe.py",
            "content": "import pickle\npickle.loads(b'')",
            "expected_findings": 1,
        },
        {
            "file_name": "mixed.py",
            "content": "import os\nimport pickle\nos.system('ls')\npickle.loads(b'')",
            "expected_findings": 1,
        },
    ]

    # Create test files
    for data in test_data:
        file_path = tmp_path / data["file_name"]
        file_path.write_text(data["content"])

        # Scan the file
        scanner = ExampleScanner()
        result = scanner.scan_file(file_path)

        # Verify the result
        assert len(result.findings) == data["expected_findings"], (
            f"Failed for {data['file_name']}"
        )

        if data["expected_findings"] > 0:
            assert result.findings[0]["file_path"] == str(file_path)
            if "import pickle" in data["content"]:
                assert result.findings[0]["message"] == "Unsafe pickle usage detected"


# Example of a test with a workflow
@pytest.mark.integration
def test_workflow(tmp_path):
    """Test a complete workflow."""
    # Set up the test environment
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    config_dir = tmp_path / ".ash"
    config_dir.mkdir()

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # Create test files
    file1 = src_dir / "main.py"
    file1.write_text("import pickle\npickle.loads(b'')")

    # Create configuration
    config_file = config_dir / "config.json"
    config = {
        "scanners": {"example": {"enabled": True}},
        "reporters": {
            "example": {"enabled": True, "output_file": str(output_dir / "report.json")}
        },
    }
    config_file.write_text(json.dumps(config))

    # Define the workflow steps
    def step1_load_config():
        with open(config_file, "r") as f:
            return json.load(f)

    def step2_scan_files(config):
        scanner = ExampleScanner(config["scanners"]["example"])
        findings = []
        for file_path in src_dir.glob("**/*.py"):
            result = scanner.scan_file(file_path)
            findings.extend(result.findings)
        return findings

    def step3_generate_report(config, findings):
        reporter = ExampleReporter(config["reporters"]["example"])
        report = reporter.generate_report(ScanResult(findings))

        output_file = Path(config["reporters"]["example"]["output_file"])
        with open(output_file, "w") as f:
            json.dump(report, f)

        return output_file

    # Execute the workflow
    config = step1_load_config()
    findings = step2_scan_files(config)
    output_file = step3_generate_report(config, findings)

    # Verify the results
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(file1)
    assert findings[0]["message"] == "Unsafe pickle usage detected"

    assert output_file.exists()

    with open(output_file, "r") as f:
        report = json.load(f)

    assert report["version"] == "1.0.0"
    assert report["scanner"] == "example"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["file"] == str(file1)
    assert report["findings"][0]["message"] == "Unsafe pickle usage detected"
