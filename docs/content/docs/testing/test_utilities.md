# Test Utilities Guide

## Overview

This document provides guidance on using the test utilities available in the ASH testing framework. These utilities are designed to make writing and maintaining tests easier, more consistent, and more effective.

## Assertion Utilities

Custom assertions are available in `tests.utils.assertions` to simplify common validation tasks.

### SARIF Report Assertions

```python
from tests.utils.assertions import assert_sarif_report_valid, assert_has_finding

def test_scanner_output(scanner_result):
    # Validate that the SARIF report is well-formed
    assert_sarif_report_valid(scanner_result.sarif_report)

    # Check for specific findings
    assert_has_finding(scanner_result.sarif_report,
                      file_path="test.py",
                      message_pattern="Unsafe pickle usage")

    # Check for findings with specific properties
    assert_has_finding(scanner_result.sarif_report,
                      severity="HIGH",
                      rule_id="B301")
```

### Suppression Assertions

```python
from tests.utils.assertions import assert_finding_suppressed

def test_suppression(scanner_result, suppression_config):
    # Check that a specific finding is suppressed
    assert_finding_suppressed(scanner_result.sarif_report,
                             file_path="test.py",
                             rule_id="B301",
                             suppression_config=suppression_config)
```

### Custom Matchers

```python
from tests.utils.assertions import assert_matches_pattern, assert_dict_contains

def test_with_pattern_matching():
    # Check that a string matches a pattern
    assert_matches_pattern("Error: File not found", r"Error: .* not found")

    # Check that a dictionary contains specific keys and values
    assert_dict_contains({"name": "bandit", "enabled": True, "options": {"level": "HIGH"}},
                        {"name": "bandit", "enabled": True})
```

## Mocking Utilities

Mocking utilities are available in `tests.utils.mocks` to simplify creating mock objects for testing.

### Mock SARIF Reports

```python
from tests.utils.mocks import create_mock_sarif_report

def test_with_mock_sarif():
    # Create a mock SARIF report with specific findings
    mock_sarif = create_mock_sarif_report(
        findings=[
            {
                "file_path": "test.py",
                "line": 10,
                "message": "Unsafe pickle usage",
                "severity": "HIGH",
                "rule_id": "B301"
            },
            {
                "file_path": "other.py",
                "line": 5,
                "message": "Weak hash algorithm",
                "severity": "MEDIUM",
                "rule_id": "B303"
            }
        ]
    )

    # Use the mock SARIF report in tests
    reporter = SarifReporter()
    report = reporter.process_report(mock_sarif)

    assert len(report.findings) == 2
```

### Mock Scanner Plugins

```python
from tests.utils.mocks import create_mock_scanner

def test_with_mock_scanner():
    # Create a mock scanner with specific findings
    mock_scanner = create_mock_scanner(
        name="bandit",
        findings=[
            {
                "file_path": "test.py",
                "line": 10,
                "message": "Unsafe pickle usage",
                "severity": "HIGH",
                "rule_id": "B301"
            }
        ]
    )

    # Use the mock scanner in tests
    result = mock_scanner.scan()
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "B301"
```

### Mock Context Generators

```python
from tests.utils.mocks import create_mock_context

def test_with_mock_context():
    # Create a mock context with specific properties
    mock_context = create_mock_context(
        config={"scanners": {"bandit": {"enabled": True}}},
        work_dir="/tmp/test",
        output_dir="/tmp/test/output"
    )

    # Use the mock context in tests
    scanner = BanditScanner(context=mock_context)
    assert scanner.is_enabled()
```

## Test Data Utilities

Test data utilities are available in `tests.utils.test_data` to simplify managing test data.

### Test Data Factories

```python
from tests.utils.test_data_factories import create_test_file, create_test_config

def test_with_generated_data():
    # Create a test file with specific content
    test_file = create_test_file(
        file_path="test.py",
        content="import pickle\npickle.loads(b'')"
    )

    # Create a test configuration
    test_config = create_test_config(
        scanners={"bandit": {"enabled": True}}
    )

    # Use the test data in tests
    scanner = BanditScanner(config=test_config)
    result = scanner.scan_file(test_file)

    assert len(result.findings) == 1
```

### Test Data Loaders

```python
from tests.utils.test_data_loaders import load_test_data, load_test_config

def test_with_loaded_data():
    # Load test data from a file
    test_data = load_test_data("scanners/bandit/vulnerable_code.py")

    # Load a test configuration
    test_config = load_test_config("scanners/bandit/config.yaml")

    # Use the loaded data in tests
    test_file = create_test_file("test.py", test_data)
    scanner = BanditScanner(config=test_config)
    result = scanner.scan_file(test_file)

    assert len(result.findings) > 0
```

## Context Managers

Context managers are available in `tests.utils.context_managers` to simplify managing test resources.

### Environment Variables

```python
from tests.utils.context_managers import environment_variable

def test_with_env_var():
    # Set an environment variable for the duration of the test
    with environment_variable("ASH_CONFIG_PATH", "/tmp/test/config.yaml"):
        # Code that uses the environment variable
        config_path = os.environ.get("ASH_CONFIG_PATH")
        assert config_path == "/tmp/test/config.yaml"

    # The environment variable is restored to its original value
    assert "ASH_CONFIG_PATH" not in os.environ
```

### Temporary Files and Directories

```python
from tests.utils.context_managers import temp_file, temp_directory

def test_with_temp_file():
    # Create a temporary file for the duration of the test
    with temp_file(content="test content") as file_path:
        # Code that uses the temporary file
        assert file_path.read_text() == "test content"

    # The file is automatically deleted
    assert not file_path.exists()

def test_with_temp_directory():
    # Create a temporary directory for the duration of the test
    with temp_directory() as dir_path:
        # Code that uses the temporary directory
        (dir_path / "test.txt").write_text("test content")
        assert (dir_path / "test.txt").exists()

    # The directory is automatically deleted
    assert not dir_path.exists()
```

### Mocking External Services

```python
from tests.utils.context_managers import mock_subprocess_run

def test_with_mock_subprocess():
    # Mock subprocess.run for the duration of the test
    with mock_subprocess_run(return_value=subprocess.CompletedProcess(
        args=["bandit", "-r", "test.py"],
        returncode=0,
        stdout="No issues found.",
        stderr=""
    )):
        # Code that calls subprocess.run
        result = subprocess.run(["bandit", "-r", "test.py"], capture_output=True, text=True)
        assert result.returncode == 0
        assert result.stdout == "No issues found."
```

## Integration Test Utilities

Integration test utilities are available in `tests.utils.integration_test_utils` to simplify setting up integration tests.

### Integration Test Environment

```python
from tests.utils.integration_test_utils import integration_test_environment

def test_end_to_end_scan():
    with integration_test_environment() as env:
        # Set up the test environment
        env.create_config_file({"scanners": {"bandit": {"enabled": True}}})
        env.create_source_file("src/main.py", "import pickle\npickle.loads(b'')")

        # Run the command being tested
        result = env.run_ash(["scan"])

        # Verify the results
        assert result.returncode == 0
        assert "pickle.loads" in env.read_output_file("bandit_report.txt")
```

### Component Interaction Testing

```python
from tests.utils.integration_test_utils import component_interaction_tester

def test_scanner_reporter_interaction():
    with component_interaction_tester() as tester:
        # Register components for testing
        scanner = tester.register_component("scanner", BanditScanner)
        reporter = tester.register_component("reporter", SarifReporter)

        # Execute the interaction
        scanner.scan()
        reporter.report(scanner.results)

        # Verify the interaction
        assert tester.verify_interaction("scanner", "reporter", "report")
```

### Integration Point Verification

```python
from tests.utils.integration_test_utils import integration_test_verifier

def test_integration_points():
    with integration_test_verifier() as verifier:
        # Register integration points to verify
        verifier.register_integration_point(
            name="scan-report",
            source="scanner",
            target="reporter",
            interface=["report"]
        )

        # Set up the test
        with component_interaction_tester() as tester:
            scanner = tester.register_component("scanner", BanditScanner)
            reporter = tester.register_component("reporter", SarifReporter)

            # Execute the interaction
            scanner.scan()
            reporter.report(scanner.results)

            # Verify all integration points
            assert verifier.verify_all(tester)
```

## Resource Management

Resource management utilities are available in `tests.utils.resource_management` to simplify managing test resources.

### Temporary Resources

```python
from tests.utils.resource_management import temp_directory, temp_file

def test_with_temp_resources():
    with temp_directory() as temp_dir:
        # Use the temporary directory
        config_file = temp_dir / "config.yaml"
        config_file.write_text("scanners:\n  bandit:\n    enabled: true")

        with temp_file(suffix=".py", content="import pickle\npickle.loads(b'')") as temp_file_path:
            # Use the temporary file
            scanner = BanditScanner(config_file=config_file)
            result = scanner.scan_file(temp_file_path)

            assert len(result.findings) == 1
```

### Process Management

```python
from tests.utils.resource_management import managed_process

def test_with_external_process():
    with temp_directory() as temp_dir:
        # Set up the test environment
        config_file = temp_dir / "config.yaml"
        config_file.write_text("scanners:\n  bandit:\n    enabled: true")

        # Start a process for the duration of the test
        with managed_process(["python", "-m", "http.server"], cwd=temp_dir) as process:
            # Test code that interacts with the HTTP server
            # The process will be automatically terminated when the context exits
            pass
```

### Service Management

```python
from tests.utils.resource_management import managed_service

def test_with_external_service():
    # Define a function to check if the service is ready
    def is_ready():
        try:
            with socket.create_connection(("localhost", 8000), timeout=1):
                return True
        except:
            return False

    # Start a service for the duration of the test
    with managed_service(
        name="http-server",
        command=["python", "-m", "http.server"],
        ready_check=is_ready
    ) as process:
        # Test code that interacts with the service
        # The service will be automatically stopped when the context exits
        pass
```

## External Service Mocks

Mock external services are available in `tests.utils.external_service_mocks` to simplify testing code that interacts with external services.

### Mock HTTP Server

```python
from tests.utils.external_service_mocks import mock_http_server

def test_with_mock_http_server():
    with mock_http_server() as server:
        # Add files to the server
        server.add_file("test.json", {"key": "value"})

        # Get the URL for a file
        url = server.get_url("test.json")

        # Test code that interacts with the HTTP server
        response = requests.get(url)
        assert response.json() == {"key": "value"}
```

### Mock API Server

```python
from tests.utils.external_service_mocks import mock_api_server

def test_with_mock_api_server():
    with mock_api_server() as server:
        # Define a route handler
        def handle_hello(method, path, query, headers, body):
            return 200, {"Content-Type": "application/json"}, {"message": "Hello, world!"}

        # Add a route to the server
        server.add_route("/hello", handle_hello)

        # Get the URL for the route
        url = server.get_url("hello")

        # Test code that interacts with the API server
        response = requests.get(url)
        assert response.json() == {"message": "Hello, world!"}
```

### Mock File Server

```python
from tests.utils.external_service_mocks import mock_file_server

def test_with_mock_file_server():
    with mock_file_server() as server:
        # Add files to the server
        server.add_file("test.json", {"key": "value"})

        # Get the path to a file
        path = server.get_file_path("test.json")

        # Test code that interacts with the file server
        with open(path, "r") as f:
            data = json.load(f)
            assert data == {"key": "value"}
```

## Best Practices

1. **Use the right utility for the job**: Choose the appropriate utility based on what you're testing.
2. **Clean up resources**: Use context managers to ensure resources are cleaned up properly.
3. **Isolate tests**: Use mocks and fixtures to isolate tests from external dependencies.
4. **Keep tests fast**: Use mocks instead of real external services when possible.
5. **Make tests readable**: Use descriptive variable names and comments to explain what the test is doing.
6. **Test edge cases**: Use utilities to create test data that covers edge cases.
7. **Reuse test code**: Create helper functions for common test patterns.
8. **Document utilities**: Add docstrings to explain how to use utilities.

## Example: Comprehensive Test

```python
import pytest
from pathlib import Path
from tests.utils.assertions import assert_sarif_report_valid, assert_has_finding
from tests.utils.mocks import create_mock_scanner
from tests.utils.test_data_factories import create_test_file
from tests.utils.context_managers import environment_variable
from tests.utils.integration_test_utils import integration_test_environment

# Unit test with mocks
@pytest.mark.unit
@pytest.mark.reporter
def test_reporter_with_mock_scanner():
    # Create a mock scanner with specific findings
    mock_scanner = create_mock_scanner(
        name="bandit",
        findings=[
            {
                "file_path": "test.py",
                "line": 10,
                "message": "Unsafe pickle usage",
                "severity": "HIGH",
                "rule_id": "B301"
            }
        ]
    )

    # Use the mock scanner in tests
    reporter = SarifReporter()
    report = reporter.generate_report(mock_scanner.scan())

    # Verify the report
    assert_sarif_report_valid(report)
    assert_has_finding(report, file_path="test.py", rule_id="B301")

# Integration test with environment
@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.reporter
def test_end_to_end_scan():
    with integration_test_environment() as env:
        # Set up the test environment
        env.create_config_file({"scanners": {"bandit": {"enabled": True}}})
        env.create_source_file("src/main.py", "import pickle\npickle.loads(b'')")

        # Set environment variables
        with environment_variable("ASH_DEBUG", "true"):
            # Run the command being tested
            result = env.run_ash(["scan"])

            # Verify the results
            assert result.returncode == 0
            assert "pickle.loads" in env.read_output_file("bandit_report.txt")
```