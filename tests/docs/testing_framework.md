# ASH Testing Framework Documentation

## Overview

This document provides comprehensive guidance on using the ASH testing framework. The framework is designed to make writing and maintaining tests easier, more consistent, and more effective. It includes utilities for test organization, fixtures, mocking, test data management, and integration testing.

## Test Organization

### Directory Structure

The test directory structure mirrors the main codebase structure to make it easier to locate tests for specific components:

```
tests/
├── unit/                  # Unit tests that test individual components in isolation
│   ├── core/              # Tests for core functionality
│   ├── scanners/          # Tests for scanner components
│   ├── reporters/         # Tests for reporter components
│   └── ...
├── integration/           # Integration tests that test component interactions
│   ├── scanners/          # Integration tests for scanner components
│   ├── reporters/         # Integration tests for reporter components
│   └── ...
├── fixtures/              # Common test fixtures
│   ├── config/            # Configuration fixtures
│   ├── models/            # Model fixtures
│   └── ...
├── utils/                 # Test utilities
│   ├── assertions.py      # Custom assertions
│   ├── mocks.py           # Mock objects and factories
│   ├── test_data.py       # Test data utilities
│   └── ...
├── conftest.py            # Pytest configuration and shared fixtures
└── docs/                  # Test documentation
    ├── testing_framework.md  # This document
    ├── test_selection.md     # Documentation for test selection
    └── ...
```

### Naming Conventions

Test files and functions follow these naming conventions:

- Test files: `test_<module_name>.py`
- Test classes: `Test<ComponentName>`
- Test functions: `test_<functionality_being_tested>`

Example:
```python
# tests/unit/scanners/test_bandit_scanner.py
class TestBanditScanner:
    def test_scan_python_file(self):
        # Test code here
        pass

    def test_scan_with_custom_config(self):
        # Test code here
        pass
```

## Test Categories and Markers

Tests are categorized using pytest markers to allow selective execution:

- `@pytest.mark.unit`: Unit tests that test individual components in isolation
- `@pytest.mark.integration`: Integration tests that test component interactions
- `@pytest.mark.slow`: Tests that take a long time to run
- `@pytest.mark.scanner`: Tests related to scanner functionality
- `@pytest.mark.reporter`: Tests related to reporter functionality
- `@pytest.mark.config`: Tests related to configuration functionality
- `@pytest.mark.model`: Tests related to data models
- `@pytest.mark.serial`: Tests that should not run in parallel

Example:
```python
import pytest

@pytest.mark.unit
@pytest.mark.scanner
def test_bandit_scanner_initialization():
    # Test code here
    pass

@pytest.mark.integration
@pytest.mark.slow
def test_end_to_end_scan():
    # Test code here
    pass
```

## Test Fixtures

### Common Fixtures

The framework provides several common fixtures to simplify test setup:

- `temp_config_dir`: Creates a temporary directory for configuration files
- `temp_output_dir`: Creates a temporary directory for output files
- `temp_project_dir`: Creates a temporary directory with a basic project structure
- `temp_env_vars`: Sets environment variables for the duration of a test

Example:
```python
def test_scanner_with_config(temp_config_dir):
    config_file = temp_config_dir / "config.yaml"
    config_file.write_text("scanners:\n  bandit:\n    enabled: true")

    scanner = BanditScanner(config_file=config_file)
    assert scanner.is_enabled()
```

### Custom Fixtures

You can create custom fixtures in `conftest.py` or in test modules:

```python
@pytest.fixture
def mock_bandit_scanner():
    scanner = MockBanditScanner()
    scanner.add_finding("test.py", "Test finding", "HIGH")
    return scanner
```

## Test Utilities

### Assertions

Custom assertions are available in `tests.utils.assertions`:

```python
from tests.utils.assertions import assert_sarif_report_valid, assert_has_finding

def test_scanner_output(scanner_result):
    assert_sarif_report_valid(scanner_result.sarif_report)
    assert_has_finding(scanner_result.sarif_report, "test.py", "Test finding")
```

### Mocking

Mocking utilities are available in `tests.utils.mocks`:

```python
from tests.utils.mocks import create_mock_sarif_report, create_mock_scanner

def test_reporter_with_mock_scanner():
    mock_scanner = create_mock_scanner("bandit", findings=[
        {"file": "test.py", "message": "Test finding", "severity": "HIGH"}
    ])

    reporter = SarifReporter()
    report = reporter.generate_report(mock_scanner.scan())

    assert "test.py" in report
    assert "Test finding" in report
```

### Test Data Management

Test data utilities are available in `tests.utils.test_data`:

```python
from tests.utils.test_data import load_test_data, create_test_file

def test_scanner_with_test_data():
    test_data = load_test_data("scanners/bandit/vulnerable_code.py")
    test_file = create_test_file("test.py", test_data)

    scanner = BanditScanner()
    result = scanner.scan_file(test_file)

    assert len(result.findings) > 0
```

## Integration Testing

### Integration Test Environment

The `IntegrationTestEnvironment` class provides utilities for setting up integration test environments:

```python
from tests.utils.integration_test_utils import integration_test_environment

def test_end_to_end_scan():
    with integration_test_environment() as env:
        env.create_config_file({"scanners": {"bandit": {"enabled": True}}})
        env.create_source_file("src/main.py", "import pickle\npickle.loads(b'')")

        result = env.run_ash(["scan"])

        assert result.returncode == 0
        assert "pickle.loads" in env.read_output_file("bandit_report.txt")
```

### Component Interaction Testing

The `ComponentInteractionTester` class provides utilities for testing interactions between components:

```python
from tests.utils.integration_test_utils import component_interaction_tester

def test_scanner_reporter_interaction():
    with component_interaction_tester() as tester:
        scanner = tester.register_component("scanner", BanditScanner)
        reporter = tester.register_component("reporter", SarifReporter)

        scanner.scan()
        reporter.report(scanner.results)

        assert tester.verify_interaction("scanner", "reporter", "report")
```

### Resource Management

Resource management utilities are available in `tests.utils.resource_management`:

```python
from tests.utils.resource_management import temp_directory, managed_process

def test_with_external_process():
    with temp_directory() as temp_dir:
        config_file = temp_dir / "config.yaml"
        config_file.write_text("scanners:\n  bandit:\n    enabled: true")

        with managed_process(["python", "-m", "http.server"], cwd=temp_dir) as process:
            # Test code that interacts with the HTTP server
            pass
```

### External Service Mocks

Mock external services are available in `tests.utils.external_service_mocks`:

```python
from tests.utils.external_service_mocks import mock_http_server, mock_api_server

def test_with_mock_http_server():
    with mock_http_server() as server:
        server.add_file("test.json", {"key": "value"})
        url = server.get_url("test.json")

        # Test code that interacts with the HTTP server
        response = requests.get(url)
        assert response.json() == {"key": "value"}

def test_with_mock_api_server():
    with mock_api_server() as server:
        def handle_hello(method, path, query, headers, body):
            return 200, {"Content-Type": "application/json"}, {"message": "Hello, world!"}

        server.add_route("/hello", handle_hello)
        url = server.get_url("hello")

        # Test code that interacts with the API server
        response = requests.get(url)
        assert response.json() == {"message": "Hello, world!"}
```

## Coverage Reporting

### Configuration

Coverage reporting is configured in `.coveragerc`:

```ini
[run]
source = automated_security_helper
omit =
    */tests/*
    */venv/*
    */site-packages/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
    if __name__ == .__main__.:
    pass
    raise ImportError
```

### Running Coverage Reports

To run tests with coverage reporting:

```bash
pytest --cov=automated_security_helper
```

To generate an HTML coverage report:

```bash
pytest --cov=automated_security_helper --cov-report=html
```

### Coverage Enforcement

Coverage thresholds are enforced in CI pipelines. The minimum coverage threshold is 80% for the overall codebase, with higher thresholds for critical components.

## Parallel Test Execution

### Configuration

Parallel test execution is configured in `pytest.ini`:

```ini
[pytest]
addopts = -xvs
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests that test individual components in isolation
    integration: Integration tests that test component interactions
    slow: Tests that take a long time to run
    scanner: Tests related to scanner functionality
    reporter: Tests related to reporter functionality
    config: Tests related to configuration functionality
    model: Tests related to data models
    serial: Tests that should not run in parallel
```

### Running Tests in Parallel

To run tests in parallel:

```bash
pytest -xvs -n auto
```

Tests marked with `@pytest.mark.serial` will not run in parallel.

## Test Selection and Filtering

### Command-Line Options

The framework provides several command-line options for selective test execution:

- `--run-slow`: Run slow tests
- `--run-integration`: Run integration tests
- `--run-changed-only`: Run only tests for changed files
- `--base-branch`: Base branch for `--run-changed-only` option (default: `main`)

Example:
```bash
pytest --run-integration --run-slow
```

### Test Selection Utilities

Test selection utilities are available in `tests.utils.test_selection`:

```python
from tests.utils.test_selection import get_changed_files, get_related_test_files

def test_selection():
    changed_files = get_changed_files("main")
    related_test_files = get_related_test_files(changed_files)

    # Run only the related tests
    for test_file in related_test_files:
        pytest.main([test_file])
```

## Best Practices

### Writing Effective Tests

1. **Test one thing per test**: Each test should focus on testing a single functionality or behavior.
2. **Use descriptive test names**: Test names should clearly describe what is being tested.
3. **Follow the AAA pattern**: Arrange, Act, Assert.
4. **Use fixtures for setup and teardown**: Use fixtures to set up test environments and clean up after tests.
5. **Mock external dependencies**: Use mocks to isolate the code being tested from external dependencies.
6. **Test edge cases**: Test boundary conditions and error cases.
7. **Keep tests independent**: Tests should not depend on the state created by other tests.
8. **Use parameterized tests**: Use `@pytest.mark.parametrize` to test multiple inputs with the same test function.

### Example:

```python
import pytest
from automated_security_helper.scanners.bandit_scanner import BanditScanner

@pytest.mark.parametrize("code,expected_findings", [
    ("import pickle\npickle.loads(b'')", 1),  # Unsafe pickle usage
    ("import hashlib\nhashlib.md5(b'')", 1),  # Weak hash algorithm
    ("print('Hello, world!')", 0),  # No security issues
])
def test_bandit_scanner_findings(temp_project_dir, code, expected_findings):
    # Arrange
    test_file = temp_project_dir / "test.py"
    test_file.write_text(code)
    scanner = BanditScanner()

    # Act
    result = scanner.scan_file(test_file)

    # Assert
    assert len(result.findings) == expected_findings
```

## Troubleshooting

### Common Issues

1. **Tests fail in CI but pass locally**: Check for environment differences, file path issues, or timing issues.
2. **Tests interfere with each other**: Check for shared state or resources that are not properly isolated.
3. **Slow tests**: Use profiling to identify bottlenecks, consider marking slow tests with `@pytest.mark.slow`.
4. **Flaky tests**: Check for race conditions, timing issues, or external dependencies.

### Debugging Tips

1. **Use `pytest -v`**: Run tests with verbose output to see more details.
2. **Use `pytest --pdb`**: Drop into the debugger on test failures.
3. **Use `print` statements**: Add print statements to see what's happening during test execution.
4. **Check test isolation**: Make sure tests don't depend on the state created by other tests.
5. **Check resource cleanup**: Make sure resources are properly cleaned up after tests.

## Contributing

When adding new tests or test utilities, please follow these guidelines:

1. **Follow naming conventions**: Use the naming conventions described in this document.
2. **Add appropriate markers**: Add markers to categorize tests appropriately.
3. **Document test utilities**: Add docstrings to test utilities to explain how to use them.
4. **Keep tests fast**: Optimize tests to run quickly, mark slow tests with `@pytest.mark.slow`.
5. **Keep tests independent**: Tests should not depend on the state created by other tests.
6. **Add examples**: Add examples to show how to use new test utilities.
7. **Update documentation**: Update this document when adding new test utilities or patterns.