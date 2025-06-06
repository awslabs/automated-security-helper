# Test Organization Guide

## Overview

This document provides guidelines for organizing tests in the ASH project. Proper test organization makes tests easier to find, understand, and maintain.

## Directory Structure

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
    ├── testing_framework.md  # Main documentation
    ├── test_organization.md  # This document
    └── ...
```

## Test Types

### Unit Tests

Unit tests focus on testing individual components in isolation. They should be fast, reliable, and independent of external dependencies.

- Location: `tests/unit/<module_path>/`
- Naming: `test_<module_name>.py`
- Marker: `@pytest.mark.unit`

Example:
```python
# tests/unit/scanners/test_bandit_scanner.py
import pytest

@pytest.mark.unit
@pytest.mark.scanner
def test_bandit_scanner_initialization():
    # Test code here
    pass
```

### Integration Tests

Integration tests focus on testing interactions between components. They verify that components work together correctly.

- Location: `tests/integration/<module_path>/`
- Naming: `test_<component1>_<component2>_integration.py`
- Marker: `@pytest.mark.integration`

Example:
```python
# tests/integration/scanners/test_scanner_reporter_integration.py
import pytest

@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.reporter
def test_scanner_reporter_integration():
    # Test code here
    pass
```

## Naming Conventions

### Test Files

Test files should be named according to the component they are testing:

- `test_<module_name>.py`

Examples:
- `test_bandit_scanner.py`
- `test_sarif_reporter.py`
- `test_config_loader.py`

### Test Classes

Test classes should be named according to the component they are testing:

- `Test<ComponentName>`

Examples:
- `TestBanditScanner`
- `TestSarifReporter`
- `TestConfigLoader`

### Test Functions

Test functions should be named according to the functionality they are testing:

- `test_<functionality_being_tested>`

Examples:
- `test_scan_python_file`
- `test_generate_sarif_report`
- `test_load_config_from_file`

For parameterized tests, include the parameter in the name:

- `test_<functionality>_with_<parameter>`

Examples:
- `test_scan_with_custom_config`
- `test_report_with_multiple_findings`

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

## Test Structure

Tests should follow the Arrange-Act-Assert (AAA) pattern:

1. **Arrange**: Set up the test environment and inputs
2. **Act**: Execute the code being tested
3. **Assert**: Verify the results

Example:
```python
def test_bandit_scanner_findings(temp_project_dir):
    # Arrange
    test_file = temp_project_dir / "test.py"
    test_file.write_text("import pickle\npickle.loads(b'')")
    scanner = BanditScanner()

    # Act
    result = scanner.scan_file(test_file)

    # Assert
    assert len(result.findings) == 1
    assert "pickle.loads" in result.findings[0].message
```

## Test Independence

Tests should be independent of each other. They should not depend on the state created by other tests.

- Use fixtures for setup and teardown
- Avoid global state
- Clean up resources after tests

Example:
```python
@pytest.fixture
def temp_config():
    config_file = Path(tempfile.mktemp())
    config_file.write_text("scanners:\n  bandit:\n    enabled: true")
    yield config_file
    config_file.unlink()

def test_with_config(temp_config):
    # Test code here
    pass
```

## Test Data

Test data should be stored in a consistent location:

- Small test data can be included directly in the test file
- Larger test data should be stored in `tests/fixtures/data/`
- Test data should be versioned with the code

Example:
```python
def test_with_test_data():
    test_data_path = Path(__file__).parent / "../fixtures/data/vulnerable_code.py"
    with open(test_data_path, "r") as f:
        test_data = f.read()

    # Test code here
    pass
```

## Best Practices

1. **Test one thing per test**: Each test should focus on testing a single functionality or behavior.
2. **Use descriptive test names**: Test names should clearly describe what is being tested.
3. **Follow the AAA pattern**: Arrange, Act, Assert.
4. **Use fixtures for setup and teardown**: Use fixtures to set up test environments and clean up after tests.
5. **Mock external dependencies**: Use mocks to isolate the code being tested from external dependencies.
6. **Test edge cases**: Test boundary conditions and error cases.
7. **Keep tests independent**: Tests should not depend on the state created by other tests.
8. **Use parameterized tests**: Use `@pytest.mark.parametrize` to test multiple inputs with the same test function.

## Example Test File

```python
# tests/unit/scanners/test_bandit_scanner.py
import pytest
from pathlib import Path
from automated_security_helper.scanners.bandit_scanner import BanditScanner

@pytest.fixture
def temp_python_file(temp_project_dir):
    file_path = temp_project_dir / "test.py"
    return file_path

@pytest.mark.unit
@pytest.mark.scanner
class TestBanditScanner:
    def test_initialization(self):
        scanner = BanditScanner()
        assert scanner.name == "bandit"
        assert scanner.is_enabled()

    def test_scan_python_file(self, temp_python_file):
        # Arrange
        temp_python_file.write_text("import pickle\npickle.loads(b'')")
        scanner = BanditScanner()

        # Act
        result = scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == 1
        assert "pickle.loads" in result.findings[0].message

    @pytest.mark.parametrize("code,expected_findings", [
        ("import pickle\npickle.loads(b'')", 1),  # Unsafe pickle usage
        ("import hashlib\nhashlib.md5(b'')", 1),  # Weak hash algorithm
        ("print('Hello, world!')", 0),  # No security issues
    ])
    def test_findings_with_different_code(self, temp_python_file, code, expected_findings):
        # Arrange
        temp_python_file.write_text(code)
        scanner = BanditScanner()

        # Act
        result = scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == expected_findings
```