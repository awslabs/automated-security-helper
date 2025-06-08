# Writing Effective Tests Guide

## Overview

This document provides guidelines for writing effective tests for the ASH project. Following these guidelines will help ensure that tests are reliable, maintainable, and provide good coverage of the codebase.

## Principles of Effective Testing

### 1. Test One Thing at a Time

Each test should focus on testing a single functionality or behavior. This makes tests easier to understand, maintain, and debug.

**Good Example:**
```python
def test_bandit_scanner_initialization():
    scanner = BanditScanner()
    assert scanner.name == "bandit"
    assert scanner.is_enabled()

def test_bandit_scanner_scan_python_file(temp_python_file):
    temp_python_file.write_text("import pickle\npickle.loads(b'')")
    scanner = BanditScanner()
    result = scanner.scan_file(temp_python_file)
    assert len(result.findings) == 1
```

**Bad Example:**
```python
def test_bandit_scanner():
    # Tests too many things in one test
    scanner = BanditScanner()
    assert scanner.name == "bandit"
    assert scanner.is_enabled()

    temp_file = Path("/tmp/test.py")
    temp_file.write_text("import pickle\npickle.loads(b'')")
    result = scanner.scan_file(temp_file)
    assert len(result.findings) == 1

    # More tests...
```

### 2. Use Descriptive Test Names

Test names should clearly describe what is being tested. This makes it easier to understand what a test is doing and what failed when a test fails.

**Good Example:**
```python
def test_bandit_scanner_finds_unsafe_pickle_usage():
    # Test code here
    pass

def test_bandit_scanner_ignores_safe_code():
    # Test code here
    pass
```

**Bad Example:**
```python
def test_scanner_1():
    # Test code here
    pass

def test_scanner_2():
    # Test code here
    pass
```

### 3. Follow the AAA Pattern

Tests should follow the Arrange-Act-Assert (AAA) pattern:

1. **Arrange**: Set up the test environment and inputs
2. **Act**: Execute the code being tested
3. **Assert**: Verify the results

This makes tests easier to read and understand.

**Good Example:**
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

### 4. Use Fixtures for Setup and Teardown

Use fixtures to set up test environments and clean up after tests. This reduces code duplication and ensures proper cleanup.

**Good Example:**
```python
@pytest.fixture
def temp_config():
    config_file = Path(tempfile.mktemp())
    config_file.write_text("scanners:\n  bandit:\n    enabled: true")
    yield config_file
    config_file.unlink()

def test_with_config(temp_config):
    scanner = BanditScanner(config_file=temp_config)
    assert scanner.is_enabled()
```

### 5. Mock External Dependencies

Use mocks to isolate the code being tested from external dependencies. This makes tests faster, more reliable, and focused on the code being tested.

**Good Example:**
```python
def test_scanner_with_mock_subprocess(mocker):
    # Mock subprocess.run to return a predefined result
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=["bandit", "-r", "test.py"],
        returncode=0,
        stdout="No issues found.",
        stderr=""
    )

    scanner = BanditScanner()
    result = scanner.scan_file(Path("test.py"))

    assert len(result.findings) == 0
    mock_run.assert_called_once()
```

### 6. Test Edge Cases

Test boundary conditions and error cases to ensure the code handles them correctly.

**Good Example:**
```python
@pytest.mark.parametrize("input_value,expected_error", [
    (None, TypeError),
    ("", ValueError),
    ("/nonexistent/file.py", FileNotFoundError),
])
def test_scanner_with_invalid_input(input_value, expected_error):
    scanner = BanditScanner()
    with pytest.raises(expected_error):
        scanner.scan_file(input_value)
```

### 7. Keep Tests Independent

Tests should not depend on the state created by other tests. Each test should be able to run independently.

**Good Example:**
```python
def test_scanner_1(temp_project_dir):
    # Test code here using temp_project_dir
    pass

def test_scanner_2(temp_project_dir):
    # Test code here using a fresh temp_project_dir
    pass
```

**Bad Example:**
```python
# Global state that tests depend on
TEMP_DIR = Path("/tmp/test")
TEMP_DIR.mkdir(exist_ok=True)

def test_scanner_1():
    # Creates files that test_scanner_2 depends on
    (TEMP_DIR / "test.py").write_text("import pickle\npickle.loads(b'')")
    # Test code here
    pass

def test_scanner_2():
    # Depends on files created by test_scanner_1
    # This test will fail if test_scanner_1 is not run first
    assert (TEMP_DIR / "test.py").exists()
    # Test code here
    pass
```

### 8. Use Parameterized Tests

Use `@pytest.mark.parametrize` to test multiple inputs with the same test function. This reduces code duplication and ensures consistent testing across different inputs.

**Good Example:**
```python
@pytest.mark.parametrize("code,expected_findings", [
    ("import pickle\npickle.loads(b'')", 1),  # Unsafe pickle usage
    ("import hashlib\nhashlib.md5(b'')", 1),  # Weak hash algorithm
    ("print('Hello, world!')", 0),  # No security issues
])
def test_bandit_scanner_findings(temp_python_file, code, expected_findings):
    # Arrange
    temp_python_file.write_text(code)
    scanner = BanditScanner()

    # Act
    result = scanner.scan_file(temp_python_file)

    # Assert
    assert len(result.findings) == expected_findings
```

## Test Structure

### Unit Tests

Unit tests should focus on testing a single unit of code in isolation. They should be fast, reliable, and independent of external dependencies.

```python
import pytest
from automated_security_helper.scanners.bandit_scanner import BanditScanner

@pytest.mark.unit
@pytest.mark.scanner
class TestBanditScanner:
    def test_initialization(self):
        scanner = BanditScanner()
        assert scanner.name == "bandit"
        assert scanner.is_enabled()

    def test_scan_python_file(self, temp_python_file, mocker):
        # Mock subprocess.run to return a predefined result
        mock_run = mocker.patch("subprocess.run")
        mock_run.return_value = subprocess.CompletedProcess(
            args=["bandit", "-r", "test.py"],
            returncode=0,
            stdout=json.dumps({
                "results": [
                    {
                        "filename": "test.py",
                        "line": 1,
                        "issue_text": "Unsafe pickle usage",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_cwe": "CWE-502",
                        "test_id": "B301"
                    }
                ]
            }),
            stderr=""
        )

        # Arrange
        temp_python_file.write_text("import pickle\npickle.loads(b'')")
        scanner = BanditScanner()

        # Act
        result = scanner.scan_file(temp_python_file)

        # Assert
        assert len(result.findings) == 1
        assert result.findings[0].file_path == "test.py"
        assert result.findings[0].line == 1
        assert "Unsafe pickle usage" in result.findings[0].message
        assert result.findings[0].severity == "HIGH"
        assert result.findings[0].rule_id == "B301"
```

### Integration Tests

Integration tests should focus on testing interactions between components. They verify that components work together correctly.

```python
import pytest
from automated_security_helper.scanners.bandit_scanner import BanditScanner
from automated_security_helper.reporters.sarif_reporter import SarifReporter

@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.reporter
def test_scanner_reporter_integration(temp_project_dir):
    # Arrange
    test_file = temp_project_dir / "test.py"
    test_file.write_text("import pickle\npickle.loads(b'')")

    scanner = BanditScanner()
    reporter = SarifReporter()

    # Act
    scan_result = scanner.scan_file(test_file)
    report = reporter.generate_report(scan_result)

    # Assert
    assert len(report["runs"][0]["results"]) == 1
    assert report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "test.py"
    assert "Unsafe pickle usage" in report["runs"][0]["results"][0]["message"]["text"]
```

### End-to-End Tests

End-to-end tests should focus on testing complete workflows from start to finish. They verify that the system works correctly as a whole.

```python
import pytest
from tests.utils.integration_test_utils import integration_test_environment

@pytest.mark.integration
@pytest.mark.slow
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

## Test Coverage

### What to Test

1. **Public API**: Test all public methods and functions.
2. **Edge Cases**: Test boundary conditions and error cases.
3. **Complex Logic**: Test complex logic with multiple paths.
4. **Bug Fixes**: Write tests for bug fixes to prevent regressions.

### What Not to Test

1. **Private Methods**: Focus on testing the public API, not implementation details.
2. **External Libraries**: Assume external libraries work correctly.
3. **Simple Getters/Setters**: Don't test trivial code.
4. **Generated Code**: Don't test code that is generated by tools.

### Coverage Goals

- **Line Coverage**: Aim for at least 80% line coverage.
- **Branch Coverage**: Aim for at least 80% branch coverage.
- **Critical Components**: Aim for 100% coverage of critical components.

## Common Testing Patterns

### Testing Functions

```python
def test_function_name():
    # Arrange
    input_value = "test input"
    expected_output = "expected output"

    # Act
    actual_output = function_name(input_value)

    # Assert
    assert actual_output == expected_output
```

### Testing Classes

```python
class TestClassName:
    def test_initialization(self):
        # Test initialization
        instance = ClassName(param1="value1")
        assert instance.param1 == "value1"

    def test_method_name(self):
        # Test a method
        instance = ClassName()
        result = instance.method_name("input")
        assert result == "expected output"
```

### Testing Exceptions

```python
def test_function_raises_exception():
    with pytest.raises(ValueError) as excinfo:
        function_that_raises()

    assert "Expected error message" in str(excinfo.value)
```

### Testing Asynchronous Code

```python
@pytest.mark.asyncio
async def test_async_function():
    # Arrange
    input_value = "test input"
    expected_output = "expected output"

    # Act
    actual_output = await async_function(input_value)

    # Assert
    assert actual_output == expected_output
```

## Testing Anti-Patterns

### 1. Slow Tests

Slow tests discourage frequent testing and slow down development. Keep tests fast by:

- Mocking external dependencies
- Using in-memory databases instead of real databases
- Focusing on unit tests over integration tests
- Marking slow tests with `@pytest.mark.slow`

### 2. Flaky Tests

Flaky tests that sometimes pass and sometimes fail reduce confidence in the test suite. Avoid flaky tests by:

- Avoiding race conditions
- Not depending on timing
- Not depending on external services
- Using deterministic test data
- Isolating tests from each other

### 3. Overspecified Tests

Tests that are too tightly coupled to implementation details make refactoring difficult. Avoid overspecified tests by:

- Testing behavior, not implementation
- Using black-box testing
- Focusing on inputs and outputs
- Not testing private methods directly

### 4. Incomplete Tests

Tests that don't cover all important cases can give a false sense of security. Avoid incomplete tests by:

- Testing edge cases
- Testing error cases
- Using parameterized tests
- Checking coverage reports

## Debugging Tests

### 1. Use Verbose Output

Run tests with verbose output to see more details:

```bash
pytest -v
```

### 2. Use the Debugger

Drop into the debugger on test failures:

```bash
pytest --pdb
```

### 3. Use Print Statements

Add print statements to see what's happening during test execution:

```python
def test_function():
    result = function_being_tested()
    print(f"Result: {result}")
    assert result == expected_result
```

### 4. Isolate the Problem

Run only the failing test to isolate the problem:

```bash
pytest path/to/test_file.py::test_function -v
```

### 5. Check Test Dependencies

Make sure tests don't depend on each other:

```bash
pytest --random-order
```

## Continuous Integration

### 1. Run Tests on Every Commit

Configure CI to run tests on every commit to catch issues early.

### 2. Run All Tests

Run all tests, including slow and integration tests, in CI.

### 3. Check Coverage

Generate coverage reports in CI to ensure coverage doesn't decrease.

### 4. Fail Fast

Configure CI to fail as soon as a test fails to get faster feedback.

## Conclusion

Writing effective tests is an investment in the quality and maintainability of the codebase. By following these guidelines, you can create tests that are reliable, maintainable, and provide good coverage of the codebase.

Remember that the goal of testing is not just to catch bugs, but also to:

- Document how the code is supposed to work
- Make it safer to refactor code
- Provide confidence that changes don't break existing functionality
- Help design better code by making it testable

By writing effective tests, you contribute to the long-term health and success of the project.