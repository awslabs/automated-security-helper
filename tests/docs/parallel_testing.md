# Parallel Test Execution Guide

This guide explains how to use and configure parallel test execution in the ASH testing framework.

## Overview

Parallel test execution allows tests to run simultaneously, significantly reducing the time required to run the test suite. However, it requires careful consideration to ensure tests don't interfere with each other when running in parallel.

## Configuration

Parallel test execution is enabled by default in the pytest configuration. The following settings in `pytest.ini` control parallel execution:

```ini
addopts =
    # Other options...
    -n auto
```

The `-n auto` option tells pytest to automatically determine the number of workers based on the number of available CPU cores.

## Writing Parallel-Safe Tests

To ensure your tests can run safely in parallel, follow these guidelines:

### 1. Use Isolated Resources

Always use isolated resources (files, directories, environment variables) that won't conflict with other tests running in parallel.

```python
# BAD: Using a fixed file path
def test_scanner_output():
    output_file = Path("/tmp/scanner_output.json")
    # This could conflict with other tests using the same path

# GOOD: Using an isolated file path
def test_scanner_output(tmp_path):
    output_file = tmp_path / "scanner_output.json"
    # This is isolated to this test
```

### 2. Use the Provided Test Utilities

The testing framework provides utilities to help write parallel-safe tests:

```python
from tests.utils.parallel_test_utils import isolated_test_context, ParallelTestHelper

def test_with_isolation():
    with isolated_test_context() as temp_dir:
        # Use temp_dir for test files
        input_file = temp_dir / "input.txt"
        input_file.write_text("test content")

        # Run your test code
        result = process_file(input_file)
        assert result == "expected output"
```

### 3. Avoid Modifying Global State

Tests should not modify global state that could affect other tests:

```python
# BAD: Modifying global configuration
def test_with_global_config():
    set_global_config({"key": "value"})  # This affects other tests

# GOOD: Using context manager for isolated configuration
def test_with_isolated_config():
    with mock_config({"key": "value"}):  # This is isolated to this test
        # Test code here
```

### 4. Use Test-Specific Environment Variables

When tests need environment variables, use isolated names:

```python
from tests.utils.parallel_test_utils import get_isolated_env_var_name

def test_with_env_vars():
    env_var_name = get_isolated_env_var_name("API_KEY")
    with environment_variables(**{env_var_name: "test_value"}):
        # Test code here
```

### 5. Use Pytest Fixtures for Resource Management

Pytest fixtures provide a clean way to set up and tear down resources:

```python
@pytest.fixture
def isolated_config_file(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("key: value")
    return config_file

def test_with_config(isolated_config_file):
    # Use isolated_config_file in your test
```

## Marking Tests as Non-Parallel

Some tests may not be suitable for parallel execution. Mark these tests with the `pytest.mark.serial` decorator:

```python
@pytest.mark.serial
def test_that_must_run_serially():
    # This test will not run in parallel with other tests
```

## Troubleshooting Parallel Test Issues

If you encounter issues with parallel test execution, consider these common problems:

1. **Resource Conflicts**: Tests might be using the same files, directories, or environment variables.
   - Solution: Use the `isolated_test_context` or pytest's `tmp_path` fixture.

2. **Database Conflicts**: Tests might be using the same database tables.
   - Solution: Use separate database schemas or in-memory databases for testing.

3. **Global State Modifications**: Tests might be modifying global state.
   - Solution: Use context managers to isolate changes to the test scope.

4. **Order Dependencies**: Tests might depend on running in a specific order.
   - Solution: Make tests independent of each other.

## Performance Considerations

- **Test Isolation**: More isolated tests run better in parallel but may have more setup/teardown overhead.
- **Resource Usage**: Running tests in parallel increases CPU and memory usage.
- **CI Environment**: Consider setting a specific number of workers in CI environments with limited resources:
  ```
  pytest -n 2  # Use 2 workers instead of auto-detection
  ```

## Advanced Configuration

For more advanced parallel test configuration, you can create a `conftest.py` file with custom settings:

```python
def pytest_xdist_make_scheduler(config, log):
    """Custom test scheduler for parallel execution."""
    from xdist.scheduler import LoadScheduling
    return LoadScheduling(config, log)
```

This allows for customizing how tests are distributed among workers.