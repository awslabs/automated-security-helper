# Test Selection and Filtering Guide

This guide explains how to use the test selection and filtering capabilities in the ASH testing framework.

## Overview

The ASH testing framework provides several ways to select and filter tests, allowing you to run specific subsets of tests based on various criteria such as:

- Test markers
- Keywords in test names
- File paths
- Related code changes
- Test categories

## Using Test Markers

Test markers allow you to categorize tests and run specific categories.

### Available Markers

The following markers are available in the ASH testing framework:

- `unit`: Unit tests that test individual components in isolation
- `integration`: Integration tests that test component interactions
- `slow`: Tests that take a long time to run
- `scanner`: Tests related to scanner functionality
- `reporter`: Tests related to reporter functionality
- `config`: Tests related to configuration functionality
- `model`: Tests related to data models

### Running Tests with Specific Markers

To run tests with a specific marker:

```bash
# Run all unit tests
pytest -m unit

# Run all integration tests
pytest -m integration

# Run all scanner tests
pytest -m scanner

# Run tests with multiple markers (OR logic)
pytest -m "unit or integration"

# Run tests with multiple markers (AND logic)
pytest -m "scanner and not slow"
```

## Using Keywords

You can run tests that match specific keywords in their names:

```bash
# Run all tests with "config" in their name
pytest -k config

# Run all tests with "parse" or "validate" in their name
pytest -k "parse or validate"

# Run all tests with "config" in their name but not "error"
pytest -k "config and not error"
```

## Running Tests for Changed Files

The testing framework provides a utility to run tests related to changed files:

```bash
# Run tests for files changed compared to the main branch
python -m tests.utils.test_selection --changed

# Run tests for files changed compared to a specific branch
python -m tests.utils.test_selection --changed --base-branch develop

# Include related test files
python -m tests.utils.test_selection --changed --include-related
```

## Command-Line Interface

The `test_selection.py` module provides a command-line interface for running selected tests:

```bash
# Run tests with specific markers
python -m tests.utils.test_selection --marker unit --marker config

# Run tests with specific keywords
python -m tests.utils.test_selection --keyword parse --keyword validate

# Exclude tests with specific markers
python -m tests.utils.test_selection --exclude-marker slow

# Exclude tests with specific keywords
python -m tests.utils.test_selection --exclude-keyword error

# Run specific test files
python -m tests.utils.test_selection tests/unit/test_config.py tests/unit/test_parser.py

# Pass additional arguments to pytest
python -m tests.utils.test_selection --marker unit -- -v --no-header
```

## Programmatic Usage

You can also use the test selection utilities programmatically in your scripts:

```python
from tests.utils.test_selection import run_selected_tests, run_tests_for_changed_files

# Run tests with specific markers
run_selected_tests(markers=["unit", "config"])

# Run tests with specific keywords
run_selected_tests(keywords=["parse", "validate"])

# Run tests for changed files
run_tests_for_changed_files(base_branch="main", include_related=True)
```

## Utility Functions

The `test_selection.py` module provides several utility functions:

- `get_changed_files(base_branch)`: Get a list of files changed compared to the base branch
- `get_related_test_files(changed_files)`: Get a list of test files related to the changed files
- `get_tests_by_marker(marker)`: Get a list of test files that have the specified marker
- `get_tests_by_keyword(keyword)`: Get a list of test files that match the specified keyword
- `get_slow_tests(threshold_seconds)`: Get a list of slow tests based on previous test runs
- `create_test_selection_args(...)`: Create pytest command-line arguments for test selection
- `run_selected_tests(...)`: Run selected tests based on the specified criteria
- `run_tests_for_changed_files(...)`: Run tests for changed files compared to the base branch

## Best Practices

1. **Use Markers Consistently**: Apply markers consistently to ensure tests can be properly categorized and selected.

2. **Name Tests Descriptively**: Use descriptive test names that include relevant keywords for easy filtering.

3. **Group Related Tests**: Keep related tests in the same file or directory to make it easier to run them together.

4. **Mark Slow Tests**: Always mark tests that take a long time to run with the `@pytest.mark.slow` decorator.

5. **Run Changed Tests First**: When making changes, run the tests related to those changes first to get quick feedback.

6. **Use Test Categories**: Use test categories (unit, integration, etc.) to organize and run tests at different levels of granularity.

## Examples

### Example 1: Running Unit Tests for a Specific Module

```bash
# Run all unit tests for the config module
pytest -m unit tests/unit/config/
```

### Example 2: Running Tests Related to a Feature

```bash
# Run all tests related to the SARIF reporter
pytest -k sarif_reporter
```

### Example 3: Running Tests for Changed Files in CI

```bash
# In a CI pipeline, run tests for files changed in the pull request
python -m tests.utils.test_selection --changed --base-branch main --include-related
```

### Example 4: Excluding Slow Tests During Development

```bash
# Run all tests except slow tests
pytest -m "not slow"
```

### Example 5: Running Tests with Multiple Criteria

```bash
# Run unit tests for the scanner module that are not slow
pytest -m "unit and scanner and not slow"
```