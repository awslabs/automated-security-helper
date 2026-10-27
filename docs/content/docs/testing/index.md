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
└── conftest.py            # Pytest configuration and shared fixtures
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

There is no marker that takes a test out of the parallel run: every test runs under `-n auto`, so a test has to be safe to run beside the others (see the [parallel testing guide](parallel_testing.md)).

### UV Migration Tests

The project includes comprehensive integration tests for the Poetry to UV migration, including:

- UV tool scanner execution tests
- UV dependency resolution and installation tests
- UV build system functionality tests
- Performance comparison tests between Poetry and UV
- Cross-platform compatibility tests

#### Migration Validation

The project includes a migration validator that can be used in tests and CI:

```bash
# Validate migration status in tests
python -m automated_security_helper.utils.migration_validator

# Use in CI with JSON output
python -m automated_security_helper.utils.migration_validator --json
```

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
- `temp_env_vars`: Sets environment variables for the duration of a test. `temp_env_vars(NAME="value")` sets each one to `str(value)`; after the test, each is back to its previous value, or unset if it had none, and no other variable is touched. It is `monkeypatch.setenv` underneath, which a test can also use directly.

Every test also runs with a home directory of its own. `tests/conftest.py` points `HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` and `XDG_CACHE_HOME` at an empty temporary directory for each test, and at another for the whole run as soon as pytest loads `tests/conftest.py`, before any other conftest imports ASH, which is where a path a module computes from the home at import time points. The one exception is uv's cache: `UV_CACHE_DIR` stays on the cache uv would use for you, so a test that runs uv does not download again. uv's tool and Python directories follow `XDG_DATA_HOME` into the test's home on Linux and macOS, because `UV_TOOL_DIR`, `UV_TOOL_BIN_DIR`, `UV_PYTHON_INSTALL_DIR`, `UV_PYTHON_BIN_DIR` and `XDG_BIN_HOME` are unset for the run and for each test (on Windows they are under `%APPDATA%`, which is not moved). For the same reason, on Linux and macOS a user-level `uv.toml`, `pip.conf`, `.npmrc` or `~/.netrc` in your home is not read during tests (on Windows only `.npmrc` and the netrc file are missed; `%APPDATA%\uv` and `%APPDATA%\pip` are still read). Behind a package mirror, export the mirror instead, as `UV_DEFAULT_INDEX` (or `UV_INDEX_URL`), `UV_EXTRA_INDEX_URL`, `PIP_INDEX_URL` or `npm_config_registry`, which reach every test unchanged; for a mirror that needs credentials, point `NETRC` at your netrc file, or give uv the index's as `UV_INDEX_<NAME>_USERNAME` and `UV_INDEX_<NAME>_PASSWORD` rather than in the URL. The tools `ash dependencies install` put in `~/.ash/bin` are out of reach too, so the integration tests that need one skip; run with `PATH="$HOME/.ash/bin:$PATH"` (in PowerShell, `$env:PATH = "$HOME\.ash\bin;$env:PATH"`; in cmd, `set "PATH=%USERPROFILE%\.ash\bin;%PATH%"`) to use them (the run's header says so when that directory has tools). Setting `ASH_BIN_PATH` to that directory instead would make it the install target of every test that installs to the default directory, and the run refuses a tool installer it can see heading into your home, and any Python or `ash` child started with `HOME` set to your home. A Python or `ash` child started with an environment that has no `HOME`, which would fall back to your real home, is given the test's home instead; one whose own command line removes `HOME` (`env -i`, `env -u HOME`, `unset HOME;`) or sets it to your home (`HOME=...;`) is refused. These checks are made where `subprocess.Popen` starts a child; a child started another way (`os.posix_spawn`, `os.system`, multiprocessing's spawn and forkserver) is not checked. A test that still writes under your `~/.ash`, through a path that does not come from `HOME` (the passwd database, or a path computed before the run moved `HOME`), is refused the write (a `PermissionError`) and fails at teardown with the paths it tried. A test that needs the real home can be marked `@pytest.mark.real_home`, and the `developer_home` and `developer_environment` fixtures give the values the run started with.

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
    mock_scanner = create_mock_scanner(
        "bandit",
        findings=[{"file": "test.py", "message": "Test finding", "severity": "HIGH"}],
    )

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
            return (
                200,
                {"Content-Type": "application/json"},
                {"message": "Hello, world!"},
            )

        server.add_route("/hello", handle_hello)
        url = server.get_url("hello")

        # Test code that interacts with the API server
        response = requests.get(url)
        assert response.json() == {"message": "Hello, world!"}
```

## Coverage Reporting

### Configuration

Coverage is configured in `.coveragerc` (what to measure and where reports go). It is not
measured by default: `pytest.ini` carries no `--cov` options, so a run of one directory or
one test passes or fails on its own tests.

### Running Coverage Reports

To see coverage for a run, pass the options yourself:

```bash
uv run pytest tests/unit/core --cov=automated_security_helper --cov-report=term-missing
```

To generate an HTML coverage report (written to `test-results/coverage_html`):

```bash
uv run pytest --cov=automated_security_helper --cov-report=html
```

### Coverage Enforcement

CI's unit-test step (`.github/actions/run-unit-tests/action.yml`) runs the full suite with
`--cov-fail-under=80` and fails below 80% total coverage. In the Unified CI workflow the
suite is split into eight shards per operating system and Python version, because one job
cannot finish it. Each shard measures coverage without a threshold, and the
`unit-coverage` job applies the 80% to the combined data of the Linux Python 3.12 shards.
To run the whole suite the way an unsharded step does:

```bash
uv sync --extra cdk --extra symbols
ASH_REQUIRE_CDK_EXTRA=1 ASH_REQUIRE_SYMBOLS_EXTRA=1 uv run pytest \
  --cov=automated_security_helper --cov-config=.coveragerc \
  --cov-report=term-missing --cov-fail-under=80
```

The threshold is for the full suite. A partial run with `--cov-fail-under` fails on the code
it did not exercise.

## Parallel Test Execution

### Configuration

Parallel test execution is configured in `pytest.ini`:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    --verbose
    --junit-xml=test-results/pytest.junit.xml
    --durations=10
    -n auto
```

### Running Tests in Parallel

`-n auto` in `pytest.ini` already runs the suite in parallel, one worker per CPU. To run tests in a single process instead, for example while debugging one test:

```bash
uv run pytest tests/unit/core/test_progress.py -n 0
```

## Test Selection and Filtering

### Command-Line Options

The framework provides several command-line options for selective test execution:

- `--run-slow`: Run slow tests
- `--run-integration`: Run integration tests
- `--run-container-snapshots`: Run the snapshot tests that need a container runtime on this host
- `--run-nix-snapshots`: Run the snapshot tests that need Nix on this host

Example:
```bash
pytest --run-integration --run-slow
```

### Test Selection Utilities

Test selection utilities are in `tests/utils/selection.py`, importable from the repository root as `tests.utils.selection`:

```python
from tests.utils.selection import get_changed_files, get_related_test_files


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


@pytest.mark.parametrize(
    "code,expected_findings",
    [
        ("import pickle\npickle.loads(b'')", 1),  # Unsafe pickle usage
        ("import hashlib\nhashlib.md5(b'')", 1),  # Weak hash algorithm
        ("print('Hello, world!')", 0),  # No security issues
    ],
)
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