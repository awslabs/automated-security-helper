# Test File Naming Conventions

This document outlines the naming conventions for test files in the ASH project.

## Directory Structure

The test directory structure mirrors the main codebase structure:

```text
tests/
├── unit/                  # Unit tests for individual components
│   ├── base/              # Tests for base classes and interfaces
│   ├── cli/               # Tests for CLI components
│   ├── config/            # Tests for configuration components
│   └── ...                # Other component directories
├── integration/           # Integration tests for component interactions
│   ├── cli/               # CLI integration tests
│   ├── scanners/          # Scanner integration tests
│   └── ...                # Other integration test directories
├── snapshot/              # Snapshot tests of ASH output
├── infrastructure/        # CDK stack for testing offline mode in an isolated VPC
├── utils/                 # Test utilities
├── test_data/             # Test data files
└── conftest.py            # Fixtures shared by every test
```

## Test tiers

Every test belongs to exactly one of three tiers, and says so with a marker. The tier
is decided by what the test does when it runs, not by the directory it sits in.

- `unit`: runs in-process. It starts no subprocess (no `subprocess.run`, no child
  Python, no `git`, no `ash` executable), touches no network, runs no real external
  tool such as bandit, semgrep, trivy or docker, and writes only under `tmp_path`.
  Mocks, monkeypatch, fakes, in-memory fixtures and Typer's `CliRunner` calling the app
  in-process are all unit, as long as the code path they drive spawns nothing real. A
  test that reads files of this repository (a docs page, a workflow YAML, `pyproject.toml`)
  in-process is unit.
- `integration`: one component with a real dependency. A real external tool or a
  product subprocess is started (a child Python, a child pytest, `git`, the `ash` CLI
  run as a subprocess for one command), a sandbox backend is exercised for real,
  boto3 or moto stands up an AWS stand-in, or a converter invokes a tool. A test that
  cannot be classed from its text is integration.
- `e2e`: the whole product, driven as an operator would drive it. The `ash` CLI runs as
  a subprocess against a real target tree with real scanners and its output is
  asserted, the container image is built or run, or the MCP server is started as a
  child process and driven through a client. A test of one scanner or one command
  against one real tool is integration, not e2e.

Mark a file whose tests are all one tier with a module-level `pytestmark`:

```python
import pytest

pytestmark = pytest.mark.unit
```

Mark a mixed file per test or per class. A class decorator covers every method of the
class, so do not also mark its methods, and a parametrized test takes one marker:

```python
@pytest.mark.integration
def test_scan_runs_the_real_tool(tmp_path): ...


class TestRendering:
    pytestmark = pytest.mark.unit
```

There is no directory default. A test with no tier marker, or with more than one (a
module-level `integration` and a function-level `unit` count as two), makes collection
refuse the whole session with a usage error that lists the first offenders, so nothing
runs until each one has exactly one. The check is in `tests/conftest.py` and is pinned
by `tests/unit/test_every_test_carries_one_tier_marker.py`. Other markers (`slow`,
`skipif`, `usefixtures` and so on) are separate and stay as they are. `pytest --strict-markers`
is on, so a marker has to be registered in `pytest.ini` or in a `conftest.py` before a
test can use it.

CI selects its jobs by tier: `-m unit` runs unsharded for each operating system and
Python version, `-m integration` runs sharded, and `-m e2e` runs unsharded. Locally,
integration and e2e tests are skipped unless `pytest --run-integration` is given:

```bash
uv run pytest -m unit
uv run pytest --run-integration -m "integration or e2e"
```

## File Naming

### Unit Tests

Unit test files should follow this naming pattern:

```text
test_<module_name>.py
```

For example:
- `test_ash_config.py` for testing the `ash_config.py` module
- `test_sarif_utils.py` for testing the `sarif_utils.py` module

### Integration Tests

Integration test files should follow this naming pattern:

```text
test_<feature_or_component>_integration.py
```

For example:
- `test_global_suppressions_integration.py` for testing global suppressions feature
- `test_scanner_workflow_integration.py` for testing scanner workflow

### Test Classes

Test classes should follow this naming pattern:

```text
class Test<ComponentName>:
    """Tests for <component description>."""
```

For example:
- `class TestAshConfig:` for testing the AshConfig class
- `class TestSarifUtils:` for testing SARIF utilities

### Test Methods

Test methods should follow this naming pattern:

```text
def test_<functionality_being_tested>(_<parameters>):
    """Test <description of what is being tested>."""
```

For example:
- `def test_parse_config_file():` for testing config file parsing
- `def test_apply_suppressions_to_sarif_with_rule_match():` for testing suppression application

## Fixtures

pytest loads fixtures from `conftest.py` files without an import, so fixtures go in a
`conftest.py` next to the tests that use them:

```text
conftest.py
```

For example:
- `tests/conftest.py` for fixtures every test can use
- `tests/integration/cli/conftest.py` for fixtures of the CLI integration tests

## Utility Files

Utility files should be named according to their purpose:

```text
<purpose>.py
```

For example:
- `mocks.py` for mock utilities
- `helpers.py` for general test helpers