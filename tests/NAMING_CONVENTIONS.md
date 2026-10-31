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
- `integration`: one component with a real dependency. A test is integration when it
  starts any child process or a real tool: a real external tool or a
  product subprocess is started (a child Python, a child pytest, `git`, the `ash` CLI
  run as a subprocess for one command), a sandbox backend is exercised for real,
  boto3 or moto stands up an AWS stand-in, or a converter invokes a tool. A child
  process counts even when the program it runs is a script the test wrote itself, such
  as a `#!/bin/sh` fixture the code under test executes. The tier is read on every
  path the test can take, not on the outcome it asserts: a test whose code path starts
  a process, opens a socket or runs git on ANY outcome is integration, even when what
  it checks is that nothing started (a refusal, a pre-filter that empties the scan
  set, a rerender), because a regression that re-enables the path would start one. A
  test that cannot be classed from its text is integration.
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
import pytest


@pytest.mark.integration
def test_scan_runs_the_real_tool(tmp_path): ...


class TestRendering:
    pytestmark = pytest.mark.unit
```

One kind of test is marked by the leg it asserts and not by what it does: a leg
assertion, such as `tests/integration/test_e2e_runner_has_its_tools.py`, checks what a CI
leg is provisioned with. It starts no process, which by the rule above would make it
unit, but it carries the tier of the leg it asserts (e2e there) so that exactly that leg
runs it, and it also carries `leg_assertion`. The marker keeps it out of the
executed-test count, so a leg whose only passing test is a leg assertion still fails the
executed-test floor in `tests/utils/sharding.py`. Do not reclassify a leg assertion by
what it does.

The executed-test floor fails a CI tier leg that selected tests and executed none of
them. The environment variable `ASH_TEST_TIER_FLOOR` is its only trigger: the
`run-unit-tests` action sets it to `1` on the unit and integration legs, and to `warn`
on the e2e legs for now. In warn mode the floor prints its line with a warning prefix and
a `::warning` annotation, which shows on the workflow run's page, and leaves the exit
status alone. A leg admitted on its `skipif` skips also executed no test, so in warn mode
it gets a `::warning title=tier run admitted on skipif skips` annotation too. The e2e
legs change to `1` once a hosted run shows neither warning title on any e2e leg, which
means each of them executing a real test with its scanners installed. An empty value, or `0`,
`false` or `off` in any letter case, leaves the floor off, which is how a developer says
"no floor" for a whole-suite run. Any other value of the variable is a usage error, so a
mistyped `WARN` cannot turn the floor off without a word. A shard alone does not turn
the floor on, so `ASH_TEST_SHARD=3of4 uv run pytest -m integration` on a developer
machine is not failed for tests that a missing `pytest --run-integration` skipped. A
leg whose every skip comes from a `skipif` marker whose condition held is admitted, with
a line that names the reasons and their counts and a `::notice` annotation (a
`::warning` in warn mode) with the same text, so that an admitted leg shows on the run
page. A skip from the `pytest --run-integration`
or `pytest --run-slow` gate, from a `pytest.skip` in a test or a fixture, or from an
unconditional `skip` mark still fails the leg, so a missing tool should be a `skipif`
only when the test is meant not to apply there. The failure line counts leg assertions
apart from the skips, for example
`2 collected, 1 skipped, 1 leg assertion not counted, 0 executed`, and a failing floor
prints a `::error` annotation with the same text. The published JUnit report lists no
failed test for such a run, because pytest has no public hook for a plugin to add one:
the step log and the annotation are the record.

A test module that a test writes out and runs in a child pytest carries a tier marker
when the suite's own `tests/conftest.py` loads it, because the collection hook refuses
it otherwise; put the marker in the module's source with a one-line comment. A child
that runs under its own rootdir and conftest is never seen by the hook and needs no
marker. A child run both ways keeps the marker and has its own conftest register it
with `config.addinivalue_line("markers", ...)`, as `pytest.ini` does for the suite, so
nothing has to suppress an unknown-mark warning. See
`tests/unit/test_environment_assertions_print_no_values.py` for a child run both ways and
`tests/unit/test_a_leaked_run_scope_fails_its_test.py` for children the suite's conftest
loads.

There is no directory default. A test with no tier marker, or with more than one (a
module-level `integration` and a function-level `unit` count as two), makes collection
refuse the whole session with a usage error that lists the first offenders, so nothing
runs until each one has exactly one. The check is in `tests/conftest.py` and is pinned
by `tests/unit/test_every_test_carries_one_tier_marker.py`. A `unit` test may not also
carry `slow`: the unit job runs without `pytest --run-slow`, so the test would be skipped
there and run in no tier, and collection refuses it the same way. Mark such a test
`integration`, which runs with `pytest --run-slow`, or drop `slow`. Other markers
(`skipif`, `usefixtures` and so on) are separate and stay as they are. `pytest --strict-markers`
is on, so a marker has to be registered in `pytest.ini` or in a `conftest.py` before a
test can use it.

CI selects its jobs by tier: `-m unit` and `-m integration` run in four shards for each
operating system and Python version, and `-m e2e` runs unsharded. Locally,
integration and e2e tests are skipped unless `pytest --run-integration` is given:

<!-- doctest: illustrative reason="selects this repository's own test tiers, which the docs runner's sample project does not have" -->
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