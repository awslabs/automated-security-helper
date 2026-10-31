# Test your change

This page covers running the tests in a development checkout, the integration and
snapshot tests, the rules the test suite enforces on new tests, and how to try an MCP
change before you open a pull request. It assumes the setup in
[Contribute to ASH](index.md#set-up-a-development-checkout), with both extras installed.

## Run the test suite

<!-- doctest: illustrative reason="runs the full test suite in a checkout of this repository" -->
```bash
uv run pytest
```

This runs every test under `tests/`, spread across one pytest-xdist worker per logical
CPU (`-n auto` in `pytest.ini`), and writes a JUnit report to `test-results/`. It does
not measure coverage: `pytest.ini` carries no coverage options, so a run passes or fails
on its tests alone. Integration tests are skipped; see
[Integration tests](#integration-tests).

To run in one process, which `pytest --pdb` and ordered print output need, pass
`pytest -n 0`.

## Run part of the suite

Name a directory, a file, or a test:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pytest tests/unit/config
uv run pytest tests/unit/cli/mcp/test_progress_monitor.py -n 0
```

`tests/utils/selection.py` chooses tests by marker, by keyword, or by what changed, and
runs pytest on them with the Python that runs it. Run it from the repository root;
`--help` lists its options, and it passes any option it does not know to pytest:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run python -m tests.utils.selection --keyword suppression --exclude-marker slow tests/unit/config
uv run python -m tests.utils.selection --changed --base-branch main
```

`python -m tests.utils.selection --changed --base-branch <branch>` runs the test files
that differ from that branch (`main` when the option is left out), and the whole suite
when no test file differs. Its functions can also be imported, for example
`from tests.utils.selection import get_changed_files, run_selected_tests`.

## Measure coverage

CI runs the suite by tier, selected by marker. The unit-test jobs run `-m unit` in four
shards per operating system and Python version and measure coverage of
`automated_security_helper/` without a threshold. The `unit-coverage` job then combines
the unit tier's coverage data of each operating system family at Python 3.12 and fails
when total coverage is under 80%. The integration-test jobs run `-m integration` in
four shards per operating system and Python version, and the e2e-test jobs run `-m e2e`
once per runner on Python 3.12; neither measures coverage. The test step passes the
options itself (`.github/actions/run-unit-tests/action.yml`); `.coveragerc` says what to
measure and where to write the reports, and sets no threshold. To run the whole suite
with the same options and the threshold:

<!-- doctest: illustrative reason="runs the full test suite in a checkout of this repository" -->
```bash
ASH_REQUIRE_CDK_EXTRA=1 ASH_REQUIRE_SYMBOLS_EXTRA=1 uv run pytest \
  --cov=automated_security_helper --cov-config=.coveragerc \
  --cov-report=term-missing --cov-fail-under=80
```

`ASH_REQUIRE_CDK_EXTRA` and `ASH_REQUIRE_SYMBOLS_EXTRA` make a test that needs a missing
extra fail instead of skipping. The threshold is for the full suite. To see the coverage
of a partial run, pass the `pytest --cov` options without `pytest --cov-fail-under`,
which would fail the run on the code it did not exercise. `pytest --cov-report=html`
writes an HTML report to `test-results/coverage_html`.

## Where tests live

| Directory | What it holds |
|-----------|---------------|
| `tests/unit/` | Unit tests, laid out like the package |
| `tests/integration/` | Tests that run real scanners, real `ash` processes, sandboxes, or other host features; skipped unless you pass `pytest --run-integration` |
| `tests/snapshot/` | Snapshot tests of what ASH prints and writes |
| `tests/test_data/` | Scanner input and sample results. It is test input, so ruff does not lint it |
| `tests/utils/` | Test helpers, including `iter_repo_files` and the walk guard described below, and the test-selection tools `selection.py` and `optimization.py` |
| `tests/infrastructure/` | A CDK stack for testing offline mode by hand in an isolated AWS VPC; it needs an AWS account and is not part of any test run |

`tests/conftest.py` provides the shared fixtures. Use pytest's `tmp_path` or the
`ash_temp_path` fixture for files a test writes; `ash_temp_path` is a fresh directory
under `tests/pytest-temp/`, which is gitignored and removed after the test. The
`test_plugin_context` fixture builds a `PluginContext` with the default configuration
and source, output, and work directories under `ash_temp_path`. Set environment
variables with pytest's `monkeypatch.setenv`, which restores them after the test, or
with the `temp_env_vars` fixture, a wrapper over it: `temp_env_vars(NAME="value")` sets
each variable to `str(value)`, and after the test each one is back to its previous
value, or unset if it had none.

## Integration tests

A test is an integration test when its path is under `tests/integration/` or it carries
the `integration` marker. A test marked `slow` is skipped unless you pass
`pytest --run-slow`. Both flags only lift the skip; they do not collect anything the
default run does not. To run the suite the way the `integration-test` CI job does:

<!-- doctest: illustrative reason="runs the integration suite in a checkout of this repository" -->
```bash
uv run pytest tests/integration tests/unit/cli/mcp/test_source_delivery_scan_e2e.py \
  --ignore=tests/integration/docs --run-integration --run-slow -n 0
```

The job runs `tests/integration/docs`, the docs examples, as a separate step; see
[Test the documentation](documentation.md).

Some integration tests run a scanner binary and skip when it is not installed. CI
installs them first, and turns a missing one into a failure:

<!-- doctest: illustrative reason="downloads scanner binaries from the network" -->
```bash
uv run ash dependencies install --tool actionlint --tool cfn-lint --tool cfn-guard
```

Binary tools go to `~/.ash/bin`, where ASH looks for them.

Other tests need something on the host, and run in their own CI jobs:

- `tests/integration/sandbox/` needs a sandbox backend: bubblewrap, firejail, or Landlock
  on Linux, sandbox-exec on macOS. Each test skips when its backend cannot run (the
  `sandbox escape` job requires them).
- `tests/integration/converters/` runs on macOS and Windows in the
  `converter-integration` job, as well as in `integration-test`.
- Snapshot tests of output that only a real container runtime or Nix can produce live
  in `tests/snapshot/container/runtime/`. They are deselected, not skipped, unless you
  pass `pytest --run-container-snapshots` or `pytest --run-nix-snapshots`; the scan
  jobs that have the runtime pass them. To update them, build the image (or install
  Nix) and run the module with its flag plus `pytest -n 0 --snapshot-update`; each
  module's docstring lists the environment variables it reads.

## Snapshot tests

What ASH prints and writes is pinned by snapshot tests, so a change to user-visible output
fails CI until someone has looked at it and recorded why it changed. The tests are under
`tests/snapshot/` and use [syrupy](https://github.com/syrupy-project/syrupy). Each test
module's snapshots are in the `__snapshots__/` directory next to it.

Snapshots must be identical on every machine. The `snapshot` and `text_snapshot`
fixtures pass output through one normalizer, `SnapshotNormalizer` in
`tests/snapshot/support/normalize.py`, which masks values that change from run to run
(temporary paths, the repository root, the home directory, IDs, and versions). The
fixtures also pin the terminal (100 columns, no color, and no TTY) and unset the CI
variables that change ASH's output. Do not normalize inside a test. If a test produces a
value that varies, register it with the normalizer (`add_root`, `add_literal`) or extend
the normalizer, with a test in `tests/snapshot/test_snapshot_normalizer.py` that shows
what it masks.

Time is not masked. When output contains the wall clock, pin it with the `pinned_clock`
fixture, or `pin_clock` in `tests/snapshot/support/fixture_model.py` for a module that
fixture does not cover. Only when the time cannot be pinned, and the test has been shown
to differ between runs or time zones (run it several times, and with `TZ` set to
`Pacific/Kiritimati` and to `America/Adak`), turn masking on for that test or module
with the `snapshot_masking` marker. `tests/snapshot/conftest.py` describes what each of
its switches masks:

<!-- doctest: illustrative reason="a fragment of a test module" -->
```python
import pytest

pytestmark = pytest.mark.snapshot_masking(mask_instants=True, mask_durations=True)
```

When output really differs by platform, render every variant on every operating system
and snapshot each under its own name, for example `text_snapshot("md")(name="windows")`.
Do not skip a snapshot test on some platforms: a skipped variant is never compared, and
its snapshot looks unused to the runs that skip it.

### Update a snapshot

1. Run the snapshot tests and read the diff that syrupy prints:

    <!-- doctest: illustrative reason="runs in a checkout of this repository" -->
    ```bash
    uv run pytest tests/snapshot
    ```

2. Decide whether the new output is what you intended. If it is not, fix the code.
3. If it is, rewrite the snapshots of the tests you changed, in one process:

    <!-- doctest: illustrative reason="runs in a checkout of this repository" -->
    ```bash
    uv run pytest tests/snapshot/cli/test_snapshot_cli_help.py -n 0 --snapshot-update
    ```

    Under xdist, several workers rewrite the same snapshot file at once and the last one
    drops the others' snapshots without an error, so always pass `pytest -n 0` here.
4. Review the change file by file with `git diff -- '**/__snapshots__/**'`.
5. Commit the code change and its snapshots together, with a trailer that says why the
   output changed:

    <!-- doctest: illustrative reason="commits in a checkout of this repository" -->
    ```bash
    git commit --trailer "Snapshot-Update: the summary table now shows suppressed findings"
    ```

The `snapshot-trailers` job fails when a golden file changed in a commit that has no
non-empty `Snapshot-Update:` trailer. Golden files are the snapshot files, the MCP
tool-surface golden, the generated JSON schemas, the generated reference pages, and the
generated MCP tool reference; the full list, with the reason for each entry, is the
`GOLDEN` table in
[`.github/scripts/check-snapshot-trailers.py`](https://github.com/awslabs/automated-security-helper/blob/main/.github/scripts/check-snapshot-trailers.py).
The trailer has to be on a commit that changed the file, so a follow-up commit that only
adds it does not count. If the change is in your latest commit, run
`git commit --amend --no-edit --trailer "Snapshot-Update: <why>"`. If it is in an
earlier commit, run the `git rebase` command that the failing job prints, which amends
only the commits that touched the file. Then push with `git push --force-with-lease`.

CI never updates snapshots: `tests/snapshot/conftest.py` refuses `pytest --snapshot-update`
when `CI` or `GITHUB_ACTIONS` is exactly `true`, and `tests/snapshot/test_snapshot_policy.py`
fails if any workflow, action, script, or pytest configuration passes it. A missing
snapshot fails, and so does a snapshot that no test asserts any more in a whole-suite run,
which is syrupy's default and what a local `pytest` does. CI's tier runs and integration
shards pass `pytest --snapshot-warn-unused`, because each sees only part of the suite, so there
an unused snapshot is reported as a warning in the run's snapshot summary and does not
fail the leg. syrupy cannot see the snapshots of a test module you deleted or renamed,
so `check-snapshot-trailers.py --orphans`, which still fails CI, checks that every file under a
`__snapshots__/` directory belongs to a test module next to it, and that no
`__snapshots__/` directory is empty. When you rename a module, move its snapshots; when
you delete one, delete its snapshots, with a trailer either way. The orphan check reads
the file list from git, so it needs a git checkout, and it does not look at directories
git ignores.

## Rules the suite enforces on new tests

The unit suite runs under xdist on 25 CI legs, so a test that depends on what another test
left behind fails on some legs and not others. No marker takes a test out of the parallel
run, so every test has to be safe beside the others; to debug one in a single process,
pass `pytest -n 0`. The suite guards against two such dependencies, keeps the install
receipts that tests write out of your home directory, refuses test modules that hold no
test, and needs a git checkout.

### Tests that walk a directory

`tests/unit/test_repo_walkers_skip_scratch.py` reads every module under `tests/`, and
every function in `scripts/` and `.github/scripts/` that a test reaches, and fails on any
directory walk (`rglob`, a `glob` with `**`, `os.walk`, `os.fwalk`, `Path.walk`, or
`shutil.copytree`) that can enter a directory other runs create and delete:
`tests/pytest-temp`, `.ash/ash_output`, `.venv`, or a `node_modules` next to a tracked
`package.json`. It also fails on a walk whose directory it cannot work out. Other
workers create and remove directories under `tests/pytest-temp` all the time, so a walk
there races them.

To list the repository's files, use `git ls-files`. To walk a tree, use
`iter_repo_files` from `tests/utils/helpers.py`: it prunes `tests/pytest-temp` before
`os.walk` descends, and takes `skip_dirs` for other directories to leave out. Walks
under `tmp_path`, `ash_temp_path`, or a `tempfile` directory are private to the test and
pass. A walk the guard cannot resolve but that is safe goes in the `_EXEMPT` table in
that test file, keyed by file, function, and the walked expression, with the reason; an
entry that no longer matches a flagged walk fails the suite too.

### State that outlives a test

Some objects are process-wide: the uv tool runner, the memos of tool-version and
executable lookups, and the plugin registry. A test that changes them changes them for
every later test on the same worker. Autouse fixtures in `tests/conftest.py` restore them
after each test:

- `_restore_process_wide_tool_state` restores the uv tool runner, the lookup memos, and
  the plugin manager's registrations and event handlers. It keeps a successful tool
  version answer, because those probes are slow.
- `_no_scanned_tree_scope_outlives_its_test` fails a test that leaves a scanned-tree
  scope active.
- `_restore_ash_logger_switches` restores the `ash` logger's level, propagation, and
  disabled flag, which any `logging.config.dictConfig` call can change.

The fixtures limit the damage; they do not make every patch safe. Build the object under
test before you patch, and patch the module's own reference, for example
`monkeypatch.setattr(module_under_test, "subprocess", fake_subprocess)`, rather than
`subprocess.run`, which every caller in the process shares, including the uv runner's
own probes. To fake a tool's version, patch `UVToolRunner.get_tool_version`, which never
reaches the memo.

### Each test's home directory

Every test runs with a home directory of its own. `tests/conftest.py` points `HOME`,
`USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and `XDG_CACHE_HOME`
at an empty temporary directory for each test, and at another for the whole run before
tests are collected, which is where a path that a module computes from the home at import
time points. `UV_CACHE_DIR` stays on the cache uv would use for you, so a test that runs uv
does not download again. uv's tool and Python directories follow `XDG_DATA_HOME` into the
test's home on Linux and macOS; on Windows they are under `%APPDATA%`, which is not moved.
The tools `ash dependencies install` puts in `~/.ash/bin` are out of reach too, so the
integration tests that need one skip. Set `ASH_BIN_PATH` to that directory to use them;
the run's header says so when the directory has tools. Mark a test
`@pytest.mark.real_home` to give it the values the run started with, and use the
`developer_home` and `developer_environment` fixtures to read them.

### Tests that install tools

An install by `ash dependencies install` or the pinned-tool installer writes a receipt
under `~/.ash/install-receipts`. An autouse fixture sends each receipt that a test writes
in the test process to a directory under pytest's base temporary directory instead. A
child process does not inherit that, so a second autouse fixture fails a test that starts
a tool-installing child, `ash dependencies install` or a child that calls
`install_pinned_tool`, with the developer's `HOME` or with no `HOME`. Give such a child an
environment with `HOME`, and `USERPROFILE` on Windows, set to a temporary directory.

### Test module names

Every tracked `test_*.py` file under `tests/` must define a test that pytest can collect.
A helper or a tool goes in `tests/utils/` under a name that does not start with `test_`;
`tests/unit/test_test_selection_tool_location.py` fails otherwise.

### Tests need a git checkout

The walk guard, the docs checks, and the orphan check list files with git, so the unit
suite fails in a directory that is not a git work tree. Run it in a clone.

## Test an MCP change locally

The MCP server is `ash mcp`. Its tests are in `tests/unit/cli/mcp/` and
`tests/snapshot/mcp/`:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pytest tests/unit/cli/mcp tests/snapshot/mcp
```

To try the server from a client, have the client start it from your checkout with
`uv run`. Add a server entry like this one to the client's MCP configuration; where that
file is depends on the client (see [Run the MCP server](../how-to/mcp-server.md)):

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash-dev": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/automated-security-helper", "ash", "mcp"]
    }
  }
}
```

Replace the path with your checkout's. The server runs your working tree's code, so
restart it in the client after each change. `uv run --directory` makes the checkout the
server's working directory, so give the scan tools absolute paths: a relative path, and
the result tools' default output directory `.ash/ash_output`, resolve inside the
checkout. Do not point the client at a package name instead: the
`automated-security-helper` name on PyPI belongs to an unrelated project.

To check the server without a client, list its tools over stdio with the MCP Python SDK,
which the project installs. Save this as a script and run it from your checkout with
`uv run python`, so that `ash` is the checkout's; in an activated environment, `python`
is enough:

```python
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    server = StdioServerParameters(command="ash", args=["mcp"])
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            for tool in sorted(tools.tools, key=lambda tool: tool.name):
                print(tool.name)


asyncio.run(main())
```

It prints the name of every tool the server registers, which the
[MCP tools reference](../reference/mcp-tools.md) describes.

If you changed what a client sees (a tool, its description or schema, a resource, or a
prompt), regenerate the committed files that record it:

1. `.github/actions/validate-mcp/tool_surface.golden.json` pins the server's tool,
   resource, and prompt lists. `tests/unit/cli/mcp/test_mcp_wire_golden_in_process.py`
   compares it with the server on every unit-test leg, and an install job compares it
   with a live server through the MCP Inspector. Regenerate it with
   `uv run python .github/actions/validate-mcp/compare_tool_surface.py --update`, which
   needs the MCP Inspector's `mcp-inspector` command on your `PATH` (CI installs
   `@modelcontextprotocol/inspector` version 2.8.0 with npm).
2. The MCP tool reference, for the agent plugins and for this site, is generated:
   `uv run python scripts/generate_mcp_tool_reference.py`.
3. The agent plugin trees copy that reference:
   `uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins build`.

The tool-surface golden and the generated references are golden files, so the commit
that changes them needs a `Snapshot-Update:` trailer (see [Snapshot tests](#snapshot-tests)).

## See why a scanner did not run

The scan phase tracks every registered scanner from registration to the final results.
Run with `--verbose` to see each checkpoint in the log: the registered scanners, which
are enabled and why each other one is not, the task queue, which scanners completed, and
whether every registered scanner is in the results:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --verbose
```

In a checkout whose environment is not activated, put `uv run` in front. The command
exits with 2 here because the scan has findings. A registered scanner that is missing
from the results at the end is added to them with no findings and the status SKIPPED,
MISSING, or ERROR, so a dropped scanner shows in the summary rather than disappearing. An
enabled scanner that gets no task in the queue does not run in that scan, and nothing
queues it again: the log line `Found <n> enabled scanners with no task: <names>` names
it, and the completeness check reports it with the reason "Scanner was expected to be
queued but was not found in task queue". A scanner the scan leaves out is SKIPPED in the
results, and the check records it as excluded with the reason it was left out: "Scanner
excluded during filtering: not in enabled scanners list" when `--scanners` does not name
it, or "Scanner excluded during filtering: excluded from this run (--exclude-scanners)"
when `--exclude-scanners` does. The tracking is `ScannerValidationManager` in
`automated_security_helper/models/scanner_validation.py`, called from
`automated_security_helper/core/phases/scan_phase.py`; its tests are
`tests/unit/models/test_scanner_validation*.py` and
`tests/unit/core/phases/test_scan_phase_validation_*.py`.
