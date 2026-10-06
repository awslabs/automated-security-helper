# Local Development Setup Guide

This guide will help you set up your local development environment for the Automated Security Helper project.

## Prerequisites

- Python 3.10 or later
- UV (Python package manager) - **Note: Project has migrated from Poetry to UV**

## Setting up UV

1. Install UV on your system

[Official instructions](https://docs.astral.sh/uv/getting-started/installation/)

Linux, macOS, Windows (WSL)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Windows PowerShell:

```ps1
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

2. Verify UV installation:

```bash
uv --version
```

### Windows: Enable Long Paths

Windows has a 260-character path limit that can cause `git clone` or `git reset` failures due to deeply nested test file paths. Run this once before cloning:

```ps1
git config --global core.longpaths true
```

## Project Setup

### Option 1: Manual Setup

1. Clone the repository:

```bash
git clone https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper
```

2. Install project dependencies:

```bash
uv sync
```

This command will:
- Create a virtual environment
- Install all dependencies from pyproject.toml and uv.lock
- Set up the project in development mode

3. Activate the virtual environment:

```bash
source .venv/bin/activate
```

Or use UV's built-in environment management:

```bash
uv run <command>
```

### Option 2: Using Development Containers

If you're using an IDE that supports devfiles (like Eclipse Che, Red Hat OpenShift Dev Spaces, or other devfile-compatible environments), you can use the provided `devfile.yaml`:

The devfile includes pre-configured commands:
- `install`: Sets up UV and installs dependencies
- `build`: Builds the project using UV
- `test`: Runs the test suite

This provides a consistent development environment across different platforms and IDEs.

## Testing

Run the test suite:

```bash
uv run pytest
```

Run specific test categories:

```bash
# Unit tests
uv run pytest tests/unit/ -v

# Integration tests
uv run pytest tests/integration/ -v

# Scanner-specific integration tests
uv run pytest tests/integration/scanners/ -v
```

## Snapshot tests

What ASH prints and writes is pinned by snapshot tests, so a change to user-visible
output fails CI until someone has looked at it and said why it changed.

### What is snapshotted

- `tests/snapshot/`: syrupy snapshot tests of CLI output, reports and other rendered
  output. Snapshots live next to their test module, in
  `tests/snapshot/**/__snapshots__/<test_module>.ambr` for structured data and
  `__snapshots__/<test_module>/<test_name>.<ext>` for whole rendered documents.
- `.github/actions/validate-mcp/tool_surface.golden.json`: the MCP tool surface a client
  sees, compared against the live server by the `validate-mcp` action.
- `editors/**/__snapshots__/`: the IDE plugins' structural snapshots and PNG baselines
  (`editors/vscode/test/visual/README.md`, `editors/jetbrains/README.jetbrains`). Each
  editor's workflow runs the same trailer check on its own tree.

The Snapshot-Update rule below also covers the other committed files that a generator
writes in full and CI regenerates and compares: the JSON schemas in
`automated_security_helper/schemas/*.json`, `docs/content/docs/cli-reference-generated.md`,
and the MCP tool reference in
`ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md`. The full
list, and why each candidate is in or out, is the `GOLDEN` table in
`.github/scripts/check-snapshot-trailers.py`.

### Normalization

Snapshots must be identical on every machine, so values that change from run to run
(temp paths, the repository root, the home directory, ids, versions) are masked by one
normalizer, `SnapshotNormalizer` in `tests/snapshot/support/normalize.py`. The `snapshot`
and `text_snapshot` fixtures in `tests/snapshot/conftest.py` apply it, and they also pin
the terminal (width, no color, no TTY) and unset the CI variables that change ASH's
output. Do not normalize inside a test. If a test produces a value that varies, register
it with the normalizer (`add_root`, `add_literal`) or extend the normalizer, together with
a test in `tests/snapshot/test_snapshot_normalizer.py` showing what it masks and what it
leaves alone.

Time is not masked by default. A wrong timestamp or duration is a defect a user reads,
so a new test sees every instant and duration it renders. When output contains the
wall clock, pin the clock rather than masking it: the `pinned_clock` fixture in
`tests/snapshot/conftest.py` (built on `pin_clock` in
`tests/snapshot/support/fixture_model.py`) replaces `datetime.now()` and `uuid4` in the
modules that stamp them into output, and `pin_clock(monkeypatch, extra_modules=(...))`
covers a module outside that list. Only when the time cannot be pinned cheaply, and
only after the test has been shown to differ between runs or between time zones (run it
several times, and under `TZ=Pacific/Kiritimati` and `TZ=America/Adak`), opt in to
masking for that test or module:

```python
pytestmark = pytest.mark.snapshot_masking(mask_instants=True, mask_durations=True)
```

The switches, all `False` unless a marker turns them on:

- `mask_instants`: ISO-8601 instants, `ASH-YYYYMMDD...` report ids, the
  `scan-YYYYMMDDHHMMSS` id from MCP `get_scan_results`, today's date, and values under
  instant keys such as `time`, `logged_time`, `generated_at`, `start_time`, `end_time`
  and `timestamp`.
- `mask_durations`: a number followed by a time unit in text (`1.2s`, `350ms`,
  `0:00:01`).
- `mask_duration_keys`: numbers under keys such as `duration` and `duration_seconds`.

No snapshot test opts in at the moment: every one that renders the time runs under a
pinned clock.

The console log's time column is not a normalizer rule: the fixtures draw it as the
constant `[<LOG_TIME>]`, so the column has one width under any clock, locale or
timezone.

### When a snapshot test fails

1. Run the tests and read the diff syrupy prints:

   ```bash
   uv run pytest tests/snapshot
   ```

2. Decide whether the new output is what you intended. If it is not, fix the code.
3. If it is, rewrite the snapshots for the tests you changed:

   ```bash
   uv run pytest tests/snapshot/<area>/test_snapshot_<area>_<topic>.py -n 0 --snapshot-update
   ```

   Pass `-n 0`. Under xdist several workers rewrite the same `.ambr` file at once, and
   the last writer drops the others' snapshots without an error.

4. Review what changed, file by file:

   ```bash
   git diff -- '**/__snapshots__/**'
   ```

5. Commit the code change and its snapshots together, with a trailer saying why the
   output changed:

   ```bash
   git commit --trailer "Snapshot-Update: the summary table now shows suppressed findings"
   ```

The `snapshot-trailers` CI job fails if a golden file changed in a commit that has no
non-empty `Snapshot-Update:` trailer. Every commit that touches a golden file needs its
own trailer: a separate follow-up commit that only adds one does not count, and neither
does the trailer of an earlier commit that changed the same file. To fix:

- if the change is in your latest commit, run
  `git commit --amend --no-edit --trailer "Snapshot-Update: <why>"`;
- if it is in an earlier commit, run the `git rebase ... --exec ...` command printed in the
  CI error, which amends only the commits that touched that file.

Then run `git push --force-with-lease`. Pull requests are squash-merged with every commit
message kept, and the check reads trailers from each commit's section of the squash
message, so the trailer survives the merge.

CI never passes `--snapshot-update`, and `tests/snapshot/conftest.py` refuses it when the
`CI` or `GITHUB_ACTIONS` environment variable equals `true` (exactly that string, so
`CI=1` does not trigger the refusal). `tests/snapshot/test_snapshot_policy.py` fails if
any workflow, action, script or pytest configuration passes `--snapshot-update` or
`--snapshot-warn-unused`. A missing snapshot fails.

### Orphaned snapshots

A snapshot that no test asserts any more fails CI. syrupy reports an unused snapshot in a
test module that still exists. If you delete or rename a test module, syrupy never opens
its snapshot file, so `check-snapshot-trailers.py --orphans` (in CI, and in
`test_snapshot_policy.py`) checks that every file under a `tests/**/__snapshots__/`
directory belongs to a `<test_module>.py` next to that directory, and that no
`__snapshots__` directory is empty. It checks the VS Code extension's `.snap` files and
PNG baselines against their test files and `scenarios.json` the same way. When you
rename a module, move its snapshots with it; when you delete one, delete its snapshots.
Either change needs a `Snapshot-Update:` trailer like any other.

### Output that differs by operating system

When output really differs by platform (path separators, line endings, a Windows-only
message), render every variant on every OS: call the code with the platform as an input
and snapshot each variant under its own name, for example
`text_snapshot("md")(name="windows")`. Do not skip a snapshot test on some platforms, and
do not keep a separate snapshot per runner. A skipped variant is never compared, and its
snapshot looks unused to the runs that skip it.

### Output that needs a container runtime or Nix

What container mode and Nix mode print before and after the runtime is snapshotted
in-process, with only the runner process or the `nix develop` call replaced, under
`tests/snapshot/container/`. What only a real runtime can produce (output from inside
the image, a real container or Nix scan, the `ash_helpers.ps1` wrapper) is
in `tests/snapshot/container/runtime/`, marked `container_runtime` or `nix_runtime`.
`tests/conftest.py` deselects those unless `--run-container-snapshots` or
`--run-nix-snapshots` is passed, which the scan-validation container legs and the Nix
legs do after their scans. Keep such modules in `runtime/`: syrupy reads every file in a
`__snapshots__` directory once one test beside it runs, so a deselected module's
snapshots next to collected ones would fail the default run as unused. To update them,
build the image (or have Nix) and run the module with its flag, `-n 0` and
`--snapshot-update`; see the module docstrings for the environment they read.

## Development Commands

- Format and lint code:

```bash
uv run ruff check .
uv run ruff format .
```

- Run a specific script:

```bash
uv run ashx
```

## Project Dependencies

Dependencies are managed in `pyproject.toml`. Key groups:

- Runtime dependencies: defined under `[project] dependencies`
- Dev dependencies: defined under `[dependency-groups] dev` (includes ruff, pytest, mypy, mkdocs, etc.)

Scanner tools (Bandit, Checkov, Semgrep) are managed via UV tool isolation at runtime — they're not project dependencies.

## Troubleshooting

If you encounter any issues:

1. Verify your Python version matches the required version (3.10+):

```bash
python --version
```

2. Try cleaning and rebuilding the environment:

```bash
rm -rf .venv
uv sync
```

3. Update UV and dependencies:

```bash
uv self update
uv sync --upgrade
```

4. If using a devfile-compatible IDE and encountering issues, try running the devfile commands manually:

```bash
# Install dependencies
curl -LsSf https://astral.sh/uv/install.sh | sh && source $HOME/.cargo/env && uv sync

# Build the project
uv build

# Run tests
uv run pytest
```

### Migration Validation

The project includes a migration validator to help diagnose UV-related issues:

```bash
# Check migration status
uv run python -m automated_security_helper.utils.migration_validator

# Get detailed JSON output for debugging
uv run python -m automated_security_helper.utils.migration_validator --json
```

The validator checks:

- UV installation and version compatibility
- Project configuration (pyproject.toml) structure
- Dependency resolution capability
- CLI tool availability via UV tool run
- Build system configuration

## Version Management

ASH uses [Semantic Versioning](https://semver.org/). The version is defined in `pyproject.toml` and propagated to documentation files via a template system.

### How It Works

- `pyproject.toml` is the single source of truth for the version.
- Documentation files that reference the version (README, install guides, etc.) have corresponding `.template` files containing `{{VERSION}}` placeholders.
- The `scripts/version_bump.py` script updates `pyproject.toml` and regenerates all documentation from templates.

### Commit Messages

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) format. A required check ("Validate PR title") enforces this. Since PRs are squash-merged, the PR title becomes the commit message that drives changelog generation.

```
feat: add OpenGrep scanner support
fix(detect-secrets): apply global_ignore_paths
chore: bump dependencies
feat!: redesign plugin API (breaking change)
```

A pre-commit hook (`commitizen`) also validates local commit messages.

### Releasing

Releases are cut by maintainers via **Actions > ASH - Create Release > Run workflow**. The workflow:

1. Determines the bump type from commit history (patch/minor/major based on conventional commits), subject to the release line described below
2. Bumps the version in `pyproject.toml`, updates `CHANGELOG.md`
3. Regenerates version references in documentation
4. Creates a release PR

After merging the release PR, a second workflow automatically:
- Creates the git tag (`v{version}`)
- Publishes a GitHub Release whose body is the version's `CHANGELOG.md` entry followed by GitHub's auto-generated notes
- Updates the floating major tag for the released version -- `v3` for a 3.x release, `v4` for a 4.x one, creating it if it does not exist yet

#### Release App setup

The release PR's required checks (`ash / SAST, SCA, and IaC Scan`, `Validate PR title`, `required-checks`) run on `pull_request`. When the PR is opened with the workflow's `GITHUB_TOKEN`, GitHub creates those runs in an approval-required state, and nothing starts until a maintainer with write access selects **Approve workflows to run** in the PR's merge box. The release PR says so in its description when that happens. To have the checks start on their own, the workflow opens the PR with a GitHub App token instead, which needs this one-time setup by a repository admin:

1. Create a GitHub App owned by the organization. It needs no webhook and no callback URL.
2. Repository permissions: **Pull requests: Read and write**. Metadata read is implicit; GitHub adds it automatically. No Contents permission, not even read, and nothing else. The branch push stays on `GITHUB_TOKEN`, so the App only opens the PR. The workflow requests exactly `pull-requests: write` when it mints the token, so the mint step fails if the App lacks it, and it would also fail if the workflow asked for a permission the App was not granted.
3. Install the App on this repository only.
4. Generate a private key for the App, and copy the App's **Client ID** from its settings page (the Client ID, not the numeric App ID).
5. Add two repository secrets under **Settings > Secrets and variables > Actions**:
   - `RELEASE_APP_CLIENT_ID`: the Client ID
   - `RELEASE_APP_PRIVATE_KEY`: the full contents of the `.pem` file

No repository variables are needed.

The workflow only uses the App when both secrets are set. With neither or only one, it falls back to `GITHUB_TOKEN`, logs a warning, and the PR waits for approval as described above. Once both are set, a misconfigured App (not installed, wrong permissions, bad key) fails the release job at the token step, before any version bump or push, rather than silently falling back.

To confirm the setup, run the release workflow and check that the **Mint a GitHub App token** step ran, that the PR author is the App rather than `github-actions`, and that the PR's checks start without an approval banner.

### Manual Version Bumping

```bash
# Show current version
uv run cz version --project

# Bump version (auto-detects type from commits)
uv run cz bump --changelog

# Dry run to preview
uv run cz bump --changelog --dry-run
```

### Release line

`main` carries breaking (`feat!`) commits that ship in 3.x by maintainer decision, because 4.0.0 is reserved for the v4 packaging work. The `RELEASE_LINE` value committed at the top of `ash-create-release.yml` controls this. It is not a dispatch input, so the line a release lands on is decided in reviewed history:

- `3.x` (the default): if commitizen detects a major increment, the workflow runs `cz bump --increment MINOR` instead, logs a warning that names every breaking commit it overrode, and lists them in the run summary. A patch or minor increment is left alone. The commits are not rewritten, so their `BREAKING CHANGE` notes still render in `CHANGELOG.md`. The job fails if the current version is not 3.x, or if the bump still produced a version outside 3.x.
- `auto`: commitizen's own semver, so a breaking change produces a major.

A release whose version understates it can carry hand-written notes in `.github/release-notes/<tag>.md`. The changelog template (`.github/changelog/CHANGELOG.md.j2`) renders that file under the version heading, and the tag workflow publishes that version's `CHANGELOG.md` entry, curated notes included, at the top of the GitHub Release body, ahead of GitHub's generated notes. `v3.8.0.md` lists the behavior changes that 3.8.0 ships in a minor release, with their opt-outs.

Hand-written notes go under `## Unreleased` in `CHANGELOG.md`. commitizen would replace that section with the generated entry, so before bumping, the workflow moves its body into `.github/release-notes/<next tag>.md`, below any curated notes already there, and removes the section. The new entry then carries the curated notes, the hand-written notes, and the generated sections, and so does the GitHub Release. The step fails before bumping if that text contains a Jinja delimiter (`{{`, `{%`, `{#`) or if the next tag cannot be determined. An empty or absent section is left alone.

To cut 4.0.0 once v4 is on `main`: set `RELEASE_LINE` to `auto` in the change that lands v4, then run the workflow. Once the version is 4.x, `3.x` refuses to run, so a setting left at `3.x` fails loudly rather than capping 4.x.

Preview either line locally:

```bash
uv run cz bump --dry-run --changelog --increment MINOR   # what RELEASE_LINE 3.x produces when a major is detected
uv run cz bump --dry-run --changelog                     # what RELEASE_LINE auto produces
```

## Scanner Plugin Development

When developing custom scanner plugins for ASH, follow these guidelines:

### Base Scanner Plugin

All scanner plugins should inherit from `ScannerPluginBase` and implement the required methods:

```python
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from typing import Optional


@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase[MyCustomScannerConfig]):
    def model_post_init(self, context):
        # Initialize scanner properties
        self.command = "my-tool"
        self.use_uv_tool = True  # Enable UV tool management if needed
        self.tool_type = "SAST"  # Scanner type

        # Set up UV tool installation if using UV tool management
        if self.use_uv_tool:
            self._setup_uv_tool_install_commands()
            self.tool_version = self._get_uv_tool_version("my-tool")

        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        # Implement validation logic
        return True

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        # Implement scanning logic
        pass
```

### UV Tool Version Constraints (Optional)

The `_get_tool_version_constraint()` method is **optional** and only needs to be implemented if your scanner requires specific version constraints for UV tool installation:

```python
def _get_tool_version_constraint(self) -> Optional[str]:
    """Get version constraint for tool installation.

    This method is optional - only implement if you need specific version constraints.

    Returns:
        Version constraint string (e.g., ">=1.0.0") or None for latest
    """
    # Optional: specify version constraints for UV tool installation
    return ">=1.0.0"
```

**Key Points:**
- This method is **not abstract** and doesn't require implementation
- If not implemented, ASH will install the latest version of the tool
- Use standard pip version specifiers (e.g., `>=1.0.0`, `==2.1.0`, `>=1.0.0,<2.0.0`)
- Consider tool stability and compatibility when setting constraints

### UV Tool Management

ASH provides automatic tool management via UV's tool isolation system:

- **Automatic Installation**: Tools are installed when needed during scanner validation
- **Version Constraints**: Use `_get_tool_version_constraint()` to specify version requirements
- **Isolation**: Tools run in isolated environments without affecting project dependencies
- **Fallback Support**: ASH falls back to system-installed tools if UV installation fails

### Testing Scanner Plugins

When testing custom scanner plugins:

1. Unit tests: test scanner logic in isolation
2. Integration tests: test with actual tool execution

```bash
# Run scanner-specific unit tests
uv run pytest tests/unit/plugin_modules/ -v

# Run scanner integration tests
uv run pytest tests/integration/scanners/ -v
```
