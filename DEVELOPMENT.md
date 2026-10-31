# Development

The development guide is part of the documentation site, under Contributing:

- [Contribute to ASH](docs/content/contributing/index.md): set up a development checkout, the project layout, running
  ASH from your checkout, pull requests, commit messages, what CI runs, code style, and the pre-commit hooks.
- [Test your change](docs/content/contributing/testing.md): the unit, integration, and snapshot tests, the rules the
  suite enforces on new tests, and testing an MCP change locally.
- [Test the documentation](docs/content/contributing/documentation.md): how the docs are checked and how to mark
  a code block.
- [Releases and versions](docs/content/contributing/releases.md): versions, the changelog, cutting a release, tags, and
  the version-pinned pages.

The short version, from a git clone:

<!-- doctest: illustrative reason="installs packages from the network and runs the full test suite" -->
```bash
uv sync
uv run pytest                                      # everything
uv run pytest tests/unit/cli                       # one directory
uv run pytest tests/unit/cli/test_config_init.py   # one file
```

`pytest.ini` runs one worker per CPU (`-n auto`) and measures no coverage, so a run of
part of the suite passes or fails on its own tests.

On Linux and macOS, tests do not write into your home directory, except into uv's
cache. `tests/conftest.py` points `HOME`, `USERPROFILE` and the `XDG_*` base directories
at a temporary directory for each test and unsets uv's own directory variables
(`UV_TOOL_DIR` and the like); `UV_CACHE_DIR` stays on your cache, so uv does not
download again. On Windows, `%APPDATA%` and `%LOCALAPPDATA%` are not moved, so what
tools keep there still lands in yours.
On Linux and macOS your user-level `uv.toml`, `pip.conf`, `.npmrc` and `~/.netrc` are in
your home, so tests don't read them (on Windows only `.npmrc` and the netrc file are
missed; `%APPDATA%\uv` and `%APPDATA%\pip` are still read). Behind a package mirror,
export it before running the tests instead: `UV_DEFAULT_INDEX` (or `UV_INDEX_URL`),
`UV_EXTRA_INDEX_URL`, `PIP_INDEX_URL` and `npm_config_registry` reach every test
unchanged. For a mirror that needs credentials, point `NETRC` at your netrc file, or give
uv the index's as `UV_INDEX_<NAME>_USERNAME` and `UV_INDEX_<NAME>_PASSWORD` rather than
in the URL.
Tools in `~/.ash/bin` are not found either, since that is in each test's home. To run
the integration tests that need them against yours, put the directory on `PATH`:
`PATH="$HOME/.ash/bin:$PATH" uv run pytest ...`, or first, in PowerShell,
`$env:PATH = "$HOME\.ash\bin;$env:PATH"`, and in cmd
`set "PATH=%USERPROFILE%\.ash\bin;%PATH%"`. Don't set `ASH_BIN_PATH` to it: tests
that install to the default directory install into `ASH_BIN_PATH`, and the run refuses
an installer it can see heading into your home. A test that writes under your `~/.ash`
some other way (a path from the passwd database, say) is refused the write and fails at
teardown. Mark a test
`@pytest.mark.real_home` if it really needs the real home.

A plain `uv sync` installs neither optional extra. The tests that need the `cdk` extra
(cdk-nag) or the `symbols` extra (tree-sitter, for symbol-scoped suppressions) skip
without it, and the skip reason names the extra. To run them:

The [design system](docs/content/developer-guide/interface-design.md) covers the
website, terminal, TUI, and human reports. The [surface review](docs/content/developer-guide/high-end-design-review.md)
records the navigation architecture, motion vocabulary, and platform decisions.

Follow the [preview workflow](docs/ui-tests/README.md) to generate representative
reports and terminal screens, build the documentation, run browser checks, and
inspect the gallery. Review the affected theme, width, keyboard, empty, and
error states. The generated GitHub comment preview approximates GitHub's native
renderer.

Edit versioned content in its `.md.template` and regenerate the output with
`uv run python scripts/version_template_manager.py generate`. Editor and agent
content has its own canonical source in
`ash-agent-plugins/agentic-coding/transpiler/_base/`.

Refresh the README's report and terminal images with `npm run capture -- --readme`
in `docs/ui-tests`. Rebuild the local MIT animation module with `npm run vendor:motion`
after changing its pinned dependency.

## Devfile environments

`devfile.yaml` defines `install`, `build`, and `test` commands for IDEs that read
devfiles (see [Devfile environments](docs/content/contributing/index.md#devfile-environments)).
To run them by hand, for example when the IDE integration fails:

<!-- doctest: illustrative reason="installs uv and packages from the network" -->
```bash
uv sync --extra cdk --extra symbols
```

Integration tests and slow tests are skipped unless you ask for them:

<!-- doctest: illustrative reason="runs this repository's tests, whose --run-integration option comes from the repository's own tests/conftest.py, so it needs a checkout of this repository" -->
```bash
uv run pytest tests/integration --run-integration
uv run pytest tests/integration/scanners --run-integration
uv run pytest --run-slow
```

CI's unit-test step (`.github/actions/run-unit-tests/action.yml`) installs both extras,
fails instead of skipping when a test cannot find its extra, and fails the run when total
coverage is below 80%. To run the suite the way it does:

<!-- doctest: illustrative reason="installs the extras from this repository's pyproject.toml and runs its test suite, so it needs a checkout of this repository" -->
```bash
uv sync --extra cdk --extra symbols
ASH_REQUIRE_CDK_EXTRA=1 ASH_REQUIRE_SYMBOLS_EXTRA=1 uv run pytest \
  --cov=automated_security_helper --cov-config=.coveragerc \
  --cov-report=term-missing --cov-fail-under=80
```

The 80% threshold applies to the full suite only. Pass `pytest --cov` options to a partial
run to see its coverage, but leave out `pytest --cov-fail-under`, or the run fails on code
it did not exercise.

## Pre-commit hooks

`.pre-commit-config.yaml` runs these hooks:

- `generate-schemas` regenerates the JSON schemas under `automated_security_helper/schemas/`.
- `sync-cdk-extra-fallback` rewrites `_CDK_EXTRA_FALLBACK_REQUIREMENTS` in
  `cdk_nag_scanner.py` from the `cdk` extra in `pyproject.toml`. It runs the script on
  Python 3.13 with `uv run --no-project`, so it leaves your `.venv` and its extras alone.
- `pretty-format-json` formats hand-written JSON.
- `ruff-check` (with `--fix`) and `ruff-format`.
- `commitizen` checks the commit message (commit-msg stage).
- `ash` runs an ASH scan of the checkout, only when asked:
  `uv run pre-commit run --hook-stage manual ash`.

Install the hooks, the commit-message one included, and run them over the whole tree:

<!-- doctest: illustrative reason="installs and runs this repository's pre-commit hooks, so it needs a checkout of this repository" -->
```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
uv run pre-commit run --all-files
```

On a clean checkout the second command changes nothing. The JSON formatter skips files a
tool writes or a check compares byte for byte: the agent plugin outputs and vendored
schemas under `ash-agent-plugins/`, the synthesized CDK templates, the npm manifests and
the snapshot files. Change those with the tool that owns them, for example
`uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins build` for
the plugin outputs.

## Snapshot tests

Moved to [Snapshot tests](docs/content/contributing/testing.md#snapshot-tests).

## Release line

Moved to [The release line](docs/content/contributing/releases.md#the-release-line).

## Release App setup

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

<!-- doctest: illustrative reason="one line for a test module, which needs pytest imported and a test file to put it in" -->
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

   <!-- doctest: illustrative reason="runs this repository's snapshot tests, so it needs a checkout of this repository" -->
   ```bash
   uv run pytest tests/snapshot
   ```

2. Decide whether the new output is what you intended. If it is not, fix the code.
3. If it is, rewrite the snapshots for the tests you changed:

   <!-- doctest: illustrative reason="rewrites this repository's snapshot files, so it needs a checkout of this repository" -->
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

   <!-- doctest: illustrative reason="commits the changes staged in a contributor's clone, and nothing is staged here" -->
   ```bash
   git commit --trailer "Snapshot-Update: the summary table now shows suppressed findings"
   ```

The `snapshot-trailers` CI job fails if a golden file changed in a commit that has no
non-empty `Snapshot-Update:` trailer. The trailer has to be on a commit that touched the
file, so a separate follow-up commit that only adds it does not count. To fix:

- if the change is in your latest commit, run
  `git commit --amend --no-edit --trailer "Snapshot-Update: <why>"`;
- if it is in an earlier commit, run the `git rebase ... --exec ...` command printed in the
  CI error, which amends only the commits that touched that file.

Then run `git push --force-with-lease`. Pull requests are squash-merged with every commit
message kept, and the check reads trailers from each commit's section of the squash
message, so the trailer survives the merge.

CI never passes `pytest --snapshot-update`, and `tests/snapshot/conftest.py` refuses it when the
`CI` or `GITHUB_ACTIONS` environment variable equals `true` (exactly that string, so
`CI=1` does not trigger the refusal). `tests/snapshot/test_snapshot_policy.py` fails if
any workflow, action, script or pytest configuration passes `pytest --snapshot-update`
or `pytest --snapshot-warn-unused`, with one exception: the "Run PyTest" step of
`.github/actions/run-unit-tests/action.yml` passes `pytest --snapshot-warn-unused` once. CI's
tier runs and shards each see only part of the suite, so the snapshots of the other
tiers' and shards' tests are unused by construction. A local whole-suite run keeps
syrupy's failing default, so an orphaned snapshot is caught by a whole-suite run (and
surfaces as a warning line in the tier runs). A missing snapshot fails.

### Orphaned snapshots

A snapshot that no test asserts any more fails a whole-suite run. That is syrupy's
default, and a local `pytest` keeps it. CI's tier runs and integration shards pass
`pytest --snapshot-warn-unused`, because each sees only part of the suite, so there an unused
snapshot is reported as a warning in the run's snapshot summary and does not fail the
leg. The `check-snapshot-trailers.py --orphans` check below still fails CI for a snapshot file whose test module
is gone. syrupy reports an unused snapshot in a
test module that still exists. If you delete or rename a test module, syrupy never opens
its snapshot file, so `check-snapshot-trailers.py --orphans` (in CI, and in
`test_snapshot_policy.py`) checks that every file under a `tests/**/__snapshots__/`
directory belongs to a `<test_module>.py` next to that directory, and that no
`__snapshots__` directory is empty. When you rename a module, move its snapshots with it;
when you delete one, delete its snapshots. Either change needs a `Snapshot-Update:`
trailer like any other. The check takes its list from git: tracked snapshots and untracked
ones that are not ignored, so a snapshot not yet added is checked, and anything under an
ignored directory, such as `tests/pytest-temp`, is not. It needs a git work tree.

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
the image, a real container or Nix scan, the `./ash` and `ash_helpers.ps1` wrappers) is
in `tests/snapshot/container/runtime/`, marked `container_runtime` or `nix_runtime`.
`tests/conftest.py` deselects those unless `pytest --run-container-snapshots` or
`pytest --run-nix-snapshots` is passed, which the scan-validation container legs and the
Nix legs do after their scans. Keep such modules in `runtime/`: syrupy reads every file in a
`__snapshots__` directory once one test beside it runs, so a deselected module's
snapshots next to collected ones would fail the default run as unused. To update them,
build the image (or have Nix) and run the module with `pytest -n 0 --snapshot-update`
and its flag; see the module docstrings for the environment they read.

## Development Commands

- Format and lint code:

```bash
uv run ruff check .
uv run ruff format .
```

- Run a specific script:

<!-- doctest: illustrative reason="runs ash from this repository's own environment, so it needs a checkout of this repository" -->
```bash
uv run ash
```

## Project Dependencies

Dependencies are managed in `pyproject.toml`. Key groups:

- Runtime dependencies: defined under `[project] dependencies`
- Dev dependencies: defined under `[dependency-groups] dev` (includes ruff, pytest, mypy, mkdocs, etc.)

Scanner tools (Bandit, Checkov, Semgrep) are managed via UV tool isolation at runtime — they're not project dependencies.

### Pinned tool versions

`automated_security_helper/utils/tool_downloads.py` pins every tool ASH provisions
itself. The weekly ASH - Pinned Tool Versions workflow compares those pins with each
upstream's latest release; to run the same check locally:

<!-- doctest: illustrative reason="runs a script from this repository's scripts directory that asks GitHub for each tool's latest release" -->
```bash
uv run python scripts/check_pinned_tool_versions.py
uv run python scripts/check_pinned_tool_versions.py --fail-on-outdated --markdown
```

For each pin that is behind it lists every value the bump has to change: the entries
in `tool_downloads.py`, the Dockerfile ARG, and each tracked file that repeats one of
the pin's digests, found with `git grep` (nix's SRI copies, a CI install check, test
fixtures). A gem (cfn-nag, Bundler) is compared with the newest release the image's
Ruby can run, read from the Dockerfile's `ruby=` apt pin; a newer release that needs
a newer Ruby is named in the report but does not count as outdated.

It exits 0 when nothing is behind, and also when a pin is behind but
`check_pinned_tool_versions.py --fail-on-outdated` was not asked for. It exits 1 when a
pin is behind with that flag or a Dockerfile apt pin is no longer installable, and
2 when a lookup failed or the pins could not be read. GitHub allows 60 anonymous API
requests an hour per address; set `GITHUB_TOKEN` or `GH_TOKEN` to lift that. A lookup
GitHub refuses with 403 while the token is set is retried once without it, and GitHub's
error message goes to stderr. The token is never printed, and it is sent across a
redirect only to the same scheme, host and port.

## Troubleshooting

If you encounter any issues:

1. Verify your Python version matches the required version (3.10+):

```bash
python --version
```

2. Try cleaning and rebuilding the environment:

<!-- doctest: illustrative reason="removes and reinstalls this repository's virtual environment over the network, so it needs a checkout of this repository" -->
```bash
rm -rf .venv
uv sync
```

3. Update UV and dependencies:

<!-- doctest: illustrative reason="updates uv itself over the network and upgrades this repository's dependencies" -->
```bash
uv self update
uv sync --upgrade
```

4. If using a devfile-compatible IDE and encountering issues, try running the devfile commands manually:

<!-- doctest: illustrative reason="downloads the uv installer over the network, then builds and tests this repository" -->
```bash
# Install dependencies
curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR="$HOME/.local/bin" sh && export PATH="$HOME/.local/bin:$PATH" && uv sync

# Build the project
export PATH="$HOME/.local/bin:$PATH" && uv build

# Run tests
export PATH="$HOME/.local/bin:$PATH" && uv run pytest
```

## Version Management

ASH uses [Semantic Versioning](https://semver.org/). The version is defined in `pyproject.toml` and propagated to documentation files via a template system.

### How It Works

- `pyproject.toml` is the single source of truth for the version.
- Documentation files that reference the version (README, install guides, etc.) have corresponding `.template` files containing `{{VERSION}}` placeholders.
- The `scripts/version_bump.py` script updates `pyproject.toml` and regenerates all documentation from templates.
- Text that is only true from a later release on goes in a version block of the template, `{{#after 3.7.1}}` ... `{{else}}` ... `{{/after}}`, each marker on its own line; `generate` keeps the first part when the version is after the one named and the `{{else}}` part (optional) otherwise. The docs publish on every push to `main`, so this is how a page can describe a feature `main` has without telling readers of the current release that it is theirs. A malformed or unclosed block stops `generate`.

### Commit Messages

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) format. A required check ("Validate PR title") enforces this. Since PRs are squash-merged, the PR title becomes the commit message that drives changelog generation.

```text
feat: add OpenGrep scanner support
fix(detect-secrets): apply global_ignore_paths
chore: bump dependencies
feat!: redesign plugin API (breaking change)
```

A pre-commit hook (`commitizen`) also validates local commit messages.

### The ASH scan of this repository

ASH scans its own repository on every pull request, in two workflows:

- "ash / SAST, SCA, and IaC Scan" (`.github/workflows/ash-repo-scan.yml`) is a required check. On a pull request it installs ASH, and the cfn-nag Gemfile it pins, from this repository at the pull request's base commit, for same-repository and fork pull requests alike. In the merge queue it installs from the branch the queue merges into (`merge_group.base_ref`), the default branch here. The job's first step resolves that ref to a commit, and every later step, the config fetch included, uses that commit, so a merge that lands mid-run cannot mix two versions of ASH or pair one version's ASH with another's config. A pull request is therefore never judged by the ASH it changes: a change that makes a scanner stop reporting, or the gate exit 0, has no effect on its own required check. On a pull request and in the merge queue the scan job also restores no cache (no uv cache, grype database or OpenGrep binary): another job running the pull request's code in the same cache scope could have written those entries. Each is downloaded and verified instead, which costs one uncached ASH install and one grype database download per run.
- `ash (pull request head, informational only -- does not gate) / SAST, SCA, and IaC Scan` (`.github/workflows/ash-repo-scan-pr-head.yml`) runs the pull request's own ASH against the same tree. It is not a required check and must not be added to a ruleset. It posts no PR comment, publishes no JUnit check and uploads no SARIF, and the job that runs the pull request's ASH holds a read-only token, so neither its inputs nor its code can post a result under the required scan's name; its findings are in the job summary and in the run's `ash_output` artifact. (In the reusable workflow the scan job always holds `contents: read` only; the PR comment, the JUnit check and the SARIF upload run in a separate job, `Report ASH results`, which downloads the scan's artifact and runs nothing from it.) When you change ASH itself, this is the run that shows what your change does.

The required check also reads its ASH config from the base commit, not from the pull request: `.ash/.ash.yaml` as of the pull request's base commit (in the merge queue, as of the branch the queue merges into) is fetched outside the checkout and passed as `--config`. Every tool config file that config names by a relative path (`scanners.<name>.options.config_file`, here `.ash/bandit.yaml`, `.ash/.checkov.yaml` and `.ash/.grype.yaml`), and opengrep's or semgrep's `config` when it names a rules file or directory, is read from the same commit, and the scan fails if that commit lacks one. The fetched copies sit outside the checkout, so they apply as operator files: ASH honors them where it refuses a tool config file inside the scanned tree, such as `.ash/.checkov.yaml`. Paths written inside them still resolve in the checkout, so a fetched checkov config whose `external-checks-dir` or `config-file` is relative, which would load code from the pull request's tree, fails the scan; use an absolute path outside the repository. A pull request therefore cannot change `.ash/.ash.yaml`, or the tool config files it names, for the check that gates it. Config edits in a pull request affect the required check only after they are merged; until then the informational check, which scans with the pull request's own config, shows their effect. What still comes from the pull request: its `.gitignore` and `.ignore` files, which shrink the set of files ASH scans; config files a scanner finds by name in the scanned tree when the config names none; and inline suppression markers such as `# nosec` and `# pragma: allowlist secret`. Review changes to those like any other change to the gate. The reusable workflow exposes this as the `config-ref` input, which other callers can set the same way. If the base commit has no file at the configured path, the required check fails rather than scanning with ASH's defaults; a caller whose first config is still in a pull request can set `config-ref-missing: defaults` for that pull request.

Because the required check runs the base commit's ASH, a workflow change that depends on an ASH change in the same pull request can fail its own required check. A new tool does not: `ash-repo-scan.yml` passes `skip-unknown-tools: true`, so the scan job sets `ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip` and the base commit's ASH names and skips a `--tool` it has no plugin for (the base config cannot enable a scanner that ASH lacks), and the pull request's own ASH installs and runs the tool in the informational check. A base commit's ASH that predates the setting refuses the whole list instead; under the setting the workflow's install step installs each tool by its own call and skips the ones that ASH refuses as unknown, so the check passes with that ASH too. Other callers of `run-ash-security-scan.yml` keep the refusal unless they pass the input too. Anything else the base commit's ASH does not know yet, such as a new `ash` flag the workflow passes, still fails. Land that kind of change in two pull requests, the ASH change first and the workflow change that uses it after. The same split works against you when the ASH on `main` cannot scan this repository at all (it crashes, or a scanner always ends in ERROR): every pull request's required check and every merge-queue run uses that ASH, including the pull request that fixes it. The way out is to merge the fix as the repository role that the "Protect main" ruleset exempts from its required checks, which the note at the top of `ash-unified-ci.yml` describes; the informational check on the fix's pull request shows whether its own ASH scans the repository again.

On `pull_request`, GitHub runs the workflow files from the pull request's merge commit, so a pull request that edits `ash-repo-scan.yml` or `run-ash-security-scan.yml` still changes its own gate. Review changes to `.github/workflows/` with that in mind; nothing inside a workflow file can prevent it. The control for that gap sits outside the workflow files: a repository ruleset's required workflow, which GitHub runs from a ref the ruleset pins rather than from the pull request.

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

The documentation site is published by the `deploy-docs` job of `.github/workflows/ash-repo-docs.yml`, the only job there with `contents: write`, from every push to `main`. The release PR's merge publishes the release's docs that way. No tag push publishes them, and a hand-pushed release tag no longer republishes the site: the workflow has no tag trigger, and the job's `if:` admits only `refs/heads/main`. That holds for commits that carry the current workflow file. A tag pushed on an older commit runs that commit's copy, which still triggers on every tag, so tag creation and updates should be limited to the release path by a tag ruleset; nothing in a workflow file can cover those commits.

#### Release App setup

The release PR's required checks ("ash / SAST, SCA, and IaC Scan", `Validate PR title`, `required-checks`) run on `pull_request`. When the PR is opened with the workflow's `GITHUB_TOKEN`, GitHub creates those runs in an approval-required state, and nothing starts until a maintainer with write access selects **Approve workflows to run** in the PR's merge box. The release PR says so in its description when that happens. To have the checks start on their own, the workflow opens the PR with a GitHub App token instead, which needs this one-time setup by a repository admin:

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

<!-- doctest: illustrative reason="bumps the version of this repository with commitizen, so it needs a checkout of this repository and its commit history" -->
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

<!-- doctest: illustrative reason="previews a version bump of this repository with commitizen, so it needs a checkout of this repository and its commit history" -->
```bash
uv run cz bump --dry-run --changelog --increment MINOR   # what RELEASE_LINE 3.x produces when a major is detected
uv run cz bump --dry-run --changelog                     # what RELEASE_LINE auto produces
```

## Scanner Plugin Development

When developing custom scanner plugins for ASH, follow these guidelines:

### Base Scanner Plugin

All scanner plugins should inherit from `ScannerPluginBase` and implement the required
methods. The template below builds as written (a test executes it from this file):

```python
from pathlib import Path
from typing import List, Literal, Optional, Tuple

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin


class MyCustomScannerConfig(ScannerPluginConfigBase):
    """The `scanners.my-tool` section of the ASH config."""

    name: str = "my-tool"


@ash_scanner_plugin
class MyCustomScanner(ScannerPluginBase[MyCustomScannerConfig]):
    def model_post_init(self, context):
        # Initialize scanner properties
        self.command = "my-tool"
        self.tool_type = "SAST"  # Scanner type

        # use_uv_tool opts into the uv-managed tool path. The helpers below
        # live on UVToolMixin (automated_security_helper/base/uv_tool_mixin.py),
        # which every plugin inherits through PluginBase: the dependency check
        # can then install the tool with `uv tool`, read its version, and run
        # it through uv. Left False (the default), the scanner runs
        # self.command straight from PATH as it is: nothing installs the tool,
        # `ash dependencies install --tool my-tool` has no install route to it
        # and exits 1 without the version check ever being asked, and
        # validate_plugin_dependencies below must find the tool itself.
        self.use_uv_tool = True
        if self.use_uv_tool:
            self._setup_uv_tool_install_commands()
            self.tool_version = self._get_uv_tool_version("my-tool")

        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        # Decide whether the tool can run (PATH lookup, version pin, ...).
        return True

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[dict]]:
        # Build the tool invocation; the base class's scan() template runs
        # it, bounds it with the scan timeout, and reads results_file back.
        # Scanners with their own flow (Python-API scanners) override scan()
        # directly instead and keep a one-line _execute_scan stub.
        results_file = self.results_dir.joinpath(target_type, "my_tool.sarif")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        final_args = [
            self.command,
            "scan",
            str(target),
            "--output",
            str(results_file),
        ]
        return final_args, results_file, None
```

### UV Tool Version Constraints (Optional)

The `_get_tool_version_constraint()` method is **optional** and only needs to be implemented if your scanner requires specific version constraints for UV tool installation:

<!-- doctest: illustrative reason="a method for a scanner plugin class, shown without the class around it" -->
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

<!-- doctest: illustrative reason="runs this repository's own unit and integration tests, so it needs a checkout of this repository" -->
```bash
# Run scanner-specific unit tests
uv run pytest tests/unit/plugin_modules/ -v

# Run scanner integration tests (skipped without --run-integration)
uv run pytest tests/integration/scanners/ --run-integration -v
```
