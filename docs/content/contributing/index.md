# Contribute to ASH

This page covers a development checkout, the layout of the repository, and what a pull
request goes through before it merges. The other contributor pages are
[Test your change](testing.md), [Test the documentation](documentation.md), and
[Releases and versions](releases.md).

To report a bug or ask for a feature, open an issue on
[GitHub](https://github.com/awslabs/automated-security-helper/issues). To report a security
issue, do not open a public issue: follow
[SECURITY.md](https://github.com/awslabs/automated-security-helper/blob/main/SECURITY.md).

## Set up a development checkout

You need git, [uv](https://docs.astral.sh/uv/getting-started/installation/), and Python
3.10 to 3.14. uv downloads a Python in that range if none is installed.

1. Fork the repository on GitHub, then clone your fork:

    <!-- doctest: illustrative reason="clones from GitHub" -->
    ```bash
    git clone https://github.com/<your-account>/automated-security-helper.git
    cd automated-security-helper
    ```

    Replace `<your-account>` with your GitHub user name.

    Work in a git clone, not in an unpacked source archive. The unit suite, the docs
    checks, and the snapshot checks list files with `git ls-files`, so they fail outside
    a git work tree, and git must be on your `PATH`.

2. Install the project, its development tools, and both optional extras:

    <!-- doctest: illustrative reason="installs packages from the network" -->
    ```bash
    uv sync --extra cdk --extra symbols
    ```

    This creates `.venv` with ASH installed in editable mode, the `dev` dependency group
    (pytest, ruff, mypy, pre-commit, mkdocs, and the rest), and the two extras that CI
    installs: `cdk` (aws-cdk-lib and cdk-nag, which the cdk-nag scanner needs) and
    `symbols` (the tree-sitter grammars that `symbol:` suppressions use). A plain
    `uv sync` leaves both extras out, and the tests that need them then skip; the skip
    reason names the extra.

    The repository has no `.python-version` file, so uv uses the newest installed Python
    in the supported range. To develop against a particular version, name it:
    `uv sync --python 3.12 --extra cdk --extra symbols`.

    The scanners are not project dependencies. A scan runs the Python-based ones, such
    as bandit, checkov, and semgrep, with `uv tool run`, and finds binary ones such as
    grype or trivy on your `PATH` or in `~/.ash/bin`, where `ash dependencies install`
    puts them. See [Manage scanner tools](../docs/advanced-usage.md).

3. Check that the ASH in your checkout runs:

    <!-- doctest: illustrative reason="runs in a checkout of this repository" -->
    ```bash
    uv run ash --version
    ```

    It prints the version in `pyproject.toml`.

### Operating system notes

- Windows: some test data paths are long. Enable long paths in git before you clone:

    <!-- doctest: illustrative reason="Windows only" -->
    ```powershell
    git config --global core.longpaths true
    ```

    Git for Windows and MSYS2 ship a shell named `ash`. `uv run ash` finds the project's
    ASH first, because `uv run` puts the project's environment at the front of `PATH`;
    outside `uv run`, the `ashv3` alias runs the same entry point.
- CI runs the unit suite on Linux (x86_64 and arm64), macOS on Apple silicon, and
  Windows, each with Python 3.10 to 3.14, so any of these works for development.
- Some tests need programs that are not Python packages, such as a container runtime,
  a sandbox backend, or Nix. [Test your change](testing.md) says which, and how they are
  selected.

### Devfile environments

An IDE that reads devfiles can use `devfile.yaml` at the root. Its `install` command
installs uv into `~/.local/bin` and runs `uv sync`, `build` runs `uv build`, and `test`
runs `uv run pytest`. Each command puts `~/.local/bin` on `PATH` itself, so it also runs
under a POSIX `sh`. That `uv sync` installs neither extra. To run the commands by hand,
copy them from `devfile.yaml` or
[DEVELOPMENT.md](https://github.com/awslabs/automated-security-helper/blob/main/DEVELOPMENT.md).

## Run ASH from your checkout

`uv run` runs a command in the checkout's environment, so `uv run ash` is the ASH you are
editing. With no arguments, `ash` scans the current directory, which inside the checkout
is the ASH repository itself. To scan another project with your checkout's code, run
from that project and point uv at the checkout with `uv run --project`:

<!-- doctest: illustrative reason="runs ASH from a checkout of this repository" -->
```bash
cd ~/src/my-project
uv run --project ~/src/automated-security-helper ash --source-dir . --output-dir .ash/ash_output
```

`uv run --project` keeps your working directory. `uv run --directory` also uses the
checkout's environment but first changes into the checkout, so relative paths then
resolve inside the checkout. To run the MCP server from your checkout, see
[Test an MCP change locally](testing.md#test-an-mcp-change-locally). Every command and
option is in the [CLI reference](../reference/cli.md).

## Project layout

| Directory | What it holds |
|-----------|---------------|
| `automated_security_helper/` | The package: the CLI and MCP server (`cli/`), configuration models (`config/`), the scan phases (`core/`), plugin base classes (`base/`), built-in and community plugins (`plugin_modules/`), result models (`models/`), JSON schemas (`schemas/`), and shared utilities (`utils/`) |
| `tests/` | Unit, integration, and snapshot tests, test data, and test helpers; see [Test your change](testing.md) |
| `docs/` | `docs/content/` is this site, built with mkdocs from `mkdocs.yml` |
| `scripts/` | Generators for the reference pages, the docs checks, the version template manager, and the verification scripts some CI jobs run |
| `.github/` | Workflows, composite actions (`actions/`), the gate scripts CI runs (`scripts/`), the changelog template, and curated release notes |
| `ash-agent-plugins/` | The agent and IDE plugins: the shared sources in `agentic-coding/transpiler/_base/`, the transpiler that renders them, and the generated per-platform plugin trees |
| `skills/` | The `ash-mcp` agent skill, generated by the transpiler |
| `deploy/` | The CDK app, CDK constructs, and Terraform for running ASH on AWS |
| `examples/` | Example CI configurations and an example plugin package |
| `.ash/` | The ASH configuration that CI uses to scan this repository |
| `Formula/` | The Homebrew formula |
| `nix/` | Nix packages for the scanners nixpkgs does not carry; `flake.nix` at the root defines the development shell |
| `utils/` | `ash_helpers.sh`, which you source from a shell profile to get an `invoke-ash` command that runs this checkout's `./ash` from any directory; `ash_helpers.ps1`, which defines `Invoke-ASH`, the container wrapper for PowerShell; and older per-scanner scripts that ASH does not run |

## Open a pull request

1. For anything beyond a small fix, open an issue first so the change can be discussed
   before you spend time on it.
2. Create a branch in your fork from the latest `main`, and keep the change to one
   purpose. A reformat of unrelated code makes the change hard to review.
3. Add or update tests for the change, and run them as described in
   [Test your change](testing.md).
4. Update the docs the change affects. Docs are checked against the code, so a page that
   names an option that no longer exists fails CI; see
   [Test the documentation](documentation.md). If users will see different behavior,
   describe it under `## Unreleased` in `CHANGELOG.md` (see
   [Releases and versions](releases.md#what-the-changelog-contains)).
5. Open the pull request against `main` with a title in the commit message format below,
   and fill in the template's checklist.

A pull request merges when it has one approving review, every review conversation is
resolved, and the required checks pass (see the table below). The "Protect main"
ruleset also requires the branch to be up to date with `main`, and it includes a code
quality rule set to every severity. A push after an approval dismisses it. Merging goes
through GitHub's merge queue, which squashes the pull request into one commit and runs
the required checks again on the result.

Pull requests from forks run with a read-only token and without repository secrets, so a
few steps that need them, such as the scan's comment on the pull request, are skipped.
GitHub can also hold the workflow runs of a first-time contributor until a maintainer
approves them.

## Commit messages and pull request titles

Commit messages and pull request titles follow
[Conventional Commits](https://www.conventionalcommits.org/), as checked by
[commitizen](https://commitizen-tools.github.io/commitizen/):

```text
<type>(<optional scope>)<optional !>: <description>
```

The type is one of `build`, `bump`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`,
`refactor`, `revert`, `style`, and `test`. A scope cannot contain whitespace, and `!`
marks a breaking change. For example:

```text
feat(reporters): add a JUnit reporter option for suite names
fix(sandbox): keep the scanner cache writable under bwrap
docs: rewrite the contributor pages
feat!: drop the v2 configuration format
```

The `Validate PR title` check runs `cz check` on the pull request title. The squash
merge takes its subject from the pull request title when the pull request has several
commits, and from the commit itself when it has one, and the title check does not see
that commit. So give a single commit a conventional subject too; the commit-msg hook
below checks it for you.
The squash commit's body keeps every commit message, so trailers such as
`Snapshot-Update:` survive the merge.

The type of the subject that lands on `main` decides what the release does with it:

| Subject on `main` | Changelog | Version bump |
|-------------------|-----------|--------------|
| `feat` | listed under Feat | minor |
| `fix`, `refactor`, `perf` | listed under Fix, Refactor, or Perf | patch |
| any type with `!`, or a `BREAKING CHANGE:` footer | listed | major, capped to minor on the 3.x line |
| `build`, `bump`, `chore`, `ci`, `docs`, `revert`, `style`, `test` | not listed | none |

So a change to CI only is `ci: ...`. Written as `fix(ci): ...`, it is listed under Fix
and makes the next release a patch release. [Releases and versions](releases.md) has
the details.

## What CI runs on a pull request

Three checks are required to merge: "ash / SAST, SCA, and IaC Scan", `Validate PR title`,
and `required-checks`. `required-checks` stands for every job in the "ASH - Unified CI"
workflow, so all of those have to pass too. The repository also requires the code
scanning results that the ASH scan uploads, so a pull request that introduces an alert
does not merge.

| Check | What it checks | Required |
|-------|----------------|----------|
| ash / SAST, SCA, and IaC Scan | ASH scans this repository with the configuration in `.ash/`, fails on actionable findings, and posts a summary on the pull request; the `sarif` job uploads the SARIF report to code scanning | yes |
| `Validate PR title` | the pull request title passes `cz check` | yes |
| `lint` | the JSON schemas match a regeneration; the docs checks pass; every CI artifact upload and cache is allowlisted; every cached content database is time-bounded; and `ruff check`, `ruff format --check`, and mypy pass. ty runs for information only | through `required-checks` |
| `actionlint` | actionlint and shellcheck over every workflow | through `required-checks` |
| `snapshot-trailers` | every changed golden file has a `Snapshot-Update:` trailer, and every snapshot belongs to a test module | through `required-checks` |
| `unit-test (<os>, py<version>)` | the unit and snapshot suite with both extras, on five runners and Python 3.10 to 3.14, plus the cdk-nag integration tests. A test that cannot find an extra fails rather than skipping, and the leg fails when total coverage of `automated_security_helper/` is under 80% | through `required-checks` |
| `integration-test (ubuntu-latest)` | the integration suite with `pytest --run-integration --run-slow`, and the examples in the docs | through `required-checks` |
| `build-docs` | `mkdocs build --strict`, and `scripts/docs_versions.py check` on the versioned site | through `required-checks` |
| `converter-integration (<os>)` | the converter integration tests on macOS and Windows | through `required-checks` |
| `scan (<method>, <os>)` | real scans by every way of running ASH: local, the Python container launcher, `./ash`, PowerShell, each container runtime, offline, and with the community plugins | through `required-checks` |
| `external-target scan (<os>)`, `multi-project attribution (<os>)` | a scan of a directory outside the repository; a workspace scan that keeps findings with their projects | through `required-checks` |
| `sandbox escape (<os>)`, `sandbox scanner parity (<sandbox>, <os>)` | the sandbox backends contain a scanner; each scanner gives the same results with and without a sandbox | through `required-checks` |
| `deploy-tree AWS helpers (moto server)` | the helper scripts in `deploy/`, against a local moto server | through `required-checks` |
| `<method> (<os>, py<version>)` | each install method (the pip, pipx, uvx, pre-commit, and MCP bundle, Homebrew, and the container runtimes) on each runner and Python it supports. The bundle runs ASH's pre-commit hooks against fixture repositories on one leg per operating system. The Homebrew legs, on Linux x86_64 and macOS with Python 3.12, install the formula built from the pull request's commit, run `brew test`, and scan with the installed ASH | through `required-checks` |
| `required-checks` | fails when any Unified CI job failed or was canceled; when all of them pass it is skipped, which GitHub counts as passing | yes |
| `Build wheel and sdist, and assert their contents` | the package builds and contains what it should | no |
| `upgrade (<from>)` | the tree installs into a clean environment, over the latest release, and over the previous commit | no |
| `dependency-review` | no new dependency with a high-severity advisory | no |
| `Assert every action is pinned to a commit sha`, `Assert no boolean workflow input is treated as a string` | workflow hygiene | no |
| `cdk template drift`, `generated buildspec drift`, `terraform hygiene`, `cdk-nag` | the committed IaC in `deploy/` matches a fresh synth, and passes its own checks | no |
| TypeScript CI, Agent Plugins Drift, CDK Extra Drift, Install Method Validation, Docs CI Runners | the TypeScript packages in `deploy/`, the generated agent plugins, the cdk extra fallback, the Nix install, and the CI examples in the docs, each under its CI system's own runner (see [Run the CI examples with their runners](documentation.md#run-the-ci-examples-with-their-runners)); each runs only when a pull request changes its files | no |

A check that is not required does not block the merge when it fails, but the failure
still shows on the pull request.

## Scheduled checks

The "ASH - Pinned Tool Versions" workflow runs every Monday and can be started by hand. It
runs `scripts/check_pinned_tool_versions.py --fail-on-outdated --markdown` and writes the
report to the job summary. The script compares:

- each version pinned in `automated_security_helper/utils/tool_downloads.py` (the release
  binaries, the Python scanners the container image installs, the license-only entries,
  and the cfn-nag gem) with its upstream's latest release on GitHub, PyPI, or RubyGems;
- each `package=version` pin on an `apt-get install` line in the `Dockerfile` with the
  Debian and NodeSource package indexes, for amd64 and arm64.

The script fetches only HTTPS URLs on `api.github.com`, `pypi.org`, `rubygems.org`,
`deb.debian.org`, and `deb.nodesource.com`, and checks every redirect hop against the same
rule before it follows it. With `GITHUB_TOKEN` or `GH_TOKEN` set, it sends the token to
the GitHub API only, carries it across a redirect only to the same scheme, host, and port,
and retries a GitHub lookup that gets 403 once without the token. It exits 2 when a
lookup fails, the pins cannot be read, an `apt-get install` line names a package without
a version, or an `apt-get install` line pins a package to a different version than another
stage does, and 1 when no package index carries an apt pin's version. A pin that
is behind makes it exit 1 only with `check_pinned_tool_versions.py --fail-on-outdated`, as
the workflow runs it; otherwise it exits 0. To run it locally, from a checkout:

<!-- doctest: illustrative reason="queries GitHub, PyPI, RubyGems, and the Debian and NodeSource archives" -->
```bash
python scripts/check_pinned_tool_versions.py
```

The workflow opens no issue or pull request. A bump changes every digest, the license
files, and the source commit in `tool_downloads.py`, so a person makes it; the report
lists each value a bump has to change.

## Code style

CI runs these, and so can you:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run ruff check .
uv run ruff format --check .
uv run --group dev --extra cdk mypy automated_security_helper/
```

`uv run ruff format .` and `uv run ruff check --fix .` fix what they can. The ruff
settings, including the line length of 88, are in `[tool.ruff]` in `pyproject.toml`,
which also requires ruff 0.16.10 or later: an older ruff exits with code 2 rather than
lint with different rules. `tests/test_data/` is excluded, because those files are
scanner input. mypy checks the package, not the tests or scripts. Its per-module
overrides in `pyproject.toml` are a baseline that only shrinks: fix a new type error
rather than adding the module to the overrides.

## Pre-commit hooks

The repository's `.pre-commit-config.yaml` runs ruff, formats JSON files, regenerates the
JSON schemas, and keeps the cdk extra fallback in sync on each commit. The fallback sync
runs its script on Python 3.13 outside the project environment
(`uv run --no-project`), so it leaves your `.venv` and its extras as they are. The config
also checks the commit message with commitizen. `pre-commit install` on its own installs
only the pre-commit stage, not the commit message check. Install both, then run the
hooks over the whole tree:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
uv run pre-commit run --all-files
```

Run pre-commit through `uv run`, so it uses the project's Python; the pinned commitizen
hook needs Python 3.10 or later. The first commit takes longer while pre-commit builds
the hook environments, and the schema regeneration runs on every commit.

On a clean checkout, `pre-commit run --all-files` passes and changes nothing. The JSON
formatter skips the files that a tool writes or a check compares byte for byte: the
generated agent plugin trees, `_base/mcp.json` that they copy, and the vendored schemas
under `ash-agent-plugins/`, the synthesized CDK templates, the npm manifests in
`deploy/`, and the snapshot files. Change those with the tool that owns them. It also
skips the editor settings under `.vscode/`, and `deploy/cdk/tsconfig.json`, which has
comments. CI runs ruff and the other checks directly rather than through these hooks,
because the ruff and JSON hooks fix what they find instead of reporting it.

The config also has a manual hook that scans the repository with your checkout's ASH:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pre-commit run --hook-stage manual ash
```

These hooks are for developing ASH. To run ASH as a pre-commit hook in your own
repository, see [Run ASH with pre-commit](../how-to/pre-commit.md).
