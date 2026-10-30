# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every docs check in scripts/docs_checks.py reports the defect it exists for.

Same contract as tests/unit/test_docs_freshness_gate_can_fail.py, which covers the gate's
first eight checks and whose registry table points here for the next eight: a check
that cannot fail turns the lint job green over broken docs. So each rule of each check
is fed a synthetic page with exactly one planted defect and must report it, with the
words a contributor would search for, and each check also gets a clean page using
every form the rule allows, which must pass. The clean pages are what make the planted
failures mean something: a check that rejected everything would pass the planted cases
and fail the controls.

Fast and platform-neutral on purpose, so it runs on every unit-test leg: nothing here
executes a docs command or needs the network. The checks get their files and repository
root as arguments, so every page lives in tmp_path. A check that lists a tree's files
asks git for them (dc.listed_files), so each tree a check lists is made a git
repository with nothing committed, whose files git lists as untracked.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
GATE_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", CHECKS_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _git_root(root: Path) -> Path:
    """Make root a git repository, so a check can list the files under it
    (dc.listed_files lists them as untracked)."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


def _messages(findings) -> list[str]:
    return [str(f) for f in findings]


def _assert_reports(findings, expected: str, line: int | None = None) -> None:
    hits = [f for f in findings if expected in f.message]
    assert hits, (
        f"expected a finding containing {expected!r}, got: {_messages(findings)}"
    )
    if line is not None:
        assert any(f.line == line for f in hits), (
            f"expected line {line}: {_messages(hits)}"
        )


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

CLEAN_MARKERS = f"""# Every marker form

{FENCE}bash
echo unmarked runs
{FENCE}

<!-- doctest: run expect-exit=2 timeout=30 env="ASH_X=1,B=2" -->
{FENCE}bash
exit 2
{FENCE}

<!-- doctest: run fixture=empty fresh -->
{FENCE}console
$ ls
{FENCE}

<!-- doctest: illustrative reason="needs Docker" -->
{FENCE}powershell
Get-ChildItem
{FENCE}

<!-- doctest: config kind=ash-fragment at=scanners.bandit -->
{FENCE}yaml
enabled: false
{FENCE}

<!-- doctest: config kind=other reason="a SARIF excerpt" -->
{FENCE}json
{{}}
{FENCE}

<!-- doctest: config kind=pyproject -->
{FENCE}toml
[tool.ash]
{FENCE}

<!-- doctest: illustrative reason="writes to a real bucket" -->
{FENCE}python
print("x")
{FENCE}

{FENCE}text
output sample
{FENCE}

    {FENCE}yaml
    indented: fence
    {FENCE}
"""

MARKER_DEFECTS = [
    (
        "unknown mode",
        f"<!-- doctest: execute -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "unknown mode 'execute'",
    ),
    (
        "unknown key",
        f"<!-- doctest: run retries=3 -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "'retries' is not a key of run",
    ),
    (
        "no reason",
        f"<!-- doctest: illustrative -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "needs reason=",
    ),
    (
        "placeholder reason",
        f'<!-- doctest: illustrative reason="TBD" -->\n{FENCE}bash\ntrue\n{FENCE}\n',
        "placeholder",
    ),
    (
        "blank line gap",
        f"<!-- doctest: run -->\n\n{FENCE}bash\ntrue\n{FENCE}\n",
        "a blank line separates",
    ),
    (
        "marker before prose",
        f"<!-- doctest: run -->\nSome prose.\n\n{FENCE}bash\ntrue\n{FENCE}\n",
        "not directly followed",
    ),
    (
        "marker at the end",
        f"{FENCE}bash\ntrue\n{FENCE}\n<!-- doctest: run -->",
        "last line of the page",
    ),
    (
        "marker before trailing blanks",
        f"{FENCE}bash\ntrue\n{FENCE}\n<!-- doctest: run -->\n\n",
        "a blank line separates",
    ),
    (
        "malformed marker",
        f"<!-- doctest: run\n-->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "malformed marker",
    ),
    (
        "windows shell unmarked",
        f"{FENCE}powershell\nGet-Item .\n{FENCE}\n",
        "cannot run in the docs job",
    ),
    (
        "windows shell run",
        f"<!-- doctest: run -->\n{FENCE}ps1\nGet-Item .\n{FENCE}\n",
        "may only be illustrative",
    ),
    ("no language", f"{FENCE}\nash --version\n{FENCE}\n", "has no language"),
    ("pycon", f"{FENCE}pycon\n>>> 1\n{FENCE}\n", "doctest-style"),
    (
        "unknown kind",
        f"<!-- doctest: config kind=helm -->\n{FENCE}yaml\na: 1\n{FENCE}\n",
        "unknown config kind 'helm'",
    ),
    (
        "fragment without at",
        f"<!-- doctest: config kind=ash-fragment -->\n{FENCE}yaml\na: 1\n{FENCE}\n",
        "needs at=",
    ),
    (
        "other without reason",
        f"<!-- doctest: config kind=other -->\n{FENCE}yaml\na: 1\n{FENCE}\n",
        "needs reason=",
    ),
    (
        "pyproject in yaml",
        f"<!-- doctest: config kind=pyproject -->\n{FENCE}yaml\na: 1\n{FENCE}\n",
        "is a toml block",
    ),
    (
        "unknown fixture",
        f"<!-- doctest: run fixture=nowhere -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "names no directory",
    ),
    (
        "bad expect-exit",
        f"<!-- doctest: run expect-exit=maybe -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "must be 0-255",
    ),
    (
        "bad timeout",
        f"<!-- doctest: run timeout=0 -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "timeout=0",
    ),
    (
        "bad env",
        f'<!-- doctest: run env="1BAD" -->\n{FENCE}bash\ntrue\n{FENCE}\n',
        "must be NAME=value",
    ),
    (
        "marker on text",
        f"<!-- doctest: run -->\n{FENCE}text\nhello\n{FENCE}\n",
        "markers apply to shell, python and config",
    ),
    ("unclosed fence", f"# Page\n\n{FENCE}bash\ntrue\n", "never closed"),
    (
        "duplicate key",
        f"<!-- doctest: run timeout=5 timeout=6 -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "sets 'timeout' twice",
    ),
]


@pytest.fixture
def fixture_root(tmp_path):
    """A repository root that has the runner's two fixture directories."""
    root = tmp_path / "repo"
    for name in ("sample-project", "empty"):
        (root / dc.DOC_FIXTURES_DIR / name).mkdir(parents=True)
    return root


@pytest.mark.unit
def test_marker_check_passes_every_valid_form(fixture_root):
    page = _write(fixture_root, "docs/page.md", CLEAN_MARKERS)
    assert dc.check_markers([page], fixture_root) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected", MARKER_DEFECTS, ids=[c[0] for c in MARKER_DEFECTS]
)
def test_marker_check_can_fail(fixture_root, case, text, expected):
    page = _write(fixture_root, "docs/page.md", text)
    _assert_reports(dc.check_markers([page], fixture_root), expected)


@pytest.mark.unit
def test_a_marker_binds_only_to_the_next_block(fixture_root):
    page = _write(
        fixture_root,
        "docs/page.md",
        f'<!-- doctest: illustrative reason="needs Docker" -->\n{FENCE}bash\ndocker ps\n{FENCE}\n\n'
        f"{FENCE}bash\necho second\n{FENCE}\n",
    )
    blocks = dc.parse_page(page, fixture_root).blocks
    assert [b.mode for b in blocks] == ["illustrative", "run"]


# ---------------------------------------------------------------------------
# CLI usage
# ---------------------------------------------------------------------------

CLEAN_CLI = f"""# Commands

{FENCE}bash
ash --source-dir . --output-dir out --scanners detect-secrets --offline
ash scan --offline \\
  --log-level INFO
ash config init --force && ash report --format text | tee report.txt
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.7.1 ash --mode local
uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.1 --version
docker run --rm -v "$(pwd):/src" ghcr.io/example/ash:latest ash --source-dir /src
ASH_LOG=1 sudo -E ash -vd --version
result=$(ash report --format text)
which ash
cat > notes.txt <<EOF
ash --not-a-command, just text in a here-document
EOF
{FENCE}

{FENCE}console
$ ash --version
ash --this-is-output-not-a-command
{FENCE}

<!-- doctest: config kind=github-actions -->
{FENCE}yaml
jobs:
  scan:
    steps:
      - run: ash --source-dir . --fail-on-findings
{FENCE}

<!-- doctest: config kind=mcp-client -->
{FENCE}json
{{"mcpServers": {{"ash": {{"command": "uvx", "args": ["--from", "git+https://github.com/awslabs/automated-security-helper.git", "ash", "mcp"]}}}}}}
{FENCE}

<!-- doctest: config kind=pre-commit -->
{FENCE}yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.7.1
    hooks:
      - id: ash-simple-scan
{FENCE}

{FENCE}dockerfile
RUN ash --version
{FENCE}

Use `ash report --format text`, pass `--offline`, or `--fail-on-findings/--no-fail-on-findings`,
and for another tool write `trivy fs --cache-backend memory`. The file `ash.yaml` is not a command.
"""

# A real newline after the ref, not "\\n": tests/unit/test_agent_plugin_ash_version.py reads
# every "automated-security-helper@<ref>" in the repository as an install pin.
USES_THIS_REPOSITORY = f"""<!-- doctest: config kind=github-actions -->
{FENCE}yaml
jobs:
  a:
    steps:
      - uses: awslabs/automated-security-helper@v3
{FENCE}
"""

CLI_DEFECTS = [
    (
        "unknown option",
        f"{FENCE}bash\nash --source-dir . --bogus\n{FENCE}\n",
        "--bogus is not an option of 'ash'",
        2,
    ),
    (
        "unknown subcommand",
        f"{FENCE}bash\nash scna\n{FENCE}\n",
        "has no subcommand 'scna'",
        2,
    ),
    (
        "subcommand option",
        f"{FENCE}bash\nash config init --source-dir .\n{FENCE}\n",
        "--source-dir is not an option of 'ash config init'",
        2,
    ),
    (
        "continued line",
        f"{FENCE}bash\necho first\nash scan \\\n  --offline \\\n  --bogus\n{FENCE}\n",
        "--bogus is not an option of 'ash scan'",
        3,
    ),
    (
        "after &&",
        f"{FENCE}bash\ncd src && ash --bogus | tee x\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "uvx wrapper",
        f"{FENCE}bash\nuvx --from git+https://github.com/awslabs/automated-security-helper.git ash --bogus\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "uvx package spec",
        f"{FENCE}bash\nuvx git+https://github.com/awslabs/automated-security-helper.git@v3 --bogus\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "pipx wrapper",
        f"{FENCE}bash\npipx run --spec automated-security-helper ash --bogus\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "docker wrapper",
        f"{FENCE}bash\ndocker run --rm -v x:/src img ash --bogus\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "substitution",
        f"{FENCE}bash\nout=$(ash report --bogus)\n{FENCE}\n",
        "--bogus is not an option of 'ash report'",
        2,
    ),
    (
        "flag with value",
        f"{FENCE}bash\nash --offline=yes\n{FENCE}\n",
        "--offline is a flag",
        2,
    ),
    (
        "missing value",
        f"{FENCE}bash\nash --source-dir\n{FENCE}\n",
        "--source-dir needs a value",
        2,
    ),
    (
        "positional to scan",
        f"{FENCE}bash\nash scan .\n{FENCE}\n",
        "takes no positional",
        2,
    ),
    (
        "console prompt",
        f"{FENCE}console\n$ ash --bogus\noutput line\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "inline span",
        "Run `ash --bogus` to scan.\n",
        "--bogus is not an option of 'ash'",
        1,
    ),
    (
        "bare option span",
        "Pass `--bogus` to scan.\n",
        "--bogus is not an option of any ash command",
        1,
    ),
    (
        "python -m",
        f"{FENCE}bash\npython -m automated_security_helper --version\n{FENCE}\n",
        "no __main__",
        2,
    ),
    (
        "run placeholder",
        f"{FENCE}bash\nash --source-dir <path>\n{FENCE}\n",
        "placeholder <path>",
        2,
    ),
    (
        "github actions run",
        f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\njobs:\n  a:\n    steps:\n      - run: ash --bogus\n{FENCE}\n",
        "--bogus",
        2,
    ),
    (
        "github actions uses",
        USES_THIS_REPOSITORY,
        "names no action",
        2,
    ),
    (
        "pre-commit hook id",
        f"<!-- doctest: config kind=pre-commit -->\n{FENCE}yaml\nrepos:\n  - repo: https://github.com/awslabs/automated-security-helper\n    hooks:\n      - id: ash-nope\n{FENCE}\n",
        "hook id 'ash-nope'",
        2,
    ),
    (
        "mcp client",
        f'<!-- doctest: config kind=mcp-client -->\n{FENCE}json\n{{"mcpServers": {{"ash": {{"command": "ash", "args": ["mcp", "--bogus"]}}}}}}\n{FENCE}\n',
        "--bogus is not an option of 'ash mcp'",
        2,
    ),
    ("dockerfile", f"{FENCE}dockerfile\nRUN ash --bogus\n{FENCE}\n", "--bogus", 2),
]


@pytest.fixture
def cli_root(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        dc.PRE_COMMIT_HOOKS,
        (REPO_ROOT / dc.PRE_COMMIT_HOOKS).read_text(encoding="utf-8"),
    )
    return root


@pytest.mark.unit
def test_cli_check_passes_every_valid_form(cli_root):
    page = _write(cli_root, "docs/page.md", CLEAN_CLI)
    assert dc.check_cli([page], cli_root) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected,line", CLI_DEFECTS, ids=[c[0] for c in CLI_DEFECTS]
)
def test_cli_check_can_fail(cli_root, case, text, expected, line):
    page = _write(cli_root, "docs/page.md", text)
    _assert_reports(dc.check_cli([page], cli_root), expected, line)


def _generated(script: str, body: str) -> str:
    """A reference page as its generator writes it: the generator's comment, then body."""
    return (
        f"<!--\n  Generated by scripts/{script} from the plugins.\n"
        "  Do not edit this file by hand.\n-->\n\n" + body
    )


def _plugin_options(of: str, description: str) -> str:
    """A plugin's options table, as the scanner, reporter and converter pages write it."""
    return (
        f"<!-- doctest: options of={of} -->\n"
        "| Option | Type | Default | Description |\n"
        "|--------|------|---------|-------------|\n"
        f'| <a id="{of}.options.config_file"></a>`config_file` | path | `null` | {description} |\n'
    )


def _env_table(*purposes: str) -> str:
    """An environment-variables.md table with one row for each purpose."""
    rows = "".join(
        f"| `TOOL_VAR_{index}` |  |  | `a.py` (module level) | {purpose} |\n"
        for index, purpose in enumerate(purposes)
    )
    return (
        "| Variable | Default | Container image | Read at | Purpose |\n"
        "|----------|---------|-----------------|---------|---------|\n" + rows
    )


GITLEAKS_COMMENT_AT = "(`automated_security_helper/plugin_modules/ash_builtin/scanners/gitleaks_scanner.py`)"

#: A bare option span in a row a plugin's code wrote: (case, page, text, span).
PLUGIN_ROW_BARE_OPTIONS = [
    (
        "scanner option ash also has",
        "docs/content/reference/scanners.md",
        _generated(
            "generate_scanner_reference.py",
            _plugin_options(
                "scanners.zizmor",
                "Path to a zizmor configuration file, passed as `--config`.",
            ),
        ),
        "`--config`",
    ),
    (
        "scanner option ash lacks",
        "docs/content/reference/scanners.md",
        _generated(
            "generate_scanner_reference.py",
            _plugin_options("scanners.zizmor", "zizmor runs with `--no-ignores`."),
        ),
        "`--no-ignores`",
    ),
    (
        "reporter option",
        "docs/content/reference/reporters.md",
        _generated(
            "generate_reporter_docs.py",
            _plugin_options("reporters.sarif", "The tool runs with `--offline`."),
        ),
        "`--offline`",
    ),
    (
        "converter short option",
        "docs/content/reference/converters.md",
        _generated(
            "generate_converter_reference.py",
            _plugin_options("converters.jupyter", "Converted with `-v`."),
        ),
        "`-v`",
    ),
    (
        "environment variable a plugin documents",
        "docs/content/reference/environment-variables.md",
        _generated(
            "generate_env_var_reference.py",
            _env_table(
                "When set, ASH passes no `--config` and gitleaks resolves it. "
                + GITLEAKS_COMMENT_AT
            ),
        ),
        "`--config`",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,rel,text,span",
    PLUGIN_ROW_BARE_OPTIONS,
    ids=[c[0] for c in PLUGIN_ROW_BARE_OPTIONS],
)
def test_a_bare_option_in_a_row_a_plugin_wrote_must_name_its_program(
    cli_root, case, rel, text, span
):
    """In those rows a bare `--config` could be ASH's or the tool's, so it names neither.

    It is reported even when ash has an option of that name, once, at its row.
    """
    page = _write(cli_root, rel, text)
    line = next(n for n, row in enumerate(text.splitlines(), 1) if span in row)
    findings = [f for f in dc.check_cli([page], cli_root) if span in f.message]
    _assert_reports(findings, "a plugin's code wrote this row", line)
    assert len(findings) == 1, _messages(findings)


@pytest.mark.unit
def test_a_row_a_plugin_wrote_passes_when_its_spans_name_the_program(cli_root):
    """The controls: the program in the span, ASH's own written as ash, and the rows and
    pages the rule does not cover, where a bare option keeps today's rule."""
    named = (
        "Passed as `zizmor --config`; ASH's own is `ash --config` or "
        "`ash scan --offline`, and `ash --config ash.yaml` takes a file."
    )
    pages = [
        _write(
            cli_root,
            "docs/content/reference/scanners.md",
            _generated(
                "generate_scanner_reference.py",
                # The inventory table names a section, not a plugin.
                "<!-- doctest: options of=scanners -->\n"
                "| Scanner | Enabled by default | Notes |\n"
                "|---------|--------------------|-------|\n"
                "| `zizmor` | yes | Skipped with `--offline`. |\n\n"
                + _plugin_options("scanners.zizmor", named)
                + "\nOutside a table, prose may say `--config`.\n",
            ),
        ),
        _write(
            cli_root,
            "docs/content/reference/environment-variables.md",
            _generated(
                "generate_env_var_reference.py",
                _env_table(
                    "When set, ASH does not pass `gitleaks --config`. "
                    + GITLEAKS_COMMENT_AT,
                    "Sets [`ash scan --config`](cli.md#scan--config).",
                    "Read before `--config` is parsed. "
                    "(`automated_security_helper/cli/main.py`, `main`)",
                ),
            ),
        ),
        _write(
            cli_root,
            "docs/content/reference/configuration.md",
            _generated(
                "generate_config_reference.py",
                "<!-- doctest: options of=global_settings -->\n"
                "| Option | Type | Default | Description |\n"
                "|--------|------|---------|-------------|\n"
                "| `fail_on_findings` | boolean | `true` | Also set by `--fail-on-findings`. |\n",
            ),
        ),
        # Hand-written: the same table with no generator comment keeps today's rule.
        _write(
            cli_root,
            "docs/content/plugins/aws.md",
            _plugin_options("reporters.aws-security-hub", "Read with `--config`."),
        ),
    ]
    assert dc.check_cli(pages, cli_root) == []


REUSABLE_WORKFLOW = """name: scan
on:
  workflow_call:
    inputs:
      ash-version: {type: string, default: main}
      token-name: {type: string, required: true}
    secrets:
      api-token: {required: false}
jobs: {}
"""


def _calling(body: str, path: str = ".github/workflows/scan.yml") -> str:
    """A docs page whose CI block calls this repository's reusable workflow."""
    return (
        f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\njobs:\n  ash:\n"
        f"    uses: awslabs/automated-security-helper/{path}@v3.7.0\n{body}{FENCE}\n"
    )


@pytest.fixture
def workflow_code(tmp_path):
    code = tmp_path / "code"
    _write(code, ".github/workflows/scan.yml", REUSABLE_WORKFLOW)
    _write(code, ".github/workflows/push-only.yml", "on: push\njobs: {}\n")
    return code


@pytest.mark.unit
def test_a_reusable_workflow_call_passes_with_declared_inputs(tmp_path, workflow_code):
    calls = {
        "clean.md": "    with:\n      ash-version: v3.7.0\n      token-name: x\n"
        "    secrets:\n      api-token: ${{ secrets.TOKEN }}\n",
        "inherit.md": "    with:\n      token-name: x\n    secrets: inherit\n",
    }
    pages = [
        _write(tmp_path, f"docs/{name}", _calling(body)) for name, body in calls.items()
    ]
    assert dc.check_cli(pages, tmp_path, code=workflow_code) == []


REUSABLE_DEFECTS = [
    (
        "misspelled input",
        _calling("    with:\n      ash-verison: v3\n      token-name: x\n"),
        "has no input 'ash-verison'",
    ),
    (
        "required input not passed",
        _calling("    with:\n      ash-version: v3\n"),
        "does not pass its required input 'token-name'",
    ),
    (
        "undeclared secret",
        _calling("    with:\n      token-name: x\n    secrets:\n      nope: y\n"),
        "has no secret 'nope'",
    ),
    (
        "missing workflow",
        _calling("    with:\n      token-name: x\n", path=".github/workflows/nope.yml"),
        "names no workflow: there is no .github/workflows/nope.yml",
    ),
    (
        "workflow that cannot be called",
        _calling("", path=".github/workflows/push-only.yml"),
        "declares no on.workflow_call",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected", REUSABLE_DEFECTS, ids=[c[0] for c in REUSABLE_DEFECTS]
)
def test_a_reusable_workflow_call_can_fail(
    tmp_path, workflow_code, case, text, expected
):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_cli([page], tmp_path, code=workflow_code), expected)


@pytest.mark.unit
def test_cli_model_is_the_real_click_tree():
    """The check reads typer's own conversion, so a renamed option cannot hide in a copy."""
    import typer

    from automated_security_helper.cli.main import app

    click_root = typer.main.get_command(app)
    model = dc.load_cli()
    assert set(model.subcommands) == set(click_root.commands)
    scan_options = {
        name
        for p in click_root.commands["scan"].params
        for name in p.opts + p.secondary_opts
    }
    assert scan_options <= set(model.subcommands["scan"].options)


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------

READ = dc.EnvReadSet(
    names={"ASH_REAL", "ASH_FAMILY_ONE", "OCI_RUNNER"}, dynamic=[], source="test"
)

CLEAN_ENV = f"""# Variables

Set `ASH_REAL` or the `ASH_FAMILY_*` family.

{FENCE}bash
export ASH_REAL=1
{FENCE}

{FENCE}python
import os

ASH_CONSTANT_IN_CODE = os.environ.get("ASH_REAL")
{FENCE}

| Variable | Meaning |
|----------|---------|
| `OCI_RUNNER` | the container runtime |
| `ASH_REAL` | something |

A config may read a variable of its own. ASH resolves `${{ASH_FROM_CONFIG}}` itself:

{FENCE}bash
export ASH_FROM_CONFIG=my-project
{FENCE}

{FENCE}yaml
project_name: ${{ASH_FROM_CONFIG}}
{FENCE}
"""

ENV_DEFECTS = [
    ("prose", "Set `ASH_INVENTED` to change it.\n", "ASH_INVENTED", 1),
    (
        "shell block",
        f"{FENCE}bash\nexport ASH_INVENTED=1\n{FENCE}\n",
        "ASH_INVENTED",
        2,
    ),
    (
        "python string",
        f'{FENCE}python\nimport os\nos.environ["ASH_INVENTED"]\n{FENCE}\n',
        "ASH_INVENTED in a python block",
        1,
    ),
    (
        "config block",
        f"{FENCE}yaml\n# set ASH_INVENTED before the scan\nproject_name: x\n{FENCE}\n",
        "ASH_INVENTED",
        2,
    ),
    (
        "read through another page's config",
        f"{FENCE}bash\nexport ASH_FROM_CONFIG=x\n{FENCE}\n",
        "ASH_FROM_CONFIG",
        2,
    ),
    (
        "table row",
        "| Environment variable | Meaning |\n|---|---|\n| `NOT_READ_ANYWHERE` | x |\n",
        "NOT_READ_ANYWHERE (in an environment-variable table)",
        3,
    ),
    ("family", "The `ASH_NOBODY_*` variables.\n", "ASH_NOBODY_*", 1),
]


@pytest.mark.unit
def test_env_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_ENV)
    assert dc.check_env_vars([page], tmp_path, READ) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected,line", ENV_DEFECTS, ids=[c[0] for c in ENV_DEFECTS]
)
def test_env_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_env_vars([page], tmp_path, READ), expected, line)


KNOWN = dc.EnvReadSet(
    names={"ASH_REAL"},
    dynamic=[],
    source="test",
    build_args={"ASH_REAL_BUILD_ARG": "Dockerfile:3 (ARG)"},
    test_only={"ASH_TEST_ONLY": "read in tests/conftest.py"},
)


@pytest.mark.unit
def test_a_build_argument_passes_where_a_made_up_name_fails(tmp_path):
    page = _write(
        tmp_path,
        "docs/content/guide.md",
        "Build with `ASH_REAL_BUILD_ARG` set. `ASH_MADE_UP_ARG` does nothing.\n",
    )
    notes: list[str] = []
    findings = dc.check_env_vars([page], tmp_path, KNOWN, notes=notes)
    assert [f.message.split()[0] for f in findings] == ["ASH_MADE_UP_ARG"], _messages(
        findings
    )
    assert any(
        "ASH_REAL_BUILD_ARG matched the build argument (Dockerfile:3 (ARG))" in n
        for n in notes
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel", ["docs/content/contributing/testing.md", "CONTRIBUTING.md", "DEVELOPMENT.md"]
)
def test_a_test_suite_variable_passes_on_a_contributor_page(tmp_path, rel):
    page = _write(tmp_path, rel, "Set `ASH_TEST_ONLY=1` to make the tests strict.\n")
    assert dc.check_env_vars([page], tmp_path, KNOWN) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "rel", ["docs/content/guide.md", "README.md", "docs/DEVELOPMENT.md"]
)
def test_a_test_suite_variable_fails_anywhere_else(tmp_path, rel):
    page = _write(tmp_path, rel, "Set `ASH_TEST_ONLY=1` to make the tests strict.\n")
    _assert_reports(
        dc.check_env_vars([page], tmp_path, KNOWN),
        "ASH_TEST_ONLY is read only by the test suite or CI (read in tests/conftest.py)",
        1,
    )


@pytest.mark.unit
def test_dockerfile_args_are_parsed_not_grepped():
    text = (
        "# syntax=docker/dockerfile:1\n"
        "# ARG ASH_IN_A_COMMENT=1\n"
        "ARG BASE_IMAGE=python:3.12\n"
        "FROM ${BASE_IMAGE}\n"
        "arg ASH_LOWER_KEYWORD\n"
        "ARG ASH_CONTINUED=value \\\n    ASH_NEXT_LINE\n"
        'ARG ASH_QUOTED="a b" ASH_SECOND\n'
        "RUN echo ASH_IN_A_RUN_LINE && cat <<EOF\n"
        "ARG ASH_IN_A_HEREDOC\n"
        "EOF\n"
    )
    declared = dc.dockerfile_args(text, "Dockerfile")
    assert set(declared) == {
        "BASE_IMAGE",
        "ASH_LOWER_KEYWORD",
        "ASH_CONTINUED",
        "ASH_NEXT_LINE",
        "ASH_QUOTED",
        "ASH_SECOND",
    }
    assert declared["ASH_CONTINUED"] == "Dockerfile:6 (ARG)"


@pytest.mark.unit
def test_build_args_the_package_passes_are_build_arguments():
    tree = ast.parse(
        'cmd = ["docker", "build", "--build-arg", f"ASH_PASSED={image}", "--build-arg", value]\n'
        'other = "--build-arg ASH_IN_ONE_STRING=x"\n'
    )
    assert {name for _line, name in dc._passed_build_args(tree, {})} == {
        "ASH_PASSED",
        "ASH_IN_ONE_STRING",
    }


@pytest.mark.integration
def test_the_real_build_arguments_include_args_and_passed_names():
    found = dc.build_argument_names(REPO_ROOT)
    assert "ASH_REPO_CLONE_URL" in found and "(ARG)" in found["ASH_REPO_CLONE_URL"]
    assert "ASH_BASE_IMAGE" in found and "(--build-arg)" in found["ASH_BASE_IMAGE"]


@pytest.mark.integration
def test_suite_env_names_come_from_tests_and_ci_env(tmp_path):
    _git_root(tmp_path)
    _write(
        tmp_path, "tests/test_x.py", 'import os\nos.environ.get("ASH_FROM_A_TEST")\n'
    )
    _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "env:\n  ASH_FROM_WORKFLOW_ENV: '1'\njobs:\n  a:\n    steps:\n"
        "      - run: true\n        env:\n          ASH_FROM_STEP_ENV: '1'\n",
    )
    _write(
        tmp_path,
        ".github/actions/x/action.yml",
        "runs:\n  steps:\n    - run: true\n      env:\n        ASH_FROM_ACTION: '1'\n",
    )
    found = dc.suite_env_names(tmp_path)
    assert set(found) == {
        "ASH_FROM_A_TEST",
        "ASH_FROM_WORKFLOW_ENV",
        "ASH_FROM_STEP_ENV",
        "ASH_FROM_ACTION",
    }
    assert found["ASH_FROM_A_TEST"] == "read in tests/test_x.py"


@pytest.mark.unit
def test_env_read_set_resolves_constant_keys():
    """os.environ.get(SOME_CONSTANT) counts as reading the constant's value."""
    import ast as std_ast

    tree = std_ast.parse(
        'import os\nNAME = "ASH_VIA_CONSTANT"\nos.environ.get(NAME)\nos.getenv(other)\n'
    )
    names, dynamic = dc.env_lookups(tree, "m.py", dc._module_string_constants(tree))
    assert names == {"ASH_VIA_CONSTANT"}
    assert dynamic == ["m.py:4 [getenv]"]


@pytest.mark.unit
def test_env_read_set_prefers_the_generator(tmp_path):
    """When scripts/generate_env_var_reference.py exists, its read_env_names() is the set.

    It is handed the code tree to read, which with separate docs and code trees is not
    the tree the generator file sits in.
    """
    _write(
        tmp_path,
        dc.ENV_VAR_GENERATOR,
        "def read_env_names(repo_root=None):\n"
        "    return {'ASH_FROM_GENERATOR', str(repo_root)}, ['x.py:1 [getenv]']\n",
    )
    read = dc.load_env_read_set(str(tmp_path))
    assert read.names == {"ASH_FROM_GENERATOR", str(tmp_path)}
    assert read.source.startswith(dc.ENV_VAR_GENERATOR)


# ---------------------------------------------------------------------------
# Config blocks
# ---------------------------------------------------------------------------

CLEAN_CONFIG = f"""# Configs

{FENCE}yaml
project_name: my-project
fail_on_findings: false
global_settings:
  severity_threshold: HIGH
  ignore_paths:
    - path: build/**
      reason: generated
scanners:
  bandit:
    enabled: true
    options:
      offline: true
      scan_timeout: 60
  detect-secrets:
    options:
      scan_settings:
        plugins_used:
          - name: HexHighEntropyString
            limit: 3.0
            extra_key_detect_secrets_reads: 1
reporters:
  sarif:
    enabled: true
{FENCE}

{FENCE}json
{{"project_name": "my-project", "scanners": {{"bandit": {{"enabled": false}}}}}}
{FENCE}

<!-- doctest: config kind=ash-fragment at=scanners.bandit -->
{FENCE}yaml
enabled: false
{FENCE}

<!-- doctest: config kind=pyproject -->
{FENCE}toml
[tool.ash]
project_name = "my-project"
{FENCE}

<!-- doctest: config kind=ash-invalid reason="fail_on_findings is a boolean" -->
{FENCE}yaml
fail_on_findings: sometimes
{FENCE}

<!-- doctest: config kind=github-actions -->
{FENCE}yaml
on: push
jobs: {{}}
{FENCE}

<!-- doctest: config kind=other reason="a SARIF excerpt" -->
{FENCE}jsonc
{{
  // a comment
  "runs": [],
}}
{FENCE}
"""

CONFIG_DEFECTS = [
    (
        "misspelled top-level key",
        f"{FENCE}yaml\nproject_name: x\nfail_on_findngs: true\n{FENCE}\n",
        "fail_on_findngs is not a field of AshConfig",
    ),
    (
        "invented option",
        f"{FENCE}yaml\nscanners:\n  bandit:\n    options:\n      severity_level: HIGH\n{FENCE}\n",
        "scanners.bandit.options: Value error, Unknown key 'severity_level'",
    ),
    (
        "ignored list item key",
        f"{FENCE}yaml\nglobal_settings:\n  ignore_paths:\n    - path: a/**\n      reason: r\n      why: nobody reads this\n{FENCE}\n",
        "global_settings.ignore_paths.0: Value error, Unknown key 'why'",
    ),
    (
        "wrong type",
        f"{FENCE}yaml\nfail_on_findings: sometimes\n{FENCE}\n",
        "fail_on_findings",
    ),
    (
        "generic key on a reporter",
        f"{FENCE}yaml\nreporters:\n  sarif:\n    options:\n      offline: true\n{FENCE}\n",
        "reporters.sarif.options: Value error, Unknown key 'offline'",
    ),
    (
        "unknown scanner",
        f"{FENCE}yaml\nscanners:\n  gosec:\n    enabled: true\n{FENCE}\n",
        "ships no scanner named 'gosec'",
    ),
    (
        "forbidden key",
        f"{FENCE}yaml\nglobal_settings:\n  not_a_setting: 1\n{FENCE}\n",
        "global_settings.not_a_setting",
    ),
    (
        "fragment path",
        f"<!-- doctest: config kind=ash-fragment at=scanners.bandit.options -->\n{FENCE}yaml\nseverity_level: HIGH\n{FENCE}\n",
        "severity_level",
    ),
    (
        "pyproject",
        f"<!-- doctest: config kind=pyproject -->\n{FENCE}toml\n[tool.ash]\nproject_nmae = 'x'\n{FENCE}\n",
        "project_nmae",
    ),
    (
        "invalid that validates",
        f'<!-- doctest: config kind=ash-invalid reason="shows a mistake" -->\n{FENCE}yaml\nproject_name: fine\n{FENCE}\n',
        "ASH accepts this one",
    ),
    (
        "not an ash config",
        f"{FENCE}yaml\non: push\njobs: {{}}\n{FENCE}\n",
        "this is not an ASH config",
    ),
    (
        "json does not parse",
        f'{FENCE}json\n{{"project_name": "x",}}\n{FENCE}\n',
        "does not parse as json",
    ),
    (
        "other kind does not parse",
        f"<!-- doctest: config kind=github-actions -->\n{FENCE}yaml\non: [push\n{FENCE}\n",
        "does not parse as yaml",
    ),
]


@pytest.mark.unit
def test_config_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_CONFIG)
    assert dc.check_config_blocks([page], tmp_path) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected", CONFIG_DEFECTS, ids=[c[0] for c in CONFIG_DEFECTS]
)
def test_config_check_can_fail(tmp_path, case, text, expected):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_config_blocks([page], tmp_path), expected)


@pytest.mark.unit
def test_passthrough_models_still_allow_extras():
    """PASSTHROUGH_MODELS exempts these from the ignored-key report; pin why."""
    models = dc.load_config_models()
    seen = set()

    def walk(cls):
        if cls in seen:
            return
        seen.add(cls)
        for info in cls.model_fields.values():
            for arg in _model_args(info.annotation):
                walk(arg)

    for configs in models.plugin_configs.values():
        for cls in configs.values():
            walk(cls)
    by_name = {cls.__name__: cls for cls in seen}
    for name in dc.PASSTHROUGH_MODELS:
        assert name in by_name, (
            f"{name} is exempt but no plugin config uses it any more"
        )
        assert by_name[name].model_config.get("extra") == "allow"


@pytest.mark.unit
def test_generic_scanner_option_keys_are_still_read_generically():
    """GENERIC_SCANNER_OPTION_KEYS exempts these keys; pin the reads that justify it."""
    source = (REPO_ROOT / "automated_security_helper/base/scanner_plugin.py").read_text(
        encoding="utf-8"
    )
    reads = {
        node.args[1].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "getattr"
        and len(node.args) >= 2
        and getattr(node.args[0], "id", None) == "options"
        and isinstance(node.args[1], ast.Constant)
    }
    assert dc.GENERIC_SCANNER_OPTION_KEYS <= reads, (
        f"the scanner base no longer reads {sorted(dc.GENERIC_SCANNER_OPTION_KEYS - reads)} "
        "from every scanner's options; drop them from GENERIC_SCANNER_OPTION_KEYS"
    )


def _model_args(annotation):
    import typing

    from pydantic import BaseModel

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
    for arg in typing.get_args(annotation):
        yield from _model_args(arg)


# ---------------------------------------------------------------------------
# Python blocks
# ---------------------------------------------------------------------------

CLEAN_PYTHON = f"""# Python

{FENCE}python
import json

from automated_security_helper.config.ash_config import AshConfig
{FENCE}

<!-- doctest: illustrative reason="needs AWS credentials" -->
{FENCE}python
import boto3
{FENCE}
"""

PYTHON_DEFECTS = [
    (
        "syntax",
        f"{FENCE}python\nx = 1\ndef broken(:\n    pass\n{FENCE}\n",
        "does not parse",
        3,
    ),
    (
        "missing module",
        f"{FENCE}python\nimport not_a_real_module_for_docs\n{FENCE}\n",
        "no such module",
        2,
    ),
    (
        "missing name",
        f"{FENCE}python\nfrom automated_security_helper.config.ash_config import NoSuchThing\n{FENCE}\n",
        "has no name NoSuchThing",
        2,
    ),
    (
        "relative import",
        f"{FENCE}python\nfrom . import sibling\n{FENCE}\n",
        "relative import",
        2,
    ),
    (
        "illustrative still imports",
        f'<!-- doctest: illustrative reason="needs AWS credentials" -->\n{FENCE}python\nimport not_a_real_module_for_docs\n{FENCE}\n',
        "no such module",
        3,
    ),
]


@pytest.mark.unit
def test_python_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_PYTHON)
    assert dc.check_python_blocks([page], tmp_path) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected,line", PYTHON_DEFECTS, ids=[c[0] for c in PYTHON_DEFECTS]
)
def test_python_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_python_blocks([page], tmp_path), expected, line)


# ---------------------------------------------------------------------------
# save-as: blocks the runner writes into the page's project
# ---------------------------------------------------------------------------

CLEAN_SAVE_AS = f"""# A plugin tutorial

<!-- doctest: save-as=my_plugins/__init__.py -->
{FENCE}python
from .scanner import MyScanner

__all__ = ["MyScanner"]
{FENCE}

<!-- doctest: save-as=my_plugins/scanner.py -->
{FENCE}python
from automated_security_helper.config.ash_config import AshConfig


class MyScanner:
    config = AshConfig
{FENCE}

<!-- doctest: run save-as=tools/check.py -->
{FENCE}python
import my_plugins.scanner
from my_plugins import MyScanner, scanner
{FENCE}

<!-- doctest: save-as=.ash/.ash.yaml -->
{FENCE}yaml
project_name: saved
{FENCE}

<!-- doctest: config kind=other reason="a settings file for the example" save-as=settings.yaml -->
{FENCE}yaml
greeting: hi
{FENCE}

<!-- doctest: save-as=Dockerfile -->
{FENCE}dockerfile
FROM python:3.12-slim
{FENCE}

<!-- doctest: save-as=notes/readme.txt -->
{FENCE}text
saved, not run
{FENCE}

<!-- doctest: save-as=scripts/setup.ps1 -->
{FENCE}powershell
Get-ChildItem
{FENCE}

<!-- doctest: run save-as=scripts/hello.sh -->
{FENCE}bash
echo hello
{FENCE}

{FENCE}python
from my_plugins.scanner import MyScanner
{FENCE}
"""


@pytest.mark.unit
def test_save_as_passes_every_valid_form(fixture_root):
    page = _write(fixture_root, "docs/page.md", CLEAN_SAVE_AS)
    assert dc.check_markers([page], fixture_root) == []
    assert dc.check_python_blocks([page], fixture_root) == []
    assert dc.check_config_blocks([page], fixture_root) == []
    blocks = dc.parse_page(page, fixture_root).blocks
    assert [b.mode for b in blocks] == [
        "save",
        "save",
        "run",
        "config",
        "config",
        "save",
        "save",
        "save",
        "run",
        "run",
    ]
    assert blocks[3].config_kind == "ash" and blocks[4].config_kind == "other"


SAVE_AS_MARKER_DEFECTS = [
    (
        "parent directory",
        f"<!-- doctest: save-as=../outside.py -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "leaves the page's project",
    ),
    (
        "parent directory inside the path",
        f"<!-- doctest: save-as=a/../../b.py -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "leaves the page's project",
    ),
    (
        "absolute path",
        f"<!-- doctest: save-as=/etc/x.py -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "is not a relative path",
    ),
    (
        "home directory",
        f"<!-- doctest: save-as=~/x.py -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "is not a relative path",
    ),
    (
        "windows drive",
        f"<!-- doctest: save-as=C:/x.py -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "is not a relative path",
    ),
    (
        "empty path",
        f"<!-- doctest: save-as= -->\n{FENCE}python\nx = 1\n{FENCE}\n",
        "needs a relative path",
    ),
    (
        "run with an escaping path",
        f"<!-- doctest: run save-as=../x.sh -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "leaves the page's project",
    ),
    (
        "config with an escaping path",
        f'<!-- doctest: config kind=other reason="an example file" save-as=../x.yaml -->\n{FENCE}yaml\na: 1\n{FENCE}\n',
        "leaves the page's project",
    ),
    (
        "illustrative",
        f'<!-- doctest: illustrative reason="needs Docker" save-as=x.sh -->\n{FENCE}bash\ndocker ps\n{FENCE}\n',
        "never saves it",
    ),
    (
        "other keys without a mode",
        f"<!-- doctest: save-as=x.sh timeout=5 -->\n{FENCE}bash\ntrue\n{FENCE}\n",
        "may only carry save-as",
    ),
    (
        "saved block without a language",
        f"<!-- doctest: save-as=x.txt -->\n{FENCE}\nhello\n{FENCE}\n",
        "has no language",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected",
    SAVE_AS_MARKER_DEFECTS,
    ids=[c[0] for c in SAVE_AS_MARKER_DEFECTS],
)
def test_save_as_marker_check_can_fail(fixture_root, case, text, expected):
    page = _write(fixture_root, "docs/page.md", text)
    _assert_reports(dc.check_markers([page], fixture_root), expected)


GREETING = f"""<!-- doctest: save-as=my_plugins/greeting.py -->
{FENCE}python
def hello():
    return "hi"
{FENCE}

"""

SAVE_AS_PYTHON_DEFECTS = [
    (
        "module the page does not save",
        f"{FENCE}python\nfrom my_plugins.greeting import hello\n{FENCE}\n",
        "from my_plugins.greeting import ...: no such module",
        2,
    ),
    (
        "name the saved module lacks",
        GREETING + f"{FENCE}python\nfrom my_plugins.greeting import goodbye\n{FENCE}\n",
        "my_plugins.greeting has no name goodbye",
        8,
    ),
    (
        "name a package without __init__ lacks",
        GREETING + f"{FENCE}python\nfrom my_plugins import hello\n{FENCE}\n",
        "my_plugins has no name hello",
        8,
    ),
    (
        "submodule the page does not save",
        GREETING + f"{FENCE}python\nimport my_plugins.farewell\n{FENCE}\n",
        "import my_plugins.farewell: no such module",
        8,
    ),
    (
        "relative import of a sibling the page does not save",
        f"<!-- doctest: save-as=my_plugins/__init__.py -->\n{FENCE}python\nfrom .scanner import MyScanner\n{FENCE}\n",
        "from my_plugins.scanner import ...: no such module",
        3,
    ),
    (
        "relative import above the package",
        f"<!-- doctest: save-as=my_plugins/scanner.py -->\n{FENCE}python\nfrom .. import base\n{FENCE}\n",
        "goes above the top-level package my_plugins",
        3,
    ),
    (
        "relative import in a top-level module",
        f"<!-- doctest: save-as=top.py -->\n{FENCE}python\nfrom . import sibling\n{FENCE}\n",
        "a relative import cannot run outside a package",
        3,
    ),
    (
        "saved where it cannot be imported",
        (
            f"<!-- doctest: save-as=.ash/greeting.py -->\n{FENCE}python\nx = 1\n{FENCE}\n\n"
            f"{FENCE}python\nimport greeting\n{FENCE}\n"
        ),
        "import greeting: no such module",
        7,
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected,line",
    SAVE_AS_PYTHON_DEFECTS,
    ids=[c[0] for c in SAVE_AS_PYTHON_DEFECTS],
)
def test_save_as_python_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_python_blocks([page], tmp_path), expected, line)


@pytest.mark.unit
def test_a_saved_module_with_run_time_names_accepts_any_import(tmp_path):
    """A module __getattr__ or a star import can define any name, so none is refused."""
    page = _write(
        tmp_path,
        "docs/page.md",
        f"""<!-- doctest: save-as=lazy.py -->
{FENCE}python
def __getattr__(name):
    return name
{FENCE}

<!-- doctest: save-as=star.py -->
{FENCE}python
from json import *
{FENCE}

{FENCE}python
from lazy import anything
from star import dumps
{FENCE}
""",
    )
    assert dc.check_python_blocks([page], tmp_path) == []


@pytest.mark.unit
def test_a_saved_config_block_is_still_validated(tmp_path):
    page = _write(
        tmp_path,
        "docs/page.md",
        f"<!-- doctest: save-as=.ash/.ash.yaml -->\n{FENCE}yaml\nproject_name: x\n"
        f"fail_on_findngs: true\n{FENCE}\n",
    )
    _assert_reports(
        dc.check_config_blocks([page], tmp_path),
        "fail_on_findngs is not a field of AshConfig",
    )


@pytest.mark.unit
def test_save_as_maps_paths_to_modules():
    assert dc.saved_module("my_plugins/scanner.py") == (
        "my_plugins.scanner",
        "my_plugins",
    )
    assert dc.saved_module("my_plugins/__init__.py") == ("my_plugins", "my_plugins")
    assert dc.saved_module("./top.py") == ("top", "")
    for not_a_module in (
        "notes.txt",
        ".ash/x.py",
        "../x.py",
        "/x.py",
        "my-plugins/x.py",
    ):
        assert dc.saved_module(not_a_module) is None, not_a_module


# ---------------------------------------------------------------------------
# A synthetic site: links, navigation, redirects, build settings
# ---------------------------------------------------------------------------

MKDOCS = """site_name: test
site_url: https://example.github.io/project
docs_dir: docs/content
strict: true
hooks:
  - docs/hooks/redirects.py
  - docs/hooks/install_refs.py
not_in_nav: |
  hidden.md
validation:
  nav:
    omitted_files: warn
    not_found: warn
    absolute_links: warn
  links:
    not_found: warn
    absolute_links: warn
    unrecognized_links: warn
    anchors: warn
plugins:
  - mike:
      alias_type: copy
      canonical_version: latest
  - privacy
  - awesome-nav
extra:
  version:
    provider: mike
    default: latest
  docs_version: !ENV [MIKE_DOCS_VERSION, ""]
markdown_extensions:
  - admonition
  - pymdownx.superfences
"""

#: The required CI workflow's docs job (dc.DOCS_BUILD_WORKFLOW).
WORKFLOW = """jobs:
  build:
    steps:
      - run: uv run mkdocs build --clean --strict
      - run: uv run python scripts/docs_versions.py check
"""

#: The docs workflow, which only deploys (dc.DOCS_WORKFLOW).
DEPLOY_WORKFLOW = """jobs:
  deploy:
    steps:
      - run: uv run python scripts/docs_versions.py deploy --ref "$GITHUB_REF" --push
"""


def _site(
    tmp_path: Path,
    pages: dict[str, str],
    *,
    nav: str | None = None,
    redirects: str = "redirects: {}\n",
    mkdocs: str = MKDOCS,
    workflow: str | None = WORKFLOW,
    deploy_workflow: str | None = DEPLOY_WORKFLOW,
    versions_script: bool = True,
) -> Path:
    root = _git_root(tmp_path / "repo")
    _write(root, "mkdocs.yml", mkdocs)
    _write(root, dc.REDIRECT_HOOK, "# hook\n")
    _write(root, dc.INSTALL_REFS_HOOK, "# hook\n")
    _write(root, dc.REDIRECTS_FILE, redirects)
    if workflow is not None:
        _write(root, dc.DOCS_BUILD_WORKFLOW, workflow)
    if deploy_workflow is not None:
        _write(root, dc.DOCS_WORKFLOW, deploy_workflow)
    if versions_script:
        _write(root, dc.DOCS_VERSIONS_SCRIPT, "# script\n")
    _write(root, "README.md", "# Project\n\n## Getting started\n")
    for rel, text in pages.items():
        _write(root, rel, text)
    if nav is None:
        nav = "nav:\n" + "".join(
            f"  - {Path(rel).relative_to('docs/content').as_posix()}\n"
            for rel in pages
            if rel.startswith("docs/content/")
            and rel.endswith(".md")
            and not rel.endswith("hidden.md")
        )
    _write(root, f"docs/content/{dc.NAV_FILE_NAME}", nav)
    return root


CLEAN_PAGES = {
    "docs/content/index.md": (
        "# Home\n\n## Local heading\n\nSee [b](b.md), [b's second section](b.md#section-two), "
        "[here](#local-heading), [c](sub/c.md), ![logo](img/logo.png), "
        "[readme](https://github.com/awslabs/automated-security-helper/blob/main/README.md#getting-started), "
        "[a site page](https://example.github.io/project/b/), "
        "[a versioned one](https://example.github.io/project/latest/b/#section-two) "
        "and <https://example.com>.\n"
    ),
    "docs/content/b.md": '# B\n\n## Section two\n\n<a id="custom-anchor"></a>\n',
    "docs/content/sub/c.md": "# C\n\nBack to [b](../b.md#custom-anchor).\n",
    "docs/content/hidden.md": "# Deliberately unlisted\n",
    "docs/content/img/logo.png": "png",
    "CONTRIBUTING.md": "# Contributing\n\nSee [the readme](README.md#getting-started) and [issues](../../issues).\n",
}

LINK_DEFECTS = [
    (
        "missing page",
        "docs/content/index.md",
        "# Home\n\n[gone](nope.md)\n",
        "nope.md does not exist",
        3,
    ),
    (
        "missing anchor",
        "docs/content/index.md",
        "# Home\n\n[b](b.md#no-such-section)\n",
        "has no heading or anchor '#no-such-section'",
        3,
    ),
    (
        "missing local anchor",
        "docs/content/index.md",
        "# Home\n\n[x](#nowhere)\n",
        "this page has no heading or anchor",
        3,
    ),
    (
        "outside docs_dir",
        "docs/content/index.md",
        "# Home\n\n[readme](../../README.md)\n",
        "mkdocs cannot serve",
        3,
    ),
    (
        "absolute link",
        "docs/content/index.md",
        "# Home\n\n[b](/b.md)\n",
        "absolute links break",
        3,
    ),
    (
        "directory link",
        "docs/content/index.md",
        "# Home\n\n[sub](sub/)\n",
        "links to a directory",
        3,
    ),
    (
        "repository blob",
        "docs/content/index.md",
        "# Home\n\n[x](https://github.com/awslabs/automated-security-helper/blob/main/NOPE.md)\n",
        "NOPE.md does not exist in this repository",
        3,
    ),
    (
        "site url",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/nowhere/)\n",
        "no page on the site serves",
        3,
    ),
    (
        "versioned site url",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/latest/nowhere/)\n",
        "no page on the site serves",
        3,
    ),
    (
        "versioned site anchor",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/3.7.0/b/#no-such-section)\n",
        "has no anchor '#no-such-section'",
        3,
    ),
    (
        "a major version is not a published version",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/3/b/)\n",
        "no page on the site serves",
        3,
    ),
    (
        "a two-part version is not a published version",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/3.7/b/)\n",
        "no page on the site serves",
        3,
    ),
    (
        "a tag name is not a published version",
        "docs/content/index.md",
        "# Home\n\n[x](https://example.github.io/project/v3.7.0/b/)\n",
        "no page on the site serves",
        3,
    ),
    (
        "github anchor",
        "CONTRIBUTING.md",
        "# Contributing\n\n[x](README.md#not-a-heading)\n",
        "has no heading or anchor '#not-a-heading'",
        3,
    ),
    (
        "outside the repository",
        "CONTRIBUTING.md",
        "# Contributing\n\n[x](../../../elsewhere.md)\n",
        "points outside the repository",
        3,
    ),
]


@pytest.mark.integration
def test_a_site_url_may_name_every_version_a_deploy_publishes(tmp_path):
    """The control for the version defects above: `latest`, `main` and a release."""
    pages = dict(CLEAN_PAGES)
    pages["docs/content/index.md"] = "# Home\n\n" + "".join(
        f"[{version}](https://example.github.io/project/{version}/b/#section-two)\n"
        for version in ("latest", "main", "0.0.1", "3.7.0")
    )
    root = _site(tmp_path, pages)
    assert dc.check_links([root / "docs/content/index.md"], root) == []


@pytest.mark.integration
def test_a_site_url_is_percent_decoded_once(tmp_path):
    """`%2541` names a page called `%41`. Decoded twice it would name `A` instead."""
    pages = dict(CLEAN_PAGES)
    pages["docs/content/odd%41.md"] = "# Odd\n"
    pages["docs/content/index.md"] = (
        "# Home\n\n[odd](https://example.github.io/project/latest/odd%2541/)\n"
    )
    root = _site(tmp_path, pages)
    assert dc.check_links([root / "docs/content/index.md"], root) == []
    pages["docs/content/index.md"] = (
        "# Home\n\n[a](https://example.github.io/project/latest/oddA/)\n"
    )
    root = _site(tmp_path / "decoded-twice", pages)
    _assert_reports(
        dc.check_links([root / "docs/content/index.md"], root),
        "no page on the site serves",
    )


@pytest.mark.integration
def test_links_check_passes_every_valid_form(tmp_path):
    root = _site(tmp_path, CLEAN_PAGES)
    files = [root / rel for rel in CLEAN_PAGES if rel.endswith(".md")] + [
        root / "README.md"
    ]
    assert dc.check_links(files, root) == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,rel,text,expected,line", LINK_DEFECTS, ids=[c[0] for c in LINK_DEFECTS]
)
def test_links_check_can_fail(tmp_path, case, rel, text, expected, line):
    root = _site(tmp_path, {**CLEAN_PAGES, rel: text})
    _assert_reports(dc.check_links([root / rel], root), expected, line)


@pytest.mark.integration
def test_nav_check_passes_a_complete_nav_and_valid_redirects(tmp_path):
    root = _site(
        tmp_path, CLEAN_PAGES, redirects="redirects:\n  old-b.md: b.md#section-two\n"
    )
    assert dc.check_nav(root) == []


NAV_DEFECTS = [
    (
        "orphan page",
        {"docs/content/orphan.md": "# Orphan\n"},
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n",
        "redirects: {}\n",
        "no reader can reach it",
    ),
    (
        "missing nav entry",
        {},
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n  - gone.md\n",
        "redirects: {}\n",
        "The nav item 'gone.md' doesn't match any files or directories",
    ),
    (
        "titled entry naming no page",
        {},
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n  - Gone: gone.md\n",
        "redirects: {}\n",
        "nav entry 'Gone: gone.md' names no page",
    ),
    (
        "glob matching nothing",
        {},
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n  - plugins/*.md\n",
        "redirects: {}\n",
        "The nav item 'plugins/*.md' doesn't match any files or directories",
    ),
    (
        "glob of pages already listed",
        {},
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n  - sub/*.md\n",
        "redirects: {}\n",
        "The nav item 'sub/*.md' doesn't match any files or directories",
    ),
    (
        "page a glob leaves out",
        {
            "docs/content/plugins/alpha.md": "# A\n",
            "docs/content/plugins/beta.md": "# B\n",
        },
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n  - plugins/a*.md\n",
        "redirects: {}\n",
        "no reader can reach it",
    ),
    (
        "redirect from a page",
        {},
        None,
        "redirects:\n  b.md: index.md\n",
        "b.md still exists",
    ),
    (
        "redirect to nothing",
        {},
        None,
        "redirects:\n  old.md: gone.md\n",
        "which is not a page",
    ),
    (
        "redirect to a missing anchor",
        {},
        None,
        "redirects:\n  old.md: b.md#nope\n",
        "has no anchor '#nope'",
    ),
    (
        "redirect chain",
        {},
        None,
        "redirects:\n  old.md: older.md\n  older.md: b.md\n",
        "itself redirected",
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,extra,nav,redirects,expected", NAV_DEFECTS, ids=[c[0] for c in NAV_DEFECTS]
)
def test_nav_check_can_fail(tmp_path, case, extra, nav, redirects, expected):
    root = _site(tmp_path, {**CLEAN_PAGES, **extra}, nav=nav, redirects=redirects)
    _assert_reports(dc.check_nav(root), expected)


@pytest.mark.integration
def test_nav_globs_expand_the_way_awesome_nav_does(tmp_path):
    """Globs, a glob entry with options, and a directory with its own .nav.yml."""
    pages = {
        **CLEAN_PAGES,
        "docs/content/plugins/builtin/one.md": "# One\n",
        "docs/content/plugins/builtin/two.md": "# Two\n",
        "docs/content/plugins/community/three.md": "# Three\n",
        "docs/content/guides/deep/four.md": "# Four\n",
        "docs/content/section/first.md": "# First\n",
        "docs/content/section/second.md": "# Second\n",
    }
    nav = (
        "nav:\n  - index.md\n  - b.md\n  - sub/c.md\n"
        "  - Built in: plugins/builtin\n"
        "  - plugins/community/*.md\n"
        # A glob entry with options. With no other key, {glob: x} is a titled link to
        # x in awesome-nav, which the titled-entry case above reports.
        "  - glob: 'guides/**/*.md'\n    flatten_single_child_sections: true\n"
        "  - section\n"
    )
    root = _site(tmp_path, pages, nav=nav)
    _write(root, "docs/content/section/.nav.yml", "nav:\n  - second.md\n  - first.md\n")
    assert dc.check_nav(root) == []

    # The directory's own .nav.yml decides what of it is reachable.
    _write(root, "docs/content/section/.nav.yml", "nav:\n  - second.md\n")
    _assert_reports(dc.check_nav(root), "no reader can reach it")


@pytest.mark.integration
def test_site_build_check_passes_a_strict_offline_config(tmp_path):
    assert dc.check_site_build(_site(tmp_path, CLEAN_PAGES)) == []


SITE_DEFECTS = [
    (
        "validation relaxed",
        MKDOCS.replace("    anchors: warn\n", "    anchors: info\n"),
        WORKFLOW,
        "validation.links.anchors is 'info'",
    ),
    (
        "validation dropped",
        MKDOCS.replace("    omitted_files: warn\n", ""),
        WORKFLOW,
        "validation.nav.omitted_files is None",
    ),
    ("not strict", MKDOCS, WORKFLOW.replace(" --strict", ""), "does not pass --strict"),
    (
        "no build",
        MKDOCS,
        "jobs:\n  build:\n    steps:\n      - run: echo nothing\n",
        "no step runs mkdocs build",
    ),
    (
        "hook unregistered",
        MKDOCS.replace("  - docs/hooks/redirects.py\n", ""),
        WORKFLOW,
        "hooks does not list docs/hooks/redirects.py",
    ),
    (
        "install refs hook unregistered",
        MKDOCS.replace("  - docs/hooks/install_refs.py\n", ""),
        WORKFLOW,
        "hooks does not list docs/hooks/install_refs.py",
    ),
    (
        "privacy dropped",
        MKDOCS.replace("  - privacy\n", ""),
        WORKFLOW,
        "privacy plugin is not configured",
    ),
    (
        "external script fetched",
        MKDOCS + "extra_javascript:\n  - https://cdn.example.com/lib/x.js\n",
        WORKFLOW,
        "cdn.example.com/lib/x.js is an external asset the privacy plugin downloads",
    ),
    (
        "theme fonts fetched",
        MKDOCS + "theme:\n  name: material\n",
        WORKFLOW,
        "theme.font",
    ),
    (
        "mermaid fetched",
        MKDOCS.replace(
            "  - pymdownx.superfences\n",
            "  - pymdownx.superfences:\n      custom_fences:\n        - name: mermaid\n"
            "          class: mermaid\n",
        )
        + "theme:\n  name: material\n  font: false\n",
        WORKFLOW,
        "unpkg.com/mermaid",
    ),
    (
        "emoji from a CDN",
        MKDOCS
        + "  - pymdownx.emoji:\n      emoji_generator: !!python/name:pymdownx.emoji.to_svg\n",
        WORKFLOW,
        "emoji_generator",
    ),
    (
        "build failure ignored with ||",
        MKDOCS,
        WORKFLOW.replace("--strict", "--strict || true"),
        "cannot fail the step",
    ),
    (
        "build failure ignored with ;",
        MKDOCS,
        WORKFLOW.replace("--strict", "--strict; true"),
        "cannot fail the step",
    ),
    (
        "build piped",
        MKDOCS,
        WORKFLOW.replace("--strict", "--strict | tee build.log"),
        "cannot fail the step",
    ),
    (
        "build in the background",
        MKDOCS,
        WORKFLOW.replace("--strict", "--strict &"),
        "cannot fail the step",
    ),
    (
        "errexit turned off",
        MKDOCS,
        WORKFLOW.replace(
            "      - run: uv run", "      - run: |\n          set +e\n          uv run"
        ),
        "set +e",
    ),
    (
        "step may fail",
        MKDOCS,
        WORKFLOW.replace(
            "      - run:", "      - continue-on-error: true\n        run:"
        ),
        "continue-on-error",
    ),
    (
        "job may fail",
        MKDOCS,
        WORKFLOW.replace("  build:\n", "  build:\n    continue-on-error: true\n"),
        "continue-on-error",
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,mkdocs,workflow,expected", SITE_DEFECTS, ids=[c[0] for c in SITE_DEFECTS]
)
def test_site_build_check_can_fail(tmp_path, case, mkdocs, workflow, expected):
    _assert_reports(
        dc.check_site_build(
            _site(tmp_path, CLEAN_PAGES, mkdocs=mkdocs, workflow=workflow)
        ),
        expected,
    )


VERSIONING_DEFECTS = [
    (
        "strict only on the command line",
        {"mkdocs": MKDOCS.replace("strict: true\n", "")},
        "strict is None; the versioned site needs True",
    ),
    (
        "no version selector",
        {"mkdocs": MKDOCS.replace("    provider: mike\n", "")},
        "extra.version.provider is None",
    ),
    (
        "outdated default is not latest",
        {"mkdocs": MKDOCS.replace("    default: latest\n", "    default: stable\n")},
        "extra.version.default is 'stable'",
    ),
    (
        "mike plugin not listed",
        {
            "mkdocs": MKDOCS.replace(
                "  - mike:\n      alias_type: copy\n      canonical_version: latest\n",
                "",
            )
        },
        "the mike plugin is not listed",
    ),
    (
        "aliases are symbolic links",
        {"mkdocs": MKDOCS.replace("alias_type: copy", "alias_type: symlink")},
        "plugins.mike.alias_type is 'symlink'",
    ),
    (
        "no canonical version",
        {"mkdocs": MKDOCS.replace("      canonical_version: latest\n", "")},
        "plugins.mike.canonical_version is None",
    ),
    (
        "gh-deploy is back",
        {
            "deploy_workflow": DEPLOY_WORKFLOW.replace(
                'uv run python scripts/docs_versions.py deploy --ref "$GITHUB_REF" --push',
                "uv run mkdocs gh-deploy --clean --force",
            )
        },
        "replaces the whole gh-pages branch",
    ),
    (
        "gh-deploy in the build workflow",
        {"workflow": WORKFLOW + "      - run: uv run mkdocs gh-deploy --force\n"},
        "replaces the whole gh-pages branch",
    ),
    (
        "nothing deploys",
        {
            "deploy_workflow": DEPLOY_WORKFLOW.replace(
                'uv run python scripts/docs_versions.py deploy --ref "$GITHUB_REF" --push',
                "echo nothing",
            )
        },
        "scripts/docs_versions.py deploy is not run",
    ),
    (
        "the build moved back out of the required workflow",
        {
            "workflow": "jobs:\n  lint:\n    steps:\n      - run: echo lint\n",
            "deploy_workflow": DEPLOY_WORKFLOW + WORKFLOW.replace("jobs:\n", ""),
        },
        "no step runs mkdocs build",
    ),
    (
        "the versions check moved back out of the required workflow",
        {
            "workflow": WORKFLOW.replace(
                "      - run: uv run python scripts/docs_versions.py check\n", ""
            ),
            "deploy_workflow": DEPLOY_WORKFLOW
            + "      - run: uv run python scripts/docs_versions.py check\n",
        },
        "scripts/docs_versions.py check is not run",
    ),
    (
        "the required workflow is gone",
        {"workflow": None},
        "the workflow that builds the docs does not exist",
    ),
    (
        "the docs workflow is gone",
        {"deploy_workflow": None},
        "the docs workflow does not exist",
    ),
    (
        "the versioned site is not checked",
        {
            "workflow": WORKFLOW.replace(
                "      - run: uv run python scripts/docs_versions.py check\n", ""
            )
        },
        "scripts/docs_versions.py check is not run",
    ),
    (
        "the versions script is gone",
        {"versions_script": False},
        "the docs versions script does not exist",
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,site,expected", VERSIONING_DEFECTS, ids=[c[0] for c in VERSIONING_DEFECTS]
)
def test_site_build_check_reports_versioning_defects(tmp_path, case, site, expected):
    _assert_reports(dc.check_site_build(_site(tmp_path, CLEAN_PAGES, **site)), expected)


@pytest.mark.integration
def test_an_external_image_in_a_page_must_be_left_external(tmp_path):
    """The privacy plugin downloads every external image a page shows, at build time.
    One that no assets_exclude pattern covers needs the network to build."""
    pages = dict(CLEAN_PAGES)
    pages["docs/content/b.md"] = pages["docs/content/b.md"] + (
        "\n![build](https://img.shields.io/badge/build-passing-green.svg)\n"
        '\n<img src="https://example.com/logo.png" alt="logo">\n'
    )
    findings = dc.check_site_build(_site(tmp_path, pages))
    _assert_reports(findings, "img.shields.io/badge/build-passing-green.svg")
    _assert_reports(findings, "example.com/logo.png")
    excluded = MKDOCS.replace(
        "  - privacy\n",
        "  - privacy:\n      assets_exclude:\n        - 'img.shields.io/*'\n"
        "        - 'example.com/*'\n",
    )
    assert dc.check_site_build(_site(tmp_path / "b", pages, mkdocs=excluded)) == []


@pytest.mark.integration
def test_an_offline_safe_privacy_setup_passes(tmp_path):
    """Controls: excluded assets, no fonts, Material's inline-SVG emoji, and a build
    command that is the step's last word all pass."""
    mkdocs = (
        MKDOCS.replace(
            "  - privacy\n",
            "  - privacy:\n      assets_exclude:\n        - 'unpkg.com/mermaid@*'\n"
            "        - 'cdn.example.com/*'\n",
        ).replace(
            "  - pymdownx.superfences\n",
            "  - pymdownx.superfences:\n      custom_fences:\n        - name: mermaid\n"
            "          class: mermaid\n"
            "  - pymdownx.emoji:\n"
            "      emoji_generator: !!python/name:material.extensions.emoji.to_svg\n",
        )
        + "theme:\n  name: material\n  font: false\n"
        + "extra_javascript:\n  - https://cdn.example.com/lib/x.js\n"
    )
    workflow = WORKFLOW.replace(
        "      - run: uv run mkdocs build --clean --strict\n",
        "      - run: |\n          uv sync\n          uv run mkdocs build --clean --strict\n",
    )
    assert (
        dc.check_site_build(
            _site(tmp_path, CLEAN_PAGES, mkdocs=mkdocs, workflow=workflow)
        )
        == []
    )


@pytest.mark.integration
def test_the_real_mkdocs_config_is_strict_and_offline():
    """The committed mkdocs.yml and docs workflows pass the build-settings check."""
    assert dc.check_site_build(REPO_ROOT) == []


# ---------------------------------------------------------------------------
# The release placeholder in templates
# ---------------------------------------------------------------------------

# Assembled, so this file holds no install reference for the tree walk in
# test_agent_plugin_ash_version.py to read as a pin.
_REPO_URL = "https://github.com/awslabs/automated-security-" + "helper"
# The check reads only the templates of the manager's target_files, so the planted
# template sits at one of those targets.
_TEMPLATE = "docs/content/docs/advanced-usage.md.template"

# Every place the release placeholder is allowed: a text sample, a sentence that is
# not a command, and a table row, next to an install command that uses {{VERSION}}.
CLEAN_RELEASE_TEMPLATE = (
    "# Install\n\n"
    f"{FENCE}bash\n"
    "uv tool install 'automated-security-helper @ git+"
    + _REPO_URL
    + ".git@v{{VERSION}}'\n"
    "ash --version\n"
    f"{FENCE}\n\n"
    f"{FENCE}text\n"
    "awslabs/automated-security-helper v{{RELEASE}}\n"
    f"{FENCE}\n\n"
    "Each file pins ASH v{{RELEASE}}, the release these files were generated for.\n\n"
    "| Reference | What you get |\n"
    "|---|---|\n"
    "| `@v{{RELEASE}}` | That release. |\n"
)


def _release_site(tmp_path: Path, template: str) -> Path:
    root = tmp_path / "repo"
    _write(
        root,
        dc.TEMPLATE_MANAGER,
        (REPO_ROOT / dc.TEMPLATE_MANAGER).read_text(encoding="utf-8"),
    )
    _write(root, _TEMPLATE, template)
    return root


@pytest.mark.unit
def test_release_placeholder_check_passes_a_release_outside_commands(tmp_path):
    assert (
        dc.check_release_placeholders(_release_site(tmp_path, CLEAN_RELEASE_TEMPLATE))
        == []
    )


RELEASE_DEFECTS = [
    (
        "git URL",
        f"{FENCE}bash\npip install 'automated-security-helper @ git+"
        + _REPO_URL
        + f".git@v{{{{RELEASE}}}}'\n{FENCE}\n",
    ),
    ("uses: in prose", "Pin `uses: ...@v{{RELEASE}}` to a commit.\n"),
    (
        "--branch",
        f"{FENCE}bash\ngit clone --branch v{{{{RELEASE}}}} {_REPO_URL}\n{FENCE}\n",
    ),
    (
        "rev:",
        f"{FENCE}yaml\nrepos:\n  - repo: {_REPO_URL}\n    rev: v{{{{RELEASE}}}}\n{FENCE}\n",
    ),
    (
        "ls-remote refs",
        f"{FENCE}bash\ngit ls-remote {_REPO_URL} refs/tags/v{{{{RELEASE}}}}\n{FENCE}\n",
    ),
    (
        "flake ref",
        (
            f"{FENCE}bash\nexport ASH_NIX_FLAKE_REF=github:awslabs/automated-security-"
            f"helper/v{{{{RELEASE}}}}\n{FENCE}\n"
        ),
    ),
    (
        "--ash-revision-to-install",
        f"{FENCE}bash\nash build-image --ash-revision-to-install v{{{{RELEASE}}}}\n{FENCE}\n",
    ),
    (
        "ash-version:",
        f"{FENCE}yaml\nwith:\n  ash-version: v{{{{RELEASE}}}}\n{FENCE}\n",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,addition", RELEASE_DEFECTS, ids=[c[0] for c in RELEASE_DEFECTS]
)
def test_release_placeholder_check_can_fail(tmp_path, case, addition):
    template = CLEAN_RELEASE_TEMPLATE + "\n" + addition
    line = next(
        number
        for number, text in enumerate(template.splitlines(), start=1)
        if "{{RELEASE}}" in text and number > CLEAN_RELEASE_TEMPLATE.count("\n")
    )
    findings = dc.check_release_placeholders(_release_site(tmp_path, template))
    _assert_reports(findings, "is the ref of an install command", line=line)
    assert len(findings) == 1, _messages(findings)


@pytest.mark.unit
def test_release_placeholder_check_reports_checking_nothing(tmp_path):
    root = _release_site(tmp_path, CLEAN_RELEASE_TEMPLATE)
    (root / _TEMPLATE).unlink()
    _assert_reports(dc.check_release_placeholders(root), "nothing was checked")


@pytest.mark.unit
def test_the_real_templates_keep_release_numbers_out_of_install_commands():
    assert dc.check_release_placeholders(REPO_ROOT) == []


# ---------------------------------------------------------------------------
# Option tables and config paths in prose
# ---------------------------------------------------------------------------

CLEAN_OPTIONS = f"""# Options

Options, under `scanners.bandit.options`:

<!-- doctest: options of=scanners.bandit -->
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| <a id="scanners.bandit.options.confidence_level"></a>`confidence_level` | string | `all` | x |
| `ignore_nosec` | boolean | `false` | x |
| `excluded_paths` | list | `[]` | x |
| `severity_threshold` | string | `null` | x |
| `tool_version` | string | `">=1.7.8,<2.0.0"` | x |
| `scan_timeout` | number | `1800` | x |

<!-- doctest: options of=global_settings -->
| Key | Default |
|-----|---------|
| `severity_threshold` | from `ASH_DEFAULT_SEVERITY_LEVEL`, else `MEDIUM` |
| `suppressions` | `[]` |
| `mcp` | see the section |

<!-- doctest: options of=global_settings.suppressions -->
| Field | Default |
|-------|---------|
| `reason` | required |
| `rule_id` | None |

<!-- doctest: options of=cli.mcp -->
| Option | Default |
|--------|---------|
| `--port` | `8000` |
| `--transport` | `stdio` |
| `--debug` | off |
| `--auth-header-name` | not set |

<!-- doctest: options of=workspace-policy.workspace -->
| Key | Default |
|-----|---------|
| `suppressions` | `[]` |

| Variable | Default |
|----------|---------|
| `OCI_RUNNER` | `docker` |

| Scanner | Type |
|---------|------|
| bandit | SAST |

Set `scanners.bandit.options.severity_threshold`, `global_settings.suppressions[0].reason`,
`fail_on_findings`, `scanners.<name>.enabled`, `scanners.*.options.tool_version`,
`scanners.bandit.enabled=false`, `sandbox.mode: off` or `workspace.suppressions`, and read
`sandbox.md` and `reporters.csv`. A {FENCE}`scanners.cdk-nag.options.nag_packs`{FENCE} works too.
"""

OPTION_DEFECTS = [
    (
        "unmarked option table",
        "| Option | Default |\n|--------|---------|\n| `confidence_level` | `all` |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "unmarked table with a Default column",
        "| Name | Default |\n|------|---------|\n| `confidence_level` | `all` |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "nonexistent option",
        "<!-- doctest: options of=scanners.bandit -->\n| Option | Default |\n|---|---|\n| `severity_level` | `HIGH` |\n",
        "'severity_level' is not a key of scanners.bandit",
        4,
    ),
    (
        "wrong default",
        "<!-- doctest: options of=scanners.bandit -->\n| Option | Default |\n|---|---|\n| `confidence_level` | `high` |\n",
        "'confidence_level' default says `high`, but the default is",
        4,
    ),
    (
        "wrong boolean default",
        "<!-- doctest: options of=scanners.bandit -->\n| Option | Default |\n|---|---|\n| `ignore_nosec` | true |\n",
        "'ignore_nosec' default says true",
        4,
    ),
    (
        "required that is not",
        "<!-- doctest: options of=scanners.bandit -->\n| Option | Default |\n|---|---|\n| `ignore_nosec` | required |\n",
        "says required, but the default is",
        4,
    ),
    (
        "wrong CLI default",
        "<!-- doctest: options of=cli.mcp -->\n| Option | Default |\n|---|---|\n| `--port` | `9000` |\n",
        "'--port' default says `9000`",
        4,
    ),
    (
        "prose default",
        "<!-- doctest: options of=scanners.bandit -->\n| Option | Default |\n|---|---|\n| `confidence_level` | `all` or `high` |\n",
        "is not a value or a recognized phrase",
        4,
    ),
    (
        "unknown plugin",
        "<!-- doctest: options of=scanners.gosec -->\n| Option | Default |\n|---|---|\n| `x` | `1` |\n",
        "ships no scanner named 'gosec'",
        1,
    ),
    (
        "marker without of",
        "<!-- doctest: options -->\n| Option | Default |\n|---|---|\n| `x` | `1` |\n",
        "needs of=<section>",
        1,
    ),
    (
        "nonexistent dotted path",
        "Set `scanners.bandit.options.severity_level` to HIGH.\n",
        "BanditScannerConfigOptions has no key 'severity_level'",
        1,
    ),
    (
        "nonexistent top-level section key",
        "Set `global_settings.severity` to HIGH.\n",
        "AshConfigGlobalSettingsSection has no key 'severity'",
        1,
    ),
    (
        "path into an unknown scanner",
        "Set `scanners.gosec.enabled` to true.\n",
        "ships no scanner named 'gosec'",
        1,
    ),
]


@pytest.mark.integration
def test_option_tables_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_OPTIONS)
    assert dc.check_option_tables([page], tmp_path) == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,text,expected,line", OPTION_DEFECTS, ids=[c[0] for c in OPTION_DEFECTS]
)
def test_option_tables_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_option_tables([page], tmp_path), expected, line)


SECTION_CODE = {
    "pkg/__init__.py": "",
    "pkg/api.py": """from enum import Enum


class Mode(Enum):
    local = "local"
    container = "container"


def scan(source_dir=None, *, offline=False, mode=Mode.local, name="t3.medium",
         retries=3, tags=("a",), **kwargs):
    pass


class Stack:
    def __init__(self, scope, vpc_cidr: str = "10.0.0.0/16"):
        pass

    def deploy(self, wait=True):
        pass
""",
    "Dockerfile": """ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}
ARG OFFLINE=NO
ARG BASE_IMAGE
ARG UNSET
""",
    "deploy/templates/A.template.json": json.dumps(
        {
            "Parameters": {
                "Version": {"Type": "String", "Default": "v1"},
                "Repo": {"Type": "String"},
                "Flag": {"Type": "String", "Default": "true"},
                "Empty": {"Type": "String", "Default": ""},
                "Diff": {"Type": "String", "Default": "y"},
            }
        }
    ),
    ".github/workflows/scan.yml": """name: scan
on:
  workflow_call:
    inputs:
      ash-version: {type: string, default: main}
      verbose: {type: boolean, default: true}
      config: {type: string, default: ""}
      token: {type: string, required: true}
  workflow_dispatch:
    inputs:
      ash-version: {type: string, default: main}
jobs: {}
""",
    "src/step.ts": """export interface StepProps {
  /** The file set to scan. */
  readonly input: string;

  /**
   * How many shards.
   *
   * @default 1
   */
  readonly shardCount?: number;

  /** @default InstallMode.PIP */
  readonly installMode?: InstallMode;

  /** @default '.ash/ash_output' */
  readonly outputDirectory?: string;

  /** @default - a pinned release */
  readonly version?: string;

  readonly extra?: string[];
}
""",
    "actions/setup/action.yml": """name: setup
inputs:
  python-version: {default: "3.12"}
  install-ash: {default: "false"}
runs:
  using: composite
  steps: []
""",
    "deploy/templates/B.template.yaml": """Parameters:
  Version: {Type: String, Default: v1}
  Schedule: {Type: String, Default: rate(1 day)}
  Diff: {Type: String, Default: x}
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref Version
""",
}


@pytest.fixture
def section_code(tmp_path):
    """A code tree with a Python module, a Dockerfile and two CloudFormation templates."""
    code = _git_root(tmp_path / "code")
    for rel, text in SECTION_CODE.items():
        _write(code, rel, text)
    return code


CLEAN_SECTIONS = """# Sections read from code

<!-- doctest: options of=mcp.run_ash_scan -->
| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `source_dir` | string \\| null | not set | x |
| `severity_threshold` | string \\| null | `null` | x |
| `config_path` | string \\| null | `null` | x |
| `clean_output` | boolean | `true` | x |

<!-- doctest: options of=mcp.resolve_ash_workspace -->
| Param | Default |
|-------|---------|
| `workspace_file` | *required* |
| `allow_missing_projects` | `false` |

<!-- doctest: options of=mcp.get_scan_progress -->
| Param | Type | Notes |
|-------|------|-------|
| `scan_id` | string | x |

<!-- doctest: options of=python.pkg.api.scan -->
| Parameter | Default | Notes |
|-----------|---------|-------|
| `source_dir` | `None` | |
| `mode` | `Mode.local` | |
| `name` | `t3.medium` | |
| `retries`, `offline` | `3`, `False` | |
| `tags` | `("a",)` | |

<!-- doctest: options of=python.pkg.api.Stack -->
| Parameter | Default |
|-----------|---------|
| `scope` | required |
| `vpc_cidr` | `"10.0.0.0/16"` |

<!-- doctest: options of=python.pkg.api.Stack.deploy -->
| Parameter | Default |
|-----------|---------|
| `wait` | `True` |

<!-- doctest: options of=dockerfile -->
| Argument | Default |
|----------|---------|
| `BASE_IMAGE` | `python:3.12-slim` |
| `OFFLINE` | `NO` |
| `UNSET` | not set |

<!-- doctest: options of=cloudformation:deploy/templates -->
| Parameter | Default |
|-----------|---------|
| `Version` | `v1` |
| `Repo` | required |
| `Flag` | `true` |
| `Empty` | empty |
| `Schedule` | `rate(1 day)` |
| `Diff` | differs between the templates |

<!-- doctest: options of=github-inputs:.github/workflows/scan.yml -->
| Input | Defaults to | Effect |
|-------|-------------|--------|
| `ash-version` | `main` | x |
| `verbose` | `true` | x |
| `config` | empty | x |
| `token` | required | x |

<!-- doctest: options of=github-inputs:actions/setup -->
| Input | If not set |
|-------|------------|
| `python-version` | `3.12` |
| `install-ash` | `false` |

<!-- doctest: options of=typescript:src/step.ts:StepProps -->
| Prop | Type | Default |
|------|------|---------|
| `input` | `string` | required |
| `shardCount` | `number` | `1` |
| `installMode` | `InstallMode` | `PIP` |
| `outputDirectory` | `string` | `.ash/ash_output` |
| `version` | `string` | a pinned release |
| `extra` | `string[]` | not set |

<!-- doctest: options of=cli.scan -->
| Option | Effect |
|--------|--------|
| `--build-target ci` | x |
"""


@pytest.mark.integration
def test_sections_read_from_code_pass_every_valid_form(tmp_path, section_code):
    page = _write(tmp_path, "docs/page.md", CLEAN_SECTIONS)
    assert dc.check_option_tables([page], tmp_path, section_code) == []


def _table(of: str, header: str, *rows: str) -> str:
    divider = "|" + "---|" * (header.count("|") - 1)
    lines = [f"<!-- doctest: options of={of} -->", header, divider, *rows]
    return "\n".join(lines) + "\n"


SECTION_DEFECTS = [
    (
        "unknown MCP tool",
        _table("mcp.run_scan", "| Param | Default |", "| `x` | `1` |"),
        "the MCP server has no tool run_scan; did you mean 'run_ash_scan'?",
        1,
    ),
    (
        "parameter the MCP tool lacks",
        _table("mcp.run_ash_scan", "| Param | Default |", "| `severity` | `1` |"),
        "'severity' is not a key of of=mcp.run_ash_scan",
        4,
    ),
    (
        "wrong MCP default",
        _table(
            "mcp.run_ash_scan", "| Param | Default |", "| `clean_output` | `false` |"
        ),
        "'clean_output' default says `false`, but the default is `true`",
        4,
    ),
    (
        "required MCP parameter given a default",
        _table(
            "mcp.resolve_ash_workspace",
            "| Param | Default |",
            "| `workspace_file` | `null` |",
        ),
        "but the key is required",
        4,
    ),
    (
        "MCP default in prose",
        _table(
            "mcp.run_ash_scan", "| Param | Default |", "| `source_dir` | current dir |"
        ),
        "'source_dir' default says current dir, but the default is `null`",
        4,
    ),
    (
        "unmarked param table",
        "| Param | Type | Notes |\n|---|---|---|\n| `scan_id` | string | x |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "wrong Python default",
        _table("python.pkg.api.scan", "| Parameter | Default |", "| `retries` | `5` |"),
        "'retries' default says `5`, but the default is `3`",
        4,
    ),
    (
        "wrong enum member",
        _table(
            "python.pkg.api.scan",
            "| Parameter | Default |",
            "| `mode` | `Mode.container` |",
        ),
        "'mode' default says `Mode.container`, but the default is `Mode.local`",
        4,
    ),
    (
        "None written as a string",
        _table(
            "python.pkg.api.scan",
            "| Parameter | Default |",
            '| `source_dir` | `"None"` |',
        ),
        "'source_dir' default says `\"None\"`, but the default is `None`",
        4,
    ),
    (
        "parameter the function lacks",
        _table(
            "python.pkg.api.scan", "| Parameter | Default |", "| `verbose` | `False` |"
        ),
        "'verbose' is not a key of of=python.pkg.api.scan",
        4,
    ),
    (
        "self is not a parameter",
        _table(
            "python.pkg.api.Stack.deploy",
            "| Parameter | Default |",
            "| `self` | required |",
        ),
        "'self' is not a key",
        4,
    ),
    (
        "keyword arguments are not parameters",
        _table(
            "python.pkg.api.scan", "| Parameter | Default |", "| `kwargs` | not set |"
        ),
        "'kwargs' is not a key",
        4,
    ),
    (
        "unknown function",
        _table("python.pkg.api.nope", "| Parameter | Default |", "| `x` | `1` |"),
        "pkg.api defines no function or class nope",
        1,
    ),
    (
        "module without a function",
        _table("python.pkg.api", "| Parameter | Default |", "| `x` | `1` |"),
        "names a module; add the function or class",
        1,
    ),
    (
        "unknown package",
        _table("python.nopkg.scan", "| Parameter | Default |", "| `x` | `1` |"),
        "no module nopkg.scan in the code tree",
        1,
    ),
    (
        "unknown submodule",
        _table("python.pkg.nothing.scan", "| Parameter | Default |", "| `x` | `1` |"),
        "pkg defines no function or class nothing, and there is no module pkg.nothing",
        1,
    ),
    (
        "a function has no methods",
        _table("python.pkg.api.scan.inner", "| Parameter | Default |", "| `x` | `1` |"),
        "scan is a function, so it has no inner",
        1,
    ),
    (
        "row of several keys, defaults swapped",
        _table(
            "python.pkg.api.scan",
            "| Parameter | Default |",
            "| `retries`, `offline` | `False`, `3` |",
        ),
        "'retries' default says `False`, but the default is `3`",
        4,
    ),
    (
        "row of several keys, one unknown",
        _table(
            "python.pkg.api.scan",
            "| Parameter | Default |",
            "| `retries`, `verbose` | `3` |",
        ),
        "'verbose' is not a key",
        4,
    ),
    (
        "wrong build argument default",
        _table(
            "dockerfile", "| Argument | Default |", "| `BASE_IMAGE` | `python:3.13` |"
        ),
        "'BASE_IMAGE' default says `python:3.13`, but the default is `python:3.12-slim`",
        4,
    ),
    (
        "build argument read as YAML",
        _table("dockerfile", "| Argument | Default |", "| `OFFLINE` | `false` |"),
        "'OFFLINE' default says `false`, but the default is `NO`",
        4,
    ),
    (
        "unknown build argument",
        _table("dockerfile", "| Argument | Default |", "| `NOPE` | `x` |"),
        "'NOPE' is not a key of of=dockerfile",
        4,
    ),
    (
        "wrong CloudFormation default",
        _table(
            "cloudformation:deploy/templates",
            "| Parameter | Default |",
            "| `Schedule` | `cron(0 6 * * ? *)` |",
        ),
        "'Schedule' default says `cron(0 6 * * ? *)`, but the default is `rate(1 day)`",
        4,
    ),
    (
        "required CloudFormation parameter given a default",
        _table(
            "cloudformation:deploy/templates",
            "| Parameter | Default |",
            "| `Repo` | empty |",
        ),
        "but the key is required",
        4,
    ),
    (
        "empty that is not",
        _table(
            "cloudformation:deploy/templates",
            "| Parameter | Default |",
            "| `Version` | empty |",
        ),
        "'Version' default says empty, but the default is `v1`",
        4,
    ),
    (
        "unknown CloudFormation parameter",
        _table(
            "cloudformation:deploy/templates",
            "| Parameter | Default |",
            "| `Region` | `x` |",
        ),
        "'Region' is not a key of of=cloudformation:deploy/templates (2 templates)",
        4,
    ),
    (
        "wrong workflow input default",
        _table(
            "github-inputs:.github/workflows/scan.yml",
            "| Input | Default |",
            "| `ash-version` | `v3` |",
        ),
        "'ash-version' default says `v3`, but the default is `main`",
        4,
    ),
    (
        "input the workflow lacks",
        _table(
            "github-inputs:.github/workflows/scan.yml",
            "| Input | Default |",
            "| `install-trivy` | `false` |",
        ),
        "'install-trivy' is not a key of of=github-inputs:.github/workflows/scan.yml",
        4,
    ),
    (
        "required workflow input given a default",
        _table(
            "github-inputs:.github/workflows/scan.yml",
            "| Input | Default |",
            "| `token` | empty |",
        ),
        "but the key is required",
        4,
    ),
    (
        "wrong action input default",
        _table(
            "github-inputs:actions/setup",
            "| Input | Default |",
            "| `install-ash` | `true` |",
        ),
        "'install-ash' default says `true`, but the default is `false`",
        4,
    ),
    (
        "path that is not an action or a workflow",
        _table("github-inputs:deploy", "| Input | Default |", "| `x` | `1` |"),
        "deploy is not an action or a workflow in the code tree",
        1,
    ),
    (
        "Default column under another name",
        _table(
            "github-inputs:.github/workflows/scan.yml",
            "| Input | If not passed |",
            "| `ash-version` | `v3` |",
        ),
        "'ash-version' default says `v3`",
        4,
    ),
    (
        "unmarked table whose Default column has another name",
        "| Input | Defaults to |\n|---|---|\n| `ash-version` | `main` |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "wrong TypeScript default",
        _table(
            "typescript:src/step.ts:StepProps",
            "| Prop | Default |",
            "| `shardCount` | `2` |",
        ),
        "'shardCount' default says `2`, but the default is `1`",
        4,
    ),
    (
        "wrong enum member by its short name",
        _table(
            "typescript:src/step.ts:StepProps",
            "| Prop | Default |",
            "| `installMode` | `UVX` |",
        ),
        "'installMode' default says `UVX`, but the default is `InstallMode.PIP`",
        4,
    ),
    (
        "required TypeScript property given a default",
        _table(
            "typescript:src/step.ts:StepProps",
            "| Prop | Default |",
            "| `input` | `x` |",
        ),
        "but the key is required",
        4,
    ),
    (
        "property the interface lacks",
        _table(
            "typescript:src/step.ts:StepProps",
            "| Prop | Default |",
            "| `region` | `x` |",
        ),
        "'region' is not a key of of=typescript:src/step.ts:StepProps",
        4,
    ),
    (
        "unknown interface",
        _table("typescript:src/step.ts:Nope", "| Prop | Default |", "| `x` | `1` |"),
        "src/step.ts declares no interface Nope",
        1,
    ),
    (
        "TypeScript marker without an interface",
        _table("typescript:src/step.ts", "| Prop | Default |", "| `x` | `1` |"),
        "name a file in the code tree and an interface in it",
        1,
    ),
    (
        "CloudFormation path outside the code tree",
        _table(
            "cloudformation:../elsewhere", "| Parameter | Default |", "| `x` | `1` |"
        ),
        "name a template or a directory of templates in the code tree",
        1,
    ),
    (
        "CloudFormation path that does not exist",
        _table(
            "cloudformation:deploy/none", "| Parameter | Default |", "| `x` | `1` |"
        ),
        "deploy/none is not in the code tree",
        1,
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,text,expected,line", SECTION_DEFECTS, ids=[c[0] for c in SECTION_DEFECTS]
)
def test_sections_read_from_code_can_fail(
    tmp_path, section_code, case, text, expected, line
):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(
        dc.check_option_tables([page], tmp_path, section_code), expected, line
    )


@pytest.mark.unit
def test_an_action_flag_that_never_reaches_the_command_is_off(tmp_path):
    """typer's --install-completion and --show-completion are flags with default None
    and expose_value False: the value never reaches the command, so not passing one is
    off. A three-way flag (--fail-on-findings/--no-fail-on-findings, default None and
    exposed) is still not set, because there unset defers to the config."""
    clean = _write(
        tmp_path,
        "docs/clean.md",
        "<!-- doctest: options of=cli -->\n| Option | Default |\n|---|---|\n"
        "| `--install-completion` | off |\n| `--show-completion` | off |\n\n"
        "<!-- doctest: options of=cli.scan -->\n| Option | Default |\n|---|---|\n"
        "| `--fail-on-findings` | not set |\n",
    )
    assert dc.check_option_tables([clean], tmp_path) == []
    wrong = _write(
        tmp_path,
        "docs/wrong.md",
        "<!-- doctest: options of=cli -->\n| Option | Default |\n|---|---|\n"
        "| `--install-completion` | on |\n\n"
        "<!-- doctest: options of=cli.scan -->\n| Option | Default |\n|---|---|\n"
        "| `--fail-on-findings` | off |\n",
    )
    findings = dc.check_option_tables([wrong], tmp_path)
    _assert_reports(
        findings, "'--install-completion' default says on, but the default is `false`"
    )
    _assert_reports(
        findings, "'--fail-on-findings' default says off, but the default is `null`"
    )


@pytest.mark.unit
def test_an_options_marker_binds_only_to_a_table(fixture_root):
    """Above a fence, or with a gap before the table, it is a markers finding."""
    above_fence = _write(
        fixture_root,
        "docs/a.md",
        f"<!-- doctest: options of=global_settings -->\n{FENCE}yaml\na: 1\n{FENCE}\n",
    )
    _assert_reports(
        dc.check_markers([above_fence], fixture_root), "not above a code block"
    )
    above_prose = _write(
        fixture_root,
        "docs/b.md",
        "<!-- doctest: options of=global_settings -->\nSome prose.\n",
    )
    _assert_reports(
        dc.check_markers([above_prose], fixture_root),
        "directly followed by a table's header row",
    )


# ---------------------------------------------------------------------------
# Docs links in the ASH source
# ---------------------------------------------------------------------------

SITE_REDIRECTS = "redirects:\n  old-b.md: b.md\n  moved.md: sub/c.md\n"

CLEAN_CODE = """\
from pathlib import Path

SITE = "https://example.github.io/project"
PAGE = f"{SITE}/b/#section-two"
THROUGH_A_REDIRECT = "https://example.github.io/project/old-b/#custom-anchor"
SCHEMA = (
    "https://raw.githubusercontent.com/awslabs/automated-security-helper/"
    "refs/heads/main/docs/content/b.md"
)
README = "https://github.com/awslabs/automated-security-helper/blob/main/README.md#getting-started"
HELP = "See 'Section two' in docs/content/b.md, and docs/content/sub/c.md."


def guide(branch):
    \"\"\"A docstring may name docs/content/gone.md; only strings the code uses count.\"\"\"
    local = Path(__file__).parent / "docs" / "content" / "b.md"
    remote = f"https://raw.githubusercontent.com/awslabs/automated-security-helper/{branch}/docs/content/b.md"
    return local, remote
"""

CODE_LINK_DEFECTS = [
    (
        "site page",
        'URL = "https://example.github.io/project/nowhere/"\n',
        "no page on the site serves",
    ),
    (
        "site URL built from a constant",
        'SITE = "https://example.github.io/project"\nURL = f"{SITE}/nowhere/"\n',
        "https://example.github.io/project/nowhere/: no page on the site serves",
    ),
    (
        "docs path after a runtime prefix",
        'def guide(root):\n    return f"{root}/docs/content/gone.md"\n',
        "docs/content/gone.md does not exist in the docs",
    ),
    (
        "site anchor",
        'URL = "https://example.github.io/project/b/#no-such-part"\n',
        "has no anchor '#no-such-part'",
    ),
    (
        "anchor through a redirect",
        'URL = "https://example.github.io/project/old-b/#no-such-part"\n',
        "(through the redirect from old-b.md) has no anchor '#no-such-part'",
    ),
    (
        "raw docs file",
        'URL = "https://raw.githubusercontent.com/awslabs/automated-security-helper/main/docs/content/gone.md"\n',
        "docs/content/gone.md does not exist in the docs",
    ),
    (
        "raw fetch of a moved page",
        'URL = "https://raw.githubusercontent.com/awslabs/automated-security-helper/main/docs/content/moved.md"\n',
        "a fetch of the file does not follow it",
    ),
    (
        "repository file",
        'URL = "https://github.com/awslabs/automated-security-helper/blob/main/NOPE.py"\n',
        "NOPE.py does not exist in this repository",
    ),
    (
        "dynamic path",
        'def url(page):\n    return f"https://example.github.io/project/{page}/"\n',
        "is built at runtime",
    ),
    (
        "path chain",
        'from pathlib import Path\nGUIDE = Path(__file__).parent / "docs" / "content" / "gone.md"\n',
        "docs/content/gone.md does not exist in the docs",
    ),
    (
        "bare path",
        'HELP = "See docs/content/gone.md for more."\n',
        "docs/content/gone.md does not exist",
    ),
    (
        "heading",
        "HELP = \"See 'No such heading' in docs/content/b.md.\"\n",
        "that page has no such heading",
    ),
]


def _package(tmp_path: Path, source: str) -> Path:
    package = _git_root(tmp_path / "pkg") / "automated_security_helper"
    _write(package, "__init__.py", "")
    _write(package, "module.py", source)
    return package


@pytest.mark.integration
def test_code_links_check_passes_every_valid_form(tmp_path):
    root = _site(tmp_path, CLEAN_PAGES, redirects=SITE_REDIRECTS)
    assert dc.check_code_links(root, _package(tmp_path, CLEAN_CODE)) == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,source,expected", CODE_LINK_DEFECTS, ids=[c[0] for c in CODE_LINK_DEFECTS]
)
def test_code_links_check_can_fail(tmp_path, case, source, expected):
    root = _site(tmp_path, CLEAN_PAGES, redirects=SITE_REDIRECTS)
    findings = dc.check_code_links(root, _package(tmp_path, source))
    _assert_reports(findings, expected)
    assert all(f.path == "automated_security_helper/module.py" for f in findings)


SITE_RELATIVE_REDIRECTS = SITE_REDIRECTS + (
    "  docs/old-guide.md: b.md\n  docs/old-part.md: b.md#section-two\n"
    "  docs/broken.md: gone.md\n"
)


def _site_relative(tmp_path: Path) -> Path:
    pages = {**CLEAN_PAGES, "docs/content/docs/kept.md": "# Kept\n\n## A part\n"}
    return _site(tmp_path, pages, redirects=SITE_RELATIVE_REDIRECTS)


@pytest.mark.integration
def test_a_site_relative_docs_path_in_code_resolves_like_its_url(tmp_path):
    """Help text names site pages by their path under docs_dir ("See
    docs/config-overrides.md"). Such a path resolves the way its URL does: to a page,
    or through docs/redirects.yml to a page, with the fragment on the final page."""
    root = _site_relative(tmp_path)
    source = (
        'HELP = "See docs/kept.md, docs/kept.md#a-part, docs/old-guide.md, '
        'docs/old-guide.md#section-two and docs/old-part.md."\n'
    )
    assert dc.check_code_links(root, _package(tmp_path, source)) == []


SITE_RELATIVE_DEFECTS = [
    (
        "no page and no redirect",
        'HELP = "See docs/never-was.md."\n',
        "docs/never-was.md: docs/never-was.md does not exist in the docs",
    ),
    (
        "anchor missing after the redirect",
        'HELP = "See docs/old-guide.md#nope."\n',
        "(through the redirect from docs/old-guide.md) has no anchor '#nope'",
    ),
    (
        "redirect to a page that does not exist",
        'HELP = "See docs/broken.md."\n',
        "the redirect from docs/broken.md ends at a page that does not exist",
    ),
    (
        "anchor missing on the page",
        'HELP = "See docs/kept.md#nope."\n',
        "has no anchor '#nope'",
    ),
]


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,source,expected",
    SITE_RELATIVE_DEFECTS,
    ids=[c[0] for c in SITE_RELATIVE_DEFECTS],
)
def test_a_site_relative_docs_path_in_code_can_fail(tmp_path, case, source, expected):
    root = _site_relative(tmp_path)
    _assert_reports(dc.check_code_links(root, _package(tmp_path, source)), expected)


@pytest.mark.integration
def test_a_docs_link_through_a_redirect_needs_the_anchor_on_the_new_page(tmp_path):
    """The same rule for links in the docs: the redirect carries the fragment across."""
    pages = {
        **CLEAN_PAGES,
        "docs/content/index.md": "# Home\n\n[x](https://example.github.io/project/old-b/#nope)\n",
    }
    root = _site(tmp_path, pages, redirects=SITE_REDIRECTS)
    _assert_reports(
        dc.check_links([root / "docs/content/index.md"], root),
        "(through the redirect from old-b.md) has no anchor '#nope'",
        3,
    )


# ---------------------------------------------------------------------------
# Docs from one tree, code from another
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_code_tree_is_the_installed_package_checkout():
    package = dc.installed_package_dir()
    import automated_security_helper

    assert package == Path(automated_security_helper.__file__).resolve().parent
    assert dc.code_root(Path("/nonexistent-docs-root")) == package.parent


@pytest.mark.unit
def test_use_trees_rebases_docs_paths_onto_the_docs_root(tmp_path):
    gate = _load("_ash_docs_gate_rebased", GATE_PATH)
    gate._use_trees(tmp_path)
    package = dc.installed_package_dir()
    assert gate.REPO_ROOT == tmp_path.resolve()
    assert (
        gate.SCANNERS_REFERENCE_MD
        == tmp_path.resolve() / "docs/content/reference/scanners.md"
    )
    assert gate.INSTALL_MD == tmp_path.resolve() / "docs/content/how-to/install.md"
    assert gate.MCP_SERVER_PY == package / "cli" / "mcp_server.py"
    assert gate.PYPROJECT_TOML == package.parent / "pyproject.toml"


@pytest.mark.unit
def test_use_trees_can_be_called_again_for_another_docs_root(tmp_path):
    """Each call rebases from the current paths, so the code paths must not be
    computed relative to the previous docs root."""
    gate = _load("_ash_docs_gate_rebased_twice", GATE_PATH)
    package = dc.installed_package_dir()
    gate._use_trees(tmp_path / "first")
    gate._use_trees(tmp_path / "second")
    assert gate.REPO_ROOT == (tmp_path / "second").resolve()
    assert (
        gate.INSTALL_MD
        == (tmp_path / "second").resolve() / "docs/content/how-to/install.md"
    )
    assert gate.MCP_SERVER_PY == package / "cli" / "mcp_server.py"


@pytest.mark.integration
def test_the_gate_checks_the_docs_root_it_is_given(tmp_path):
    """--docs-root: markdown from that tree, and the header says which trees were used."""
    import subprocess

    root = _site(tmp_path, CLEAN_PAGES)
    _write(
        root,
        "docs/content/index.md",
        f"# Home\n\n<!-- doctest: execute -->\n{FENCE}bash\nash --bogus\n{FENCE}\n",
    )
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    result = subprocess.run(
        [sys.executable, str(GATE_PATH), "--docs-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    # The package a fresh interpreter imports, which is what the gate process sees; in
    # this process the current directory may come first on the import path.
    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import importlib.util, pathlib; s = importlib.util.find_spec("
                "'automated_security_helper'); print(pathlib.Path("
                "next(iter(s.submodule_search_locations))).resolve())"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.splitlines()
    assert lines[0] == f"ASH package: {probe.stdout.strip()}", result.stdout[:500]
    assert lines[1] == f"Docs root:   {root.resolve()}"
    assert "docs/content/index.md:3: [markers] unknown mode 'execute'" in result.stdout
    assert "'ash --bogus': --bogus is not an option of 'ash'" in result.stdout
    # The site has none of the generated reference pages, so the checks that read
    # them cannot run there, and a check that did not run makes the gate exit 2.
    not_run = [
        line for line in lines if line.startswith("        - the check did not run: ")
    ]
    assert not_run, result.stdout
    assert all("docs/content/reference/" in line for line in not_run), not_run
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# The redirect hook, in a real (tiny) mkdocs build
# ---------------------------------------------------------------------------


def _mkdocs_site(tmp_path: Path, redirects: str) -> Path:
    root = tmp_path / "site-src"
    _write(root, "docs/content/index.md", "# Home\n")
    _write(root, "docs/content/new/place.md", "# New place\n\n## Part\n")
    _write(root, dc.REDIRECTS_FILE, redirects)
    hook = root / dc.REDIRECT_HOOK
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        (REPO_ROOT / dc.REDIRECT_HOOK).read_text(encoding="utf-8"), encoding="utf-8"
    )
    _write(
        root,
        "mkdocs.yml",
        "site_name: t\nsite_url: https://example.github.io/project/\ndocs_dir: docs/content\n"
        "theme: mkdocs\nhooks:\n  - docs/hooks/redirects.py\n",
    )
    return root


def _build(root: Path):
    from mkdocs.commands.build import build
    from mkdocs.config import load_config

    config = load_config(
        config_file=str(root / "mkdocs.yml"), site_dir=str(root / "site")
    )
    build(config)
    return root / "site"


@pytest.mark.integration
def test_the_redirect_hook_writes_a_page_at_the_old_url(tmp_path):
    site = _build(
        _mkdocs_site(tmp_path, "redirects:\n  old/page.md: new/place.md#part\n")
    )
    page = (site / "old" / "page" / "index.html").read_text(encoding="utf-8")
    assert 'content="0; url=../../new/place/#part"' in page
    # The fragment the reader followed wins over the redirect's own.
    assert 'location.replace("../../new/place/" + (location.hash || "#part"));' in page
    assert (
        '<link rel="canonical" href="https://example.github.io/project/new/place/#part">'
        in page
    )


@pytest.mark.integration
def test_the_redirect_hook_refuses_to_overwrite_a_page(tmp_path, caplog):
    from mkdocs.exceptions import Abort

    with pytest.raises(Abort):
        _build(_mkdocs_site(tmp_path, "redirects:\n  index.md: new/place.md\n"))
    assert "index.md is still a page" in caplog.text


@pytest.mark.integration
def test_the_redirect_hook_refuses_a_missing_target(tmp_path, caplog):
    from mkdocs.exceptions import Abort

    with pytest.raises(Abort):
        _build(_mkdocs_site(tmp_path, "redirects:\n  old.md: nowhere.md\n"))
    assert "old.md redirects to nowhere.md, which is not a page" in caplog.text


# ---------------------------------------------------------------------------
# Wiring: the gate runs every check, on its own corpus
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_every_check_in_the_module_is_registered_in_the_gate():
    """A check_* function the gate never calls is a check that never runs."""
    module_checks = {
        node.name
        for node in ast.parse(CHECKS_PATH.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("check_")
    }
    gate_tree = ast.parse(GATE_PATH.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(gate_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Call)
        and getattr(node.func.value.func, "id", None) == "_docs_checks"
        and node.func.attr.startswith("check_")
    }
    assert module_checks == called, (
        f"in docs_checks.py but not called by the gate: {sorted(module_checks - called)}; "
        f"called but not defined: {sorted(called - module_checks)}"
    )


@pytest.mark.unit
def test_the_gate_wrappers_read_the_gates_corpus(tmp_path, monkeypatch, fixture_root):
    """Steering collect_md_files steers the new checks, as it does the first eight."""
    gate = _load("_ash_docs_gate_for_docs_checks", GATE_PATH)
    page = _write(
        fixture_root,
        "docs/page.md",
        f"<!-- doctest: execute -->\n{FENCE}bash\nash --bogus\n{FENCE}\n",
    )
    monkeypatch.setattr(gate, "collect_md_files", lambda: [page])
    monkeypatch.setattr(gate, "REPO_ROOT", fixture_root)
    assert any("unknown mode" in f for f in gate.check_doc_markers())
    assert any("--bogus" in f for f in gate.check_doc_cli())


# ---------------------------------------------------------------------------
# What the checks could not look at, and how mkdocs.yml and TOML blocks are read
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_a_plugin_module_that_does_not_import_is_reported_as_skipped(
    monkeypatch, capsys, fixture_root
):
    """A broken optional extra is not a finding, and the checks say they skipped it.

    The module that declares the semgrep scanner config is made to raise on import.
    load_config_models records it instead of dropping it, the semgrep config class is
    missing from the models, the option-tables and config-blocks checks put a note
    in ``notes`` and report no finding for it, and the gate prints the note as a
    ``skipped:`` line under the check, with or without --verbose.
    """
    dc.load_config_models.cache_clear()
    try:
        broken = dc.load_config_models().plugin_configs["scanners"]["semgrep"]
        broken_module = broken.__module__
        real_import = dc.importlib.import_module

        def import_module(name, *args, **kwargs):
            if name == broken_module:
                raise ImportError("planted: an optional extra is not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(dc.importlib, "import_module", import_module)
        dc.load_config_models.cache_clear()
        models = dc.load_config_models()
        assert models.unloaded == {
            broken_module: "ImportError: planted: an optional extra is not installed"
        }
        assert "semgrep" not in models.plugin_configs["scanners"]
        expected = (
            f"plugin module {broken_module} did not import (ImportError: planted: "
            "an optional extra is not installed), so its plugins' config classes "
            "were not checked"
        )
        assert models.skipped_notes() == [expected]

        page = _write(
            fixture_root,
            "docs/page.md",
            "<!-- doctest: config kind=ash -->\n"
            f"{FENCE}yaml\nproject_name: x\n{FENCE}\n",
        )
        notes: list[str] = []
        assert dc.check_option_tables([page], fixture_root, notes=notes) == []
        assert notes == [expected]
        notes = []
        assert dc.check_config_blocks([page], fixture_root, notes=notes) == []
        assert notes == [expected]

        gate = _load("_ash_docs_gate_for_docs_checks", GATE_PATH)
        monkeypatch.setattr(gate, "collect_md_files", lambda: [page])
        monkeypatch.setattr(gate, "REPO_ROOT", fixture_root)
        monkeypatch.setattr(gate, "_VERBOSE", False)
        capsys.readouterr()
        assert gate.check_doc_option_tables() == []
        assert gate.check_doc_config_blocks() == []
        printed = capsys.readouterr().out.splitlines()
        assert printed == [f"        skipped: {expected}"] * 2
    finally:
        dc.load_config_models.cache_clear()


@pytest.mark.unit
def test_every_plugin_module_imports_here():
    """The positive control: in this environment nothing is skipped."""
    dc.load_config_models.cache_clear()
    try:
        models = dc.load_config_models()
        assert models.unloaded == {}
        assert models.skipped_notes() == []
        assert "semgrep" in models.plugin_configs["scanners"]
    finally:
        dc.load_config_models.cache_clear()


@pytest.mark.unit
def test_the_mkdocs_loader_adds_three_constructors_to_the_safe_loader(monkeypatch):
    """``!!python/name:`` imports only from the allowlist, and nothing else changes.

    A name under pymdownx, material or markdown resolves to the object; any other
    module stays the tag's text and is not imported; ``!!python/object`` tags read
    as None; ``!ENV`` reads the variable or its default. A tag SafeLoader does not
    know is still an error, and so is a second document.
    """
    import yaml
    from pymdownx import emoji, superfences

    monkeypatch.setenv("DOCS_CHECKS_PLANTED_SET", "set")
    monkeypatch.delenv("DOCS_CHECKS_PLANTED_UNSET", raising=False)
    monkeypatch.delitem(sys.modules, "this_module_is_not_imported", raising=False)
    data = dc._TolerantLoader.load(
        "index: !!python/name:pymdownx.emoji.twemoji\n"
        "format: !!python/name:pymdownx.superfences.fence_code_format\n"
        "outside: !!python/name:os.system\n"
        "unimported: !!python/name:this_module_is_not_imported.attr\n"
        "missing: !!python/name:pymdownx.no_such_module.attr\n"
        "applied: !!python/object/apply:os.system ['true']\n"
        "plain_object: !!python/object:os.PathLike {}\n"
        "env_set: !ENV [DOCS_CHECKS_PLANTED_UNSET, DOCS_CHECKS_PLANTED_SET, fallback]\n"
        "env_unset: !ENV [DOCS_CHECKS_PLANTED_UNSET, fallback]\n"
        "env_scalar: !ENV DOCS_CHECKS_PLANTED_SET\n"
        "env_scalar_unset: !ENV DOCS_CHECKS_PLANTED_UNSET\n"
        "plain: [1, two, {three: 3.0}]\n"
    )
    assert data == {
        "index": emoji.twemoji,
        "format": superfences.fence_code_format,
        "outside": "os.system",
        "unimported": "this_module_is_not_imported.attr",
        "missing": "pymdownx.no_such_module.attr",
        "applied": None,
        "plain_object": None,
        "env_set": "set",
        "env_unset": "fallback",
        "env_scalar": "set",
        "env_scalar_unset": None,
        "plain": [1, "two", {"three": 3.0}],
    }
    assert "this_module_is_not_imported" not in sys.modules
    for text in ("docs_dir: !relative docs\n", "a: 1\n---\nb: 2\n", "a: [1\n"):
        with pytest.raises(yaml.YAMLError):
            dc._TolerantLoader.load(text)


@pytest.mark.unit
def test_toml_blocks_parse_the_same_without_tomllib(monkeypatch):
    """Both arms of _parse_toml: tomllib, and the toml package Python 3.10 uses."""
    text = 'title = "x"\n[tool.ash]\nfail_on_findings = true\nignore = ["a"]\n'
    expected = {
        "title": "x",
        "tool": {"ash": {"fail_on_findings": True, "ignore": ["a"]}},
    }
    assert dc.parse_config_text(text, "toml") == (expected, None)
    with monkeypatch.context() as patched:
        patched.setitem(sys.modules, "tomllib", None)
        assert dc.parse_config_text(text, "toml") == (expected, None)
        document, problem = dc.parse_config_text("title = \n", "toml")
    assert document is None
    assert problem.startswith("does not parse as toml: ")
