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
executes a docs command, needs the network or calls git. The checks get their files
and repository root as arguments, so every page lives in tmp_path.
"""

from __future__ import annotations

import ast
import importlib.util
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


def test_marker_check_passes_every_valid_form(fixture_root):
    page = _write(fixture_root, "docs/page.md", CLEAN_MARKERS)
    assert dc.check_markers([page], fixture_root) == []


@pytest.mark.parametrize(
    "case,text,expected", MARKER_DEFECTS, ids=[c[0] for c in MARKER_DEFECTS]
)
def test_marker_check_can_fail(fixture_root, case, text, expected):
    page = _write(fixture_root, "docs/page.md", text)
    _assert_reports(dc.check_markers([page], fixture_root), expected)


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
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.7.0 ash --mode local
uvx git+https://github.com/awslabs/automated-security-helper.git@v3.7.0 --version
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
    rev: v3.7.0
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


def test_cli_check_passes_every_valid_form(cli_root):
    page = _write(cli_root, "docs/page.md", CLEAN_CLI)
    assert dc.check_cli([page], cli_root) == []


@pytest.mark.parametrize(
    "case,text,expected,line", CLI_DEFECTS, ids=[c[0] for c in CLI_DEFECTS]
)
def test_cli_check_can_fail(cli_root, case, text, expected, line):
    page = _write(cli_root, "docs/page.md", text)
    _assert_reports(dc.check_cli([page], cli_root), expected, line)


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


def test_env_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_ENV)
    assert dc.check_env_vars([page], tmp_path, READ) == []


@pytest.mark.parametrize(
    "case,text,expected,line", ENV_DEFECTS, ids=[c[0] for c in ENV_DEFECTS]
)
def test_env_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_env_vars([page], tmp_path, READ), expected, line)


def test_env_read_set_resolves_constant_keys():
    """os.environ.get(SOME_CONSTANT) counts as reading the constant's value."""
    import ast as std_ast

    tree = std_ast.parse(
        'import os\nNAME = "ASH_VIA_CONSTANT"\nos.environ.get(NAME)\nos.getenv(other)\n'
    )
    names, dynamic = dc.env_lookups(tree, "m.py", dc._module_string_constants(tree))
    assert names == {"ASH_VIA_CONSTANT"}
    assert dynamic == ["m.py:4 [getenv]"]


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
        "scanners.bandit.options.severity_level is not a field of BanditScannerConfigOptions",
    ),
    (
        "ignored list item key",
        f"{FENCE}yaml\nglobal_settings:\n  ignore_paths:\n    - path: a/**\n      reason: r\n      why: nobody reads this\n{FENCE}\n",
        "global_settings.ignore_paths[0].why",
    ),
    (
        "wrong type",
        f"{FENCE}yaml\nfail_on_findings: sometimes\n{FENCE}\n",
        "fail_on_findings",
    ),
    (
        "generic key on a reporter",
        f"{FENCE}yaml\nreporters:\n  sarif:\n    options:\n      offline: true\n{FENCE}\n",
        "reporters.sarif.options.offline is not a field",
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


def test_config_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_CONFIG)
    assert dc.check_config_blocks([page], tmp_path) == []


@pytest.mark.parametrize(
    "case,text,expected", CONFIG_DEFECTS, ids=[c[0] for c in CONFIG_DEFECTS]
)
def test_config_check_can_fail(tmp_path, case, text, expected):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_config_blocks([page], tmp_path), expected)


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


def test_python_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_PYTHON)
    assert dc.check_python_blocks([page], tmp_path) == []


@pytest.mark.parametrize(
    "case,text,expected,line", PYTHON_DEFECTS, ids=[c[0] for c in PYTHON_DEFECTS]
)
def test_python_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_python_blocks([page], tmp_path), expected, line)


# ---------------------------------------------------------------------------
# A synthetic site: links, navigation, redirects, build settings
# ---------------------------------------------------------------------------

MKDOCS = """site_name: test
site_url: https://example.github.io/project
docs_dir: docs/content
hooks:
  - docs/hooks/redirects.py
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
  - privacy
  - awesome-nav
markdown_extensions:
  - admonition
  - pymdownx.superfences
"""

WORKFLOW = """jobs:
  build:
    steps:
      - run: uv run mkdocs build --clean --strict
"""


def _site(
    tmp_path: Path,
    pages: dict[str, str],
    *,
    nav: str | None = None,
    redirects: str = "redirects: {}\n",
    mkdocs: str = MKDOCS,
    workflow: str = WORKFLOW,
) -> Path:
    root = tmp_path / "repo"
    _write(root, "mkdocs.yml", mkdocs)
    _write(root, dc.REDIRECT_HOOK, "# hook\n")
    _write(root, dc.REDIRECTS_FILE, redirects)
    _write(root, dc.DOCS_WORKFLOW, workflow)
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
        "[a site page](https://example.github.io/project/b/) and <https://example.com>.\n"
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


def test_links_check_passes_every_valid_form(tmp_path):
    root = _site(tmp_path, CLEAN_PAGES)
    files = [root / rel for rel in CLEAN_PAGES if rel.endswith(".md")] + [
        root / "README.md"
    ]
    assert dc.check_links(files, root) == []


@pytest.mark.parametrize(
    "case,rel,text,expected,line", LINK_DEFECTS, ids=[c[0] for c in LINK_DEFECTS]
)
def test_links_check_can_fail(tmp_path, case, rel, text, expected, line):
    root = _site(tmp_path, {**CLEAN_PAGES, rel: text})
    _assert_reports(dc.check_links([root / rel], root), expected, line)


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


@pytest.mark.parametrize(
    "case,extra,nav,redirects,expected", NAV_DEFECTS, ids=[c[0] for c in NAV_DEFECTS]
)
def test_nav_check_can_fail(tmp_path, case, extra, nav, redirects, expected):
    root = _site(tmp_path, {**CLEAN_PAGES, **extra}, nav=nav, redirects=redirects)
    _assert_reports(dc.check_nav(root), expected)


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
        MKDOCS.replace("hooks:\n  - docs/hooks/redirects.py\n", ""),
        WORKFLOW,
        "hooks does not list",
    ),
    (
        "privacy dropped",
        MKDOCS.replace("  - privacy\n", ""),
        WORKFLOW,
        "privacy plugin is not configured",
    ),
]


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


def test_the_real_mkdocs_config_is_strict_and_offline():
    """The committed mkdocs.yml and docs workflow pass the build-settings check."""
    assert dc.check_site_build(REPO_ROOT) == []


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
| `tool_version` | string | `">=1.7.0,<2.0.0"` | x |
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


def test_option_tables_check_passes_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_OPTIONS)
    assert dc.check_option_tables([page], tmp_path) == []


@pytest.mark.parametrize(
    "case,text,expected,line", OPTION_DEFECTS, ids=[c[0] for c in OPTION_DEFECTS]
)
def test_option_tables_check_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_option_tables([page], tmp_path), expected, line)


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
    package = tmp_path / "pkg" / "automated_security_helper"
    _write(package, "__init__.py", "")
    _write(package, "module.py", source)
    return package


def test_code_links_check_passes_every_valid_form(tmp_path):
    root = _site(tmp_path, CLEAN_PAGES, redirects=SITE_REDIRECTS)
    assert dc.check_code_links(root, _package(tmp_path, CLEAN_CODE)) == []


@pytest.mark.parametrize(
    "case,source,expected", CODE_LINK_DEFECTS, ids=[c[0] for c in CODE_LINK_DEFECTS]
)
def test_code_links_check_can_fail(tmp_path, case, source, expected):
    root = _site(tmp_path, CLEAN_PAGES, redirects=SITE_REDIRECTS)
    findings = dc.check_code_links(root, _package(tmp_path, source))
    _assert_reports(findings, expected)
    assert all(f.path == "automated_security_helper/module.py" for f in findings)


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


def test_the_code_tree_is_the_installed_package_checkout():
    package = dc.installed_package_dir()
    import automated_security_helper

    assert package == Path(automated_security_helper.__file__).resolve().parent
    assert dc.code_root(Path("/nonexistent-docs-root")) == package.parent


def test_use_trees_rebases_docs_paths_onto_the_docs_root(tmp_path):
    gate = _load("_ash_docs_gate_rebased", GATE_PATH)
    gate._use_trees(tmp_path)
    package = dc.installed_package_dir()
    assert gate.REPO_ROOT == tmp_path.resolve()
    assert (
        gate.CLI_REFERENCE_MD
        == tmp_path.resolve() / "docs/content/docs/cli-reference.md"
    )
    assert gate.README_TEMPLATE_MD == tmp_path.resolve() / "README.md.template"
    assert gate.CLI_SCAN_PY == package / "cli" / "scan.py"
    assert gate.PYPROJECT_TOML == package.parent / "pyproject.toml"


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
    assert result.returncode == 1


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


def test_the_redirect_hook_refuses_to_overwrite_a_page(tmp_path, caplog):
    from mkdocs.exceptions import Abort

    with pytest.raises(Abort):
        _build(_mkdocs_site(tmp_path, "redirects:\n  index.md: new/place.md\n"))
    assert "index.md is still a page" in caplog.text


def test_the_redirect_hook_refuses_a_missing_target(tmp_path, caplog):
    from mkdocs.exceptions import Abort

    with pytest.raises(Abort):
        _build(_mkdocs_site(tmp_path, "redirects:\n  old.md: nowhere.md\n"))
    assert "old.md redirects to nowhere.md, which is not a page" in caplog.text


# ---------------------------------------------------------------------------
# Wiring: the gate runs every check, on its own corpus
# ---------------------------------------------------------------------------


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
