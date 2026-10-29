# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CLI check reads option values, and finds ash commands outside shell blocks.

Same contract as tests/unit/test_docs_checks_can_fail.py: each rule gets a page with
one planted defect that must be reported, and a clean page using every form the rule
allows that must pass. Two holes in "ASH commands in docs match the CLI" are covered
here.

Option values. The check parsed every option name against the click tree but took any
word as its value, so `ash --mode containr`, `--log-level LOUD`, `--output-formats sarf`,
`--scanners not-a-scanner` and `ash dependencies install --tool notatool` all passed.
A click choice option is now held to its choices, and the options click takes as plain
strings but ASH checks against a registry after parsing (scanner, reporter and tool
names, output formats) are held to that registry.

Blocks the check did not read. Only shell, Dockerfile and CI-config blocks had their
commands parsed. An `ash` line in a text, markdown, diff, groovy, json5 or ini block,
in a shell-session block, in an indented code block or in a fence inside a blockquote
was never looked at. Those are parsed now too. A block marked
``<!-- doctest: output -->`` directly after a block the runner runs is that block's
output, not commands; marked anywhere else, its ash lines are still read. The
TypeScript blocks of the CDK construct's README are held to the props interface and
enums the construct declares.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
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


@pytest.fixture
def cli_root(tmp_path):
    root = tmp_path / "repo"
    _write(
        root,
        dc.PRE_COMMIT_HOOKS,
        (REPO_ROOT / dc.PRE_COMMIT_HOOKS).read_text(encoding="utf-8"),
    )
    return root


def _check(root: Path, text: str, rel: str = "docs/page.md", code: Path | None = None):
    page = _write(root, rel, text)
    return dc.check_cli([page], root, code=code)


# ---------------------------------------------------------------------------
# Option values
# ---------------------------------------------------------------------------


# Built-in plugins every ASH this runs against ships. The registry tests below hold the
# check's names to the plugin modules themselves.
SCANNER = "bandit"
REPORTER = "sarif"
CONVERTER = "jupyter"

CLEAN_VALUES = f"""# Values

{FENCE}bash
ash --mode local --log-level QUIET --strategy sequential --build-target ci
ash --sandbox AUTO --phases convert --phases scan
ash --log-level=DEBUG --mode=precommit
ash scan --scanners {SCANNER} --exclude-scanners {SCANNER},{SCANNER}
ash --scanners {SCANNER.upper()} --output-formats sarif,junitxml -f html --format text
ash merge --results a --results b --output-formats sarif
ash report --format {REPORTER}
ash report --format {REPORTER.upper()}
ash dependencies install --tool {SCANNER} --tool {REPORTER} -T {CONVERTER}
ash --mode "$MODE" --scanners "${{SCANNERS}}"
ash scan --ash-plugin-modules acme_plugins --scanners acme-scanner
ash report --format acme-format --config-overrides 'ash_plugin_modules+=[acme_plugins]'
ash scan --ash-plugin-modules automated_security_helper.plugin_modules.x --scanners {SCANNER}
{FENCE}

<!-- doctest: illustrative reason="shows the synopsis with placeholders" -->
{FENCE}bash
ash --log-level <level> --mode <mode>
{FENCE}

Run `ash --mode container` or `ash --mode <mode>`, and `ash report --format {REPORTER}`.
"""

VALUE_DEFECTS = [
    (
        "choice",
        f"{FENCE}bash\nash --mode containr\n{FENCE}\n",
        "--mode takes precommit, container, local, or nix, not 'containr'",
        2,
    ),
    (
        "choice after =",
        f"{FENCE}bash\nash scan --log-level=LOUD\n{FENCE}\n",
        "--log-level takes",
        2,
    ),
    (
        "choice hint",
        f"{FENCE}bash\nash --mode containr\n{FENCE}\n",
        "did you mean 'container'?",
        2,
    ),
    (
        "case-sensitive choice",
        f"{FENCE}bash\nash --log-level debug\n{FENCE}\n",
        "not 'debug'",
        2,
    ),
    (
        "repeated choice",
        f"{FENCE}bash\nash --phases scan --phases reprot\n{FENCE}\n",
        "not 'reprot'",
        2,
    ),
    (
        "output format",
        f"{FENCE}bash\nash --output-formats sarf\n{FENCE}\n",
        "'sarf' is not an output format",
        2,
    ),
    (
        "output format alias in a list",
        f"{FENCE}bash\nash scan -f sarif,htm\n{FENCE}\n",
        "'htm' is not an output format",
        2,
    ),
    (
        "merge output format",
        f"{FENCE}bash\nash merge --results a --output-formats sarf\n{FENCE}\n",
        "'sarf' is not an output format",
        2,
    ),
    (
        "scanner",
        f"{FENCE}bash\nash --scanners not-a-scanner\n{FENCE}\n",
        "ASH has no scanner named 'not-a-scanner'",
        2,
    ),
    (
        "scanner in a list",
        f"{FENCE}bash\nash scan --exclude-scanners {SCANNER},not-a-scanner\n{FENCE}\n",
        "ASH has no scanner named 'not-a-scanner'",
        2,
    ),
    (
        "reporter",
        f"{FENCE}bash\nash report --format not-a-reporter\n{FENCE}\n",
        "ASH has no reporter named 'not-a-reporter'",
        2,
    ),
    (
        "tool",
        f"{FENCE}bash\nash dependencies install --tool notatool\n{FENCE}\n",
        "ASH has no converter, scanner, or reporter named 'notatool'",
        2,
    ),
    (
        "short tool option",
        f"{FENCE}bash\nash dependencies install -T notatool\n{FENCE}\n",
        "named 'notatool'",
        2,
    ),
    (
        "a misspelled built-in next to a plugin module",
        f"{FENCE}bash\nash scan --ash-plugin-modules acme_plugins --scanners {SCANNER}x\n{FENCE}\n",
        f"ASH has no scanner named '{SCANNER}x'",
        2,
    ),
    (
        "inline span",
        "Run `ash --mode containr` to scan.\n",
        "not 'containr'",
        1,
    ),
    (
        "illustrative block",
        f'<!-- doctest: illustrative reason="needs Docker" -->\n{FENCE}bash\nash --mode containr\n{FENCE}\n',
        "not 'containr'",
        3,
    ),
    (
        "run block that expects a different failure",
        f"<!-- doctest: run expect-exit=1 -->\n{FENCE}bash\nash --mode containr\n{FENCE}\n",
        "not 'containr'",
        3,
    ),
]


@pytest.mark.unit
def test_option_values_pass_every_valid_form(cli_root):
    assert _check(cli_root, CLEAN_VALUES) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,expected,line", VALUE_DEFECTS, ids=[c[0] for c in VALUE_DEFECTS]
)
def test_option_values_can_fail(cli_root, case, text, expected, line):
    _assert_reports(_check(cli_root, text), expected, line)


@pytest.mark.unit
def test_the_cli_model_records_click_choices():
    """The choices come from click's own parameter types, not a copy of them."""
    import typer

    from automated_security_helper.cli.main import app

    click_root = typer.main.get_command(app)
    scan = dc.load_cli().subcommands["scan"]
    for param in click_root.commands["scan"].params:
        choices = getattr(param.type, "choices", None)
        if param.param_type_name != "option" or choices is None:
            continue
        option = scan.options[param.opts[0]]
        assert option.choices == tuple(str(getattr(c, "value", c)) for c in choices)
        assert option.case_sensitive == getattr(param.type, "case_sensitive", True)
    assert scan.options["--source-dir"].choices is None


@pytest.mark.unit
def test_the_registries_match_the_inventories_the_reference_checks_read():
    """Plugin names come from the plugin modules' ASH_* lists. The gate's scanner and
    reporter checks read the same plugins another way, so the two must agree."""
    gate = _load(
        "_ash_docs_gate_for_values", REPO_ROOT / "scripts" / "verify_docs_freshness.py"
    )
    assert dc.plugin_names("scanner") == frozenset(gate.scanner_names())
    assert dc.plugin_names("reporter") == frozenset(gate.reporter_names())
    assert dc.plugin_names("converter") == frozenset(
        dc.load_config_models().plugin_configs["converters"]
    )
    assert SCANNER in dc.plugin_names("scanner")
    assert REPORTER in dc.plugin_names("reporter")
    assert CONVERTER in dc.plugin_names("converter")


@pytest.mark.unit
def test_output_formats_are_the_export_formats():
    from automated_security_helper.core.enums import ExportFormat

    for command in (("ash",), ("ash", "scan"), ("ash", "merge")):
        values = dc.option_value_set(command, "--output-formats")
        assert values is not None, command
        assert values.names == frozenset(f.value for f in ExportFormat)


@pytest.mark.unit
def test_a_run_block_that_expects_the_usage_error_may_show_a_refused_value(
    cli_root, monkeypatch
):
    """A page may run a refused value to show the refusal, when the exit says only that.

    Where ASH exits with its own usage-error code and that code is not also the
    actionable-findings code, the runner proves the refusal, so the static check
    leaves the value alone. Where the two codes are the same, an expect-exit block
    cannot tell a typo from findings, so the value is still reported.
    """
    text = (
        f"<!-- doctest: run expect-exit=5 -->\n{FENCE}bash\n"
        f"ash dependencies install --tool gryp\n{FENCE}\n"
    )
    monkeypatch.setattr(dc, "usage_error_exit", lambda: 5)
    assert _check(cli_root, text) == []
    monkeypatch.setattr(dc, "usage_error_exit", lambda: None)
    _assert_reports(_check(cli_root, text), "named 'gryp'", 3)
    monkeypatch.setattr(dc, "usage_error_exit", lambda: 5)
    _assert_reports(
        _check(cli_root, text.replace("expect-exit=5", "expect-exit=2")),
        "named 'gryp'",
        3,
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "first,second,reported,line",
    [
        (
            "ash dependencies install --tool gryp",
            "ash --mode containr --version",
            "not 'containr'",
            4,
        ),
        (
            "ash --log-level LOUD --version",
            "ash dependencies install --tool gryp",
            "named 'gryp'",
            4,
        ),
    ],
    ids=["bad value after the refusal", "refusal after a bad value"],
)
def test_an_expected_refusal_covers_only_the_command_that_refuses(
    cli_root, monkeypatch, first, second, reported, line
):
    """The block stops at its first refused command (set -e), so only that one is shown
    refusing; a refused value in any other command of the block is still reported."""
    monkeypatch.setattr(dc, "usage_error_exit", lambda: 5)
    text = f"<!-- doctest: run expect-exit=5 -->\n{FENCE}bash\n{first}\n{second}\n{FENCE}\n"
    findings = _check(cli_root, text)
    _assert_reports(findings, reported, line)
    assert len(findings) == 1, _messages(findings)
    control = f"<!-- doctest: run expect-exit=5 -->\n{FENCE}bash\nash --version\n{first}\n{FENCE}\n"
    assert _check(cli_root, control) == []


@pytest.mark.unit
def test_a_subshell_paren_ends_the_word_before_it():
    """`(cd x && ash dependencies install --tool trivy)` passes trivy, not 'trivy)'."""
    (command,) = [
        c
        for c in dc.split_shell('(cd "$TMP" && ash dependencies install --tool grype)')
        if c.words[:1] == ["ash"]
    ]
    assert command.words[-1] == "grype"
    (literal,) = dc.split_shell("echo 'a)' b\\) c")
    assert literal.words == ["echo", "a)", "b)", "c"]


# ---------------------------------------------------------------------------
# Commands outside shell blocks
# ---------------------------------------------------------------------------

BAD = "ash scan --no-such-option"
NOT_AN_OPTION = "--no-such-option is not an option of 'ash scan'"

CLEAN_FORMS = f"""# Commands in other forms

{FENCE}text
ash scan --offline
  ash --version
ASH is a scanner; ash-like words such as ashtray are not commands.
ash [OPTIONS] COMMAND [ARGS]...
ash config get [OPTIONS] [config_path]
{FENCE}

{FENCE}groovy
pipeline {{
  stages {{
    stage('ASH') {{
      steps {{
        sh '''
          (cd "$WORKSPACE_TMP" && ash dependencies install --tool {SCANNER})
          ash scan --mode local \\\\
            --fail-on-findings
        '''
        sh "ash --version"
        sh(script: 'ash report --format {REPORTER}', returnStatus: true)
      }}
    }}
  }}
}}
{FENCE}

{FENCE}diff
- ash scan --a-removed-option
+ ash scan --offline
  ash --version
{FENCE}

{FENCE}shell-session
$ ash --version
ash --this-is-output
{FENCE}

{FENCE}bash-session
$ ash scan --offline
{FENCE}

````markdown
{FENCE}bash
ash --mode container --source-dir .
{FENCE}
````

{FENCE}bash
echo the output sample below is this block's
{FENCE}

<!-- doctest: output -->
{FENCE}text
ash scan default                        -> exit 0
{FENCE}

Run this:

    ash scan --offline \\
      --fail-on-findings

> {FENCE}bash
> ash --version
> {FENCE}

> ash is quoted prose here, not a command.

{FENCE}json5
{{command: "ash scan --no-such-option inside a string is not a line"}}
{FENCE}

{FENCE}ini
[ash]
args = --offline
{FENCE}
"""

FORM_DEFECTS = [
    ("text", f"{FENCE}text\n{BAD}\n{FENCE}\n", 2),
    (
        "synopsis with a bad option",
        f"{FENCE}text\nash scan [OPTIONS] --no-such-option\n{FENCE}\n",
        2,
    ),
    ("text with a prompt", f"{FENCE}text\n$ {BAD}\n{FENCE}\n", 2),
    (
        "text continued",
        f"{FENCE}text\nash scan --offline \\\n  --no-such-option\n{FENCE}\n",
        2,
    ),
    (
        "groovy sh '''",
        f"{FENCE}groovy\nnode {{\n  sh '''\n    echo first\n    {BAD}\n  '''\n}}\n{FENCE}\n",
        5,
    ),
    ('groovy sh ""', f'{FENCE}groovy\nnode {{\n  sh "{BAD}"\n}}\n{FENCE}\n', 3),
    (
        "groovy sh(script:)",
        f"{FENCE}groovy\nnode {{\n  sh(script: '{BAD}', returnStatus: true)\n}}\n{FENCE}\n",
        3,
    ),
    (
        "groovy subshell",
        f"{FENCE}groovy\nsh '''\n  (cd x && {BAD})\n'''\n{FENCE}\n",
        3,
    ),
    ("markdown", f"````markdown\n{FENCE}bash\n{BAD}\n{FENCE}\n````\n", 3),
    ("diff", f"{FENCE}diff\n- ash scan --old\n+ {BAD}\n{FENCE}\n", 3),
    ("diff context", f"{FENCE}diff\n  {BAD}\n{FENCE}\n", 2),
    ("shell-session", f"{FENCE}shell-session\n$ {BAD}\noutput\n{FENCE}\n", 2),
    ("bash-session", f"{FENCE}bash-session\n$ {BAD}\n{FENCE}\n", 2),
    ("indented code block", f"Run this:\n\n    {BAD}\n", 3),
    ("indented with a tab", f"Run this:\n\n\t{BAD}\n", 3),
    ("fence in a blockquote", f"> {FENCE}bash\n> echo first\n> {BAD}\n> {FENCE}\n", 3),
    ("nested blockquote", f"> > {FENCE}console\n> > $ {BAD}\n> > {FENCE}\n", 2),
    ("json5", f'{FENCE}json5\n{{project_name: "x"}}\n{BAD}\n{FENCE}\n', 3),
    ("ini", f"{FENCE}ini\n[ash]\n{BAD}\n{FENCE}\n", 3),
    (
        "marked output after no run block",
        f"Some prose.\n\n<!-- doctest: output -->\n{FENCE}text\n{BAD}\n{FENCE}\n",
        5,
    ),
    (
        "marked output after an illustrative block",
        (
            f'<!-- doctest: illustrative reason="needs Docker" -->\n{FENCE}bash\n'
            f"docker ps\n{FENCE}\n<!-- doctest: output -->\n{FENCE}text\n{BAD}\n{FENCE}\n"
        ),
        7,
    ),
    (
        "ash config kind=other",
        (
            f'<!-- doctest: config kind=other reason="a CI file of another tool" -->\n'
            f"{FENCE}yaml\nscript: |\n  {BAD}\n{FENCE}\n"
        ),
        4,
    ),
]


@pytest.mark.unit
def test_commands_in_every_form_pass_when_valid(cli_root):
    assert _check(cli_root, CLEAN_FORMS) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "case,text,line", FORM_DEFECTS, ids=[c[0] for c in FORM_DEFECTS]
)
def test_commands_in_every_form_can_fail(cli_root, case, text, line):
    _assert_reports(_check(cli_root, text), NOT_AN_OPTION, line)


@pytest.mark.unit
def test_an_output_marker_binds_only_to_a_block_that_is_not_run():
    """`output` is for samples; on a shell, python or config block it is a mistake."""
    root = Path(__file__).parent
    page = dc.parse_page(
        root / "page.md",
        root,
        text=f"<!-- doctest: output -->\n{FENCE}bash\nash --version\n{FENCE}\n"
        f"<!-- doctest: output key=1 -->\n{FENCE}text\nx\n{FENCE}\n",
    )
    problems = [dc.marker_problems(block, root) for block in page.blocks]
    assert any("output" in p for p in problems[0]), problems
    assert any("takes no keys" in p for p in problems[1]), problems


@pytest.mark.unit
def test_shell_session_blocks_are_console_blocks():
    assert {"shell-session", "bash-session"} <= dc.CONSOLE_LANGS <= dc.RUNNER_SHELLS


# ---------------------------------------------------------------------------
# TypeScript blocks: the construct's props and enums
# ---------------------------------------------------------------------------

STEP_SOURCE = """\
import * as codebuild from 'aws-cdk-lib/aws-codebuild';

export enum ASHInstallMode {
  /** Install with pip. */
  PIP = 'pip',
  PREINSTALLED = 'preinstalled',
}

export interface ASHScanStepProps {
  /** The source to scan. */
  readonly input: string;
  /** Shards. @default 1 */
  readonly shardCount?: number;
  readonly installMode?: ASHInstallMode;
  readonly buildImage?: codebuild.IBuildImage;
}

export class ASHScanStep {
  constructor(id: string, props: ASHScanStepProps) {}
}
"""


@pytest.fixture
def construct(tmp_path):
    """A docs tree with a construct README, and a code tree with the construct."""
    root = tmp_path / "docs"
    code = _git_root(tmp_path / "code")
    _write(code, "deploy/cdk/package.json", '{"name": "ash-cdk"}\n')
    _write(code, "deploy/cdk/src/ash-scan-step.ts", STEP_SOURCE)
    _write(
        code, "deploy/cdk/node_modules/x/index.ts", "export interface OtherProps {}\n"
    )
    return root, code


CLEAN_TS = f"""# Construct

{FENCE}ts
import {{ ASHScanStep, ASHInstallMode }} from 'ash-cdk';

new ASHScanStep('SecurityScan', {{
  input,
  shardCount: 4,
  installMode: ASHInstallMode.PREINSTALLED,
  buildImage: codebuild.LinuxBuildImage.fromEcrRepository(repo, 'latest'),
}});
new CodePipeline(this, 'Pipeline', {{ synth: step, anything: 1 }});
{FENCE}
"""

TS_DEFECTS = [
    (
        "unknown prop",
        f"{FENCE}ts\nnew ASHScanStep('Scan', {{\n  input: source,\n  shardCont: 4,\n}});\n{FENCE}\n",
        "'shardCont', which ASHScanStepProps",
        4,
    ),
    (
        "unknown enum member",
        f"{FENCE}typescript\nnew ASHScanStep('Scan', {{ input, installMode: ASHInstallMode.PREINSTALED }});\n{FENCE}\n",
        "ASHInstallMode has no member PREINSTALED",
        2,
    ),
]


@pytest.mark.integration
def test_typescript_blocks_pass_with_declared_props(construct):
    root, code = construct
    assert _check(root, CLEAN_TS, rel="deploy/cdk/README.md", code=code) == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "case,text,expected,line", TS_DEFECTS, ids=[c[0] for c in TS_DEFECTS]
)
def test_typescript_blocks_can_fail(construct, case, text, expected, line):
    root, code = construct
    _assert_reports(
        _check(root, text, rel="deploy/cdk/README.md", code=code), expected, line
    )


@pytest.mark.integration
def test_the_real_construct_readme_names_declared_props():
    """The README's blocks are read against the real construct, and they call it."""
    readme = REPO_ROOT / "deploy" / "cdk-constructs" / "README.md"
    page = dc.parse_page(readme, REPO_ROOT)
    calls = dc.typescript_calls(page, REPO_ROOT)
    assert len(calls) >= 3, calls
    assert dc.check_cli([readme], REPO_ROOT) == []
