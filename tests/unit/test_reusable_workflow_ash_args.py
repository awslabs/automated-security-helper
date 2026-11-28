# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reusable workflow's ash-args holds options only.

Why this file exists
--------------------
The Run ASH step of run-ash-security-scan.yml passes its own options first
(--source-dir, --output-dir, --fail-on-findings, --mode, --changed-files-only and
--base-ref) and ash-args after them. `ash` is a click group whose callback is the scan
(cli/main.py) and which returns early when a subcommand is invoked (cli/scan.py). Click
reads the first bare word after the group's options as the name of a subcommand. So
a bare word in ash-args such as `scan` would select a subcommand that gets the
caller's words alone, without the workflow's --output-dir, --fail-on-findings and
--changed-files-only; the step refuses it, so the scan always runs with the
workflow's output directory and its findings gate. A bare word after a flag
(`--verbose scan`) is a subcommand name just the same.

Refusing every word that names a subcommand, wherever it stands, would refuse
option values too, which click reads as values, not commands: `--phases` is a
choice of convert, scan, report and inspect (cli/scan.py), so `--phases scan --phases
report` would be refused, as would `--output-dir report`, `--base-ref merge` and
`--config config`. The step reads the words as click does: the word after an option that
takes a value is that option's value (`--phases scan`, `-c config`; for clustered short
options, the first letter that takes a value takes the rest of the word, or the next
word when it is last), and every other word must be an option.

What is asserted
----------------
* An ash-args holding a bare word, one that is neither an option nor an option's
  value, fails the step with exactly one `::` line before uvx starts, whatever the word
  names: a subcommand after a flag (`--verbose scan`), every subcommand ash registers,
  a word after `--phases scan`, and `--` (after which click reads every word as bare).
* An option that takes a value, with no word after it (`--config`, `-vc`,
  `--source-dir`), fails the step the same way: passed on, it would take the next option
  the step adds as its value.
* `--cli-json-input`, written either way, fails the step the same way, named by the
  position of its word: it hands `ash scan fs` a document of parameters, and the step
  checks ash-args word by word, so a mode, a directory or a workspace set inside the
  document would reach ASH past every check the step makes. The word after another
  option that takes a value is that value, though it is spelled `--cli-json-input`.
* Options whose values name a subcommand reach uvx unchanged, after the workflow's own
  options, and ash's own CLI parses that command line, strictly as a run does (an
  option the command lacks, or a value its type refuses, is a failure here too), as the
  scan with the workflow's options: no subcommand, --fail-on-findings set, the checkout
  as the directory.
* What the workflow adds from its own inputs (--config, --verbose, --changed-files-only
  with --base-ref, and the three --config-overrides of the betterleaks switch) reaches
  uvx in order and is parsed by `ash` and by `ash scan fs` alike.
* A directory named in ash-args (`--source-dir sub`) is the directory scanned, on both
  spellings.
* A workspace named in ash-args (`--workspace FILE`, with `--workspace-config`) goes to
  the `workspace` subject of an ASH whose help for it names it: the step runs `ash scan
  workspace FILE` with the workflow's options, and this tree's own CLI reads that
  command line strictly, as the scan of that workspace with its policy file. An ASH
  that does not have the subject keeps ash-args as it was written, on the spelling it
  has, where `ash scan fs` refuses `--workspace` by name or hands it on to the engine;
  it is never dropped. A workspace named beside a directory, an image or a clone is not
  routed either: the options stay as written, for ASH to refuse. What else names what is
  scanned and which `fs` takes beside its PATH (`--source-git`) is refused by `fs` or
  handed on to the engine as it was typed, and never dropped.
  tests/unit/test_reusable_workflow_scan_subject.py holds the rest of the routing, the
  image and git subjects among it.
* The step's list of options that take a value is the `ash` group's and `ash scan fs`'s:
  every option that is not a flag or a count, long and short spellings, each taking one
  word. `ash scan fs` takes two the group does not, `--archive` and `--cli-json-input`.
  The scan step refuses the second by name, so a document of parameters cannot come in
  through ash-args; it stays in the list so that the step that reads the effective mode
  skips its value, as click does. It has no short spelling for the refusal to miss.
* Click does read a bare word after the options as a subcommand, and a word after a
  value-taking option as its value (a control on ASH's own CLI).
* An ASH that has the `fs` subject (3.9 and later) scans the checkout as the path of
  `ash scan fs`, so its log carries no deprecation line for the subject-less form;
  the step asks that ASH's `ash scan fs --help`, with color off, before it scans. An
  ASH whose help does not name `scan fs` (an older release that ash-version names), or
  that refuses the word, gets the command line it always got, and a help that cannot be
  read never makes the step scan with the newer spelling.

What it does not cover
----------------------
ash-args is split by `read -r -a`, which reads its first line only; a second line is
dropped, not passed.

The engine is replaced by a recorder where a test runs `ash scan fs`: it is the
command's own parsing and refusals that are read, and nothing is scanned.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import typer
import yaml

# Typer 0.27 vendors click as ``typer._click``, so the usage errors of ASH's commands
# are that copy's, not the ``click`` package's.
from typer._click.exceptions import UsageError

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.utils.workflow_one_line import COMMAND_TEXT, command_lines, write_helper

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]


def _run_ash_step() -> dict:
    steps = _steps()
    matches = [step for step in steps if step.get("name") == "Run ASH"]
    assert len(matches) == 1, f"expected one Run ASH step, found {len(matches)}"
    return matches[0]


#: What the step passes before ash-args, with the env values _run gives it.
_OWN_OPTIONS = [
    "--reinstall",
    "--from",
    "ash-source",
    "ash",
    "--source-dir",
    ".",
    "--output-dir",
    "out",
    "--no-progress",
    "--fail-on-findings",
    "--build-target",
    "ci",
    "--mode",
    "local",
]


#: What the step passes before ash-args to an ASH that has the `fs` subject.
_SUBJECT_OPTIONS = [
    "--reinstall",
    "--from",
    "ash-source",
    "ash",
    "scan",
    "fs",
    ".",
    "--output-dir",
    "out",
    "--no-progress",
    "--fail-on-findings",
    "--build-target",
    "ci",
    "--mode",
    "local",
]
#: The first lines `ash scan fs --help` prints, from an ASH with the subject and from
#: one without it (which prints its subject-less scan's help, as click reads --help
#: before it refuses `fs` as an extra argument). With NO_COLOR set, as the step asks, it
#: prints the first; in a terminal that takes color it puts the codes rich writes around
#: each part of the usage line, which fall between the words `scan` and `fs`.
SUBJECT_HELP = (
    "\n Usage: ash scan fs [OPTIONS] [PATH]\n\n"
    " Scan a directory for code, infrastructure, secrets, and dependency findings.\n"
)
SUBJECT_HELP_IN_COLOR = (
    "\n \x1b[33mUsage:\x1b[0m \x1b[1mash scan\x1b[0m \x1b[1mfs\x1b[0m [OPTIONS] [PATH]\n\n"
    " Scan a directory for code, infrastructure, secrets, and dependency findings.\n"
)
#: The help of an ASH that has the `workspace` subject as well as `fs`. The stand-in
#: prints one text for every probe, so this one names both subjects: the probe for `fs`
#: finds `scan fs` in it, and the probe for `workspace` finds `scan workspace`.
SUBJECTS_HELP = (
    "\n Usage: ash scan fs [OPTIONS] [PATH]\n\n"
    " Usage: ash scan workspace [OPTIONS] {FILE}\n"
)
OLDER_HELP = (
    "\n Usage: ash scan [OPTIONS]\n\n"
    " Scan code, infrastructure, secrets, dependencies.\n"
)
#: What an ASH older than 3.9 prints when it refuses the extra word: a usage error. ASH
#: 3.8 exits 5 with it, as with every usage error, and an ASH before 3.8 exits 2.
OLDER_REFUSAL = (
    "Usage: ash scan [OPTIONS]\n"
    "Try 'ash scan --help' for help.\n\n"
    "Error: Got unexpected extra argument (fs)\n"
)

#: The values of the step's own inputs that `_run` leaves empty: the flags it adds from
#: `verbose` and `changed-files-only`, the config, and the betterleaks switch. The base
#: is not ASH's own default (`origin/main`), so a parse that read it back would show it
#: came from the command line.
_ALL_INPUTS = {
    "VERBOSE": "--verbose",
    "CHANGED_FILES_ONLY": "--changed-files-only",
    "BASE_REF": "origin/release",
    "ASH_CONFIG": "ash.yaml",
    "USE_BETTERLEAKS": "true",
}
#: What those inputs add: the first group right after the workflow's own options, in the
#: order the step writes them, and the three overrides of the betterleaks switch after
#: ash-args.
_INPUT_FLAGS = [
    "--config",
    "ash.yaml",
    "--verbose",
    "--changed-files-only",
    "--base-ref",
    "origin/release",
]
_BETTERLEAKS_OVERRIDES = [
    "ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_betterleaks_plugins]",
    "scanners.betterleaks.enabled=true",
    "scanners.gitleaks.enabled=false",
]
_BETTERLEAKS_FLAGS = [
    word
    for override in _BETTERLEAKS_OVERRIDES
    for word in ("--config-overrides", override)
]


def _without_no_config(argv: list[str]) -> list[str]:
    """*argv* without uv's --no-config, wherever it stands before `ash`.

    Every uvx call of the workflow carries it, which
    tests/unit/test_reusable_workflow_scan_subject.py holds; the rows here read the
    rest of the call: uvx's install options and the words ASH is given.
    """
    command = argv.index("ash") if "ash" in argv else len(argv)
    return [word for word in argv[:command] if word != "--no-config"] + argv[command:]


def _run(
    tmp_path: Path,
    ash_args: str,
    help_text: str = "",
    help_exit: int = 0,
    *,
    in_color: str | None = None,
    inputs: dict[str, str] | None = None,
):
    """Run the step's script with a uvx that records its argv; return (result, argv).

    A call whose last word is ``--help`` is the step asking which spelling the ASH it
    installed reads: the stand-in prints ``help_text``, or ``in_color`` (the same text
    unless given) when NO_COLOR is not set, exits ``help_exit``, and writes the
    directory it was started in to ``uvx-help-cwd``. Any other call is the scan, whose
    argv is returned without uv's --no-config (``_without_no_config``). ``inputs``
    gives the step's own inputs a value on top of the ones
    left empty (VERBOSE, CHANGED_FILES_ONLY, BASE_REF), as ASH_CONFIG and
    USE_BETTERLEAKS, which are not set at all otherwise.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "uvx-argv"
    help_file = tmp_path / "uvx-help.txt"
    help_file.write_text(help_text, encoding="utf-8")
    color_file = tmp_path / "uvx-help-in-color.txt"
    color_file.write_text(help_text if in_color is None else in_color, encoding="utf-8")
    help_cwd = tmp_path / "uvx-help-cwd"
    uvx = bin_dir / "uvx"
    uvx.write_text(
        "#!/bin/sh\n"
        "for last; do :; done\n"
        'if [ "${last:-}" = "--help" ]; then\n'
        f'  pwd > "{help_cwd}"\n'
        '  if [ -n "${NO_COLOR:-}" ]; then\n'
        f'    cat "{help_file}"\n'
        "  else\n"
        f'    cat "{color_file}"\n'
        "  fi\n"
        f"  exit {help_exit}\n"
        "fi\n"
        f'printf "%s\\n" "$@" > "{calls}"\n',
        encoding="utf-8",
    )
    uvx.chmod(0o755)
    # The job's definer runs before this step does, into the same RUNNER_TEMP.
    runner_temp = tmp_path / "runner_temp"
    write_helper(_steps(), runner_temp)
    result = subprocess.run(
        [
            shutil.which("bash") or "bash",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _run_ash_step()["run"],
        ],
        cwd=tmp_path,
        env={
            "PATH": os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"]),
            "HOME": str(tmp_path),
            "RUNNER_TEMP": str(runner_temp),
            "ASH_UVX_SOURCE": "ash-source",
            "ASH_OUTPUT_DIR": "out",
            "ASH_MODE": "local",
            "ASH_ARGS": ash_args,
            "FAIL_ON_FINDINGS_PARAM": "--fail-on-findings",
            "VERBOSE": "",
            "CHANGED_FILES_ONLY": "",
            "BASE_REF": "",
            **(inputs or {}),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    argv = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else None
    return result, None if argv is None else _without_no_config(argv)


posix_only = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the step's bash script, which the workflow runs on Linux",
)


def _assert_refused(result, argv) -> None:
    message = result.stdout + result.stderr
    assert result.returncode != 0, message
    assert argv is None, f"uvx ran with {argv}"
    commands = [line for line in message.splitlines() if line.startswith("::")]
    assert len(commands) == 1 and commands[0].startswith("::error::"), commands
    assert "ash-args" in commands[0], commands


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args",
    [
        "scan",
        "scan --mode local",
        "report",
        "not-an-option",
        "--verbose scan",
        "-v scan",
        "-vp report",
        "--exclude-scanners grype merge",
        "--progress mcp --verbose",
        "--phases scan report",
        "--output-dir=out report",
        "-cconfig inspect",
        "-",
        "--",
        "-- --verbose",
        "--verbose --",
        "--phases scan -- scan",
    ],
)
def test_a_bare_word_is_refused(tmp_path, ash_args):
    result, argv = _run(tmp_path, ash_args)
    _assert_refused(result, argv)


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args",
    ["--verbose scan" + COMMAND_TEXT, "--verbose -- scan" + COMMAND_TEXT],
    ids=["bare-word", "after-dashdash"],
)
def test_a_refused_word_cannot_add_a_workflow_command(tmp_path, ash_args):
    """The refusal names the word by its position; the word itself is not printed.

    Counted the way the runner reads lines: at CR as well as LF, and `##[` anywhere.
    """
    result, argv = _run(tmp_path, ash_args)

    _assert_refused(result, argv)
    (line,) = command_lines(result.stdout + result.stderr)
    assert line.startswith("::error::ash-args word "), line


@pytest.mark.integration
@posix_only
def test_the_dashdash_refusal_says_what_click_does(tmp_path):
    """After `--` click reads the next word as the subcommand, the rest as its args."""
    result, argv = _run(tmp_path, "--verbose -- scan")
    _assert_refused(result, argv)
    message = result.stdout + result.stderr
    assert "the next word" in message and "every word" not in message, message


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args, position",
    [
        ("--config", 1),
        ("--verbose -c", 2),
        ("--exclude-scanners grype --phases", 3),
        # A cluster whose last letter takes a value.
        ("-vc", 1),
        ("--source-dir", 1),
        ("--verbose --source-dir", 2),
    ],
)
def test_an_option_with_no_value_after_it_is_refused(tmp_path, ash_args, position):
    """Passed on, it would take the next option the step adds as its value.

    With use-betterleaks on that is `--config-overrides`, and ASH would refuse the word
    after it for the wrong reason. The step refuses the option itself, by position as
    it refuses a bare word, before it runs anything.
    """
    result, argv = _run(tmp_path, ash_args)

    _assert_refused(result, argv)
    (command,) = command_lines(result.stdout + result.stderr)
    assert command.startswith(f"::error::ash-args word {position} is "), command


def _ash_group():
    from automated_security_helper.cli.main import app

    return typer.main.get_command(app)


@pytest.mark.integration
@posix_only
def test_every_subcommand_after_a_flag_is_refused(tmp_path):
    for index, name in enumerate(sorted(_ash_group().commands)):
        run_dir = tmp_path / str(index)
        run_dir.mkdir()
        result, argv = _run(run_dir, f"--verbose {name}")
        _assert_refused(result, argv)


#: Option values that name a subcommand, which click reads as values.
_VALUES_NAMING_A_SUBCOMMAND = [
    "--phases scan --phases report --scanners detect-secrets",
    "--phases inspect",
    "--output-dir report",
    "--base-ref merge",
    "--config config",
    "-c config",
    "-vc config",
    "-f sarif --exclude-scanners scan",
    "-fsarif",
    "-u 1000 -g 1000",
    "--verbose --phases=report --phases convert",
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args",
    [
        "",
        "--exclude-scanners grype",
        "--mode=local --verbose",
        "--config .ash.yaml --exclude-scanners npm-audit",
        "--workspace services.code-workspace --workspace-config policy.yaml",
        *_VALUES_NAMING_A_SUBCOMMAND,
    ],
)
def test_options_reach_uvx_after_the_workflows_own(tmp_path, ash_args):
    result, argv = _run(tmp_path, ash_args)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _OWN_OPTIONS + ash_args.split(), argv


def _fs():
    """The `fs` subject of `ash scan`: the command the step's scan runs on ASH 3.9."""
    return _ash_group().commands["scan"].commands["fs"]


def _workspace():
    """The `workspace` subject of `ash scan`: the command the step's scan runs when
    ash-args names a workspace and the ASH has the subject."""
    return _ash_group().commands["scan"].commands["workspace"]


def _parse(ash_argv: list[str], *, strict: bool = True):
    """ASH's own CLI parsing a command line: (subcommand or None, params).

    Strict, as a run parses it: an option the group lacks, or a value its type refuses,
    raises. Not strict, it is click reading the grammar alone, which the tests of the
    step's reading of words use: they give it a word that is no valid value on purpose
    (``--mode --verbose``), to see that click takes it as the value all the same.
    """
    context = _ash_group().make_context(
        "ash", list(ash_argv), resilient_parsing=not strict
    )
    protected = getattr(context, "_protected_args", None)
    if protected is None:
        protected = context.protected_args
    rest = [*protected, *context.args]
    return (rest[0] if rest else None), context.params


def _parse_fs(after_fs: list[str]):
    """The parameters `ash scan fs` reads from the words after `fs`, strictly."""
    return _fs().make_context("fs", list(after_fs)).params


def _ash_words(argv: list[str]) -> list[str]:
    """What `ash` itself is given in the uvx call: the words after the command."""
    return argv[argv.index("ash") + 1 :]


def _runs_the_fs_subject(words: list[str]) -> bool:
    return words[:2] == ["scan", "fs"]


def _runs_the_workspace_subject(words: list[str]) -> bool:
    return words[:2] == ["scan", "workspace"]


def _hand_to_the_engine(after_name: list[str], monkeypatch, command=None) -> dict:
    """Run `ash scan fs`, or the subject *command*, on its words with the engine
    replaced by a recorder.

    Returns the keywords the engine is handed, or raises the usage error the command
    refuses with: an option it lacks, a value its type refuses, a directory named twice.
    Nothing is scanned: the command's own parsing and refusals are what is read.
    """
    from automated_security_helper.cli import scan_group

    handed: dict = {}

    def engine(*_args, **kwargs):
        handed.update(kwargs)

    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", engine)
    command = _fs() if command is None else command
    command.main(
        args=list(after_name),
        prog_name=f"ash scan {command.name}",
        standalone_mode=False,
    )
    return handed


def _what_the_scan_is_given(argv: list[str], monkeypatch) -> dict:
    """What the scan of a uvx call is given, by the spelling it runs: the keywords the
    engine is handed by `ash scan fs` or by `ash scan workspace`, or the parameters the
    `ash` group parses."""
    words = _ash_words(argv)
    if _runs_the_fs_subject(words):
        return _hand_to_the_engine(words[2:], monkeypatch)
    if _runs_the_workspace_subject(words):
        return _hand_to_the_engine(words[2:], monkeypatch, _workspace())
    subcommand, params = _parse(words)
    assert subcommand is None, f"click runs {subcommand!r} for {argv}"
    return params


@pytest.mark.unit
def test_the_parse_is_strict():
    """The control for every parse below: an option the command lacks and a value its
    type refuses fail the parse, where resilient parsing reads both as a pass.

    The root group prints a usage error and exits with the usage-error code; `ash scan
    fs` raises it.
    """
    with pytest.raises(typer.Exit) as refused:
        _parse(["--no-such-option"])
    assert refused.value.exit_code == ASH_EXIT_USAGE_ERROR
    with pytest.raises(typer.Exit) as refused:
        _parse(["--phases", "not-a-phase"])
    assert refused.value.exit_code == ASH_EXIT_USAGE_ERROR
    with pytest.raises(UsageError, match="--no-such-option"):
        _parse_fs([".", "--no-such-option"])
    with pytest.raises(UsageError, match="not-a-phase"):
        _parse_fs([".", "--phases", "not-a-phase"])
    # What the grammar tests use on purpose: the same words, read without refusing.
    assert _parse(["--no-such-option"], strict=False)[0] is None


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("ash_args", _VALUES_NAMING_A_SUBCOMMAND)
def test_ash_runs_the_scan_with_the_workflows_options(tmp_path, ash_args):
    result, argv = _run(tmp_path, ash_args)
    assert result.returncode == 0, result.stdout + result.stderr

    subcommand, params = _parse(_ash_words(argv))

    assert subcommand is None, f"click runs {subcommand!r} for {argv}"
    assert params["fail_on_findings"] is True, params
    assert params["source_dir"] == ".", params
    assert params["build_target"] == "ci", params


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    "ash_args", ["", "--exclude-scanners grype", *_VALUES_NAMING_A_SUBCOMMAND]
)
def test_an_ash_with_the_fs_subject_scans_the_checkout_as_its_path(
    tmp_path, monkeypatch, ash_args
):
    """ASH 3.9 and later print a deprecation line for the subject-less scan (bare
    `ash` with --source-dir), so an ASH whose help names `scan fs` is run as
    `ash scan fs .`, and its own CLI reads that as the fs scan of the checkout with
    the workflow's options. The help it is asked is the one a terminal that takes color
    would color, so this holds only when the step has color off or strips it."""
    monkeypatch.delenv("ASH_SOURCE_DIR", raising=False)
    result, argv = _run(
        tmp_path, ash_args, help_text=SUBJECT_HELP, in_color=SUBJECT_HELP_IN_COLOR
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _SUBJECT_OPTIONS + ash_args.split(), argv
    words = _ash_words(argv)
    assert _runs_the_fs_subject(words), words
    params = _parse_fs(words[2:])
    assert params["path"] == ".", params
    assert params["source_dir"] is None, params
    assert params["fail_on_findings"] is True, params
    assert params["build_target"] == "ci", params


@pytest.mark.integration
@posix_only
def test_the_help_is_asked_outside_the_checkout(tmp_path):
    """The install preflight asks `ash scan fs --help` from RUNNER_TEMP, with no
    config of the scanned repository to read, and the step asks it the same way."""
    result, argv = _run(tmp_path, "", help_text=SUBJECT_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "uvx-help-cwd").read_text(encoding="utf-8").strip() == str(
        tmp_path / "runner_temp"
    )


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    ("help_text", "help_exit"),
    [(OLDER_HELP, 0), ("", 0), (OLDER_REFUSAL, 5), (OLDER_REFUSAL, 2)],
    ids=[
        "an-older-ash",
        "no-help",
        "an-ash-3.8-refuses-fs",
        "an-ash-before-3.8-refuses-fs",
    ],
)
def test_an_ash_without_the_fs_subject_gets_the_command_line_it_always_got(
    tmp_path, help_text, help_exit
):
    """ash-version can name an ASH older than 3.9, which has no `fs` subject; a help
    that does not name it, or the usage error that refuses the word, gives the
    spelling every ASH reads."""
    result, argv = _run(tmp_path, "--verbose", help_text=help_text, help_exit=help_exit)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _OWN_OPTIONS + ["--verbose"], argv


@pytest.mark.integration
@posix_only
def test_a_help_that_fails_never_picks_the_newer_spelling(tmp_path):
    """A help that cannot be read says nothing about the ASH. The step either runs the
    scan with the spelling every ASH reads or stops before uvx scans: it never takes
    the newer one on a guess, which an ASH older than 3.9 would refuse."""
    result, argv = _run(tmp_path, "--verbose", help_text=SUBJECT_HELP, help_exit=1)

    if result.returncode == 0:
        assert argv == _OWN_OPTIONS + ["--verbose"], argv
    else:
        assert argv is None, f"uvx scanned with {argv}"
        assert "::error::" in result.stdout + result.stderr


_BOTH_SPELLINGS = pytest.mark.parametrize(
    ("help_text", "own"),
    [(OLDER_HELP, _OWN_OPTIONS), (SUBJECT_HELP, _SUBJECT_OPTIONS)],
    ids=["older", "fs"],
)


@pytest.mark.integration
@posix_only
@_BOTH_SPELLINGS
@pytest.mark.parametrize("ash_args", ["", "--exclude-scanners grype"])
def test_the_workflows_own_inputs_reach_ash_in_order_on_both_spellings(
    tmp_path, monkeypatch, help_text, own, ash_args
):
    """The inputs the other cases leave empty: the config, `verbose`, `changed-files-only`
    with its base, and the betterleaks switch. Each is passed where the step writes it,
    and each is read by `ash` and by `ash scan fs` as the option it is."""
    result, argv = _run(tmp_path, ash_args, help_text=help_text, inputs=_ALL_INPUTS)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == own + _INPUT_FLAGS + ash_args.split() + _BETTERLEAKS_FLAGS, argv
    given = _what_the_scan_is_given(argv, monkeypatch)
    assert given["config"] == "ash.yaml", given
    assert given["verbose"] is True, given
    assert given["changed_files_only"] is True, given
    assert given["base_ref"] == "origin/release", given
    assert list(given["config_overrides"]) == _BETTERLEAKS_OVERRIDES, given
    assert given["source_dir"] == ".", given
    assert given["fail_on_findings"] is True, given


#: What a caller can put in ash-args to name the directory scanned, with the directory
#: it names. The workflow names the checkout, `.`, when ash-args does not.
_DIRECTORY_IN_ASH_ARGS = [
    ("", "."),
    ("--source-dir .", "."),
    ("--source-dir sub", "sub"),
    ("--source-dir=sub", "sub"),
    ("--verbose --source-dir sub --exclude-scanners grype", "sub"),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("help_text", [OLDER_HELP, SUBJECT_HELP], ids=["older", "fs"])
@pytest.mark.parametrize(("ash_args", "directory"), _DIRECTORY_IN_ASH_ARGS)
def test_the_directory_a_caller_names_is_the_directory_scanned(
    tmp_path, monkeypatch, help_text, ash_args, directory
):
    """A --source-dir in ash-args names the directory the scan scans, as it always has:
    the step passed its own `--source-dir .` ahead of ash-args and click kept the last
    value. `ash scan fs` takes the directory as its PATH and refuses a --source-dir
    that names another one ("Name the directory once"), so on that spelling the
    directory has to be named once, by the step, whichever way the caller named it."""
    result, argv = _run(tmp_path, ash_args, help_text=help_text)

    assert result.returncode == 0, result.stdout + result.stderr
    assert _what_the_scan_is_given(argv, monkeypatch)["source_dir"] == directory, argv


_WORKSPACE = "services.code-workspace"
_CLONE = "https://example.invalid/repo.git"


@pytest.mark.integration
@posix_only
@_BOTH_SPELLINGS
def test_a_workspace_in_ash_args_is_refused_or_handed_on_never_dropped(
    tmp_path, monkeypatch, help_text, own
):
    """--workspace is an option that takes a value, so it reaches uvx as the caller typed
    it. A scan of the checkout is not a scan of a workspace: `ash` refuses the pair
    (--workspace and --source-dir are exclusive) once the engine has it, and `ash scan
    fs` either takes the option and hands it on to the same refusal or refuses it as an
    option it does not have. It is not left out of the scan. The ASH here has no
    `workspace` subject (its help names `scan fs` and no other), so the step leaves the
    option as typed; the tests below are for an ASH that has it."""
    result, argv = _run(tmp_path, f"--workspace {_WORKSPACE}", help_text=help_text)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == own + ["--workspace", _WORKSPACE], argv
    try:
        given = _what_the_scan_is_given(argv, monkeypatch)
    except UsageError as refusal:
        assert "--workspace" in str(refusal), refusal
    except typer.Exit as refusal:
        # The root group prints a usage error and exits with the usage-error code.
        assert refusal.exit_code == ASH_EXIT_USAGE_ERROR, refusal
    else:
        assert given["workspace"] == _WORKSPACE, given


#: What the step passes before ash-args to an ASH that has the `workspace` subject, for
#: a workspace named in ash-args: the file comes right after the subject's name.
_WORKSPACE_OPTIONS = [
    "--reinstall",
    "--from",
    "ash-source",
    "ash",
    "scan",
    "workspace",
    _WORKSPACE,
    "--output-dir",
    "out",
    "--no-progress",
    "--fail-on-findings",
    "--build-target",
    "ci",
    "--mode",
    "local",
]


@pytest.mark.integration
@posix_only
def test_a_workspace_in_ash_args_goes_to_the_workspace_subject_of_an_ash_with_it(
    tmp_path, monkeypatch
):
    """The strict reading of the test above, for an ASH whose help names the subject:
    the workspace is scanned, not refused and not dropped. The step runs `ash scan
    workspace FILE` with its own options, and this tree's CLI reads that command line
    strictly (an option the subject lacks, or a value its type refuses, fails here), as
    the scan of that workspace with its policy file, behind the workflow's findings
    gate."""
    result, argv = _run(
        tmp_path,
        f"--workspace {_WORKSPACE} --workspace-config policy.yaml",
        help_text=SUBJECTS_HELP,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _WORKSPACE_OPTIONS + ["--workspace-config", "policy.yaml"], argv
    # The subject is asked as `fs` is: from RUNNER_TEMP.
    assert (tmp_path / "uvx-help-cwd").read_text(encoding="utf-8").strip() == str(
        tmp_path / "runner_temp"
    )
    given = _what_the_scan_is_given(argv, monkeypatch)
    assert given["workspace"] == _WORKSPACE, given
    assert given["workspace_config"] == "policy.yaml", given
    assert given["fail_on_findings"] is True, given


def _fs_options_for(directory: str) -> list[str]:
    """What the step passes before ash-args to an ASH that has the `fs` subject, for
    the directory *directory*."""
    return [*_SUBJECT_OPTIONS[:6], directory, *_SUBJECT_OPTIONS[7:]]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize(
    ("ash_args", "directory", "words", "refused"),
    [
        pytest.param(
            f"--source-dir sub --workspace {_WORKSPACE}",
            "sub",
            ["--workspace", _WORKSPACE],
            "--workspace",
            id="a-directory-and-a-workspace",
        ),
        pytest.param(
            f"--workspace {_WORKSPACE} --source-git {_CLONE}",
            ".",
            ["--workspace", _WORKSPACE, "--source-git", _CLONE],
            "--workspace",
            id="a-workspace-and-a-clone",
        ),
    ],
)
def test_a_workspace_named_with_something_else_is_left_for_fs_to_refuse(
    tmp_path, monkeypatch, ash_args, directory, words, refused
):
    """No scan has a directory or a clone and a workspace, so the step does not take
    the workspace for the subject of an ASH that has it: the words stay as typed on
    `ash scan fs`, which refuses the one it lacks by name. Nothing is dropped, and
    nothing scans one of the two in place of both."""
    result, argv = _run(tmp_path, ash_args, help_text=SUBJECTS_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _fs_options_for(directory) + words, argv
    with pytest.raises(UsageError, match=refused):
        _what_the_scan_is_given(argv, monkeypatch)


@pytest.mark.integration
@posix_only
def test_a_source_git_in_ash_args_reaches_the_older_spelling_as_typed(
    tmp_path, monkeypatch
):
    result, argv = _run(tmp_path, f"--source-git {_CLONE}", help_text=OLDER_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _OWN_OPTIONS + ["--source-git", _CLONE], argv
    assert _what_the_scan_is_given(argv, monkeypatch)["source_git"] == _CLONE


@pytest.mark.integration
@posix_only
def test_a_source_git_in_ash_args_is_refused_beside_the_path_of_fs(
    tmp_path, monkeypatch
):
    """The clone is the directory `ash scan fs` scans, so it refuses a PATH beside
    --source-git, or an option it does not have: a caller's clone stops the scan with an
    error that names it, and is not scanned in place of the checkout or dropped."""
    result, argv = _run(tmp_path, f"--source-git {_CLONE}", help_text=SUBJECT_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _SUBJECT_OPTIONS + ["--source-git", _CLONE], argv
    with pytest.raises(UsageError, match="--source-git"):
        _what_the_scan_is_given(argv, monkeypatch)


def _value_option_lists() -> dict[str, set[str]]:
    """Each step's ASH_VALUE_OPTIONS, by step name.

    Run ASH reads ash-args with it, and the changed-files-only base step reads it to
    find the mode the scan runs in; each step has its own copy.
    """
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]
    lists = {}
    for step in steps:
        found = re.findall(
            r'^\s*ASH_VALUE_OPTIONS="([^"]*)"$',
            str(step.get("run") or ""),
            re.MULTILINE,
        )
        assert len(found) <= 1, (step.get("name"), found)
        if found:
            lists[step.get("name")] = set(found[0].split())
    return lists


def _value_options_in_the_step() -> set[str]:
    lists = _value_option_lists()
    assert set(lists) == {"Run ASH", "Resolve the base for changed-files-only"}, lists
    (first, second) = lists.values()
    assert first == second, "the two steps' option lists differ"
    return first


def _options_of(command) -> list:
    return [p for p in command.params if p.param_type_name == "option"]


def _takes_a_value(command) -> set[str]:
    """Every spelling of the options of ``command`` that is not a flag or a count."""
    return {
        spelling
        for option in _options_of(command)
        if not option.is_flag and not option.count
        for spelling in option.opts
    }


@pytest.mark.unit
def test_the_options_that_take_a_value_are_those_of_the_ash_group_and_the_fs_subject():
    """The step reads the options of the `ash` group, which an ASH older than 3.9 runs
    the scan with, and of `ash scan fs`, which an ASH with the subject runs it with. The
    list holds neither fewer nor more: an option it lacks has its value read as a bare
    word and refused, and one it holds that neither command takes would skip a word
    both commands read.

    `--cli-json-input` is in it, though the scan step refuses that option by name: the
    document it names would carry past the step's word-by-word checks what the words do
    not show. The step that reads the effective mode reads the same list, and skips the
    word after the option, its value, as click does."""
    assert _value_options_in_the_step() == (
        _takes_a_value(_ash_group()) | _takes_a_value(_fs())
    )
    # The step skips exactly one word after each, as click does for nargs 1; that the
    # word is skipped even when it starts with a dash is the next test's.
    assert all(option.nargs == 1 for option in _options_of(_ash_group()))
    assert all(option.nargs == 1 for option in _options_of(_fs()))


@pytest.mark.unit
def test_the_options_that_take_a_value_include_those_of_the_fs_subject():
    """ash-args goes to `ash scan fs` on an ASH that has the subject, so the step has to
    know every option that takes a value there. One it does not know would have its
    value read as a bare word and refused, though the scan takes it as the value; the
    step's reading of a cluster of short options and of `--name=value` follows from
    the same list."""
    missing = _takes_a_value(_fs()) - _value_options_in_the_step()

    assert not missing, sorted(missing)
    assert all(option.nargs == 1 for option in _options_of(_fs()))


@pytest.mark.unit
def test_the_document_option_of_fs_has_its_long_spelling_only():
    """The scan step refuses `--cli-json-input` by that one spelling, alone or with `=`.
    A short one would come in inside a cluster of short options (`-vX params.json`),
    which the step reads letter by letter and passes on, so a short spelling added to
    the option needs a refusal of its own, and this test fails first."""
    (option,) = [o for o in _options_of(_fs()) if "--cli-json-input" in o.opts]

    assert option.opts == ["--cli-json-input"], option.opts
    assert not option.secondary_opts, option.secondary_opts


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("option", ["--archive"])
def test_an_option_only_the_fs_subject_takes_keeps_its_value_in_ash_args(
    tmp_path, option
):
    """`--archive` is one of the two options `ash scan fs` takes and the `ash` group
    does not. It is in the step's list, so the word after it is its value and is passed
    on to `fs`, not refused as a bare word, as the word after any other option is. The
    other, `--cli-json-input`, is refused by name (the next test)."""
    result, argv = _run(tmp_path, f"{option} source.zip", help_text=SUBJECT_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _SUBJECT_OPTIONS + [option, "source.zip"], argv


#: --cli-json-input in ash-args, written either way and after other words, with the
#: position of the word that names it.
_DOCUMENT_OPTION_IN_ASH_ARGS = [
    ("--cli-json-input params.json", 1),
    ("--cli-json-input=params.json", 1),
    ("--exclude-scanners grype --cli-json-input params.json", 3),
    ("--verbose --cli-json-input=params.json", 2),
]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("help_text", [OLDER_HELP, SUBJECT_HELP], ids=["older", "fs"])
@pytest.mark.parametrize(("ash_args", "position"), _DOCUMENT_OPTION_IN_ASH_ARGS)
def test_a_document_of_parameters_in_ash_args_is_refused_by_name(
    tmp_path, help_text, ash_args, position
):
    """`--cli-json-input FILE` hands `ash scan fs` a JSON document of parameters, which
    the step does not read. The step checks ash-args word by word: the changed-files-only
    check reads `--mode` among the words, and the directory and the subject are taken
    from them. A mode, a directory or a workspace set inside the document would reach
    ASH past each of those checks, so the step refuses the option by name, in both
    forms, on either spelling of the scan, and starts no scan. The refusal names the
    word by its position, as the others do, and says why; the value is the caller's and
    is not printed."""
    result, argv = _run(tmp_path, ash_args, help_text=help_text)

    assert result.returncode == 1, result.stdout + result.stderr
    _assert_refused(result, argv)
    output = result.stdout + result.stderr
    (command,) = command_lines(output)
    assert command.startswith(f"::error::ash-args word {position} "), command
    assert "--cli-json-input" in command, command
    assert "a document of parameters" in command, command
    assert "word by word" in command, command
    assert "params.json" not in output, output


@pytest.mark.integration
@posix_only
def test_a_value_spelled_like_the_document_option_is_that_value(tmp_path):
    """The control of the refusal above: the word after an option that takes a value is
    that value, as click reads it, so `--config --cli-json-input` names a config file
    and no document. The step refuses the option, not its spelling."""
    result, argv = _run(tmp_path, "--config --cli-json-input", help_text=SUBJECT_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _SUBJECT_OPTIONS + ["--config", "--cli-json-input"], argv


@pytest.mark.integration
@posix_only
def test_an_archive_in_ash_args_is_refused_beside_the_path_of_fs(tmp_path, monkeypatch):
    """The archive is the directory `ash scan fs` scans, so it refuses a PATH beside
    --archive. The step always gives the PATH, so a caller's archive stops the scan with
    an error that names it, and is not scanned in place of the checkout or dropped."""
    result, argv = _run(tmp_path, "--archive source.zip", help_text=SUBJECT_HELP)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _SUBJECT_OPTIONS + ["--archive", "source.zip"], argv
    with pytest.raises(UsageError, match="--archive"):
        _what_the_scan_is_given(argv, monkeypatch)


def _value_spellings() -> list[str]:
    return sorted(_takes_a_value(_ash_group()))


@pytest.mark.integration
@pytest.mark.parametrize("spelling", _value_spellings())
def test_a_value_option_takes_the_next_word_even_with_a_dash(tmp_path, spelling):
    """Both readings take `--phases` after a value option as its value, not an option.

    So the `scan` after it is bare: click runs it as a subcommand, and the step must
    refuse it. An option whose value were optional would stop at the dash in click
    (and the step would let `scan` through as `--phases`'s value); this measures it.
    """
    subcommand, params = _parse([spelling, "--verbose"], strict=False)
    assert subcommand is None and params["verbose"] is False, (spelling, params)
    assert _parse([spelling, "--phases", "scan"], strict=False)[0] == "scan", spelling

    result, argv = _run(tmp_path, f"{spelling} --phases scan")
    _assert_refused(result, argv)


@pytest.mark.unit
def test_the_config_option_takes_a_dash_word_as_its_value():
    """The row measured by hand: --config's value is '--verbose', and verbose is off."""
    subcommand, params = _parse(["--config", "--verbose"], strict=False)
    assert subcommand is None
    assert params["config"] == "--verbose" and params["verbose"] is False, params


@pytest.mark.unit
@pytest.mark.parametrize("command", ["ash", "fs"])
def test_every_short_option_is_one_letter(command):
    """The step reads a single-dash word letter by letter; click tries it whole first.

    click's parser matches a word such as `-dc` against the option names before it
    splits it into `-d` and `-c`, so a two-letter short option `-dc` would be taken
    whole, while the step would read `-c` and skip the next word as its value: a
    subcommand there would run. Every single-dash spelling must be one letter for
    the two readings to agree, on the `ash` group and on `ash scan fs`, which the
    step's scan runs on an ASH that has the subject.
    """
    spellings = [
        spelling
        for option in _options_of(_ash_group() if command == "ash" else _fs())
        for spelling in [*option.opts, *option.secondary_opts]
        if not spelling.startswith("--")
    ]

    assert spellings, f"{command} has no short options to check"
    longer = sorted(spelling for spelling in spellings if len(spelling) != 2)
    assert not longer, f"short options longer than one letter: {longer}"


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv, subcommand",
    [
        (["--source-dir", ".", "--fail-on-findings", "scan"], "scan"),
        (["--fail-on-findings", "--verbose", "report"], "report"),
        (["--fail-on-findings", "--exclude-scanners", "grype", "merge"], "merge"),
        (["--fail-on-findings", "--exclude-scanners", "grype"], None),
        (["--fail-on-findings", "--phases", "scan"], None),
        (["--fail-on-findings", "-vc", "config"], None),
        (["--fail-on-findings", "--", "--verbose"], "--verbose"),
    ],
)
def test_click_reads_bare_words_as_subcommands_and_values_as_values(argv, subcommand):
    """Control on ASH's own CLI: the premise of the step's reading."""
    assert _parse(argv, strict=False)[0] == subcommand
