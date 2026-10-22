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
* Options whose values name a subcommand reach uvx unchanged, after the workflow's own
  options, and ash's own CLI parses that command line as the scan with the workflow's
  options: no subcommand, --fail-on-findings set, --source-dir `.`.
* The step's list of options that take a value is the `ash` group's: every option that
  is not a flag or a count, long and short spellings, each taking one word.
* Click does read a bare word after the options as a subcommand, and a word after a
  value-taking option as its value (a control on ASH's own CLI).

What it does not cover
----------------------
ash-args is split by `read -r -a`, which reads its first line only; a second line is
dropped, not passed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

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


def _run(tmp_path: Path, ash_args: str):
    """Run the step's script with a uvx that records its argv; return (result, argv)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "uvx-argv"
    uvx = bin_dir / "uvx"
    uvx.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{calls}"\n', encoding="utf-8")
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
        },
        capture_output=True,
        text=True,
        check=False,
    )
    argv = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else None
    return result, argv


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


@posix_only
def test_the_dashdash_refusal_says_what_click_does(tmp_path):
    """After `--` click reads the next word as the subcommand, the rest as its args."""
    result, argv = _run(tmp_path, "--verbose -- scan")
    _assert_refused(result, argv)
    message = result.stdout + result.stderr
    assert "the next word" in message and "every word" not in message, message


def _ash_group():
    import typer.main

    from automated_security_helper.cli.main import app

    return typer.main.get_command(app)


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


@posix_only
@pytest.mark.parametrize(
    "ash_args",
    [
        "",
        "--exclude-scanners grype",
        "--mode=local --verbose",
        "--config .ash/.ash.yaml --exclude-scanners npm-audit",
        *_VALUES_NAMING_A_SUBCOMMAND,
    ],
)
def test_options_reach_uvx_after_the_workflows_own(tmp_path, ash_args):
    result, argv = _run(tmp_path, ash_args)

    assert result.returncode == 0, result.stdout + result.stderr
    assert argv == _OWN_OPTIONS + ash_args.split(), argv


def _parse(ash_argv: list[str]):
    """ASH's own CLI parsing a command line: (subcommand or None, params)."""
    context = _ash_group().make_context("ash", list(ash_argv), resilient_parsing=True)
    protected = getattr(context, "_protected_args", None)
    if protected is None:
        protected = context.protected_args
    rest = [*protected, *context.args]
    return (rest[0] if rest else None), context.params


@posix_only
@pytest.mark.parametrize("ash_args", _VALUES_NAMING_A_SUBCOMMAND)
def test_ash_runs_the_scan_with_the_workflows_options(tmp_path, ash_args):
    result, argv = _run(tmp_path, ash_args)
    assert result.returncode == 0, result.stdout + result.stderr

    subcommand, params = _parse(argv[argv.index("ash") + 1 :])

    assert subcommand is None, f"click runs {subcommand!r} for {argv}"
    assert params["fail_on_findings"] is True, params
    assert params["source_dir"] == ".", params
    assert params["build_target"] == "ci", params


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


def test_the_options_that_take_a_value_are_the_ash_groups():
    options = [p for p in _ash_group().params if p.param_type_name == "option"]
    takes_a_value = {
        spelling
        for option in options
        if not option.is_flag and not option.count
        for spelling in option.opts
    }

    assert _value_options_in_the_step() == takes_a_value
    # The step skips exactly one word after each, as click does for nargs 1; that the
    # word is skipped even when it starts with a dash is the next test's.
    assert all(option.nargs == 1 for option in options)


def _value_spellings() -> list[str]:
    return sorted(
        spelling
        for option in _ash_group().params
        if option.param_type_name == "option"
        and not option.is_flag
        and not option.count
        for spelling in option.opts
    )


@pytest.mark.parametrize("spelling", _value_spellings())
def test_a_value_option_takes_the_next_word_even_with_a_dash(tmp_path, spelling):
    """Both readings take `--phases` after a value option as its value, not an option.

    So the `scan` after it is bare: click runs it as a subcommand, and the step must
    refuse it. An option whose value were optional would stop at the dash in click
    (and the step would let `scan` through as `--phases`'s value); this measures it.
    """
    subcommand, params = _parse([spelling, "--verbose"])
    assert subcommand is None and params["verbose"] is False, (spelling, params)
    assert _parse([spelling, "--phases", "scan"])[0] == "scan", spelling

    result, argv = _run(tmp_path, f"{spelling} --phases scan")
    _assert_refused(result, argv)


def test_the_config_option_takes_a_dash_word_as_its_value():
    """The row measured by hand: --config's value is '--verbose', and verbose is off."""
    subcommand, params = _parse(["--config", "--verbose"])
    assert subcommand is None
    assert params["config"] == "--verbose" and params["verbose"] is False, params


def test_every_short_option_is_one_letter():
    """The step reads a single-dash word letter by letter; click tries it whole first.

    click's parser matches a word such as `-dc` against the option names before it
    splits it into `-d` and `-c`, so a two-letter short option `-dc` would be taken
    whole, while the step would read `-c` and skip the next word as its value: a
    subcommand there would run. Every single-dash spelling must be one letter for
    the two readings to agree.
    """
    spellings = [
        spelling
        for option in _ash_group().params
        if option.param_type_name == "option"
        for spelling in [*option.opts, *option.secondary_opts]
        if not spelling.startswith("--")
    ]

    assert spellings, "the ash group has no short options to check"
    longer = sorted(spelling for spelling in spellings if len(spelling) != 2)
    assert not longer, f"short options longer than one letter: {longer}"


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
    assert _parse(argv)[0] == subcommand
