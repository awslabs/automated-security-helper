# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`./ash <subcommand>` runs the subcommand with arguments it takes.

`ash` passes options given before a subcommand on to it when it takes them and
refuses them otherwise, and `report` does not take --source-dir, so the bash
entrypoint does not put `--source-dir /src --output-dir /out` before a subcommand: it
passes the mounted paths as ASH_SOURCE_DIR and ASH_OUTPUT_DIR. CI runs
`./ash report --format text` after every bash-entrypoint scan.

A fake OCI runner stands in for docker, as in test_ash_bash_entrypoint_build_failure.py,
and prints the argv it was given.
"""

import inspect
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ASH_SCRIPT = REPO_ROOT / "ash"
IMAGE = "automated-security-helper:non-root"

pytestmark = [
    # The same reasons as test_ash_bash_entrypoint_build_failure.py: Windows runners'
    # bash is the WSL stub, and the installed-package layout has no ./ash.
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; ./ash is the POSIX entrypoint",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the entrypoint under test is bash"
    ),
    pytest.mark.skipif(
        not ASH_SCRIPT.is_file(),
        reason="repository ash entrypoint not present (installed-package layout)",
    ),
]

RECORDING_RUNNER = """#!/bin/bash
echo "FAKE-RUNNER-INVOKED-WITH: $*"
exit 0
"""


@pytest.fixture
def runner(tmp_path):
    path = tmp_path / "fake-oci-runner"
    path.write_text(RECORDING_RUNNER)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


def _run_argv(runner, tmp_path, *args, cwd=None):
    """The argv `./ash` hands the OCI runner's `run`."""
    source_dir = tmp_path / "src"
    source_dir.mkdir(exist_ok=True)
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        [
            "bash",
            str(ASH_SCRIPT),
            "--no-build",
            "--source-dir",
            str(source_dir),
            "--output-dir",
            str(tmp_path / "out"),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
        env={**os.environ, "OCI_RUNNER": str(runner)},
        timeout=180,
        check=False,
    )
    lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("FAKE-RUNNER-INVOKED-WITH: run ")
    ]
    assert len(lines) == 1, result.stdout + result.stderr
    return lines[0].split()


def _inner_argv(run_argv):
    return run_argv[run_argv.index(IMAGE) + 1 :]


#: What the entrypoint gives scan, and ash with no command named (which scans),
#: right after the command word or ahead of every word: the scan in the image never
#: sandboxes, the container is the boundary.
#: tests/unit/test_sandbox_refused_by_every_container_entrypoint.py covers why and
#: where it goes.
SANDBOX_OFF = ["--sandbox", "off"]


@pytest.mark.integration
def test_the_mounted_paths_go_in_as_environment_variables(runner, tmp_path):
    run_argv = _run_argv(runner, tmp_path, "--scanners", "bandit")

    assert "ASH_SOURCE_DIR=/src" in run_argv
    assert "ASH_OUTPUT_DIR=/out" in run_argv
    assert _inner_argv(run_argv) == ["ash", *SANDBOX_OFF, "--scanners", "bandit"]


@pytest.mark.integration
def test_a_subcommand_runs_on_its_own_arguments(runner, tmp_path):
    inner = _inner_argv(_run_argv(runner, tmp_path, "report", "--format", "text"))

    assert inner == ["ash", "report", "--format", "text"], (
        "report does not take --source-dir, so putting it before 'report' is a usage "
        f"error: {inner}"
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    "args, expected",
    [
        pytest.param(
            ["report", "--format", "text"],
            ["ash", "report", "--format", "text"],
            id="report-format",
        ),
        pytest.param(
            ["--format", "sarif"],
            ["ash", *SANDBOX_OFF, "--format", "sarif"],
            id="scan-format",
        ),
    ],
)
def test_format_reaches_ash(runner, tmp_path, args, expected):
    """--format is ash's option, for scan (its output formats) and for report.

    The entrypoint passes it to ash as given, not into ASH_OUTPUT_FORMAT, which
    nothing in ASH reads, so `./ash report --format text`, which CI runs after every
    bash-entrypoint scan, prints text.
    """
    run_argv = _run_argv(runner, tmp_path, *args)

    assert _inner_argv(run_argv) == expected
    assert not any(arg.startswith("ASH_OUTPUT_FORMAT=") for arg in run_argv)


@pytest.mark.integration
def test_an_option_before_a_subcommand_is_left_where_it_was_typed(runner, tmp_path):
    inner = _inner_argv(_run_argv(runner, tmp_path, "--verbose", "report"))

    assert inner == ["ash", "--verbose", "report"]


@pytest.mark.integration
@pytest.mark.parametrize(
    "args, expected",
    [
        pytest.param(
            ["--quiet", "scan"],
            ["ash", "--quiet", "scan", *SANDBOX_OFF],
            id="scan-takes-quiet",
        ),
        pytest.param(
            ["-q"], ["ash", "--quiet", *SANDBOX_OFF], id="bare-scan-takes-quiet"
        ),
        pytest.param(
            ["--quiet", "report"], ["ash", "report"], id="report-has-no-quiet"
        ),
        pytest.param(
            ["report", "-q"], ["ash", "report"], id="after-the-subcommand-too"
        ),
        pytest.param(
            ["--no-color", "report"],
            ["ash", "--no-color", "report"],
            id="report-takes-color",
        ),
        pytest.param(
            ["-q", "-c", "build-image"],
            ["ash", "--quiet", "--no-color", "build-image"],
            id="build-image-takes-both",
        ),
        pytest.param(
            ["--quiet", "--no-color", "config", "get"],
            ["ash", "config", "get"],
            id="a-group-takes-neither",
        ),
    ],
)
def test_the_entrypoints_own_flags_go_only_where_ash_takes_them(
    runner, tmp_path, args, expected
):
    """--quiet and --no-color are the entrypoint's options as well as ash's.

    The entrypoint consumes them (for the image build and the -t decision) and
    re-emits them for ash. Re-emitted in front of a subcommand that does not take
    them, ash refuses the command: `./ash --quiet report` exited 5, because report has
    no --quiet.
    """
    assert _inner_argv(_run_argv(runner, tmp_path, *args)) == expected


@pytest.mark.integration
@pytest.mark.parametrize(
    "args, expected",
    [
        pytest.param(
            ["-q", "merge", "--results", "scan"],
            ["ash", "merge", "--results", "scan"],
            id="a-later-value-names-scan",
        ),
        pytest.param(
            ["--quiet", "scan", "--config", "report"],
            ["ash", "--quiet", "scan", *SANDBOX_OFF, "--config", "/ash-config/report"],
            id="a-later-value-names-report",
        ),
    ],
)
def test_the_subcommand_is_the_first_token_that_names_one(
    runner, tmp_path, args, expected
):
    """A later argument can be a subcommand's name: a results directory called scan,
    a config file called report. It is a value, and must not decide where --quiet
    goes. The config file exists (the scan handling mounts it and rewrites its
    word to the container path), so what reaches the scan is the rewritten pair."""
    (tmp_path / "report").write_text("project_name: p\n", encoding="utf-8")
    assert _inner_argv(_run_argv(runner, tmp_path, *args, cwd=tmp_path)) == expected


@pytest.mark.integration
@pytest.mark.parametrize(
    "args, expected",
    [
        pytest.param(
            ["--quiet", "--phases", "report"],
            ["ash", "--quiet", *SANDBOX_OFF, "--phases", "report"],
            id="a-value-names-report",
        ),
        pytest.param(
            ["-q", "--no-color", "--phases", "inspect"],
            ["ash", "--quiet", "--no-color", *SANDBOX_OFF, "--phases", "inspect"],
            id="a-value-names-inspect",
        ),
        pytest.param(
            ["--quiet", "--phases=report", "report"],
            ["ash", "--phases=report", "report"],
            id="an-attached-value-is-not-the-next-token",
        ),
        pytest.param(
            ["--quiet", "-f", "report", "scan"],
            ["ash", "--quiet", "-f", "report", "scan", *SANDBOX_OFF],
            id="a-short-option-value",
        ),
        pytest.param(
            ["--quiet", "-Pf", "report", "scan"],
            ["ash", "--quiet", "-Pf", "report", "scan", *SANDBOX_OFF],
            id="a-value-after-clustered-short-options",
        ),
        pytest.param(
            ["--quiet", "-Pfreport", "report"],
            ["ash", "-Pfreport", "report"],
            id="a-value-attached-to-clustered-short-options",
        ),
    ],
)
def test_an_option_value_is_not_the_subcommand(runner, tmp_path, args, expected):
    """A root option's value can be a subcommand's name: --phases takes report and
    inspect. It is the option's value, so the entrypoint's --quiet and --no-color
    still go to the scan; reading it as the subcommand dropped them."""
    assert _inner_argv(_run_argv(runner, tmp_path, *args)) == expected


@pytest.mark.unit
def test_the_options_that_take_a_value_are_the_roots():
    """The entrypoint's list of root options that take a value, checked against the
    real root command so a new option cannot be read as a subcommand's name."""
    import re

    import typer.main

    from automated_security_helper.cli.main import app

    script = ASH_SCRIPT.read_text(encoding="utf-8")
    listed = set(
        re.search(r"ASH_ROOT_VALUE_OPTIONS=\"([^\"]*)\"", script).group(1).split()
    )
    root = typer.main.get_command(app)
    takes_a_value = {
        spelling
        for param in root.params
        if param.param_type_name == "option" and not param.is_flag and not param.count
        for spelling in param.opts
    }
    assert listed == takes_a_value
    assert all(
        param.nargs == 1 for param in root.params if param.param_type_name == "option"
    )


@pytest.mark.unit
def test_every_re_emitted_flag_is_one_the_subcommand_takes():
    """The entrypoint's table of which subcommands take --quiet and --color, checked
    against the real commands so it cannot drift from them."""
    import re

    import typer.main

    from automated_security_helper.cli.main import app

    script = ASH_SCRIPT.read_text(encoding="utf-8")
    subcommands = set(
        re.search(r"ASH_SUBCOMMANDS=\"([^\"]*)\"", script).group(1).split()
    )
    quiet = set(re.search(r"ASH_TAKES_QUIET=\"([^\"]*)\"", script).group(1).split())
    color = set(re.search(r"ASH_TAKES_COLOR=\"([^\"]*)\"", script).group(1).split())
    root = typer.main.get_command(app)
    declared = {
        name: {param.name for param in command.params}
        for name, command in root.commands.items()
    }
    assert subcommands == set(declared)
    assert quiet == {name for name, params in declared.items() if "quiet" in params}
    assert color == {name for name, params in declared.items() if "color" in params}


# What marks a module as reading stdin: the console helpers' confirm and prompt
# (typer's and click's, bare or qualified, which read the terminal), rich's prompts,
# the builtin input, the Textual app, or a read of the stdin stream in any of its
# spellings. A bare `confirm(` alone let `typer.confirm(` through, so a new prompt
# written qualified passed this guard.
STDIN_READER = re.compile(
    r"(?<![\w.])(?:(?:typer|click)\.)?(?:confirm|prompt)\("
    r"|\b(?:Confirm|Prompt|IntPrompt|FloatPrompt)\.ask\("
    r"|(?<![\w.])input\("
    r"|^\s*(?:from|import) textual\b"
    r"|\bsys\.(?:stdin|__stdin__)\b"
    r"|get_text_stream\(['\"]stdin['\"]\)",
    re.MULTILINE,
)


def _callback_modules(command) -> set[Path]:
    """The source files of a click command's callback and of every command under it."""
    found: set[Path] = set()
    callback = getattr(command, "callback", None)
    if callback is not None:
        # typer wraps the function it was given; the wrapper carries the original.
        module = inspect.getmodule(getattr(callback, "__wrapped__", callback))
        if module is not None and module.__file__:
            found.add(Path(module.__file__).resolve())
    for sub in getattr(command, "commands", {}).values():
        found |= _callback_modules(sub)
    return found


def _defaults_its_transport_to_stdio(command) -> bool:
    """Whether the command, or any command under it, defaults --transport to stdio."""
    if any(p.name == "transport" and p.default == "stdio" for p in command.params):
        return True
    return any(
        _defaults_its_transport_to_stdio(sub)
        for sub in getattr(command, "commands", {}).values()
    )


@pytest.mark.unit
def test_stdin_is_kept_open_for_the_subcommands_that_read_it():
    """The entrypoint's list of the subcommands whose container keeps stdin open
    (ASH_READS_STDIN), checked against the CLI so it cannot drift from it: a
    subcommand reads stdin when its command, or one under it, prompts, runs the
    Textual app, or defaults its --transport to stdio. The one reader outside the
    list is `--cli-json-input -`, which every command takes and the entrypoint reads
    by its flag; every other stdin-reading module under the CLI package belongs to a
    listed subcommand, so a new reader fails here until the list names it. The
    scan covers the CLI package only (the callbacks' own modules and everything
    under automated_security_helper/cli/): a prompt a command reaches through
    utils/ or core/ is outside it, and a test that runs each command with stdin
    closed would be the stronger guard."""
    import typer.main

    from automated_security_helper import cli as cli_package
    from automated_security_helper.cli.json_input import CLI_JSON_INPUT_FLAG
    from automated_security_helper.cli.main import app

    script = ASH_SCRIPT.read_text(encoding="utf-8")
    reads_stdin = set(
        re.search(r"ASH_READS_STDIN=\"([^\"]*)\"", script).group(1).split()
    )
    # The flag is read in both spellings, by the CLI's own name for it.
    assert f"{CLI_JSON_INPUT_FLAG})" in script
    assert f"{CLI_JSON_INPUT_FLAG}=-)" in script

    root = typer.main.get_command(app)
    owned = {
        name: _callback_modules(command) for name, command in root.commands.items()
    }
    assert all(owned.values()), "every subcommand's callback resolves to a source file"
    derived = {
        name
        for name, command in root.commands.items()
        if _defaults_its_transport_to_stdio(command)
        or any(
            STDIN_READER.search(path.read_text(encoding="utf-8"))
            for path in owned[name]
        )
    }
    assert reads_stdin == derived

    cli_dir = Path(cli_package.__file__).resolve().parent
    reading = {
        path
        for path in cli_dir.rglob("*.py")
        if STDIN_READER.search(path.read_text(encoding="utf-8"))
    }
    assert reading, "the CLI's stdin readers are found at all"
    listed = set().union(*(owned[name] for name in reads_stdin))
    assert reading - listed == {cli_dir / "json_input.py"}, sorted(reading - listed)
