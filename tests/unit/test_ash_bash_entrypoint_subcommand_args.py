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

import ast
import importlib.util
import inspect
import os
import re
import shutil
import stat
import subprocess
import sys
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
    # `ash --quiet container build` hands the root's --quiet to the leaf the group
    # names (AshTyperGroup._options_for_subcommand), so the group takes what
    # `build` takes.
    declared["container"] = {
        param.name for param in root.commands["container"].commands["build"].params
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


#: What a module's own definitions are: the functions and classes at its top level.
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _leaves(command, words=()):
    """Every command with no command under it, and the words that name it from the
    root down, as ./ash is given them: ("config", "lint")."""
    subcommands = getattr(command, "commands", None)
    if not subcommands:
        yield words, command
        return
    for name, sub in subcommands.items():
        yield from _leaves(sub, (*words, name))


def _callback_function(command):
    """The function a click command runs. typer wraps the one it was given, and the
    wrapper carries the original."""
    callback = getattr(command, "callback", None)
    assert callback is not None, f"the command {command.name!r} has no callback"
    return inspect.unwrap(callback)


def _text_the_function_acts_on(source: str, name: str) -> str:
    """The text of a module in which one command's behavior can come from, so a
    command is judged by its own code and not by what its neighbors in the module do.

    That is the top-level function *name*, every function and class of the module
    that it names, those named by them in turn, and the statements outside any
    definition: the module's imports and constants, which is where a module that is
    the Textual app says so. A prompt in a helper that only another command calls is
    not in it."""
    tree = ast.parse(source)
    definitions = {
        node.name: node for node in tree.body if isinstance(node, _DEFINITIONS)
    }
    assert name in definitions, (
        f"{name} is not a function or class at the top of its module"
    )
    reached = {name}
    pending = [definitions[name]]
    while pending:
        node = pending.pop()
        for used in {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}:
            if used in definitions and used not in reached:
                reached.add(used)
                pending.append(definitions[used])
    segments = [ast.get_source_segment(source, definitions[n]) for n in sorted(reached)]
    segments += [
        ast.get_source_segment(source, node)
        for node in tree.body
        if not isinstance(node, _DEFINITIONS)
    ]
    return "\n".join(segments)


def _source_file(command) -> Path:
    return Path(inspect.getsourcefile(_callback_function(command))).resolve()


def _prompts_through_a_param(command) -> bool:
    """Whether a command has a parameter that asks for its own value when none is given:
    `typer.Option(..., prompt=True)`, with or without a confirmation, and click's
    confirmation and password options, which are built the same way. The parser asks,
    so no `prompt(` or `confirm(` stands in the command's code for STDIN_READER to
    find."""
    return any(
        getattr(param, "prompt", None) or getattr(param, "confirmation_prompt", None)
        for param in command.params
    )


def _reads_stdin(command) -> bool:
    """Whether a command, judged by its own code, reads stdin: it defaults --transport
    to stdio (its client drives it over stdin), one of its parameters prompts, or the
    code its callback acts on prompts, runs the Textual app, or reads the stream."""
    if any(p.name == "transport" and p.default == "stdio" for p in command.params):
        return True
    if _prompts_through_a_param(command):
        return True
    text = _text_the_function_acts_on(
        _source_file(command).read_text(encoding="utf-8"),
        _callback_function(command).__name__,
    )
    return STDIN_READER.search(text) is not None


def _entries_in(script: str) -> set[tuple[str, ...]]:
    """The commands ASH_READS_STDIN lists, each as the words that name it."""
    listed = re.search(r"ASH_READS_STDIN=\"([^\"]*)\"", script).group(1).split()
    return {tuple(entry.split(":")) for entry in listed}


def _drift(script: str, derived) -> tuple[set, set]:
    """(commands that read stdin and are not listed, commands listed that do not)."""
    listed = _entries_in(script)
    return set(derived) - listed, listed - set(derived)


@pytest.fixture(scope="module")
def the_cli():
    """Every command of the ash CLI with nothing under it: (words, command) pairs."""
    import typer.main

    from automated_security_helper.cli.main import app

    return list(_leaves(typer.main.get_command(app)))


@pytest.mark.unit
def test_stdin_is_kept_open_for_the_commands_that_read_it(the_cli):
    """The entrypoint's list of the commands whose container keeps stdin open
    (ASH_READS_STDIN), checked against the CLI so it cannot drift from it. A command
    reads stdin when its code prompts, runs the Textual app, defaults its --transport
    to stdio or has a parameter that prompts, and it is judged by its own code: `config
    lint` and `config wizard` ask before they change a file, and `config get` in the
    same module does not, so listing the group would keep stdin open for every command
    of it. Which runs of `config lint` ask is the condition on it, checked against its
    options in test_wrapper_contract_spec.py, not judged here. The one
    reader outside the list is `--cli-json-input -`, which every command takes and the
    entrypoint reads by its flag; every other stdin-reading module under the CLI
    package holds a listed command, so a new reader module fails here until a command
    of it is listed. The scan covers the CLI package only (the callbacks' own modules
    and everything under automated_security_helper/cli/): a prompt a command reaches
    through utils/ or core/ is outside it, and a test that runs each command with
    stdin closed would be the stronger guard."""
    from automated_security_helper import cli as cli_package
    from automated_security_helper.cli.json_input import CLI_JSON_INPUT_FLAG

    script = ASH_SCRIPT.read_text(encoding="utf-8")
    # The flag is read in both spellings, by the CLI's own name for it.
    assert f"{CLI_JSON_INPUT_FLAG})" in script
    assert f"{CLI_JSON_INPUT_FLAG}=-)" in script

    derived = {words for words, command in the_cli if _reads_stdin(command)}
    assert derived, "the CLI's stdin readers are found at all"
    unlisted, stale = _drift(script, derived)
    assert (unlisted, stale) == (set(), set()), (
        f"read stdin and are not in ASH_READS_STDIN: {sorted(unlisted)}; "
        f"are in ASH_READS_STDIN and read none: {sorted(stale)}. The list is "
        "STDIN_READING_COMMANDS in interactions/wrapper_contract.py; regenerate "
        "./ash with scripts/generate_wrapper_tables.py."
    )

    cli_dir = Path(cli_package.__file__).resolve().parent
    reading = {
        path
        for path in cli_dir.rglob("*.py")
        if STDIN_READER.search(path.read_text(encoding="utf-8"))
    }
    assert reading, "the CLI's stdin readers are found at all"
    listed = {_source_file(command) for words, command in the_cli if words in derived}
    assert reading - listed == {cli_dir / "json_input.py"}, sorted(reading - listed)


@pytest.mark.unit
def test_a_command_that_reads_stdin_and_is_not_listed_fails_the_check(the_cli):
    """The control: with one reader taken out of the entrypoint's list, the check
    names it, and with a command that reads nothing put in, it names that one, so
    the equality above is not a check that passes whatever the list says."""
    script = ASH_SCRIPT.read_text(encoding="utf-8")
    derived = {words for words, command in the_cli if _reads_stdin(command)}
    assert _drift(script, derived) == (set(), set())

    assert script.count(" config:wizard") == 1
    without_wizard = script.replace(" config:wizard", "")
    assert _drift(without_wizard, derived) == ({("config", "wizard")}, set())

    assert script.count(" mcp results:inspect:findings") == 1
    with_config_get = script.replace(
        " mcp results:inspect:findings", " config:get mcp results:inspect:findings"
    )
    assert _drift(with_config_get, derived) == (set(), {("config", "get")})


_TWO_COMMANDS = """
from helpers import confirm


def asks():
    return _ask_through_a_helper()


def _ask_through_a_helper():
    return confirm("Apply these fixes?")


def tells():
    return _say_something()


def _say_something():
    return "done"
"""


@pytest.mark.unit
def test_a_command_is_judged_by_its_own_code_not_by_its_modules():
    """Two commands of one module, one asking through a helper: the scan reads the one
    that asks as a reader and the other as not, which a scan of the whole module
    could not tell apart."""
    assert STDIN_READER.search(_text_the_function_acts_on(_TWO_COMMANDS, "asks"))
    assert not STDIN_READER.search(_text_the_function_acts_on(_TWO_COMMANDS, "tells"))


@pytest.mark.unit
def test_a_module_that_is_the_textual_app_reads_stdin_for_every_command_in_it():
    """The Textual import stands at the top of the module, outside every function,
    and the commands defined there are the app."""
    source = "from textual.app import App\n\n\ndef view():\n    return App\n\n\ndef other():\n    return 1\n"
    assert STDIN_READER.search(_text_the_function_acts_on(source, "other"))
    # The control: the same module without the import reads nothing.
    assert not STDIN_READER.search(
        _text_the_function_acts_on(source.replace("textual.app", "helpers"), "other")
    )


@pytest.mark.unit
def test_a_callback_that_is_not_a_top_level_function_is_refused_not_guessed():
    nested = "def outer():\n    def inner():\n        return 1\n    return inner\n"
    with pytest.raises(AssertionError, match="not a function or class at the top"):
        _text_the_function_acts_on(nested, "inner")


#: A module of two commands: one with a parameter the parser prompts for, one that
#: prompts nowhere. Neither holds a prompt in its own code, so only the parameter gives
#: the first away.
_PLANTED_CLI = """\
from typing import Annotated

import typer

app = typer.Typer()


@app.command()
def asks(name: Annotated[str, typer.Option(prompt=True)]):
    print(name)


@app.command()
def tells(name: Annotated[str, typer.Option()] = "world"):
    print(name)
"""


@pytest.mark.unit
def test_a_parameter_that_prompts_makes_its_command_a_stdin_reader(tmp_path):
    """`typer.Option(prompt=True)` asks from inside the parser, so the command's code
    holds no `prompt(` for STDIN_READER to find, and a command like that would lose -i
    and get end of input at its question. The planted module holds one such command and
    one that prompts nowhere, the control: the first is a reader and the second is not,
    though the scan of their code finds nothing in either."""
    import typer.main

    assert not STDIN_READER.search(_PLANTED_CLI)
    path = tmp_path / "planted_cli_with_a_prompting_parameter.py"
    path.write_text(_PLANTED_CLI, encoding="utf-8")
    name = path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        commands = typer.main.get_command(module.app).commands
        assert _prompts_through_a_param(commands["asks"]) is True
        assert _prompts_through_a_param(commands["tells"]) is False
        assert _reads_stdin(commands["asks"]) is True
        assert _reads_stdin(commands["tells"]) is False
    finally:
        sys.modules.pop(name, None)
