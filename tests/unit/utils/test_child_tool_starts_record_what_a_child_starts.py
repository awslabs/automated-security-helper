# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ChildToolStarts`` records a tool start however the child found the tool.

The cells that run ``ash scan`` in a child hold ``ChildToolStarts.starts()`` at
none. That only proves something if the record would show a start, so each way a
child can start a probed tool is driven here directly, with a program that starts
it on purpose, and so is the one case where the record must end the child before
it runs: a directory ahead of the stand-ins on PATH. The children run only the
audit hook's prelude and a few lines of their own, never ASH.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tests.utils import tool_guard
from tests.utils.child_tool_starts import (
    POSIX_ONLY,
    SHADOWED_EXIT,
    ChildToolStarts,
    readers,
)
from tests.utils.helpers import checkout_env

pytestmark = POSIX_ONLY


def _program_named(directory: Path, name: str) -> Path:
    """An executable *name* in *directory* that starts nothing and succeeds."""
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / name
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return program


def _run_child(
    tmp_path: Path, started: ChildToolStarts, body: str, ahead: Path | None = None
) -> "subprocess.CompletedProcess[str]":
    """Run *body* in a child after the prelude, with PATH as the cell would give it,
    less *ahead*, a directory put in front of the stand-ins when given."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = checkout_env(
        started.child_env({"PATH": os.environ["PATH"], "HOME": str(home)})
    )
    if ahead is not None:
        env["PATH"] = f"{ahead}{os.pathsep}{env['PATH']}"
    return subprocess.run(  # nosec B603 - fixed argv, the interpreter running this test
        [sys.executable, "-c", started.prelude() + body],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.integration
def test_a_child_that_starts_nothing_leaves_no_record(tmp_path):
    started = ChildToolStarts(tmp_path)

    done = _run_child(tmp_path, started, "pass\n")

    assert done.returncode == 0, done.stderr
    assert started.starts() == []


@pytest.mark.integration
def test_a_start_of_a_tool_by_its_path_is_recorded(tmp_path):
    """The uv installed with ASH is asked for by path before PATH is searched, so no
    stand-in sees it, and a uv that resolves nothing leaves its directories empty."""
    started = ChildToolStarts(tmp_path)
    bundled = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        f"import subprocess\nsubprocess.run([{str(bundled)!r}, '--version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert len(recorded) == 1, recorded
    assert recorded[0].startswith("subprocess.Popen uv "), recorded
    assert "--version" in recorded[0], recorded


@pytest.mark.integration
def test_a_start_of_a_tool_found_on_path_is_recorded_twice(tmp_path):
    """The audit hook and the stand-in each log it: either alone would show it."""
    started = ChildToolStarts(tmp_path)

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\nsubprocess.run(['detect-secrets', '--version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen")], recorded
    assert "detect-secrets --version" in recorded, recorded


@pytest.mark.integration
def test_a_start_through_a_shell_command_line_is_recorded(tmp_path):
    started = ChildToolStarts(tmp_path)

    done = _run_child(tmp_path, started, "import os\nos.system('uvx --version')\n")

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("os.system uvx ")], recorded


@pytest.mark.integration
def test_a_tool_named_by_path_inside_a_shell_line_is_recorded(tmp_path):
    """A shell -c argv names the tool only inside its command string: no PATH
    lookup reaches a recording stand-in, so the audit hook's reading of the
    shell's own command line is the whole record."""
    started = ChildToolStarts(tmp_path)
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run(['/bin/sh', '-c', {str(quiet)!r} + ' --version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen uv ")], (
        recorded
    )


@pytest.mark.integration
def test_a_module_run_by_an_interpreter_is_recorded(tmp_path):
    """-m names the tool after the interpreter's own word, so the first-word
    read sees only the interpreter; the module name, written with the
    underscore an import needs, is the probed tool's."""
    started = ChildToolStarts(tmp_path)
    interpreter = _program_named(tmp_path / "quiet", "python3")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run([{str(interpreter)!r}, '-m', 'detect_secrets', '-V'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [
        line for line in recorded if line.startswith("subprocess.Popen detect-secrets ")
    ], recorded


@pytest.mark.integration
def test_a_direct_posix_spawn_start_is_recorded_once(tmp_path):
    """A posix_spawn with no subprocess.Popen before it is a start of its own:
    dropping subprocess's second report of one start must not drop this one."""
    started = ChildToolStarts(tmp_path)
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import os\n"
        f"pid = os.posix_spawn({str(quiet)!r}, [{str(quiet)!r}, '--version'],"
        " dict(os.environ))\n"
        "os.waitpid(pid, 0)\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert len(recorded) == 1, recorded
    assert recorded[0].startswith("os.posix_spawn uv "), recorded


@pytest.mark.integration
def test_a_cwd_popen_then_a_direct_spawn_of_the_same_tool_records_two(tmp_path):
    """A Popen given a cwd takes the fork_exec path and reports no posix_spawn
    echo, so a direct posix_spawn of the same tool right after it is a second
    start, not the first one's echo: the record names two."""
    started = ChildToolStarts(tmp_path)
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import os\n"
        "import subprocess\n"
        f"subprocess.run([{str(quiet)!r}, '--version'], cwd={str(tmp_path)!r})\n"
        f"pid = os.posix_spawn({str(quiet)!r}, [{str(quiet)!r}, '--version'],"
        " dict(os.environ))\n"
        "os.waitpid(pid, 0)\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert len(recorded) == 2, recorded


@pytest.mark.integration
def test_a_popen_that_spawns_with_close_fds_off_is_recorded_once(tmp_path):
    """Before Python 3.13 subprocess takes the posix_spawn path only with close_fds
    off (a directory in the executable, no cwd and no pipes besides): its second
    report of that one start, os.posix_spawn from Popen._posix_spawn, is the echo
    the frame reader drops, and this is the real child that reaches that reader.
    From 3.13 the path is taken with close_fds on as well, and the record reads
    the same either way: one Popen line, no posix_spawn line."""
    started = ChildToolStarts(tmp_path)
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run([{str(quiet)!r}, '--version'], close_fds=False)\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert len(recorded) == 1, recorded
    assert recorded[0].startswith("subprocess.Popen uv "), recorded


@pytest.mark.integration
def test_a_module_run_with_a_valued_x_option_is_recorded(tmp_path):
    """-X takes a value, so the module walk must step over the value to reach
    -m: the option's value is not where the options end."""
    started = ChildToolStarts(tmp_path)
    interpreter = _program_named(tmp_path / "quiet", "python3")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run([{str(interpreter)!r}, '-X', 'utf8', '-m', 'uv', '--version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen uv ")], (
        recorded
    )


@pytest.mark.integration
def test_a_module_named_inside_the_m_cluster_is_recorded(tmp_path):
    """-muv runs uv exactly as -m uv does: the module can end the cluster with
    no space before its name."""
    started = ChildToolStarts(tmp_path)
    interpreter = _program_named(tmp_path / "quiet", "python3")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run([{str(interpreter)!r}, '-muv', '--version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen uv ")], (
        recorded
    )


@pytest.mark.integration
def test_a_tool_inside_a_login_shell_command_line_is_recorded(tmp_path):
    """bash -lc puts -c at the end of a cluster: the command operand follows
    wherever the shell's options put -c, not only at argv[1]."""
    started = ChildToolStarts(tmp_path)
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run(['/bin/bash', '-lc', {str(quiet)!r} + ' --version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen uv ")], (
        recorded
    )


@pytest.mark.integration
def test_a_tool_inside_a_ksh_command_line_is_recorded(tmp_path):
    """ksh's -c runs a command line the same way sh's does, and the shell set
    of record (the conftest's) includes it: a stand-in named ksh keeps the
    cell off any real shell."""
    started = ChildToolStarts(tmp_path)
    shell = _program_named(tmp_path / "quiet", "ksh")
    quiet = _program_named(tmp_path / "beside-the-interpreter", "uv")

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\n"
        f"subprocess.run([{str(shell)!r}, '-c', {str(quiet)!r} + ' --version'])\n",
    )

    assert done.returncode == 0, done.stderr
    recorded = started.starts()
    assert [line for line in recorded if line.startswith("subprocess.Popen uv ")], (
        recorded
    )


@pytest.mark.integration
def test_a_start_of_something_else_is_not_recorded(tmp_path):
    """The record names the probed tools, not every start: a child that starts
    only a shell leaves it empty."""
    started = ChildToolStarts(tmp_path)

    done = _run_child(
        tmp_path,
        started,
        "import subprocess\nsubprocess.run(['/bin/sh', '-c', 'exit 0'])\n",
    )

    assert done.returncode == 0, done.stderr
    assert started.starts() == []


@pytest.mark.integration
def test_a_directory_ahead_of_the_stand_ins_ends_the_child_with_a_record(tmp_path):
    """A uv found before the stand-in would start for real where the cell looks
    for it, and log nothing. The child ends before its own code runs instead,
    and says which name was shadowed."""
    started = ChildToolStarts(tmp_path)
    shadow = tmp_path / "shadow"
    _program_named(shadow, "uv")
    ran = tmp_path / "ran"

    done = _run_child(tmp_path, started, f"open({str(ran)!r}, 'w').close()\n", shadow)

    assert done.returncode == SHADOWED_EXIT, (done.returncode, done.stderr)
    assert not ran.exists(), "the child's own code ran past the shadowed stand-in"
    recorded = started.starts()
    assert len(recorded) == 1, recorded
    assert recorded[0].startswith("stand-in for uv is shadowed"), recorded


@pytest.mark.unit
def test_the_directories_the_child_is_given_are_the_ones_the_record_reads(tmp_path):
    started = ChildToolStarts(tmp_path)

    env = started.child_env({"PATH": "/usr/bin"})

    assert env["UV_CACHE_DIR"] == str(started.uv_cache)
    assert env["UV_TOOL_DIR"] == str(started.uv_tools)
    assert env["UV_OFFLINE"] == "1"
    assert set(started.uv_directories) == {started.uv_cache, started.uv_tools}


@pytest.mark.unit
def test_child_env_passes_pythonpath_through_unchanged(tmp_path):
    """child_env only adds (PATH's front, the uv directories): a variable it
    does not own, PYTHONPATH here, reaches the child exactly as given."""
    started = ChildToolStarts(tmp_path)

    env = started.child_env({"PATH": "/usr/bin", "PYTHONPATH": "/x"})

    assert env["PYTHONPATH"] == "/x"


@pytest.mark.unit
def test_child_env_changes_exactly_path_and_the_uv_variables(tmp_path):
    """The contract the structural check of the child-scan tests trusts: child_env
    adds the stand-ins to PATH's front and sets uv's three variables, and every
    other variable, known to it or not, reaches the child as given. The mapping
    it is given is read, never written."""
    started = ChildToolStarts(tmp_path)
    given = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "p", "X": "y"}
    before = dict(given)

    env = started.child_env(given)

    changed = {name for name in env if env[name] != given.get(name)}
    assert changed == {"PATH", "UV_CACHE_DIR", "UV_TOOL_DIR", "UV_OFFLINE"}, changed
    assert set(given) <= set(env), "a variable given was dropped"
    assert env["PATH"] == f"{started.directory}{os.pathsep}/usr/bin:/bin"
    assert env["PYTHONPATH"] == "p"
    assert env["X"] == "y"
    assert given == before, "the caller's mapping was written to"


@pytest.mark.unit
def test_child_env_puts_the_stand_ins_first_even_with_no_path_given(tmp_path):
    """A caller that sets no PATH still gets the stand-ins first: the prelude's
    check would otherwise end the child for a PATH that finds no stand-in."""
    started = ChildToolStarts(tmp_path)

    env = started.child_env({"HOME": "/h"})

    assert env["PATH"].split(os.pathsep)[0] == str(started.directory)
    assert env["HOME"] == "/h"


@pytest.mark.integration
def test_an_entry_a_uv_left_in_its_directories_is_recorded(tmp_path):
    """The second record: a start no audit hook saw, shown by what it left."""
    started = ChildToolStarts(tmp_path)

    done = _run_child(
        tmp_path,
        started,
        "import os\n"
        "cache = os.environ['UV_CACHE_DIR']\n"
        "os.makedirs(cache)\n"
        "open(os.path.join(cache, 'entry'), 'w').close()\n",
    )

    assert done.returncode == 0, done.stderr
    assert started.starts() == ["uv-cache/entry"]


# The prelude's readers, run in this process on an argv that is never started
# (``readers``): what the child's hook would make of each command line.


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv, command",
    [
        pytest.param(["sh", "-c", "uv sync"], "uv sync", id="c-then-the-string"),
        pytest.param(["bash", "-lc", "uv sync"], "uv sync", id="c-ends-a-cluster"),
        pytest.param(
            ["bash", "-c", "-e", "uv sync"], "uv sync", id="an-option-after-c"
        ),
        pytest.param(
            ["sh", "-c", "-o", "pipefail", "uv sync"],
            "uv sync",
            id="a-valued-option-after-c",
        ),
        pytest.param(
            ["bash", "-o", "pipefail", "-c", "uv sync"],
            "uv sync",
            id="a-valued-option-before-c",
        ),
        pytest.param(
            ["bash", "--rcfile", "rc", "-c", "uv sync"],
            "uv sync",
            id="a-valued-long-option-before-c",
        ),
        pytest.param(["bash", "--norc", "-c", "uv sync"], "uv sync", id="a-long-flag"),
        pytest.param(
            ["sh", "-c", "--", "uv sync"], "uv sync", id="double-dash-ends-the-options"
        ),
        pytest.param(
            ["sh", "-c", "-", "uv sync"], "uv sync", id="a-lone-dash-ends-the-options"
        ),
        pytest.param(["sh", "-s", "-c", "uv sync"], "uv sync", id="s-then-c"),
        pytest.param(["sh", "-sc", "uv sync"], "uv sync", id="s-and-c-in-one-cluster"),
        pytest.param(
            ["bash", "-euo", "pipefail", "-c", "uv sync"],
            "uv sync",
            id="a-valued-letter-inside-a-cluster-before-c",
        ),
        pytest.param(
            ["bash", "-co", "pipefail", "uv sync"],
            "uv sync",
            id="c-and-a-valued-letter-in-one-cluster",
        ),
        pytest.param(
            ["bash", "-oo", "pipefail", "errexit", "-c", "uv sync"],
            "uv sync",
            id="two-valued-letters-take-two-values",
        ),
    ],
)
def test_the_shell_command_string_is_the_first_operand_after_every_option(
    argv, command
):
    """A shell reads all of its options before it takes the command string, so the
    string is the first operand after them, wherever -c sat among the options; the
    old walk took the word right after the cluster holding c, and so read ``-e`` or
    ``-o`` as the command, and the one before this read ``pipefail`` as the command
    of ``bash -euo pipefail -c STRING``, so a tool named by path in STRING started
    with no stand-in seeing it."""
    assert readers()["_shell_command_line"](argv) == command


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["sh", "-c", "uv sync"], id="c-then-the-string"),
        pytest.param(["bash", "-euo", "pipefail", "-c", "uv sync"], id="a-cluster"),
        pytest.param(["bash", "-co", "pipefail", "uv sync"], id="c-with-a-value"),
        pytest.param(["bash", "--mystery", "-c", "uv sync"], id="options-unread"),
        pytest.param(["sh", "script.sh", "-c", "uv sync"], id="a-script"),
        pytest.param(["sh", "-c", "--", "uv sync"], id="double-dash"),
        pytest.param(["sh", "-c"], id="c-with-no-string"),
    ],
)
def test_the_exec_d_shell_walk_answers_as_the_conftests_own_does(argv):
    """The two shell walks are one function in two processes: the text the child
    runs answers each command line as the root conftest's function does here,
    index and options-read flag alike."""
    from tests import conftest as root_conftest

    assert readers()["_shell_command_string"](argv) == (
        root_conftest._shell_command_string(argv)
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["sh", "--", "-c", "uv sync"], id="a-script-named-dash-c"),
        pytest.param(["sh", "script.sh", "-c", "uv sync"], id="a-script-before-c"),
        pytest.param(["sh", "-c"], id="c-with-no-string"),
        pytest.param(
            ["bash", "--mystery", "-c", "uv sync"], id="an-unknown-long-option"
        ),
        pytest.param(["sh", "-e", "uv sync"], id="no-c-at-all"),
    ],
)
def test_a_shell_argv_with_no_readable_command_string_gives_none(argv):
    """After ``--`` the next word is a script, however it is spelled; a script before
    any -c ends the options; a long option the reader does not know might take a
    value, so where the string would be is a guess, and the reader says so with
    None rather than naming the wrong word."""
    assert readers()["_shell_command_line"](argv) is None


@pytest.mark.unit
def test_a_tool_named_by_path_after_a_shell_option_is_among_the_words():
    """The case the module docstring promises: a tool named by path inside the
    shell's command string is a word the hook compares, even when an option
    follows -c."""
    words = readers()["_words_of"](["bash", "-c", "-e", "/venv/bin/uv sync"])

    assert "/venv/bin/uv" in words, words
    assert "-e" not in words, words


def _frame_of(module_name: str, function_name: str) -> types.SimpleNamespace:
    """A stand-in for the frame an audit event fired in: its code's name and the
    ``__name__`` of the module that code belongs to, which is all the reader
    reads of a frame."""
    code = types.SimpleNamespace(co_name=function_name)
    return types.SimpleNamespace(f_code=code, f_globals={"__name__": module_name})


@pytest.mark.unit
def test_a_posix_spawn_made_by_subprocess_for_a_popen_is_its_echo():
    """subprocess reports a Popen it starts with posix_spawn twice, the second
    time from Popen._posix_spawn; that frame, and only that frame, marks the
    second report."""
    popen_reported = readers()["_popen_reported"]

    assert popen_reported(_frame_of("subprocess", "_posix_spawn")) is True


@pytest.mark.unit
@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(_frame_of("__main__", "<module>"), id="the-childs-own-code"),
        pytest.param(
            _frame_of("subprocess", "_execute_child"), id="forked-not-spawned"
        ),
        pytest.param(
            _frame_of("my_subprocess", "_posix_spawn"), id="a-same-named-helper"
        ),
        pytest.param(None, id="no-frame"),
    ],
)
def test_a_posix_spawn_made_by_anything_else_is_a_start_of_its_own(frame):
    """A direct os.posix_spawn, one from another module's function of the same
    name, or an event with no frame to read, is recorded: nothing before it is
    assumed to have been its first report, so no shared arm and no thread can
    drop it."""
    assert readers()["_popen_reported"](frame) is False


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv, word",
    [
        pytest.param(
            "python3 -m detect_secrets scan", "detect-secrets", id="os-system-string"
        ),
        pytest.param(
            ["sh", "-c", "python -m uv.__main__ pip install x"],
            "uv",
            id="inside-a-shell-c-string",
        ),
        pytest.param(
            ["bash", "-c", "cd /x && /opt/py/bin/python3.12 -Im detect_secrets"],
            "detect-secrets",
            id="an-interpreter-by-path-after-other-words",
        ),
        pytest.param(
            ["python3", "-W", "ignore", "-m", "uv", "--version"],
            "uv",
            id="the-program-itself",
        ),
    ],
)
def test_a_module_run_by_an_interpreter_inside_a_shell_line_is_a_word(argv, word):
    """The -m rule holds for an interpreter that is a word of a shell command
    line as it does for one that is the program: the module's top-level package,
    spelled with the hyphen a probed name uses, is among the words compared, so
    ``python -m detect_secrets`` inside a shell line is recorded as the direct
    form is."""
    assert word in readers()["_words_of"](argv)


@pytest.mark.unit
def test_a_shell_line_with_no_interpreter_adds_no_module_word():
    """The control: a shell line whose words run no Python module is read word
    by word and nothing is added."""
    assert readers()["_words_of"]("ls -l /tmp") == ["ls", "-l", "/tmp"]


@pytest.mark.unit
def test_the_prelude_carries_the_conftests_tables_and_the_guards_walk(tmp_path):
    """The child reads a command line with the sets and the shell walk the root
    conftest reads with and the -m walk the tool guard runs, taken from those homes
    when the prelude is built, so none can drift from its copy: there is no copy.
    The future import comes first, so the walks' annotations are never evaluated
    in the child."""
    from tests import conftest as root_conftest

    text = ChildToolStarts(tmp_path).prelude()

    assert text.startswith("from __future__ import annotations\n")
    for name in (
        "_SHELLS",
        "_SHELL_OPTIONS_WITH_A_VALUE",
        "_SHELL_CLUSTER_LETTERS_WITH_A_VALUE",
        "_SHELL_LONG_FLAGS",
    ):
        expected = f"{name} = {tuple(sorted(getattr(root_conftest, name)))!r}\n"
        assert text.count(expected) == 1, name
    assert text.count(inspect.getsource(root_conftest._shell_command_string)) == 1
    assert text.count(inspect.getsource(tool_guard._module_run_by)) == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["python3", "-m", "uv", "--version"], id="m-then-the-module"),
        pytest.param(["python3", "-Im", "uv"], id="m-ends-a-cluster"),
        pytest.param(["python3", "-muv"], id="the-module-inside-the-cluster"),
        pytest.param(["python3", "-W", "ignore", "-m", "uv"], id="a-valued-w-before-m"),
        pytest.param(["python3", "-X", "utf8", "-m", "uv"], id="a-valued-x-before-m"),
        pytest.param(["python3", "-c", "import uv"], id="c-ends-the-options"),
        pytest.param(
            ["python3", "script.py", "-m", "uv"], id="a-script-ends-the-options"
        ),
        pytest.param(["python3", "-", "-m", "uv"], id="a-lone-dash-ends-the-options"),
        pytest.param(["python3", "-m"], id="m-with-no-module"),
        pytest.param([b"python3", b"-m", b"detect_secrets"], id="bytes"),
    ],
)
def test_the_exec_d_walk_answers_as_the_guards_own_does(argv):
    """The two walkers are one function in two processes: the text the child runs
    answers each command line as the tool guard's function does here."""
    assert readers()["_module_run_by"](argv) == tool_guard._module_run_by(argv)
