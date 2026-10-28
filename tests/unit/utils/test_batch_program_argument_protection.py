# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Arguments to a batch program are read by cmd.exe as written, in both of its reads.

On Windows ``CreateProcess`` starts a ``.bat`` or ``.cmd`` file through cmd.exe, which
reads the whole command line, and the batch file then passes its arguments on with
``%*``, which cmd.exe reads a second time. ``subprocess.list2cmdline`` quotes an
argument only when it is empty or holds a space or tab, and it writes a double quote
inside an argument as ``\\"``, which cmd.exe does not read as an escape. A caret put
before an operator protects it in the first read and leaves it bare in the second, so
the only spelling both reads leave alone is one inside double quotes. A batch wrapper
can put ``%*`` inside a parenthesized block, where a bare ``)`` closes the block early,
so a parenthesis is a character cmd.exe acts on too.
These tests check the command line that ``list2cmdline`` makes from the list ASH hands
to ``Popen``:

* an argument ``list2cmdline`` puts in double quotes reaches the program as it is;
* an argument it would write bare, holding a character cmd.exe acts on (``< > | & ^``
  or a parenthesis), is refused before anything starts, without its text in the
  message, and so is a double quote or a line break anywhere. ASH refuses these where
  quoting them itself would need the whole command line as one string, which the spawn
  helpers, the sandbox plan and the callers of ``resolve_command`` do not carry. The
  message tells the caller that an argument with a space is passed as it is, and how
  to write a version range without ``^``;
* a percent sign passes only when it is the only one in the command line, because
  cmd.exe looks for ``%name%`` across the whole line and a lone sign names nothing;
* the program path is read the same way, and is never rewritten;
* nothing changes for a program that is not a batch file or on a host that is not
  Windows, and a list the caller passes twice is handed on the same both times.

``list2cmdline`` is plain Python and gives the same text on every host, so the command
line the operating system would be given is checked here without Windows. How cmd.exe
reads it is checked against ``tests/utils/cmd_exe_model.py``, a model of the rules these
tests rely on. Every host runs the model's tests and starts no cmd.exe; the one test
marked Windows-only starts a real batch file with each argument ASH accepts and compares
what the program receives with the model, so on the Windows leg of the test workflow it
is the measurement of the model.
"""

import ast
import errno
import subprocess  # nosec B404 - list2cmdline, and one Windows-only batch test
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    create_process_with_pipes,
    resolve_command,
    run_command_stream_output,
    run_command_with_output_handling,
)
from tests.utils.cmd_exe_model import delivered, reads_as_a_command

MODULE = "automated_security_helper.utils.subprocess_utils"
PROGRAM = "C:/tools/npm.cmd"


def resolved(arguments, program=PROGRAM, system="Windows"):
    """The list ``resolve_command`` returns for ``npm`` followed by ``arguments``."""
    with (
        patch("platform.system", return_value=system),
        patch(f"{MODULE}.find_executable", return_value=program),
    ):
        return resolve_command(["npm", *arguments])


def command_line_of(arguments, program=PROGRAM, system="Windows") -> str:
    return subprocess.list2cmdline(resolved(arguments, program, system))


def assert_cmd_leaves_alone(command_line: str) -> None:
    """The batch program receives ``command_line`` and no operator acts on the way."""
    assert reads_as_a_command(command_line) == [], command_line
    assert delivered(command_line) == command_line


# The model must flag what it claims to flag, and pass what it claims to pass.


@pytest.mark.parametrize(
    "command_line, acts_on",
    [
        ("npm a<b", ["<"]),
        ("npm a>b", [">"]),
        ("npm x|y", ["|"]),
        ("npm p&q", ["&"]),
        ("npm c^d", ["^"]),
        # A caret protects an operator in the first read and not in the second.
        ("npm p^&q", ["&"]),
        ("npm c^^d", ["^"]),
        ("npm 100%", []),
        ("npm 100% 50%", ["%"]),
        ('npm "100%"', []),
        ('npm "%PATH%"', ["%"]),
        ('npm "a\\" & b"', ["&"]),
        ('npm "a & b"', []),
        ('npm "a ^ b"', []),
        ('npm "a & b" p^&q', ["&"]),
        # A parenthesis acts in the second read, where %* can sit inside a block.
        ("npm foo)", [")"]),
        ("npm a(b", ["("]),
        ("npm --filter=a)b", [")"]),
        ("npm f(x)", ["(", ")"]),
        ("npm f^)g", [")"]),
        ("npm ^(x^)", ["(", ")"]),
        ('npm "f(x)"', []),
        ('npm "a (b)"', []),
    ],
)
def test_the_model_of_cmd_flags_what_it_claims_to(command_line, acts_on):
    assert reads_as_a_command(command_line) == acts_on


@pytest.mark.parametrize(
    "command_line, received",
    [
        ("npm p^&q", "npm p&q"),
        ("npm c^^d", "npm cd"),
        ('npm "a ^ b"', 'npm "a ^ b"'),
        ("npm 100%", "npm 100%"),
        ("npm f^)g", "npm f)g"),
        ('npm "a (b)"', 'npm "a (b)"'),
    ],
)
def test_the_model_of_cmd_delivers_what_both_reads_leave(command_line, received):
    assert delivered(command_line) == received


# Whatever reaches Popen reads as no command in either read, or is refused.

BATTERY = [
    "plain",
    "p&q",
    "a|b",
    "x<y",
    "x>y",
    "c^d",
    "p^&q",
    "100%",
    "%PATH%",
    "pkg@^1.0.0",
    "foo)",
    "--filter=a)b",
    "f(x)",
    "(",
    ")",
    "a b&c",
    "a & b",
    "a b^c",
    "100% sure",
    "a b)",
    "(a b)",
    # The way out the refusal of a caret names: a version range with a space.
    "pkg@>=1.0.0 <2.0.0",
    "pkg@^1.0.0 || ^2.0.0",
    "",
]


@pytest.mark.parametrize("argument", BATTERY)
def test_nothing_cmd_would_act_on_reaches_popen_in_either_read(argument):
    try:
        arguments = resolved(["install", argument])
    except OSError:
        return

    assert_cmd_leaves_alone(subprocess.list2cmdline(arguments))


@pytest.mark.parametrize(
    "argument",
    [
        "plain",
        "a b&c",
        "a & b",
        "a b^c",
        "100% sure",
        "100%",
        "a b)",
        "(a b)",
        "pkg@>=1.0.0 <2.0.0",
        "pkg@^1.0.0 || ^2.0.0",
        "",
    ],
)
def test_these_arguments_reach_the_program_as_they_were_given(argument):
    # The control for the test above: it does not pass by refusing everything.
    assert resolved(["install", argument]) == [PROGRAM, "install", argument]


# An argument list2cmdline would write bare, with a character cmd.exe acts on, is
# refused. Writing a caret before it protects the first read only.


@pytest.mark.parametrize(
    "argument",
    [
        "left<right",
        "a>b",
        "x|y",
        "p&q",
        "c^d",
        "p^&q",
        "pkg@^1.0.0",
        "a&b|c>d",
        # A bare parenthesis: a wrapper can hold %* inside a parenthesized block,
        # where a bare ")" closes the block early. (A lone "(" or ")" is in
        # BATTERY; the message itself holds parentheses, so it cannot be checked
        # for the argument's text here.)
        "foo)",
        "--filter=a)b",
        "f(x)",
        "a(b",
        "x^)y",
    ],
)
def test_a_bare_argument_cmd_would_read_is_refused_not_written_with_carets(argument):
    with pytest.raises(OSError) as refused:
        resolved(["install", argument])

    assert refused.value.errno == errno.EINVAL
    assert PROGRAM in str(refused.value)
    assert argument not in str(refused.value)


def test_the_refusal_of_a_caret_says_how_to_write_a_version_range():
    # The one place the default of npm and its relatives puts a bare caret in an
    # argument: pkg@^1.0.0. The message names the way out and still not the text.
    with pytest.raises(OSError) as caret:
        resolved(["install", "pkg@^1.0.0"])
    with pytest.raises(OSError) as ampersand:
        resolved(["install", "p&q"])

    assert "version range" in str(caret.value)
    assert "pkg@^1.0.0" not in str(caret.value)
    assert "version range" not in str(ampersand.value)


@pytest.mark.parametrize("program", ["C:/tools/npm.cmd", "C:/tools/gem.bat"])
@pytest.mark.parametrize("suffix_case", [str.lower, str.upper])
def test_both_batch_suffixes_are_read_in_either_case(program, suffix_case):
    program = program[: program.rindex(".")] + suffix_case(
        program[program.rindex(".") :]
    )

    with pytest.raises(OSError) as refused:
        resolved(["a&b"], program=program)

    assert refused.value.errno == errno.EINVAL


# An argument list2cmdline quotes is left as it is: the quotes protect it in both reads.


def test_an_argument_with_a_space_is_left_to_list2cmdline_quoting():
    command_line = command_line_of(["--prefix", "C:/Program Files/a & b|c<d>e^f"])

    assert command_line == f'{PROGRAM} --prefix "C:/Program Files/a & b|c<d>e^f"'
    assert_cmd_leaves_alone(command_line)


def test_an_empty_argument_stays_an_empty_quoted_argument():
    assert command_line_of(["", "x"]) == f'{PROGRAM} "" x'


def test_an_argument_that_is_not_text_is_left_for_popen_to_report():
    arguments = resolved(["install", 3])

    assert arguments[2] == 3


def test_a_path_argument_is_read_like_text():
    assert resolved([Path("a b")])[1] == Path("a b")
    with pytest.raises(OSError) as refused:
        resolved([Path("a&b")])

    assert refused.value.errno == errno.EINVAL


def test_a_bytes_argument_is_read_like_text():
    assert resolved([b"plain"])[1] == b"plain"
    with pytest.raises(OSError) as refused:
        resolved([b"a&b"])

    assert refused.value.errno == errno.EINVAL


# What no spelling carries through both reads is refused, and the message does not
# carry the argument.


@pytest.mark.parametrize(
    "argument",
    ['a" & b', 'a"&b', 'say "hi"', "line\nbreak", "line\rbreak", 'tab\tand"quote'],
)
def test_an_argument_that_cannot_be_passed_on_is_refused(argument):
    with pytest.raises(OSError) as refused:
        resolved(["install", argument])

    assert refused.value.errno == errno.EINVAL
    assert PROGRAM in str(refused.value)
    assert argument not in str(refused.value)
    assert argument.strip() not in str(refused.value)


# A percent sign passes alone and is refused where it could pair with another.


@pytest.mark.parametrize("argument", ["100%", "%", "%PATH", "100% sure"])
def test_a_lone_percent_sign_reaches_the_program_as_it_is(argument):
    assert resolved(["install", argument]) == [PROGRAM, "install", argument]


@pytest.mark.parametrize(
    "arguments",
    [
        ["%PATH%"],
        ["100% and 50%"],
        ["%a", "b%"],
        ["%a %b"],
        ["50%", "100%"],
    ],
)
def test_percent_signs_that_could_pair_are_refused(arguments):
    with pytest.raises(OSError) as refused:
        resolved(["install", *arguments])

    assert refused.value.errno == errno.EINVAL


def test_a_percent_sign_in_the_program_path_can_pair_with_one_in_an_argument():
    with pytest.raises(OSError) as refused:
        resolved(["100%"], program="C:/Users/50%off/tools/npm.cmd")

    assert refused.value.errno == errno.EINVAL


# The program path is read like an argument and is never rewritten.


@pytest.mark.parametrize(
    "program",
    ["C:/Users/50%off/tools/npm.cmd", "C:\\Users\\50%off\\tools\\npm.cmd"],
)
def test_a_program_path_with_one_percent_sign_starts_as_it_is(program):
    assert resolved(["--version"], program=program) == [program, "--version"]


@pytest.mark.parametrize(
    "program",
    [
        "C:/tools&more/npm.cmd",
        "C:/tools^more/npm.cmd",
        "C:/a|b/npm.cmd",
        "C:/a<b/npm.cmd",
        "C:/a>b/npm.cmd",
        # The program path is read by the same rule, parentheses included: one rule
        # for the whole line is simpler to state and to check. A path with a space,
        # such as "Program Files (x86)", is quoted by list2cmdline and passes.
        "C:/tools(x86)/npm.cmd",
        "C:/a)b/npm.cmd",
    ],
)
def test_a_program_path_cmd_would_read_is_refused_not_written_with_carets(program):
    with pytest.raises(OSError) as refused:
        resolved(["--version"], program=program)

    assert refused.value.errno == errno.EINVAL
    assert "the program" in str(refused.value)


def test_a_program_path_with_a_space_is_quoted_by_list2cmdline():
    program = "C:/Program Files/a&b/npm.cmd"

    command_line = command_line_of(["--version"], program=program)

    assert command_line == f'"{program}" --version'
    assert_cmd_leaves_alone(command_line)


def test_a_program_path_with_parentheses_and_a_space_is_quoted_by_list2cmdline():
    program = "C:/Program Files (x86)/nodejs/npm.cmd"

    command_line = command_line_of(["--version"], program=program)

    assert command_line == f'"{program}" --version'
    assert_cmd_leaves_alone(command_line)


def test_a_program_path_that_cannot_be_passed_on_is_refused():
    with pytest.raises(OSError) as refused:
        resolved(["--version"], program='C:/a "b"/npm.cmd')

    assert refused.value.errno == errno.EINVAL


# Nothing changes where the operating system does not start the file through cmd.exe.


@pytest.mark.parametrize("argument", ["a&b", "p|q", "100%", 'a" & b', "x^y"])
def test_a_program_that_is_not_a_batch_file_gets_its_arguments_as_they_are(argument):
    arguments = resolved(["install", argument], program="C:/tools/npm.exe")

    assert arguments == ["C:/tools/npm.exe", "install", argument]


@pytest.mark.parametrize("argument", ["a&b", "p|q", "100%", 'a" & b', "x^y"])
@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_a_file_named_like_a_batch_file_is_left_alone_off_windows(system, argument):
    arguments = resolved(
        ["install", argument], program="/opt/tools/npm.cmd", system=system
    )

    assert arguments == ["/opt/tools/npm.cmd", "install", argument]


# Every helper that starts a process hands Popen the list it was given, resolved.


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_create_process_with_pipes_hands_popen_the_list_it_was_given(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    with patch("platform.system", return_value="Windows"):
        create_process_with_pipes(["npm", "install", "100%", "a b&c"])

    argv = mock_popen.call_args.args[0]
    assert argv == [PROGRAM, "install", "100%", "a b&c"]
    assert_cmd_leaves_alone(subprocess.list2cmdline(argv))


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_run_command_stream_output_hands_popen_the_list_it_was_given(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    mock_popen.return_value = MagicMock(stdout=[], returncode=0)
    with patch("platform.system", return_value="Windows"):
        run_command_stream_output(["npm", "install", "50%", "a & b"])

    argv = mock_popen.call_args.args[0]
    assert argv == [PROGRAM, "install", "50%", "a & b"]
    assert_cmd_leaves_alone(subprocess.list2cmdline(argv))


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_run_command_stream_output_starts_nothing_for_an_argument_cmd_would_read(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    with patch("platform.system", return_value="Windows"):
        codes = [
            run_command_stream_output(["npm", "install", argument])
            for argument in ('a" & b', "p&q", "x|y", "foo)")
        ]

    assert mock_popen.call_args_list == []
    assert codes == [SPAWN_FAILURE_RETURNCODE] * 4


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_create_process_with_pipes_starts_nothing_for_an_argument_cmd_would_read(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    with patch("platform.system", return_value="Windows"):
        for argument in ("p&q", "100% and 50%", "foo)"):
            with pytest.raises(OSError):
                create_process_with_pipes(["npm", "install", argument])

    assert mock_popen.call_args_list == []


def test_run_command_with_output_handling_starts_nothing_for_an_argument_cmd_would_read(
    tmp_path,
):
    started = []

    def runner(args, **kwargs):
        started.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    with (
        patch("platform.system", return_value="Windows"),
        patch(f"{MODULE}.find_executable", return_value=PROGRAM),
        # _runner takes the one argument ``sandboxed`` (def _runner(sandboxed: bool),
        # called as _runner(sandboxed=...)), so this stand-in takes the same one.
        patch(f"{MODULE}._runner", new=lambda sandboxed: runner),
    ):
        responses = [
            run_command_with_output_handling(
                ["npm", "install", argument], results_dir=tmp_path
            )
            for argument in ("p&q", "foo)")
        ]

    assert started == []
    for response in responses:
        assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
        assert response["spawn_failed"] is True


# A list the caller passes twice is handed on the same both times, and is left as it
# was: the helpers resolve a copy.


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_create_process_with_pipes_leaves_the_callers_list_as_it_was(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    command = ["npm", "install", "50%"]
    with patch("platform.system", return_value="Windows"):
        create_process_with_pipes(command)
        create_process_with_pipes(command)

    assert command == ["npm", "install", "50%"]
    first, second = (call.args[0] for call in mock_popen.call_args_list)
    assert first == second == [PROGRAM, "install", "50%"]


@patch("subprocess.Popen")
@patch(f"{MODULE}.find_executable")
def test_run_command_stream_output_leaves_the_callers_list_as_it_was(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = PROGRAM
    mock_popen.return_value = MagicMock(stdout=[], returncode=0)
    command = ["npm", "install", "50%"]
    with patch("platform.system", return_value="Windows"):
        run_command_stream_output(command)
        run_command_stream_output(command)

    assert command == ["npm", "install", "50%"]
    first, second = (call.args[0] for call in mock_popen.call_args_list)
    assert first == second == [PROGRAM, "install", "50%"]


def test_run_command_with_output_handling_leaves_the_callers_list_as_it_was(tmp_path):
    started = []

    def runner(args, **kwargs):
        started.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    command = ["npm", "install", "50%"]
    with (
        patch("platform.system", return_value="Windows"),
        patch(f"{MODULE}.find_executable", return_value=PROGRAM),
        patch(f"{MODULE}._runner", new=lambda sandboxed: runner),
    ):
        run_command_with_output_handling(command, results_dir=tmp_path)
        run_command_with_output_handling(command, results_dir=tmp_path)

    assert command == ["npm", "install", "50%"]
    assert started == [[PROGRAM, "install", "50%"]] * 2


# The model against the real cmd.exe. Windows only: every other test in this module
# checks the command line and the model, and none starts cmd.exe.

#: The batch files the test writes. Both pass ``%*`` to a one-line Python program that
#: prints the arguments it received. ``plain`` is the simplest wrapper; ``block`` puts
#: ``%*`` inside parentheses, as a wrapper can.
_SHOW_ARGUMENTS = '"{python}" -c "import sys; print(sys.argv[1:])" %*'
BATCH_FILES = {
    "plain": f"@echo off\n{_SHOW_ARGUMENTS}\n",
    "block": (
        '@echo off\nIF EXIST "{python}" (\n'
        f"  {_SHOW_ARGUMENTS}\n"
        ") ELSE (\n"
        f"  {_SHOW_ARGUMENTS}\n"
        ")\n"
    ),
}


@pytest.mark.skipif(sys.platform != "win32", reason="starts a real batch file")
@pytest.mark.parametrize("shape", sorted(BATCH_FILES))
@pytest.mark.parametrize("argument", BATTERY)
def test_a_real_batch_file_receives_each_accepted_argument_as_it_was_given(
    tmp_path, shape, argument
):
    try:
        arguments = resolved(["install", argument])[1:]
    except OSError:
        return  # refused before anything starts: the other tests cover that
    batch_file = tmp_path / "show_arguments.cmd"
    text = BATCH_FILES[shape].format(python=sys.executable)
    batch_file.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
    command_line = subprocess.list2cmdline([str(batch_file), *arguments])

    # What the model says both reads leave alone must be what cmd.exe leaves alone.
    assert_cmd_leaves_alone(command_line)
    completed = subprocess.run(  # nosec B603 - the batch file this test just wrote
        [str(batch_file), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert ast.literal_eval(completed.stdout.strip()) == arguments
