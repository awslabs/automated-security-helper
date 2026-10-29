# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH hands the operating system when the program it resolved is a batch file.

On Windows ASH's lookup resolves a tool to ``<name>.bat`` or ``<name>.cmd`` when no
``.exe`` exists (``subprocess_utils._executable_candidate_names``): RubyGems leaves a
``.bat``, npm leaves a ``.cmd``. ``CreateProcess`` starts such a file through
cmd.exe, which reads the command line itself, and the batch file passes its arguments
on with ``%*``, which cmd.exe reads again. So ``<``, ``>``, ``|``, ``&`` and ``^`` in
an argument are redirections, pipes, command separators and escapes, and a parenthesis
closes or opens the block that can hold ``%*``, unless the argument is in double
quotes. ``subprocess.list2cmdline`` quotes an argument only when it is empty or holds a
space or tab.

The spawn helpers (``run_command_stream_output``, ``run_command_with_output_handling``
and ``create_process_with_pipes``) replace the program with the resolved path and pass
the list on to ``subprocess.Popen`` with ``shell=False``. ``_resolve_for_spawn`` looks
at the program's suffix, and for a batch file refuses, before ``Popen`` is called, an
argument that ``list2cmdline`` would write bare with one of those characters in it.
Without that a batch program would receive its arguments as ``list2cmdline`` writes
them, and an argument with one of those characters in it would be read by cmd.exe
instead of reaching the program.

The spawn is checked on a Windows host as ASH sees one: the platform is patched, the
way ``test_find_executable_windows_wrappers.py`` patches it.

``list2cmdline`` is plain Python and gives the same text on every host, so the
command line the operating system would be given is checked here without Windows.
How cmd.exe reads it is the model in ``tests/utils/cmd_exe_model.py``; the model is
measured against a real batch file by the Windows-only test in
``test_batch_program_argument_protection.py``.
"""

import subprocess  # nosec B404 - only list2cmdline, which starts nothing
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    run_command_stream_output,
)
from tests.utils.cmd_exe_model import delivered, reads_as_a_command


@patch("platform.system", new=lambda: "Windows")
@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_the_arguments_of_a_batch_program_reach_cmd_with_their_metacharacters_protected(
    mock_find_executable, mock_popen
):
    program = "C:/tools/npm.cmd"
    mock_find_executable.return_value = program
    mock_popen.return_value = MagicMock(stdout=[], returncode=0)

    run_command_stream_output(
        [
            "npm",
            "install",
            "left<right x",
            "a>b y",
            "x|y z",
            "p&q r",
            "c^d e",
            "--prefix",
            "C:/Program Files/tools",
        ]
    )

    if len(mock_popen.call_args_list) != 1:
        pytest.fail(f"expected one spawn, got {mock_popen.call_args_list}")
    argv = mock_popen.call_args.args[0]
    if argv[0] != program:
        pytest.fail(f"the program was not resolved to the batch file: {argv[0]!r}")
    command_line = subprocess.list2cmdline(argv)
    # The control: an argument with a space is quoted, so the command line below is
    # one the quoting reached.
    if '"C:/Program Files/tools"' not in command_line:
        pytest.fail(
            f"list2cmdline did not quote an argument with a space: {command_line}"
        )

    assert reads_as_a_command(command_line) == [], (
        f"cmd.exe would read these in {command_line!r}"
    )
    assert delivered(command_line) == command_line


@patch("platform.system", new=lambda: "Windows")
@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_a_batch_program_is_not_started_with_a_bare_metacharacter_in_an_argument(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = "C:/tools/npm.cmd"

    code = run_command_stream_output(["npm", "install", "left<right", "p&q", "c^d"])

    assert mock_popen.call_args_list == []
    assert code == SPAWN_FAILURE_RETURNCODE


@patch("platform.system", new=lambda: "Windows")
@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_a_batch_program_is_not_started_with_a_bare_parenthesis_in_an_argument(
    mock_find_executable, mock_popen
):
    mock_find_executable.return_value = "C:/tools/npm.cmd"

    code = run_command_stream_output(["npm", "install", "--filter=a)b"])

    assert mock_popen.call_args_list == []
    assert code == SPAWN_FAILURE_RETURNCODE
