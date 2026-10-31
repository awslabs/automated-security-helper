# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A string command is the program's name in every spawn helper.

Five helpers already read a string argv as a one-element list (``_argv_list``).
``run_ended_with_the_server`` and ``resolve_command`` still copied it with
``list()``, which turned ``"git"`` into ``["g", "i", "t"]`` and resolved the
letter ``g`` as the program. Both now go through the same copy.

No process is started: the cancellable runner and the resolution are stood in for.

The two cases for the helpers that were fixed are not the whole set. The last case
runs all seven public entry points that take a command (the five that already read
a string as one program, and those two), each with the string, and asserts the
resolution seam of every one is handed the string as a single program.
"""

import contextlib
import subprocess
from typing import Any, Dict, List

import pytest

from automated_security_helper.utils import subprocess_utils as spu

pytestmark = pytest.mark.unit

_TOOL = "ash-u26 no such tool"

#: The seven public entry points that take a command, each called with the
#: string on its own.
_HELPERS = {
    "resolve_command": lambda: spu.resolve_command(_TOOL),
    "spawn_run": lambda: spu.spawn_run(_TOOL),
    "run_ended_with_the_server": lambda: spu.run_ended_with_the_server(_TOOL),
    "run_command": lambda: spu.run_command(_TOOL),
    "run_command_with_output_handling": lambda: spu.run_command_with_output_handling(
        _TOOL
    ),
    "run_command_stream_output": lambda: spu.run_command_stream_output(_TOOL),
    "create_process_with_pipes": lambda: spu.create_process_with_pipes(_TOOL),
}


def test_run_ended_with_the_server_reads_a_string_as_the_programs_name(monkeypatch):
    seen: Dict[str, Any] = {}

    def run_cancellable(args, **kwargs):
        seen["args"] = args
        return None

    monkeypatch.setattr(spu, "_resolve_for_spawn", lambda args, cwd, env: None)
    monkeypatch.setattr(spu, "_run_cancellable", run_cancellable)
    spu.run_ended_with_the_server(_TOOL)
    assert seen["args"] == [_TOOL]


def test_run_ended_with_the_server_copies_a_list_and_a_tuple(monkeypatch):
    seen: Dict[str, Any] = {}

    def run_cancellable(args, **kwargs):
        seen["args"] = args
        return None

    monkeypatch.setattr(spu, "_resolve_for_spawn", lambda args, cwd, env: None)
    monkeypatch.setattr(spu, "_run_cancellable", run_cancellable)
    given = [_TOOL, "--x"]
    spu.run_ended_with_the_server(given)
    assert seen["args"] == given and seen["args"] is not given
    spu.run_ended_with_the_server((_TOOL, "--x"))
    assert seen["args"] == [_TOOL, "--x"]


def test_resolve_command_reads_a_string_as_the_programs_name(monkeypatch):
    def found(args, cwd, env):
        args[0] = "/opt/ash-u26/bin/tool"

    monkeypatch.setattr(spu, "_resolve_for_spawn", found)
    assert spu.resolve_command(_TOOL) == ["/opt/ash-u26/bin/tool"]
    given = [_TOOL, "--x"]
    assert spu.resolve_command(given) == ["/opt/ash-u26/bin/tool", "--x"]
    assert given == [_TOOL, "--x"], "the caller's list is left as it was"


@pytest.mark.parametrize("helper", sorted(_HELPERS))
def test_every_helper_hands_its_resolution_the_string_as_one_program(
    helper, monkeypatch
):
    seen: List[List[Any]] = []

    def resolved_or_refused(args, *rest):
        seen.append(list(args))

    def resolve_for_spawn(args, *rest):
        seen.append(list(args))

    def runner(sandboxed):
        def run(args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "", "")

        return run

    def popen_that_cannot_start(*args, **kwargs):
        raise OSError(2, "no such program")

    # The resolution seams record what they were given and refuse nothing; the
    # runners and Popen are stood in for, so no process is started and every
    # helper returns (or fails to start) right after its resolution.
    monkeypatch.setattr(spu, "_resolved_or_refused", resolved_or_refused)
    monkeypatch.setattr(spu, "_resolve_for_spawn", resolve_for_spawn)
    monkeypatch.setattr(spu, "_runner", runner)
    monkeypatch.setattr(spu, "_run_cancellable", lambda args, **kwargs: None)
    monkeypatch.setattr(spu.subprocess, "Popen", popen_that_cannot_start)

    with contextlib.suppress(OSError):
        _HELPERS[helper]()

    assert seen == [[_TOOL]], f"{helper} resolved {seen}"
