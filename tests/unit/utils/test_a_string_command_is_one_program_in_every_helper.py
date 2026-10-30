# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A string command is the program's name in every spawn helper.

Five helpers already read a string argv as a one-element list (``_argv_list``).
``run_ended_with_the_server`` and ``resolve_command`` still copied it with
``list()``, which turned ``"git"`` into ``["g", "i", "t"]`` and resolved the
letter ``g`` as the program. Both now go through the same copy.

No process is started: the cancellable runner and the resolution are stood in for.
"""

from typing import Any, Dict

import pytest

from automated_security_helper.utils import subprocess_utils as spu

pytestmark = pytest.mark.unit

_TOOL = "ash-u26 no such tool"


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
