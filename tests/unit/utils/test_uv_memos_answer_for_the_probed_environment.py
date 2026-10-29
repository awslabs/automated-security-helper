# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv memos answer only for the environment they probed.

The runner's getter re-resolves uv on every call (``find_uv_or_none``:
the uv installed with ASH, then PATH), and the production runner is built
bare (``UVToolRunner()``), so nothing ever assigns ``uv_executable``. An
answer memoized through one executable is therefore no answer once the
getter resolves another: a uv installed into the ASH bin dir after a miss
(the MCP server's "uv is not available" until restart), or one that
disappears after a hit, is a different question and is probed.

The same holds for the version memo: ``uv tool run <tool> --version``
through one uv is not another uv's answer, and an offline probe is not an
online one. Both memos key their answers to (executable, offline mode);
the availability memo forgets the other executable's answer wholesale,
the version memo keeps one answer per environment under its tool::spec
key, so invalidation by tool name still drops them all at once.

Every executable here is a fake /bin/sh script under tmp_path; no cell
starts a real uv.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


@pytest.fixture
def probes(monkeypatch):
    """Every spawn through the runner's spawn_run: the executable started and
    whether it was an availability probe (--version) or a tool-version one."""
    log = []
    real = uv_tool_runner.spawn_run

    def _spawn_run(command, **kwargs):
        log.append(list(command))
        return real(command, **kwargs)

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return log


def _answering_uv(tmp_path: Path, name: str, version: str = "0.0.0") -> str:
    script = tmp_path / name
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv 0.13.0"; exit 0; fi\n'
        'if [ "$1" = "tool" ] && [ "$2" = "run" ]; then '
        f'echo "{version}"; exit 0; fi\n'
        "exit 64\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return str(script)


def _quiet_patches():
    return (
        patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ),
        patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ),
    )


@pytest.mark.parametrize(
    "case", ["absent-then-present", "present-then-gone", "setter-control"]
)
def test_the_availability_memo_answers_for_the_executable_that_was_probed(
    tmp_path, monkeypatch, probes, case
):
    """A memoized answer follows the executable it probed, not the runner:
    when the getter resolves another uv (or the setter assigns one), the
    other executable's memo is no answer and the new one is probed."""
    missing = str(tmp_path / "zz-not-there")
    present = _answering_uv(tmp_path, "zz-answers")
    first, second = (
        (present, missing) if case == "present-then-gone" else (missing, present)
    )
    resolved = {"path": first}
    if case == "setter-control":
        runner = UVToolRunner(uv_executable=first)
    else:
        monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: resolved["path"])
        runner = UVToolRunner()

    first_answer = runner.is_uv_available()
    if case == "setter-control":
        runner.uv_executable = second
    else:
        resolved["path"] = second
    assert runner.uv_executable == second, "premise: the runner names the other uv"
    second_answer = runner.is_uv_available()

    started = [argv[0] for argv in probes]
    assert (first_answer, second_answer, started) == (
        first == present,
        second == present,
        [first, second],
    )


def test_a_version_answer_does_not_follow_a_swapped_uv(tmp_path):
    """The version memo is keyed to the uv that answered: after the swap,
    the second uv's answer comes from the second uv, with no refresh flag."""
    a = _answering_uv(tmp_path, "uva", version="1.0.0")
    b = _answering_uv(tmp_path, "uvb", version="2.0.0")
    runner = UVToolRunner(uv_executable=a)
    p1, p2 = _quiet_patches()
    with p1, p2:
        assert runner.get_tool_version("bandit") == "1.0.0"
        runner.uv_executable = b
        assert runner.get_tool_version("bandit") == "2.0.0"


def test_swap_control_a_refresh_asks_the_new_uv(tmp_path):
    """The control for the cell above: the two fakes really answer
    differently, read through the explicit re-probe."""
    a = _answering_uv(tmp_path, "uva", version="1.0.0")
    b = _answering_uv(tmp_path, "uvb", version="2.0.0")
    runner = UVToolRunner(uv_executable=a)
    p1, p2 = _quiet_patches()
    with p1, p2:
        assert runner.get_tool_version("bandit") == "1.0.0"
        runner.uv_executable = b
        assert runner.get_tool_version("bandit", refresh=True) == "2.0.0"


def test_a_version_answer_is_remembered_per_environment(tmp_path, probes):
    """Keying is memory, not amnesia: swapping back to the first uv answers
    from its remembered entry, with no third version probe."""
    a = _answering_uv(tmp_path, "uva", version="1.0.0")
    b = _answering_uv(tmp_path, "uvb", version="2.0.0")
    runner = UVToolRunner(uv_executable=a)
    p1, p2 = _quiet_patches()
    with p1, p2:
        assert runner.get_tool_version("bandit") == "1.0.0"
        runner.uv_executable = b
        assert runner.get_tool_version("bandit") == "2.0.0"
        runner.uv_executable = a
        assert runner.get_tool_version("bandit") == "1.0.0"
    version_probes = [argv for argv in probes if argv[1:3] == ["tool", "run"]]
    assert len(version_probes) == 2, version_probes


def test_invalidation_by_tool_name_drops_every_environments_answer(tmp_path):
    """invalidate_tool_version_cache matches the tool::spec key, so one
    invalidation drops the answers of every environment at once."""
    a = _answering_uv(tmp_path, "uva", version="1.0.0")
    b = _answering_uv(tmp_path, "uvb", version="2.0.0")
    runner = UVToolRunner(uv_executable=a)
    p1, p2 = _quiet_patches()
    with p1, p2:
        assert runner.get_tool_version("bandit") == "1.0.0"
        runner.uv_executable = b
        assert runner.get_tool_version("bandit") == "2.0.0"
    uv_tool_runner.invalidate_tool_version_cache("bandit")
    with uv_tool_runner._uv_tool_runner_cache_lock:
        assert "bandit::" not in uv_tool_runner._uv_tool_version_cache
