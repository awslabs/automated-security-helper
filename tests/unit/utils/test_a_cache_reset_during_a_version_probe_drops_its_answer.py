# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A version probe that finishes after a cache reset does not remember its answer.

The probe reads its key's generation before it spawns and stores its answer
only if the generation is unchanged when it finishes. A reset that cleared
the generation table made the key read 0 again, so a probe that had read 0
before the reset passed that check and wrote its pre-reset answer into the
fresh memo. The command memo avoids the same trap by moving its lookup
generation; the version memo's generations now move on a reset too.

The hold is forced: the probe's spawn blocks on an event, the reset runs
while it is held, and the probe is released only after that.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

_KEY = "zz-tool::zz-package"


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def _probe_with_a_reset_while_held(monkeypatch) -> dict:
    runner = UVToolRunner()
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    runner.uv_executable = "/zz-fake/uv"
    in_probe = threading.Event()
    release = threading.Event()

    def blocking_spawn(command, **kwargs):
        in_probe.set()
        assert release.wait(timeout=30.0), "the probe was never released"
        return SimpleNamespace(returncode=0, stdout="9.9.9\n", stderr="")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", blocking_spawn)

    outcome: dict = {}
    holder = threading.Thread(
        target=lambda: outcome.setdefault(
            "answer", runner.get_tool_version("zz-tool", "zz-package")
        )
    )
    holder.start()
    try:
        assert in_probe.wait(timeout=10.0), "the probe never started"
        _reset_uv_tool_runner_caches()
    finally:
        release.set()
        holder.join(timeout=10.0)
    # After the finally, so a failure above is not replaced by this one.
    assert not holder.is_alive(), "the probe thread never returned"
    return outcome


def test_a_probe_finishing_after_a_reset_does_not_write_its_answer_to_the_memo(
    monkeypatch,
):
    outcome = _probe_with_a_reset_while_held(monkeypatch)

    # The caller that asked still gets the answer it probed for.
    assert outcome.get("answer") == "9.9.9", outcome
    # The memo the reset emptied does not take it back.
    assert _KEY not in uv_tool_runner._uv_tool_version_cache


def test_a_probe_after_the_reset_is_remembered(monkeypatch):
    """The must-not-flag control: only a probe the reset overtook is skipped.

    The probe after the reset answers a different value from the held one, so
    a stale store (a cache hit on the held probe's answer) cannot satisfy it:
    the answer and the remembered entry must both be the second probe's.
    """
    _probe_with_a_reset_while_held(monkeypatch)
    spawned: list = []

    def second_spawn(command, **kwargs):
        spawned.append(command)
        return SimpleNamespace(returncode=0, stdout="10.0.0\n", stderr="")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", second_spawn)
    runner = UVToolRunner()
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    runner.uv_executable = "/zz-fake/uv"

    assert runner.get_tool_version("zz-tool", "zz-package") == "10.0.0"
    assert len(spawned) == 1, "the probe after the reset did not run"
    remembered = uv_tool_runner._uv_tool_version_cache.get(_KEY)
    assert isinstance(remembered, dict)
    assert "10.0.0\n" in remembered.values()
    assert "9.9.9\n" not in remembered.values()
