# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool-version probe that crosses an invalidation is not remembered.

The version memo's store ran unconditionally after the probe, while
``invalidate_tool_version_cache`` (an install, an uninstall, a version
change) deliberately does not wait for the probe lock, so a drop can land
while the probe's subprocess runs. The store then wrote the pre-drop answer
back over the drop, and later callers were answered with the version of a
tool that had just been replaced or removed.

The interleaving is forced, not raced: the probe's spawn blocks on an event,
the invalidation lands while it is blocked, and the probe then finishes. The
crossed probe's own caller still gets the answer it asked for; what must not
happen is that answer being remembered for everyone after the drop.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
    invalidate_tool_version_cache,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def _probe_crossing_an_invalidation(monkeypatch, invalidated_name: str):
    """One ``get_tool_version`` whose probe is mid-flight when
    *invalidated_name* is invalidated. Returns the runner, for follow-ups."""
    runner = UVToolRunner()
    monkeypatch.setattr(UVToolRunner, "is_uv_available", lambda self: True)
    runner.uv_executable = "/zz-fake/uv"

    in_probe = threading.Event()
    release_probe = threading.Event()

    def blocking_spawn(command, **kwargs):
        in_probe.set()
        assert release_probe.wait(timeout=10.0), "the probe was never released"
        return SimpleNamespace(returncode=0, stdout="9.9.9\n", stderr="")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", blocking_spawn)

    answers: list = []
    thread = threading.Thread(
        target=lambda: answers.append(runner.get_tool_version("zz-tool", "zz-package"))
    )
    thread.start()
    try:
        assert in_probe.wait(timeout=10.0), "the probe never started"
        invalidate_tool_version_cache(invalidated_name)
    finally:
        release_probe.set()
        thread.join(timeout=10.0)
    assert not thread.is_alive(), "the probing thread never returned"
    assert answers == ["9.9.9"], (
        "the crossed probe's own caller still gets the answer it asked for",
        answers,
    )
    return runner


def test_an_invalidation_during_the_probe_discards_the_store(monkeypatch):
    _probe_crossing_an_invalidation(monkeypatch, "zz-tool")

    assert uv_tool_runner._uv_tool_version_cache == {}, (
        (
            "the probe's pre-drop answer was remembered over the invalidation, "
            "so later callers would be answered with a replaced tool's version"
        ),
        uv_tool_runner._uv_tool_version_cache,
    )


def test_an_invalidation_of_another_tool_keeps_the_store(monkeypatch):
    """The must-not-flag control: only the probed tool's own drop discards.

    An invalidation of an unrelated tool while this probe runs must not cost
    the memo, or every install would empty every in-flight probe's answer.
    """
    _probe_crossing_an_invalidation(monkeypatch, "zz-other")

    # The memo stores the probe's unstripped stdout; the strip runs on the
    # way out, after the redaction.
    remembered = uv_tool_runner._uv_tool_version_cache.get("zz-tool::zz-package")
    assert isinstance(remembered, dict) and list(remembered.values()) == ["9.9.9\n"], (
        uv_tool_runner._uv_tool_version_cache
    )


def test_the_next_probe_after_the_drop_is_remembered(monkeypatch):
    """The discard covers one crossed probe, not the key forever: the next
    call probes the post-drop tool and its answer is remembered normally."""
    runner = _probe_crossing_an_invalidation(monkeypatch, "zz-tool")

    monkeypatch.setattr(
        uv_tool_runner,
        "spawn_run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="10.0.0\n", stderr=""
        ),
    )
    assert runner.get_tool_version("zz-tool", "zz-package") == "10.0.0"

    # Unstripped in the memo, stripped on the way out (see the control above).
    remembered = uv_tool_runner._uv_tool_version_cache.get("zz-tool::zz-package")
    assert isinstance(remembered, dict) and list(remembered.values()) == ["10.0.0\n"], (
        uv_tool_runner._uv_tool_version_cache
    )
