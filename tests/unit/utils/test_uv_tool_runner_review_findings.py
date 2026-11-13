# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Details of the uv runner a review found.

* A version probe that timed out is not remembered, and a refresh that timed
  out does not replace a version an earlier probe found.
* A thread answered by another thread's refused probe reads the refusal.
* A successful install drops the lookups it may have outdated, as a failed or
  stopped one does.
* ``get_installed_tool_version`` passes the offline mode and the package the
  spec was built around, as its siblings do.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.sandbox.policy import SandboxUnavailable
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

UV_PATH = os.path.abspath("/opt/uv/bin/uv")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    _reset_uv_tool_runner_caches()
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("UV_OFFLINE", raising=False)
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def stub_uv(monkeypatch):
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH)
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)


def _ready_runner() -> UVToolRunner:
    runner = UVToolRunner(uv_executable=UV_PATH)
    runner._uv_available_cache = True
    return runner


def _scripted_spawn(monkeypatch, outcomes):
    """spawn_run stand-in: one scripted outcome per call, the last repeated."""
    calls = []

    def _spawn_run(command, **kwargs):
        calls.append(list(command))
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(command, 0, outcome, "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    return calls


def _expire_windows():
    """Make every open version-probe retry window read as already passed."""
    with uv_tool_runner._uv_tool_runner_cache_lock:
        for key in uv_tool_runner._uv_version_probe_windows:
            uv_tool_runner._uv_version_probe_windows[key] = 0.0


def test_a_timed_out_version_probe_opens_a_retry_window_and_is_not_remembered(
    monkeypatch, stub_uv
):
    calls = _scripted_spawn(
        monkeypatch,
        [subprocess.TimeoutExpired(["uv"], 15), "bandit 1.7.8\n"],
    )
    runner = _ready_runner()

    assert runner.get_tool_version("bandit") is None
    assert len(uv_tool_runner._uv_version_probe_windows) == 1
    outcome: dict = {}
    assert runner.get_tool_version("bandit", probe_outcome=outcome) is None
    assert len(calls) == 1, "a call inside the window paid the probe timeout again"
    assert "retry window" in outcome["error"]
    assert uv_tool_runner._uv_tool_version_cache == {}, "the timeout was stored"

    _expire_windows()
    assert runner.get_tool_version("bandit") == "bandit 1.7.8"
    assert len(calls) == 2


def test_a_refresh_skips_the_retry_window(monkeypatch, stub_uv):
    calls = _scripted_spawn(
        monkeypatch, [subprocess.TimeoutExpired(["uv"], 15), "bandit 1.7.8\n"]
    )
    runner = _ready_runner()
    assert runner.get_tool_version("bandit") is None

    assert runner.get_tool_version("bandit", refresh=True) == "bandit 1.7.8"
    assert len(calls) == 2


def test_a_refresh_that_timed_out_keeps_the_version_found_earlier(monkeypatch, stub_uv):
    calls = _scripted_spawn(
        monkeypatch,
        ["bandit 1.7.8\n", subprocess.TimeoutExpired(["uv"], 15)],
    )
    runner = _ready_runner()
    found = runner.get_tool_version("bandit")
    assert found == "bandit 1.7.8"

    assert runner.get_tool_version("bandit", refresh=True) is None

    assert runner.get_tool_version("bandit") == found
    assert len(calls) == 2, "the remembered version was probed away"


def test_a_probe_that_failed_without_timing_out_is_still_remembered(
    monkeypatch, stub_uv
):
    calls = _scripted_spawn(monkeypatch, [OSError(8, "Exec format error"), "x 1\n"])
    runner = _ready_runner()

    assert runner.get_tool_version("bandit") is None
    assert runner.get_tool_version("bandit") is None
    assert len(calls) == 1


def test_a_waiter_answered_by_a_refused_probe_reads_the_refusal(monkeypatch, stub_uv):
    started = threading.Event()
    release = threading.Event()
    waiter_queued = threading.Event()
    spawned = []

    def refuse(command, **kwargs):
        spawned.append(command)
        started.set()
        assert release.wait(30)
        raise SandboxUnavailable("landlock is not available")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", refuse)
    runner = UVToolRunner(uv_executable=UV_PATH)

    waiter_thread: dict = {}

    class _Spy:
        """The probe lock, noting when the waiter first asks for it."""

        def __init__(self, lock):
            self._lock = lock

        def acquire(self, *args, **kwargs):
            if threading.current_thread() is waiter_thread.get("thread"):
                waiter_queued.set()
            return self._lock.acquire(*args, **kwargs)

        def release(self):
            return self._lock.release()

    runner._uv_probe_lock = _Spy(runner._uv_probe_lock)
    answers: dict = {}

    def probe(name):
        answers[name] = runner.uv_availability()
        answers[name + "_reason"] = runner.unavailable_reason()

    prober = threading.Thread(target=probe, args=("prober",))
    waiter = threading.Thread(target=probe, args=("waiter",))
    waiter_thread["thread"] = waiter
    prober.start()
    assert started.wait(30)
    waiter.start()
    assert waiter_queued.wait(30)
    release.set()
    prober.join(30)
    waiter.join(30)

    assert len(spawned) == 1, "the waiter probed for itself"
    assert answers["prober"][0] is False and answers["waiter"][0] is False
    assert "landlock is not available" in answers["prober_reason"]
    assert answers["waiter_reason"] == answers["prober_reason"]


_POSIX = pytest.mark.skipif(
    sys.platform == "win32", reason="the fake uv is a POSIX shell script"
)


@_POSIX
def test_a_successful_install_drops_the_lookups_that_said_absent(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    mark = tmp_path / "installed"
    tool = bindir / "zz_ash_fake_tool"
    uv = tmp_path / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "uv 0.13.0"; exit 0; fi\n'
        'if [ "$1" = "tool" ] && [ "$2" = "list" ]; then\n'
        f'  if [ -e "{mark}" ]; then echo "zz_ash_fake_tool v1.2.3"; echo "- zz_ash_fake_tool"; fi\n'
        "  exit 0; fi\n"
        'if [ "$1" = "tool" ] && [ "$2" = "install" ]; then\n'
        f'  echo x > "{mark}"; echo "#!/bin/sh" > "{tool}"; /bin/chmod 755 "{tool}"\n'
        "  exit 0; fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(subprocess_utils, "_refuse_unresolved_on_windows", False)
    subprocess_utils.clear_find_executable_cache()
    runner = UVToolRunner(uv_executable=str(uv))
    runner._uv_available_cache = True

    assert (
        subprocess_utils.find_executable("zz_ash_fake_tool") is None
    )  # remembered absent
    cleared = MagicMock(wraps=subprocess_utils.clear_find_executable_cache)
    monkeypatch.setattr(subprocess_utils, "clear_find_executable_cache", cleared)
    with patch(
        "automated_security_helper.core.constants.is_offline_mode",
        return_value=False,
    ):
        assert runner.install_tool_with_version("zz_ash_fake_tool", timeout=60) is True

    assert cleared.called, "the lookups that said absent before the install stayed"

    assert subprocess_utils.find_executable("zz_ash_fake_tool") == str(tool)
    subprocess_utils.clear_find_executable_cache()


def test_the_installed_version_probe_is_given_the_offline_mode_and_package(
    monkeypatch,
):
    runner = _ready_runner()
    monkeypatch.setattr(runner, "is_tool_installed", lambda name: True)
    seen = []

    def fake_get_tool_version(*args, **kwargs):
        seen.append((args, kwargs))
        return "1.0"

    monkeypatch.setattr(runner, "get_tool_version", fake_get_tool_version)

    runner.get_installed_tool_version(
        "bandit", "bandit[sarif]", offline=True, package="bandit"
    )
    runner.get_installed_tool_version(
        "bandit", "bandit[sarif]", offline=True, package="bandit", python_request="3.12"
    )

    for _args, kwargs in seen:
        assert kwargs["offline"] is True
        assert kwargs["package"] == "bandit"
    assert seen[1][1]["python_request"] == "3.12"
