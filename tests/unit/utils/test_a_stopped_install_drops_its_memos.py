# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An install stopped mid-flight drops the memos it may have outdated.

ASH stops a timed-out or cancelled install without knowing how far uv got:
the tool can be fully installed by the time the stop lands. Two memos then
no longer describe the environment and both are dropped on the stop paths,
exactly as a completed install drops them:

- the version memo (``_uv_tool_version_cache``): a pre-install probe of a
  missing tool remembered None;
- the lookup memos behind ``get_uv_tool_command`` and ``find_executable``:
  a pre-install lookup remembered that nothing serves the tool.

``ScanCancelled`` is a BaseException, so the cancel path is its own arm:
the TimeoutExpired, CalledProcessError and Exception arms all let it pass,
and before this file's fixes it dropped nothing. A CalledProcessError
keeps the memos by design: that is uv's own answer that it did not
install.

Every uv here is a fake /bin/sh script under tmp_path, started by absolute
path; no cell starts a real uv.
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    _reset_uv_tool_runner_caches,
)


@pytest.fixture(autouse=True)
def _isolated_caches(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()
    yield
    _reset_uv_tool_runner_caches()
    subprocess_utils.clear_find_executable_cache()


def _fake_uv(tmp_path: Path, name: str, *, version: str, install: str) -> Path:
    """A fake uv. ``install`` is the shell body of ``uv tool install``;
    ``tool run <x> --version`` prints *version* once the install marker
    exists and exits 2 before; ``tool list`` lists bandit once it exists."""
    mark = tmp_path / f"{name}.installed"
    script = tmp_path / name
    script.write_text(
        "#!/bin/sh\n"
        f'MARK="{mark}"\n'
        'if [ "$1" = "--version" ]; then echo "uv 0.13.0"; exit 0; fi\n'
        'if [ "$1" = "tool" ] && [ "$2" = "list" ]; then\n'
        '  if [ -e "$MARK" ]; then echo "bandit v1.2.3"; echo "- bandit"; fi; exit 0; fi\n'
        'if [ "$1" = "tool" ] && [ "$2" = "install" ]; then\n'
        f"  {install}\n"
        "  exit 0; fi\n"
        'if [ "$1" = "tool" ] && [ "$2" = "run" ]; then\n'
        f'  if [ -e "$MARK" ]; then echo "{version}"; exit 0; fi; exit 2; fi\n'
        "exit 64\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


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


def _version_memo_keys():
    with uv_tool_runner._uv_tool_runner_cache_lock:
        return set(uv_tool_runner._uv_tool_version_cache)


@pytest.mark.unit
def test_a_cancelled_install_drops_the_memo():
    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    with uv_tool_runner._uv_tool_runner_cache_lock:
        uv_tool_runner._uv_tool_version_cache["bandit::"] = None
    p1, p2 = _quiet_patches()
    with (
        patch("automated_security_helper.utils.subprocess_utils._run_plain") as run,
        p1,
        p2,
    ):
        run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # tool list: not installed
            ScanCancelled("the scan was cancelled while uv was running"),
        ]
        with pytest.raises(ScanCancelled):
            runner.install_tool_with_version("bandit", timeout=300)
        assert run.call_count == 2, "premise: the install's spawn raised the cancel"
    assert "bandit::" not in _version_memo_keys()


@pytest.mark.integration
def test_a_cancelled_install_through_a_real_cancel_scope_drops_the_memo(tmp_path):
    uv = _fake_uv(
        tmp_path, "uvc", version="1.2.3", install='touch "$MARK"; exec sleep 30'
    )
    runner = UVToolRunner(uv_executable=str(uv))
    # The pre-install probe memoizes its answer for a tool uv has not installed.
    assert runner.get_tool_version("bandit") is None
    assert "bandit::" in _version_memo_keys()
    event = CancelEvent()
    timer = threading.Timer(1.0, event.set)
    p1, p2 = _quiet_patches()
    started = time.monotonic()
    with p1, p2, cancel_scope(event):
        timer.start()
        try:
            with pytest.raises(ScanCancelled):
                runner.install_tool_with_version("bandit", timeout=60)
        finally:
            timer.cancel()
    assert time.monotonic() - started < 30, "the cancel did not stop the install"
    assert (tmp_path / "uvc.installed").exists(), (
        "premise: the install landed before the cancel"
    )
    assert "bandit::" not in _version_memo_keys()
    assert runner.get_tool_version("bandit") == "1.2.3"


def _timed_out_install(tmp_path, monkeypatch):
    """An install that lands and then outlives its timeout, after a probe and
    a command lookup both remembered the tool as absent."""
    uv = _fake_uv(
        tmp_path, "uvt", version="1.2.3", install='touch "$MARK"; exec sleep 20'
    )
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: str(uv))
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)
    runner = UVToolRunner(uv_executable=str(uv))
    assert runner.get_tool_version("bandit") is None
    # Remembered: a probe ran and found nothing serving the tool.
    assert uv_tool_runner.get_uv_tool_command("bandit") is None
    p1, p2 = _quiet_patches()
    with p1, p2:
        with pytest.raises(UVToolRunnerError, match="timed out"):
            runner.install_tool_with_version("bandit", timeout=2)
    assert (tmp_path / "uvt.installed").exists(), (
        "premise: the install landed before the timeout"
    )
    return runner


@pytest.mark.integration
def test_a_timed_out_install_lets_the_version_be_asked_again(tmp_path, monkeypatch):
    runner = _timed_out_install(tmp_path, monkeypatch)
    assert runner.get_tool_version("bandit") == "1.2.3"


@pytest.mark.integration
def test_a_timed_out_install_lets_the_command_be_found(tmp_path, monkeypatch):
    """The lookup memos drop with the version memo: a completed install
    clears them (the mixin's success arm), and a timed-out one that may
    have landed must not keep answering the pre-install None."""
    _timed_out_install(tmp_path, monkeypatch)
    assert uv_tool_runner.get_uv_tool_command("bandit") == [
        "uv",
        "tool",
        "run",
        "bandit",
    ]


@pytest.mark.integration
def test_a_probe_racing_the_install_is_dropped_after_the_stop(tmp_path, monkeypatch):
    """The order pin: a version probe that runs WHILE the install runs
    memoizes the pre-install answer again, so the drop has to come after
    the stop, not before the attempt."""
    uv = _fake_uv(
        tmp_path,
        "uvq",
        version="1.2.3",
        install='sleep 1; touch "$MARK"; exec sleep 20',
    )
    runner = UVToolRunner(uv_executable=str(uv))
    probed = []

    def probe_mid_install():
        time.sleep(0.3)
        probed.append(runner.get_tool_version("bandit"))

    worker = threading.Thread(target=probe_mid_install)
    p1, p2 = _quiet_patches()
    with p1, p2:
        worker.start()
        with pytest.raises(UVToolRunnerError, match="timed out"):
            runner.install_tool_with_version("bandit", timeout=3)
        worker.join(timeout=10)
    assert probed == [None], "premise: the mid-install probe answered and memoized None"
    assert "bandit::" not in _version_memo_keys()
    assert runner.get_tool_version("bandit") == "1.2.3"


@pytest.mark.unit
def test_uvs_own_refusal_keeps_the_memo():
    """The must-not-flag control: a CalledProcessError is uv's own answer
    that it did not install, so the pre-install memo still describes the
    environment and is kept (the retry loop re-raises after its attempts)."""
    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    with uv_tool_runner._uv_tool_runner_cache_lock:
        uv_tool_runner._uv_tool_version_cache["bandit::"] = None
    p1, p2 = _quiet_patches()
    with (
        patch("automated_security_helper.utils.subprocess_utils._run_plain") as run,
        p1,
        p2,
    ):
        run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # tool list: not installed
            subprocess.CalledProcessError(1, "uv", stderr="resolver says no"),
        ]
        with pytest.raises(UVToolRunnerError):
            runner.install_tool_with_version("bandit", timeout=300)
    assert "bandit::" in _version_memo_keys()
