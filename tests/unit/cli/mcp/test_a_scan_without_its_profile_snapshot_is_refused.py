# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan whose profile snapshot cannot be written is refused, not run live.

The runner copies the session's profile for the scan -- the trusted base of
a delivered config, or the profile standing as the scan's own config -- so
the file the redaction set saw is the file the scan runs under. When that
copy cannot be written (no space, no quota, no file handles), running the
scan on the live profile instead would reopen the window the copy closes:
a rebind landing while the scan waits at the session lock would run it on
values the redaction set never saw. The runner therefore fails closed: the
scan is refused with a reason naming the failure's type only, the live
profile is not read in its place, and whatever was partly written is
removed.

Driven end to end through the directory tool against a real session sandbox,
with only ``run_ash_scan`` replaced.
"""

import asyncio
import contextlib
import errno
import json
import os
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.mcp_sessions import a_session_with_a_bound_profile
from tests.utils.tasks import drain

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

_PROFILE_VALUE = "a-profile-value-read-from-the-environment"
_REBOUND_VALUE = "a-rebound-value-read-from-the-environment"
_PLANTED_STRERROR = "a-planted-strerror-the-reason-must-not-carry"


def _a_session_with_a_bound_profile(tmp_path, monkeypatch, session_id):
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    target, delivered, profile, config_dir = a_session_with_a_bound_profile(
        tmp_path / "ws",
        monkeypatch,
        session_id,
        profile_text="project_name: ${ASH_REFUSAL_PROFILE:unset}\n",
        profile_name="first",
        env={
            "ASH_REFUSAL_PROFILE": _PROFILE_VALUE,
            "ASH_REFUSAL_SWAP": _REBOUND_VALUE,
        },
    )
    other = tmp_path / "operator"
    other.mkdir(exist_ok=True)
    (other / "second.ash.yaml").write_text(
        "project_name: ${ASH_REFUSAL_SWAP:unset}\n", encoding="utf-8"
    )

    def a_rebind_of_the_sessions_profile():
        config = load_config_file_for_run(other / "second.ash.yaml")[1]
        written = profile_registry.materialize_session_config(session_id, config)
        assert Path(written).resolve() == profile.resolve(), (written, profile)
        profile_registry.bind_session_config(
            session_id, config=config, profile_name="second", config_path=written
        )

    return target, delivered, profile, config_dir, a_rebind_of_the_sessions_profile


class _ARebindOnLockAcquire:
    """The session's lock, rebinding the profile once just before it is
    taken: the window the snapshot closes. A refused scan never reaches the
    lock, so a fired hook is itself a finding."""

    def __init__(self, real, rebind):
        self._real = real
        self._rebind = rebind
        self.fired = False
        self.trouble: list = []

    def _fire(self):
        if not self.fired:
            self.fired = True
            try:
                self._rebind()
            except BaseException as trouble:  # noqa: BLE001 - re-raised by the cell
                self.trouble.append(trouble)

    def __enter__(self):
        self._fire()
        self._real.acquire()
        return self

    def __exit__(self, *exc):
        self._real.release()
        return False

    def acquire(self, *args, **kwargs):
        self._fire()
        return self._real.acquire(*args, **kwargs)

    def release(self):
        self._real.release()


def _a_lock_that_rebinds_on_acquire(monkeypatch, session_id, rebind):
    from automated_security_helper.cli.mcp.sessions import get_default_registry

    session = get_default_registry().get_or_create(session_id)
    hook = _ARebindOnLockAcquire(session.lock, rebind)
    monkeypatch.setattr(session, "_lock", hook)
    assert get_default_registry().get_or_create(session_id).lock is hook
    return hook


def _snapshot_writes_fail(monkeypatch, *, partly: bool = False) -> List[str]:
    """Every write of a per-scan copy fails like a full disk: at the create
    itself, or -- ``partly`` -- after the file was created and half its
    content written, as a mid-copy failure leaves it."""
    attempts: List[str] = []
    snapshot_fds = set()
    real_open, real_fdopen = os.open, os.fdopen

    def an_open_that_runs_out_of_space(path, flags, *args, **kwargs):
        name = Path(path).name if isinstance(path, (str, Path)) else ""
        if name.startswith(".ash-scan-"):
            attempts.append(name)
            if not partly:
                raise OSError(errno.ENOSPC, f"No space left: {_PLANTED_STRERROR}")
            fd = real_open(path, flags, *args, **kwargs)
            snapshot_fds.add(fd)
            return fd
        return real_open(path, flags, *args, **kwargs)

    class _AHandleOutOfSpace:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()
            return False

        def fileno(self):
            return self._handle.fileno()

        def write(self, data):
            self._handle.write(data[: max(1, len(data) // 2)])
            self._handle.flush()
            raise OSError(errno.ENOSPC, f"No space left: {_PLANTED_STRERROR}")

    def an_fdopen_whose_write_fails(fd, *args, **kwargs):
        handle = real_fdopen(fd, *args, **kwargs)
        if fd in snapshot_fds:
            return _AHandleOutOfSpace(handle)
        return handle

    monkeypatch.setattr(os, "open", an_open_that_runs_out_of_space)
    if partly:
        monkeypatch.setattr(os, "fdopen", an_fdopen_whose_write_fails)
    return attempts


def _a_recorded_live_read(monkeypatch) -> List[str]:
    """Record what the runner's profile-values read is pointed at."""
    reads: List[str] = []
    real_read = mcp_tools._profile_environment_values

    def read(profile, *args, **kwargs):
        reads.append(str(profile))
        return real_read(profile, *args, **kwargs)

    monkeypatch.setattr(mcp_tools, "_profile_environment_values", read)
    return reads


def _the_scan_in_the_session(target, config_path, session_id, run):
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(config_path), session_id=session_id
        )
        await drain(return_exceptions=True)
        return started

    try:
        with contextlib.ExitStack() as stack:
            for manager in (
                patch.object(ras, "run_ash_scan", run),
                patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
                patch(f"{_MGMT}.get_scan_registry", return_value=registry),
                patch(f"{_TOOLS}._logger", logger),
            ):
                stack.enter_context(manager)
            started = asyncio.run(start_and_wait_for_the_runner())
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(
                    scans[0]["scan_id"], session_id=session_id
                )
            )
    finally:
        profile_registry.clear_session_state(session_id)
    return entry, str(logger.mock_calls), json.dumps(progress, default=str)


def _snapshot_leftovers(config_dir: Path) -> List[str]:
    return sorted(
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    )


@pytest.mark.parametrize("branch", ["delivered-config", "profile-as-config"])
def test_a_scan_whose_profile_snapshot_cannot_be_written_is_refused(
    tmp_path, monkeypatch, branch
):
    """Both branches that snapshot the profile fail closed when the copy
    cannot be written: the scan never runs, the live profile is not read in
    its place, the entry's reason names the failure's type and not its text,
    and the session lock is never taken, so no rebind window even opens."""
    session_id = f"snapshot-refusal-{branch}"
    target, delivered, profile, config_dir, rebind = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    config_path = (
        delivered
        if branch == "delivered-config"
        else profile_registry.resolve_session_config_path(session_id)
    )
    attempts = _snapshot_writes_fail(monkeypatch)
    reads = _a_recorded_live_read(monkeypatch)
    hook = _a_lock_that_rebinds_on_acquire(monkeypatch, session_id, rebind)
    seen: Dict[str, Any] = {}

    def a_run_that_must_not_start(*args, **kwargs):
        seen["ran"] = True
        raise RuntimeError("the tool crashed")

    entry, logged, progress = _the_scan_in_the_session(
        target, config_path, session_id, a_run_that_must_not_start
    )

    assert attempts, "control: no copy was ever attempted"
    # The scan never ran and the live profile was never read in the copy's
    # place: fail closed, not fall back.
    assert "ran" not in seen, seen
    assert reads == [], reads
    assert not hook.fired, "the refused scan still reached the session lock"
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    message = entry.error_message or ""
    assert "could not be copied" in message, message
    # The reason names the failure's type only: the file it failed to copy is
    # the one whose values no recorded reason may hold.
    assert "OSError" in message, message
    for surface, text in (
        ("the registry's error_message", message),
        ("the progress answer", progress),
        ("the log", logged),
    ):
        assert _PLANTED_STRERROR not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
        assert _REBOUND_VALUE not in text, (surface, text)
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)


def test_the_refusal_removes_a_partly_written_copy(tmp_path, monkeypatch):
    """A write that fails midway, as a full disk fails it, leaves a partial
    copy on disk: the refusal removes it with the scan."""
    session_id = "snapshot-refusal-partial"
    target, delivered, profile, config_dir, _rebind = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    attempts = _snapshot_writes_fail(monkeypatch, partly=True)

    def a_run_that_must_not_start(*args, **kwargs):
        raise RuntimeError("the tool crashed")

    entry, _logged, _progress = _the_scan_in_the_session(
        target, delivered, session_id, a_run_that_must_not_start
    )

    assert attempts, "control: no copy was ever attempted"
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert "could not be copied" in (entry.error_message or ""), entry.error_message
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)


def test_a_planned_name_the_writer_refuses_resets_the_record_and_keeps_the_file(
    tmp_path, monkeypatch
):
    """A scan id the copy's name grammar rejects is refused like a failed write.

    The registry takes any non-empty string as a scan id, but a copy's name
    parses as a scan copy's only with a UUID in it. The runner records the
    planned path before it calls the writer, and the writer's guard refuses
    the name with ProfileSnapshotUnavailable, so the runner takes its one
    reset path: the record is cleared, the type-only sentence is the entry's
    reason, and a file already sitting at the planned path -- which this
    scan did not create -- is neither discarded nor removed."""
    session_id = "snapshot-refusal-unparseable-name"
    target, delivered, profile, config_dir = a_session_with_a_bound_profile(
        tmp_path / "ws", monkeypatch, session_id
    )
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(target / ".ash" / "ash_output"),
        session_id=session_id,
        scan_id="not-a-uuid",
    )
    planted = mcp_tools._scan_snapshot_path(profile, scan_id)
    planted_content = "a file this scan did not create\n"
    planted.write_text(planted_content, encoding="utf-8")
    forgotten: List[str] = []
    ran: List[bool] = []

    def a_run_that_must_not_start(*args, **kwargs):
        ran.append(True)
        raise RuntimeError("the tool crashed")

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_must_not_start),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
            patch.object(
                mcp_tools, "_forget_own_scan_copy", side_effect=forgotten.append
            ),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(target),
                    output_dir=str(target / ".ash" / "ash_output"),
                    severity_threshold=None,
                    config_path=str(delivered),
                    session_id=session_id,
                )
            )
    finally:
        profile_registry.clear_session_state(session_id)
    entry = registry.get_scan(scan_id)

    assert ran == [], "the refused scan still started"
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    message = entry.error_message or ""
    assert "could not be copied" in message, message
    assert "refused rather than run on the live profile" in message, message
    # The record was reset: the runner's discard never saw the planted name.
    assert planted.name not in forgotten, forgotten
    assert planted.read_text(encoding="utf-8") == planted_content
    assert _snapshot_leftovers(config_dir) == [planted.name]


def test_the_refusal_precedes_the_scans_clock(tmp_path, monkeypatch):
    """With a timeout armed, a scan refused for its snapshot still records
    the refusal, never the timeout's reason: the clock starts with the scan,
    and the scan never starts."""
    import time

    session_id = "snapshot-refusal-timeout"
    target, delivered, profile, config_dir, _rebind = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    _snapshot_writes_fail(monkeypatch)
    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(target / ".ash" / "ash_output"),
        session_id=session_id,
    )

    def a_run_that_outlives_the_limit(*args, **kwargs):
        time.sleep(0.5)
        raise RuntimeError("the tool crashed")

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_outlives_the_limit),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
        ):
            asyncio.run(
                mcp_tools._run_scan_async(
                    scan_id=scan_id,
                    directory_path=str(target),
                    output_dir=str(target / ".ash" / "ash_output"),
                    severity_threshold=None,
                    config_path=str(delivered),
                    session_id=session_id,
                    scan_timeout_seconds=0.05,
                )
            )
    finally:
        profile_registry.clear_session_state(session_id)
    entry = registry.get_scan(scan_id)

    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    message = entry.error_message or ""
    assert "could not be copied" in message, message
    assert "exceeded the server's scan_timeout_seconds" not in message, message
    assert _snapshot_leftovers(config_dir) == [], _snapshot_leftovers(config_dir)
