# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sweep keeps a scan's copy while the scan's thread may still load it.

The timeout (and the runner's BaseException arm) closes the registry entry
FAILED while the scan thread is still running; the runner's own finally waits
on ``runner_done`` before it discards the copy, because a thread still
running may yet load the snapshot. The sweep that runs when a session's
config is written must use the same test, or a select_profile landing in that
window deletes the file from under the live thread.

The race cell is a choreography, not a timing test: a stub runner thread
signals that it is past the point where the entry was closed FAILED, then
blocks on an event before it loads the copy. The test runs the sweep while the
thread is blocked there, then releases it. Every ordering is forced by an
Event; nothing waits on a clock.

The window is reached by closing the entry through the registry directly
(finish_scan, the call the timeout makes) rather than by driving the real
timer through _run_scan_async: the window is the state "entry closed, runner
live", however it is reached.
"""

import threading
import uuid
from unittest import mock

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit

_WAIT = 30  # seconds; only a failure path ever reaches it


def _profile(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _bind(profile):
    """Run the bind's write step with a stand-in that reports *profile* written.

    ``_materialize_or_error`` writes through ``profile_registry
    .materialize_session_binding`` and returns ``(config_path,
    trusted_config_path)``; the write is stood in for so what runs is the sweep
    beside the written path, and the path a scan would be handed is returned.
    """
    with mock.patch.object(
        profile_registry,
        "materialize_session_binding",
        lambda session_id, registered, patched: (str(profile), str(profile)),
    ):
        materialized = mcp_tools._materialize_or_error(None, None, None)
    if isinstance(materialized, dict):
        return materialized
    return materialized[0]


def _registered_scan_with_a_runner(registry, tmp_path):
    (tmp_path / "src").mkdir()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / "out"),
    )
    entry = registry.get_scan(scan_id)
    entry.has_runner = True
    return scan_id, entry


def test_a_copy_survives_a_sweep_that_lands_between_the_close_and_the_threads_load(
    tmp_path, monkeypatch
):
    registry = ScanRegistry()
    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    profile = _profile(tmp_path)
    scan_id, entry = _registered_scan_with_a_runner(registry, tmp_path)
    copy = mcp_tools._scan_snapshot_path(profile, scan_id)
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")

    entry_closed = threading.Event()
    thread_past_the_close = threading.Event()
    sweep_done = threading.Event()
    outcome: dict = {}

    def runner_thread():
        # The scan thread: it learns the entry was closed FAILED under it,
        # says so, and holds before it loads its copy.
        assert entry_closed.wait(_WAIT)
        thread_past_the_close.set()
        assert sweep_done.wait(_WAIT)
        try:
            outcome["loaded"] = copy.read_text(encoding="utf-8")
        except OSError as exc:  # FileNotFoundError at base
            outcome["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            # The runner's finally, in its own order: done first, then discard.
            entry.runner_done.set()

    thread = threading.Thread(target=runner_thread)
    thread.start()
    try:
        # The timeout's close: FAILED while the thread above is still live.
        assert registry.finish_scan(scan_id, MCScanStatus.FAILED, "timed out")
        assert not entry.runner_done.is_set()
        entry_closed.set()
        assert thread_past_the_close.wait(_WAIT)

        # The race: select_profile's bind sweeps while the thread is blocked.
        assert _bind(profile) == str(profile)
        sweep_done.set()
    finally:
        sweep_done.set()
        thread.join(_WAIT)

    assert not thread.is_alive()
    assert outcome == {"loaded": "project_name: a-bound-profile\n"}, outcome


def test_the_copy_goes_once_the_thread_is_done_and_the_entry_ended(
    tmp_path, monkeypatch
):
    """The control: the same state one step later -- runner_done set, entry
    FAILED -- is a leftover, and the sweep removes it."""
    registry = ScanRegistry()
    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    profile = _profile(tmp_path)
    scan_id, entry = _registered_scan_with_a_runner(registry, tmp_path)
    copy = mcp_tools._scan_snapshot_path(profile, scan_id)
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    assert registry.finish_scan(scan_id, MCScanStatus.FAILED, "timed out")

    assert _bind(profile) == str(profile)
    assert copy.is_file(), "swept while the runner was not done"

    entry.runner_done.set()
    assert _bind(profile) == str(profile)
    assert not copy.exists(), "a copy past runner_done on an ended entry stayed"


def test_an_ended_entry_no_runner_ever_drove_is_swept(tmp_path, monkeypatch):
    """A closed entry with no in-process runner has no thread to wait for
    (has_runner is False), so its copy is a leftover at once."""
    registry = ScanRegistry()
    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    profile = _profile(tmp_path)
    (tmp_path / "src").mkdir()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / "out"),
    )
    copy = mcp_tools._scan_snapshot_path(profile, scan_id)
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    registry.finish_scan(scan_id, MCScanStatus.COMPLETED)

    assert _bind(profile) == str(profile)

    assert not copy.exists()
    assert uuid.UUID(scan_id)
