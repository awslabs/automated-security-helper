# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The record of this process's scan copies follows the file, not the attempt.

Where a host cannot read its identity (every host on Windows), a copy carries no
host token, and the record of the copies this process's writer created is the only
way the sweep knows one is its own. A copy that a delete failed to remove must stay
in that record, so the next bind finds it and retries; a copy forgotten before its
delete is left for the age bound (a week) instead.

The cells also pin what the record does around the sweep's two other inputs: a
copy this process wrote is its own whatever the identity reads at the sweep, and
the record does not outlive a successful discard.

Every file is written by the cell in its own tmp directory.
"""

import asyncio
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import scan_copy_writer_host
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

#: The host identity function as the module defines it, before the shared fixture
#: replaces it with a fixed token for each cell.
_REAL_HOST_TOKEN = mcp_tools._this_host_token

#: Another place's identity token, well formed.
READABLE = "0123456789abcdef"


@pytest.fixture(autouse=True)
def _the_registry_knows_none_of_these(monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)


def _profile(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _copies_beside(profile):
    return sorted(profile.parent.glob(".ash-scan-*"))


def _written_copy(profile):
    """The writer, called as the runner calls it: the planned name handed in
    (``_snapshot_profile_for_scan`` requires ``snapshot_path``)."""
    scan_id = str(uuid.uuid4())
    return mcp_tools._snapshot_profile_for_scan(
        profile, scan_id, snapshot_path=mcp_tools._scan_snapshot_path(profile, scan_id)
    )


def _the_delete_of_a_scan_copy_fails(monkeypatch):
    """Make ``Path.unlink`` refuse a scan copy while ``state["failing"]`` is set.

    PermissionError is what a delete reads as when another handle holds the file
    (Windows) or the directory refuses the write (POSIX).
    """
    state = {"failing": True, "refused": 0}
    real_unlink = Path.unlink

    def unlink(self, *args, **kwargs):
        if state["failing"] and self.name.startswith(".ash-scan-"):
            state["refused"] += 1
            raise PermissionError(13, "the copy is in use")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    return state


def _the_copy_cannot_be_given_the_profiles_mode(monkeypatch):
    """Fail the writer after it created the file (the write-error path)."""

    def refuse(*args, **kwargs):
        raise PermissionError(1, "the mode cannot be set")

    monkeypatch.setattr(mcp_tools.os, "fchmod", refuse, raising=False)
    monkeypatch.setattr(mcp_tools.os, "chmod", refuse)


def _a_session_with_a_bound_profile(tmp_path, monkeypatch, session_id):
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    ws = tmp_path / "ws"
    target = ws / session_id / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / session_id / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-held-profile\n", encoding="utf-8")
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    # The delivered config is checked against the bound profile's runtime-
    # override policy, read from the registered profile of that name
    # (profile_registry.session_profile_entry fails closed on an unregistered
    # one), so the profile is registered under the name the binding carries.
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"held={profile}"])
    )
    profile_registry.bind_session_config(
        session_id, config=AshConfig(), profile_name="held", config_path=str(profile)
    )
    return target, delivered, profile


def _a_scan_runs_to_its_end(tmp_path, monkeypatch, session_id):
    """Run one scan through the directory tool until its runner is done.

    Returns the session profile and the copies the scan's writer made.
    """
    target, delivered, profile = _a_session_with_a_bound_profile(
        tmp_path, monkeypatch, session_id
    )
    written = []
    real_snapshot = mcp_tools._snapshot_profile_for_scan

    def spy(*args, **kwargs):
        copy = real_snapshot(*args, **kwargs)
        written.append(copy)
        return copy

    monkeypatch.setattr(mcp_tools, "_snapshot_profile_for_scan", spy)
    registry = ScanRegistry()

    def a_run_that_ends(*args, **kwargs):
        raise RuntimeError("the tool crashed")

    async def start_and_wait():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        tasks = [
            task
            for task, scan in list(mcp_tools._scan_tasks.items())
            if scan == started.get("scan_id")
        ]
        if len(tasks) != 1:
            raise RuntimeError(("control: not one runner task", tasks))
        await asyncio.gather(*tasks, return_exceptions=True)

    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_ends),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            asyncio.run(start_and_wait())
    finally:
        profile_registry.clear_session_state(session_id)
        profile_registry.clear_profile_registry()
    return profile, written


def test_a_copy_the_writer_could_not_delete_is_still_this_servers_own(
    tmp_path, monkeypatch
):
    """The write-error path: the delete fails, the next bind's sweep retries it."""
    profile = _profile(tmp_path)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    _the_copy_cannot_be_given_the_profiles_mode(monkeypatch)
    deletes = _the_delete_of_a_scan_copy_fails(monkeypatch)

    with pytest.raises(mcp_tools.ProfileSnapshotUnavailable):
        _written_copy(profile)

    # Controls: the copy was written and the delete was tried and refused.
    left = _copies_beside(profile)
    assert len(left) == 1, left
    assert deletes["refused"] >= 1, deletes
    deletes["failing"] = False

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not left[0].exists(), "the retry left this server's own copy for a week"


def test_a_copy_the_runner_could_not_delete_is_still_this_servers_own(
    tmp_path, monkeypatch
):
    """The runner's discard: the delete fails, the next bind's sweep retries it."""
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    deletes = _the_delete_of_a_scan_copy_fails(monkeypatch)

    profile, written = _a_scan_runs_to_its_end(tmp_path, monkeypatch, "undeletable")

    # Controls: one copy was written, the discard tried and was refused.
    assert len(written) == 1, written
    assert written[0].exists()
    assert deletes["refused"] >= 1, deletes
    deletes["failing"] = False

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not written[0].exists(), "the retry left this server's own copy for a week"


def test_a_copy_the_runner_discarded_is_no_longer_remembered(tmp_path, monkeypatch):
    """The record follows the runner's discard: a file that later takes the
    discarded copy's name is not this server's."""
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)

    profile, written = _a_scan_runs_to_its_end(tmp_path, monkeypatch, "discarded")

    assert len(written) == 1, written
    assert not written[0].exists(), "control: the runner left its copy"
    written[0].write_text("project_name: a-siblings-copy\n", encoding="utf-8")

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert written[0].exists(), "a file with a discarded copy's name was taken as own"


def test_a_copy_written_with_a_token_is_own_when_the_sweep_cannot_read_identity(
    tmp_path, monkeypatch
):
    profile = _profile(tmp_path)
    mine = _written_copy(profile)
    assert scan_copy_writer_host(mine.name) is not None, "control: no token"
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not mine.exists(), "this process's own copy was kept for the age bound"


def test_a_copy_written_without_a_token_is_own_when_the_sweep_reads_identity(
    tmp_path, monkeypatch
):
    profile = _profile(tmp_path)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    mine = _written_copy(profile)
    assert scan_copy_writer_host(mine.name) is None, "control: the copy has a token"
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: READABLE)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not mine.exists(), "this process's own copy was kept for the age bound"


def test_a_copy_is_registered_from_its_creation_until_it_is_discarded(tmp_path):
    copy = tmp_path / f".ash-scan-{uuid.uuid4()}.ash.yaml"
    assert not config_sources.is_registered_scan_copy(copy)

    config_sources.register_scan_copy(copy)
    assert config_sources.is_registered_scan_copy(copy)
    assert config_sources.is_registered_scan_copy(str(copy))

    config_sources.discard_scan_copy(copy)
    assert not config_sources.is_registered_scan_copy(copy)


def test_a_cell_that_writes_a_copy_and_never_discards_it(tmp_path):
    """Half of a pair: this cell leaves a name in the record on purpose."""
    _written_copy(_profile(tmp_path))

    assert config_sources._LIVE_SCAN_COPIES, "control: the writer recorded nothing"


def test_the_record_is_empty_when_a_cell_starts():
    """The other half: nothing a cell wrote is still recorded in the next one.
    Meaningful only after the cell above ran in this process."""
    assert config_sources._LIVE_SCAN_COPIES == set()


@pytest.mark.skipif(
    sys.platform != "win32", reason="a handle held open blocks a delete"
)
def test_on_windows_a_copy_held_open_is_swept_once_the_handle_closes(
    tmp_path, monkeypatch
):
    """Windows reads no host identity, so every copy is tokenless and the record is
    the only evidence. A handle held on the copy makes the writer's own delete fail
    for real (Python opens files without delete sharing there)."""
    monkeypatch.setattr(mcp_tools, "_this_host_token", _REAL_HOST_TOKEN)
    assert mcp_tools._this_host_token() is None, "control: this host reads an identity"
    profile = _profile(tmp_path)
    handles = []

    def hold_the_copy_then_fail(*args, **kwargs):
        # The writer sets the mode by descriptor where it can (os.fchmod) and by
        # name where it cannot, so the copy is found beside the profile either way.
        handles.append(open(_copies_beside(profile)[0], "rb"))
        raise PermissionError(1, "the mode cannot be set")

    monkeypatch.setattr(mcp_tools.os, "fchmod", hold_the_copy_then_fail, raising=False)
    monkeypatch.setattr(mcp_tools.os, "chmod", hold_the_copy_then_fail)

    try:
        with pytest.raises(mcp_tools.ProfileSnapshotUnavailable):
            _written_copy(profile)
        left = _copies_beside(profile)
        assert len(left) == 1, "control: the held copy was deleted"
    finally:
        for handle in handles:
            handle.close()

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not left[0].exists(), "the retry left this server's own copy for a week"
