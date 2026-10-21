# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A copy that only shares this process's pid is not this process's own.

Where a host cannot read its identity, a scan copy it writes is named with its pid
and no host token. Two servers started from one container image usually run at the
same small pid and share one session config directory, so the other server's live
copy carries the same pid and the same absence of a token. The sweep must tell the
two apart by what this process created, not by the pid in the name: it removes the
copies the writer made here and keeps the other server's until they are old.

Every file is planted or written by the cell in its own tmp directory, under a
fixed absence of host identity.
"""

import os
import time
import uuid

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config.config_sources import scan_copy_writer_host
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

#: Far past any age bound the sweep puts on a copy it did not write.
A_MONTH = 30 * 24 * 3600


@pytest.fixture(autouse=True)
def _a_host_with_no_identity_and_a_registry_that_knows_no_scan(monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    monkeypatch.setattr(mcp_tools, "_UNREADABLE_IDENTITY_REPORTED", True, raising=False)


def _profile(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _another_servers_copy(profile):
    """A copy planted by name, as a sibling server of the same image names it: this
    process's pid, no token, and not written through this process's writer."""
    copy = profile.with_name(f".ash-scan-{uuid.uuid4()}-p{os.getpid()}.{profile.name}")
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return copy


def _age(path, seconds):
    then = time.time() - seconds
    os.utime(path, (then, then))


def test_a_sibling_servers_young_copy_survives_and_this_servers_own_goes(tmp_path):
    profile = _profile(tmp_path)
    siblings = _another_servers_copy(profile)
    scan_id = str(uuid.uuid4())
    mine = mcp_tools._snapshot_profile_for_scan(
        profile, scan_id, snapshot_path=mcp_tools._scan_snapshot_path(profile, scan_id)
    )
    assert mine.exists(), "the writer made no copy"
    assert scan_copy_writer_host(mine.name) is None, "the copy carries a host token"

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert siblings.exists(), "a same-pid copy this process did not write was removed"
    assert not mine.exists(), "this process's own unheld copy was kept"


def test_a_sibling_servers_copy_goes_once_it_is_older_than_the_bound(tmp_path):
    profile = _profile(tmp_path)
    old = _another_servers_copy(profile)
    young = _another_servers_copy(profile)
    _age(old, A_MONTH)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not old.exists(), "a copy past the age bound was kept"
    assert young.exists(), "a copy inside the age bound was removed"


def test_a_copy_this_server_discarded_is_not_remembered_as_its_own(tmp_path):
    """The record follows the file: once the writer's copy is gone, a sibling's copy
    that later takes the same name is not this server's."""
    profile = _profile(tmp_path)
    scan_id = str(uuid.uuid4())
    mine = mcp_tools._snapshot_profile_for_scan(
        profile, scan_id, snapshot_path=mcp_tools._scan_snapshot_path(profile, scan_id)
    )
    mcp_tools._sweep_stale_scan_snapshots(profile)
    assert not mine.exists()

    mine.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert mine.exists(), "a file with a removed copy's name was taken for its own"
