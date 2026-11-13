# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scan copies no scan holds are removed when a session's config is written.

A scan's runner discards its profile copy in its finally, but a process
killed outright between the write and that finally leaves the copy -- the
profile's full content -- in the session's config directory, and nothing
else removes it. Binding a profile writes the session's config into that
directory, so it is the moment leftovers are swept: a copy whose scan id is
still registered and not ended stays, since a scan started under an earlier
binding may still read it, and a sweep that cannot remove a file does not
fail the bind.
"""

import uuid
from pathlib import Path
from unittest import mock

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit


def _session_config_dir(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _materialized(profile):
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


def test_the_copys_own_name_is_described_as_the_profiles(tmp_path):
    """The name the scan writes is the name messages map back: the two
    conventions cannot drift apart."""
    profile = _session_config_dir(tmp_path)
    copy = mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4()))
    config_sources.register_scan_copy(copy)
    try:
        assert describe_config_path(copy) == profile.as_posix()
    finally:
        config_sources.discard_scan_copy(copy)


def test_a_copy_no_scan_holds_is_swept_at_the_write(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _session_config_dir(tmp_path)
    stale = mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4()))
    stale.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    bystander = profile.with_name("notes.yaml")
    bystander.write_text("kept\n", encoding="utf-8")
    not_a_copy = profile.with_name(".ash-scan-name-with-no-copied-part")
    not_a_copy.write_text("kept\n", encoding="utf-8")

    assert _materialized(profile) == str(profile)

    assert not stale.exists()
    assert profile.is_file()
    assert bystander.is_file()
    assert not_a_copy.is_file()


def test_a_live_scans_copy_stays_and_an_ended_scans_goes(tmp_path, monkeypatch):
    registry = ScanRegistry()
    monkeypatch.setattr(mcp_tools, "get_scan_registry", lambda: registry)
    profile = _session_config_dir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src-two").mkdir()
    live_id = registry.register_scan(
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / "out"),
    )
    ended_id = registry.register_scan(
        directory_path=str(tmp_path / "src-two"),
        output_directory=str(tmp_path / "out-two"),
    )
    registry.finish_scan(ended_id, MCScanStatus.COMPLETED)
    held = mcp_tools._scan_snapshot_path(profile, live_id)
    held.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    finished = mcp_tools._scan_snapshot_path(profile, ended_id)
    finished.write_text("project_name: a-bound-profile\n", encoding="utf-8")

    assert _materialized(profile) == str(profile)

    assert held.is_file()
    assert not finished.exists()


def test_a_write_failure_still_answers_the_bind(tmp_path, monkeypatch):
    """The sweep never turns a successful write into a failed bind: a copy
    that cannot be removed is left for the next bind to retry."""
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)
    profile = _session_config_dir(tmp_path)
    stale = mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4()))
    stale.write_text("project_name: a-bound-profile\n", encoding="utf-8")

    def refusing_unlink(self, missing_ok=False):
        raise PermissionError("the copy is not removable")

    monkeypatch.setattr(Path, "unlink", refusing_unlink)
    assert _materialized(profile) == str(profile)
