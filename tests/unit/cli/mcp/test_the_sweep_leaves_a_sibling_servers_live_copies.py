# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A server's sweep does not remove a copy another server's live scan holds.

Two stdio servers both resolve to the default session, and the sandbox grants
a per-session config directory only for a real session id, so they share one.
Each keeps its own scan registry, so "this registry does not know the scan"
cannot tell a leftover from a sibling's live copy. A copy's name records the
pid of the process that wrote it and the identity of the place it ran in; on
this host the sweep keeps an unknown-id copy while that process runs and removes
it once it is gone. A name with no identity (an older writer's) matches no host
and is judged by age, never by the pid
(test_a_scan_copy_written_elsewhere_is_judged_by_age_not_by_pid).

Names in these cells are spelled out by hand, not built by
_scan_snapshot_path, so they say what the grammar is.
"""

import os
import subprocess
import sys
import uuid
from unittest import mock

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    describe_config_path,
    parse_scan_copy_name,
    scan_copy_writer_pid,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)


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


def _here():
    """This host's identity token, as the writer spells it in a copy's name."""
    token = mcp_tools._this_host_token()
    assert token is not None, "this host cannot read its own identity"
    return f"-h{token}"


def _copy_beside(profile, scan_id, pid_part):
    copy = profile.with_name(f".ash-scan-{scan_id}{pid_part}.{profile.name}")
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return copy


@pytest.fixture(autouse=True)
def _the_servers_registry_knows_none_of_these(monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)


@pytest.fixture
def sibling():
    """A running process that is not this one: the other server."""
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield child.pid
    finally:
        child.kill()
        child.wait()


@pytest.fixture
def gone_pid():
    """The pid of a process that ran and was reaped."""
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child.wait()
    return child.pid


@pytest.mark.integration
def test_a_copy_an_unknown_scan_wrote_in_a_running_process_survives(tmp_path, sibling):
    profile = _profile(tmp_path)
    live = _copy_beside(profile, uuid.uuid4(), f"-p{sibling}{_here()}")

    assert _bind(profile) == str(profile)

    assert live.is_file(), "a sibling server's live copy was swept"


@pytest.mark.integration
def test_a_copy_whose_writer_is_gone_is_swept(tmp_path, gone_pid):
    profile = _profile(tmp_path)
    dead = _copy_beside(profile, uuid.uuid4(), f"-p{gone_pid}{_here()}")

    assert _bind(profile) == str(profile)

    assert not dead.exists(), "a dead writer's leftover survived the sweep"


@pytest.mark.unit
def test_a_copy_this_process_wrote_and_does_not_hold_is_swept(tmp_path):
    """This process's own pid is no shelter: its registry is the authority
    on its own scans."""
    profile = _profile(tmp_path)
    mine = _copy_beside(profile, uuid.uuid4(), f"-p{os.getpid()}{_here()}")

    assert _bind(profile) == str(profile)

    assert not mine.exists()


@pytest.mark.unit
def test_a_copy_with_no_pid_has_no_identity_and_is_judged_by_age(tmp_path):
    """An older writer's name: no pid and no identity, so it matches no host."""
    profile = _profile(tmp_path)
    legacy = _copy_beside(profile, uuid.uuid4(), "")

    assert _bind(profile) == str(profile)

    assert legacy.exists(), "a copy with no identity was swept before it was old"


@pytest.mark.unit
def test_the_writers_own_names_carry_its_pid(tmp_path):
    profile = _profile(tmp_path)
    scan_id = str(uuid.uuid4())

    name = mcp_tools._scan_snapshot_path(profile, scan_id).name

    assert scan_copy_writer_pid(name) == os.getpid()
    assert parse_scan_copy_name(name) == (scan_id, "ash.yaml")
    assert (
        mcp_tools._scan_snapshot_path(
            profile, scan_id, writer_pid=4242, writer_host=None
        ).name
        == f".ash-scan-{scan_id}-p4242.ash.yaml"
    )
    assert (
        mcp_tools._scan_snapshot_path(profile, scan_id, writer_pid=4242).name
        == f".ash-scan-{scan_id}-p4242{_here()}.ash.yaml"
    )


@pytest.mark.parametrize(
    "pid_part",
    ["-p0", "-p01", "-p-5", "-p", "-pabc", "-p1234567890", "-q42"],
)
@pytest.mark.unit
def test_a_malformed_pid_segment_is_no_scan_copys_name(tmp_path, pid_part):
    scan_id = uuid.uuid4()
    name = f".ash-scan-{scan_id}{pid_part}.ash.yaml"

    assert parse_scan_copy_name(name) is None
    assert scan_copy_writer_pid(name) is None


@pytest.mark.unit
def test_the_pid_segment_does_not_change_what_a_name_parses_to():
    scan_id = str(uuid.uuid4())
    assert parse_scan_copy_name(f".ash-scan-{scan_id}.ash.yaml") == (
        scan_id,
        "ash.yaml",
    )
    assert parse_scan_copy_name(f".ash-scan-{scan_id}-p77.ash.yaml") == (
        scan_id,
        "ash.yaml",
    )
    assert scan_copy_writer_pid(f".ash-scan-{scan_id}.ash.yaml") is None


@pytest.mark.unit
def test_a_registered_copy_with_a_pid_is_still_described_as_its_profile(tmp_path):
    """The registered-copy mapping the messages use survives the longer name."""
    profile = _profile(tmp_path)
    copy = mcp_tools._scan_snapshot_path(profile, str(uuid.uuid4()))
    config_sources.register_scan_copy(copy)
    try:
        assert describe_config_path(copy) == profile.as_posix()
    finally:
        config_sources.discard_scan_copy(copy)


@pytest.mark.integration
def test_a_probe_failure_reads_as_running(tmp_path, monkeypatch, sibling):
    """The sweep deletes only what it can prove abandoned: a pid it cannot
    ask about (PermissionError, or any other OSError) is treated as alive."""
    profile = _profile(tmp_path)
    kept = _copy_beside(profile, uuid.uuid4(), f"-p{sibling}{_here()}")

    def refusing_kill(pid, sig):
        raise PermissionError("not ours to signal")

    # Scoped to the bind: the fixture's teardown kills the child through
    # os.kill too.
    with monkeypatch.context() as patched:
        patched.setattr(os, "kill", refusing_kill)
        assert _bind(profile) == str(profile)

    assert kept.is_file()
