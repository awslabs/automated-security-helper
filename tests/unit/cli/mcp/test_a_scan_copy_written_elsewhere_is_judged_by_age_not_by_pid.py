# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan copy written somewhere else is kept until it is old, whatever its pid says.

The sweep of leftover scan copies (mcp_tools._sweep_stale_scan_snapshots) kept a
copy its registry did not know while the pid in the copy's name ran, and removed
it once that pid was gone. A pid means something only in the pid view of the
process that wrote it, and a session's config directory can sit on a filesystem
several hosts share: a live sibling's copy, written under a pid that is not running
in this view, read as abandoned and was deleted.

The copy's name now records the identity of the place it was written in (the key the
sweep of interrupted container runs uses, hashed to 16 hex digits). The pid is
asked about only for a copy with this host's identity. A copy with any other
identity, or none (an older writer's, or one whose writer could not read its own),
matches no host: it stays until it is older than the age bound and then goes.

Every file is planted by the cell in its own tmp directory; the one live process is
a sleeping interpreter the cell starts and kills.
"""

import os
import subprocess
import sys
import time
import uuid
from unittest import mock

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.config.config_sources import (
    parse_scan_copy_name,
    scan_copy_writer_pid,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import container_leftovers

#: Another place's identity token: well formed, and not this host's.
ELSEWHERE = "0123456789abcdef"


@pytest.fixture(autouse=True)
def _the_registry_knows_none_of_these(monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)


@pytest.fixture
def gone_pid():
    """The pid of a process that ran and was reaped: dead in this view."""
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child.wait()
    return child.pid


@pytest.fixture
def live_pid():
    """The pid of a process that is running in this view."""
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


def _here_token():
    token = mcp_tools._this_host_token()
    assert token is not None, "this host cannot read its own identity"
    return token


def _copy(profile, pid, host):
    """A copy as a writer of the given identity names it. ``host`` is a token, or
    None for a copy with no identity (written as the older grammar spelled it)."""
    suffix = "" if host is None else f"-h{host}"
    copy = profile.with_name(f".ash-scan-{uuid.uuid4()}-p{pid}{suffix}.{profile.name}")
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return copy


def _age(path, seconds):
    then = time.time() - seconds
    os.utime(path, (then, then))


def _older_than_the_bound():
    return container_leftovers.RECORD_MAX_AGE_SECONDS + 3600


@pytest.mark.parametrize("identity", ["another-host", "no-identity"])
@pytest.mark.integration
def test_a_copy_written_elsewhere_survives_a_pid_that_is_dead_here(
    tmp_path, gone_pid, identity
):
    """The finding: the pid is dead in THIS view, so the copy read as abandoned."""
    profile = _profile(tmp_path)
    copy = _copy(profile, gone_pid, ELSEWHERE if identity == "another-host" else None)

    assert _bind(profile) == str(profile)

    assert copy.exists(), "a copy written elsewhere was swept on a pid read here"


@pytest.mark.integration
def test_a_copy_written_elsewhere_survives_a_pid_that_is_live_here(tmp_path, live_pid):
    """A colliding live pid is no reason to remove it either: the pid is not asked."""
    profile = _profile(tmp_path)
    copy = _copy(profile, live_pid, ELSEWHERE)

    assert _bind(profile) == str(profile)

    assert copy.exists()


@pytest.mark.integration
def test_a_copy_written_here_by_a_dead_writer_still_goes(tmp_path, gone_pid):
    """The must-not twin: the pid is asked about for this host's own identity."""
    profile = _profile(tmp_path)
    copy = _copy(profile, gone_pid, _here_token())

    assert _bind(profile) == str(profile)

    assert not copy.exists(), "a dead writer's leftover on this host survived"


@pytest.mark.integration
def test_a_copy_written_here_by_a_live_writer_stays(tmp_path, live_pid):
    profile = _profile(tmp_path)
    copy = _copy(profile, live_pid, _here_token())

    assert _bind(profile) == str(profile)

    assert copy.exists()


@pytest.mark.parametrize("identity", ["another-host", "no-identity"])
@pytest.mark.integration
def test_a_copy_written_elsewhere_goes_once_it_is_older_than_the_bound(
    tmp_path, live_pid, identity
):
    """The age half: old enough, it goes, a live colliding pid notwithstanding."""
    profile = _profile(tmp_path)
    old = _copy(profile, live_pid, ELSEWHERE if identity == "another-host" else None)
    young = _copy(profile, live_pid, ELSEWHERE if identity == "another-host" else None)
    _age(old, _older_than_the_bound())

    assert _bind(profile) == str(profile)

    assert not old.exists(), "a copy past the age bound was kept"
    assert young.exists(), "a copy inside the age bound was swept"


@pytest.mark.integration
def test_an_unreadable_identity_here_matches_nothing(tmp_path, monkeypatch, gone_pid):
    """Fail safe: where this host cannot read its own identity, no copy is judged by
    pid, not even one that names this host's token. Both halves."""
    profile = _profile(tmp_path)
    token = _here_token()
    young = _copy(profile, gone_pid, token)
    old = _copy(profile, gone_pid, token)
    _age(old, _older_than_the_bound())
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)

    assert _bind(profile) == str(profile)

    assert young.exists(), "a copy was judged by pid with no identity to compare"
    assert not old.exists()


@pytest.mark.integration
def test_the_identity_is_read_once_for_the_whole_sweep(tmp_path, gone_pid, monkeypatch):
    """The identity is a property of the sweeping process, read once per sweep.

    The candidates are built by the writer's own name builder and checked
    against the sweep's parse before they count: a hand-spelled name would
    skip the candidate loop at the parse gate if the name grammar moved, and
    the one unconditional read before the loop would keep the count green
    while the control proved nothing about the loop.
    """
    profile = _profile(tmp_path)
    copies = []
    for _ in range(3):
        copy = mcp_tools._scan_snapshot_path(
            profile, str(uuid.uuid4()), writer_pid=gone_pid, writer_host=None
        )
        copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
        copies.append(copy)
    for copy in copies:
        # Control: every planted name is one the sweep's parse admits.
        assert parse_scan_copy_name(copy.name) is not None, copy.name
    reads = []
    real = mcp_tools._this_host_token

    def a_counted_read():
        reads.append(1)
        return real()

    monkeypatch.setattr(mcp_tools, "_this_host_token", a_counted_read)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    # Control: the sweep looked at all three candidates (they are young and
    # carry no identity, so all three stay) before the count means anything.
    assert all(copy.exists() for copy in copies)
    assert len(reads) == 1, len(reads)


@pytest.mark.unit
def test_the_writer_records_this_hosts_identity_in_its_names(tmp_path):
    from automated_security_helper.config.config_sources import scan_copy_writer_host

    profile = _profile(tmp_path)
    scan_id = str(uuid.uuid4())

    name = mcp_tools._scan_snapshot_path(profile, scan_id).name

    assert scan_copy_writer_host(name) == _here_token()
    assert scan_copy_writer_pid(name) == os.getpid()
    assert parse_scan_copy_name(name) == (scan_id, "ash.yaml")
    assert (
        mcp_tools._scan_snapshot_path(
            profile, scan_id, writer_pid=7, writer_host=ELSEWHERE
        ).name
        == f".ash-scan-{scan_id}-p7-h{ELSEWHERE}.ash.yaml"
    )
    # A writer that cannot read its identity names none, and says so by omission.
    bare = mcp_tools._scan_snapshot_path(
        profile, scan_id, writer_pid=7, writer_host=None
    ).name
    assert bare == f".ash-scan-{scan_id}-p7.ash.yaml"
    assert scan_copy_writer_host(bare) is None


@pytest.mark.parametrize(
    "tail",
    ["-h", "-hABCDEF0123456789", "-h0123456789abcde", "-h0123456789abcdef0", "-hxyz"],
)
@pytest.mark.unit
def test_a_malformed_identity_segment_is_no_scan_copys_name(tail):
    from automated_security_helper.config.config_sources import scan_copy_writer_host

    name = f".ash-scan-{uuid.uuid4()}-p7{tail}.ash.yaml"

    assert parse_scan_copy_name(name) is None
    assert scan_copy_writer_host(name) is None
