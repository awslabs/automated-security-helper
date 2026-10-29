# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the sweep of leftover scan copies does with a copy it cannot place by pid.

A copy written elsewhere, or with no identity, stays until it is old
(test_a_scan_copy_written_elsewhere_is_judged_by_age_not_by_pid). These cells pin
the edges of that rule:

* where this host cannot read its own identity, a copy this process's writer made is
  this process's own and goes at once, and the sweep says once that it judges the
  rest by age only (a copy that only shares this process's pid is the rest);
* a copy dated more than a day ahead of this clock is aged by its change time, and
  the sweep says so once for that name, so it is not held until this clock passes
  a date no writer wrote at;
* the age bound is the one the sweep of interrupted container runs puts on its own
  records, not a second copy of the number.
"""

import os
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import container_leftovers

#: Another place's identity token: well formed, and not the pinned one.
ELSEWHERE = "0123456789abcdef"


@pytest.fixture(autouse=True)
def _the_registry_knows_none_of_these(monkeypatch):
    monkeypatch.setattr(mcp_tools, "get_scan_registry", ScanRegistry)


@pytest.fixture
def said():
    """The warnings the sweep gives, with the once-flags cleared for the cell."""
    lines = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(mcp_tools, "_logger", SimpleNamespace(warning=lines.append))
        patch.setattr(mcp_tools, "_UNREADABLE_IDENTITY_REPORTED", False, raising=False)
        patch.setattr(mcp_tools, "_FUTURE_DATED_REPORTED", set(), raising=False)
        yield lines


@pytest.fixture
def gone_pid():
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "pass"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child.wait()
    return child.pid


def _profile(tmp_path):
    config_dir = tmp_path / "session" / "config"
    config_dir.mkdir(parents=True)
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return profile


def _copy(profile, pid, host=None):
    suffix = "" if host is None else f"-h{host}"
    copy = profile.with_name(f".ash-scan-{uuid.uuid4()}-p{pid}{suffix}.{profile.name}")
    copy.write_text("project_name: a-bound-profile\n", encoding="utf-8")
    return copy


def _written_copy(profile):
    """The writer, called as the runner calls it: the planned name handed in
    (``_snapshot_profile_for_scan`` requires ``snapshot_path``)."""
    scan_id = str(uuid.uuid4())
    return mcp_tools._snapshot_profile_for_scan(
        profile, scan_id, snapshot_path=mcp_tools._scan_snapshot_path(profile, scan_id)
    )


@pytest.mark.integration
def test_where_this_host_has_no_identity_its_own_unnamed_copy_goes_at_once(
    tmp_path, monkeypatch, gone_pid, said
):
    profile = _profile(tmp_path)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    mine = _written_copy(profile)
    another_process_with_no_identity = _copy(profile, gone_pid)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not mine.exists(), "this process's own copy was kept for the age bound"
    assert another_process_with_no_identity.exists(), "a foreign copy went young"


@pytest.mark.unit
def test_the_record_not_the_pid_or_the_identity_places_a_copy_with_no_token(
    tmp_path, monkeypatch, said
):
    """The must-keep twin: of two copies with no token and this process's pid, the
    one the writer made goes and the planted one stays, whatever the identity reads
    at the sweep. Neither the pid nor the identity is the evidence."""
    profile = _profile(tmp_path)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)
    mine = _written_copy(profile)
    planted = _copy(profile, os.getpid())
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: ELSEWHERE)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not mine.exists(), "this process's own copy was kept for the age bound"
    assert planted.exists(), "a copy with no token was taken for this process's own"


@pytest.mark.unit
def test_the_sweep_says_once_that_it_judges_by_age_only(tmp_path, monkeypatch, said):
    profile = _profile(tmp_path)
    monkeypatch.setattr(mcp_tools, "_this_host_token", lambda: None)

    mcp_tools._sweep_stale_scan_snapshots(profile)
    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert len(said) == 1, said
    assert "identity cannot be read" in said[0]


@pytest.mark.unit
def test_a_host_that_reads_its_identity_has_nothing_to_say(tmp_path, said):
    profile = _profile(tmp_path)

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert said == []


def _at_a_clock_ahead_by(monkeypatch, seconds):
    real = time.time
    monkeypatch.setattr(mcp_tools.time, "time", lambda: real() + seconds)


@pytest.mark.integration
def test_a_copy_dated_far_ahead_goes_once_its_change_time_is_old(
    tmp_path, monkeypatch, gone_pid, said
):
    profile = _profile(tmp_path)
    ahead = _copy(profile, gone_pid, ELSEWHERE)
    far = time.time() + 30 * 24 * 3600
    os.utime(ahead, (far, far))
    older_than_the_bound = container_leftovers.RECORD_MAX_AGE_SECONDS + 3600

    with monkeypatch.context() as clock:
        _at_a_clock_ahead_by(clock, older_than_the_bound)
        mcp_tools._sweep_stale_scan_snapshots(profile)

    assert not ahead.exists(), "a copy dated in the future was never swept"
    assert len(said) == 1 and ahead.name in said[0], said


@pytest.mark.integration
def test_a_copy_dated_far_ahead_stays_while_its_change_time_is_young(
    tmp_path, monkeypatch, gone_pid, said
):
    profile = _profile(tmp_path)
    ahead = _copy(profile, gone_pid, ELSEWHERE)
    far = time.time() + 30 * 24 * 3600
    os.utime(ahead, (far, far))

    with monkeypatch.context() as clock:
        _at_a_clock_ahead_by(clock, 3600)
        mcp_tools._sweep_stale_scan_snapshots(profile)

    assert ahead.exists(), "a copy changed an hour ago was swept"
    assert len(said) == 1, said


@pytest.mark.integration
def test_a_copy_dated_slightly_ahead_is_a_clock_skew_not_a_report(
    tmp_path, gone_pid, said
):
    profile = _profile(tmp_path)
    skewed = _copy(profile, gone_pid, ELSEWHERE)
    soon = time.time() + 3600
    os.utime(skewed, (soon, soon))

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert skewed.exists()
    assert said == []


@pytest.mark.integration
def test_the_age_bound_is_the_container_sweeps_bound(tmp_path, monkeypatch, gone_pid):
    """The bound is read from the container sweep's public name each time: moving
    that number moves the line between a kept copy and a removed one."""
    monkeypatch.setattr(container_leftovers, "RECORD_MAX_AGE_SECONDS", 1000)
    profile = _profile(tmp_path)
    just_inside = _copy(profile, gone_pid, ELSEWHERE)
    just_past = _copy(profile, gone_pid, ELSEWHERE)
    now = time.time()
    os.utime(just_inside, (now - 500, now - 500))
    os.utime(just_past, (now - 1500, now - 1500))

    mcp_tools._sweep_stale_scan_snapshots(profile)

    assert just_inside.exists(), "a copy inside the bound was removed"
    assert not just_past.exists(), "a copy past the bound was kept"
