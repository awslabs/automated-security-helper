# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Landlock below ABI 3 is unavailable, because it cannot deny truncation.

LANDLOCK_ACCESS_FS_TRUNCATE arrived with ABI 3 (Linux 6.2). Below it the wrapper
cannot hand it out or withhold it (utils/sandbox/landlock_exec.py:fs_rights_for), so
a scanner could truncate a file in the "read-only" source tree. These tests stand in
for the wrapper's ``--abi`` answer, so they run on any kernel.
"""

import subprocess
from typing import List

import pytest

from automated_security_helper.utils.sandbox import (
    SandboxUnavailable,
    clear_backend_cache,
    resolve_backend,
)
from automated_security_helper.utils.sandbox import backends
from automated_security_helper.utils.sandbox.backends import (
    MIN_LANDLOCK_ABI,
    BwrapBackend,
    FirejailBackend,
    LandlockBackend,
)


@pytest.fixture
def kernel_abi(monkeypatch):
    """A Linux host whose Landlock reports the ABI the test sets."""
    monkeypatch.setattr(backends.platform, "system", lambda: "Linux")
    restricted: List[List[str]] = []

    def probe_run(argv, env=None):
        if "--policy" in argv:
            restricted.append(list(argv))
        return None

    monkeypatch.setattr(backends, "_probe_run", probe_run)

    def install(abi: int) -> List[List[str]]:
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, f"{abi}\n", "")

        monkeypatch.setattr(backends.subprocess, "run", run)
        return restricted

    clear_backend_cache()
    yield install
    clear_backend_cache()


@pytest.mark.parametrize("abi", [1, 2])
def test_an_abi_without_truncate_control_is_unavailable(kernel_abi, abi):
    restricted = kernel_abi(abi)
    reason = LandlockBackend().probe()
    assert reason is not None
    assert f"ABI {abi} is below {MIN_LANDLOCK_ABI}" in reason
    assert "truncat" in reason
    # Refused before a process is restricted under it.
    assert restricted == []


@pytest.mark.parametrize("abi", [MIN_LANDLOCK_ABI, 6])
def test_an_abi_with_truncate_control_is_used(kernel_abi, abi):
    restricted = kernel_abi(abi)
    assert LandlockBackend().probe() is None
    assert len(restricted) == 1


def test_an_explicit_landlock_request_is_refused_with_the_reason(kernel_abi):
    kernel_abi(2)
    with pytest.raises(SandboxUnavailable, match="ABI 2 is below 3"):
        resolve_backend("landlock")


def test_auto_does_not_settle_on_landlock_below_abi_3(kernel_abi, monkeypatch):
    # Landlock is last in the Linux order, so with bwrap and firejail absent auto
    # fails closed with the reason.
    kernel_abi(2)
    monkeypatch.setattr(BwrapBackend, "probe", lambda self: "bwrap is absent")
    monkeypatch.setattr(FirejailBackend, "probe", lambda self: "firejail is absent")
    with pytest.raises(SandboxUnavailable) as raised:
        resolve_backend("auto")
    assert "landlock: Landlock ABI 2 is below 3" in str(raised.value)
