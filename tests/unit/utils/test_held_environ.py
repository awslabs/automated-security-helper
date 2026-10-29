# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A variable held by several callers keeps its value until the last one releases it.

``apply_environ_overrides`` returns the value it saw and ``restore_environ`` writes it
back, with no count of who else wants the change. Two overlapping offline scans in one
process (two MCP sessions, two ``run_ash_scan(offline=True)`` threads) then broke both
ways: when the first ended it restored "unset" while the second was still running, so
everything that reads offline mode when it is used read "online"; and the second, ending
last, restored the "YES" it had seen, so the process stayed offline afterwards.

``hold_environ`` and ``release_environ`` count holders: the first records the original
value and sets the variable, the last release restores the original.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.process_env import hold_environ, release_environ

pytestmark = pytest.mark.unit

KEY = "ASH_TEST_HELD_VARIABLE"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    yield


def test_the_value_stays_until_the_last_holder_releases(monkeypatch):
    import os

    hold_environ(KEY, "YES")
    hold_environ(KEY, "YES")
    release_environ(KEY)  # the first scan ends while the second still runs

    assert os.environ.get(KEY) == "YES"

    release_environ(KEY)

    assert KEY not in os.environ


def test_the_original_value_comes_back(monkeypatch):
    import os

    monkeypatch.setenv(KEY, "YES")  # a server started offline

    hold_environ(KEY, "YES")
    hold_environ(KEY, "YES")
    release_environ(KEY)
    release_environ(KEY)

    assert os.environ.get(KEY) == "YES"


def test_an_original_different_value_comes_back(monkeypatch):
    import os

    monkeypatch.setenv(KEY, "NO")

    hold_environ(KEY, "YES")
    assert os.environ.get(KEY) == "YES"
    release_environ(KEY)

    assert os.environ.get(KEY) == "NO"


def test_offline_mode_reads_held_until_the_last_release(monkeypatch):
    from automated_security_helper.core.constants import is_offline_mode

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    hold_environ("ASH_OFFLINE", "YES")
    hold_environ("ASH_OFFLINE", "YES")
    try:
        release_environ("ASH_OFFLINE")
        assert is_offline_mode() is True
    finally:
        release_environ("ASH_OFFLINE")

    assert is_offline_mode() is False


def test_releasing_a_variable_nobody_holds_is_an_error():
    with pytest.raises(RuntimeError):
        release_environ(KEY)


def test_holding_at_another_value_while_held_is_an_error():
    hold_environ(KEY, "YES")
    try:
        with pytest.raises(ValueError):
            hold_environ(KEY, "NO")
    finally:
        release_environ(KEY)
