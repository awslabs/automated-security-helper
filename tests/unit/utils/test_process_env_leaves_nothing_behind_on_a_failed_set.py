# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A set that raises leaves the environment and the hold table as they were.

apply_environ_overrides set its variables in order and raised from the first
assignment it could not make, leaving the variables before it set and the
previous values lost to the caller; it now puts them back before raising.
hold_environ recorded the hold before the set, so a failed set left a hold
nobody would release; the set now comes first.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.utils import process_env

pytestmark = pytest.mark.unit

FIRST = "ASH_TEST_PROCESS_ENV_FIRST_7F3E"
SECOND = "ASH_TEST_PROCESS_ENV_SECOND_7F3E"


def test_a_failed_override_puts_back_the_ones_already_set(monkeypatch):
    monkeypatch.delenv(FIRST, raising=False)
    monkeypatch.delenv(SECOND, raising=False)
    with pytest.raises(TypeError):
        process_env.apply_environ_overrides({FIRST: "one", SECOND: 2})  # type: ignore[dict-item]
    assert FIRST not in os.environ
    assert SECOND not in os.environ


def test_a_failed_hold_is_not_recorded(monkeypatch):
    monkeypatch.delenv(FIRST, raising=False)
    with pytest.raises(TypeError):
        process_env.hold_environ(FIRST, 2)  # type: ignore[arg-type]
    assert FIRST not in os.environ
    with pytest.raises(RuntimeError):
        process_env.release_environ(FIRST)
