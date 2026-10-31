# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI cache checks and the timestamp parser of utils/content_databases.py.

- ``save_allowed`` and ``use_allowed`` refuse a database whose build time is further
  ahead of the clock than the skew allowance, as ``is_stale`` refuses it at scan time:
  before, a future-dated database passed the CI check and was then read as stale by
  every scan that restored it.
- ``parse_timestamp`` reads a Go timestamp with any number of fractional digits.
  Go drops trailing zeros, so one, two, four or five digits are common; Python
  3.10's fromisoformat takes exactly three or six, and rejected the rest.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from automated_security_helper.utils.content_databases import (
    CLOCK_SKEW_ALLOWANCE,
    CONTENT_DATABASES,
    is_stale,
    parse_timestamp,
    save_allowed,
    use_allowed,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


def _cacheable():
    return next(entry for entry in CONTENT_DATABASES if entry.cacheable)


def test_a_future_dated_database_is_refused_by_the_ci_checks_as_the_scan_refuses_it():
    entry = _cacheable()
    built = _NOW + CLOCK_SKEW_ALLOWANCE + timedelta(minutes=1)
    assert is_stale(entry, built, _NOW)
    assert not save_allowed(entry, built, _NOW)
    assert not use_allowed(entry, built, _NOW)


def test_a_build_time_inside_the_skew_allowance_is_still_cacheable():
    entry = _cacheable()
    built = _NOW + CLOCK_SKEW_ALLOWANCE - timedelta(minutes=1)
    assert save_allowed(entry, built, _NOW)
    assert use_allowed(entry, built, _NOW)
    # The scan reads the same build time the same way: inside the allowance it is
    # not stale, so the CI check and the scan agree on this side as on the other.
    assert not is_stale(entry, built, _NOW)


def test_the_skew_allowance_is_inclusive_and_one_second_past_it_is_refused():
    """Exactly the allowance ahead is still measured (the comparison is strict);
    a second more is not, for the scan and for both CI checks alike."""
    entry = _cacheable()
    at_the_edge = _NOW + CLOCK_SKEW_ALLOWANCE
    assert not is_stale(entry, at_the_edge, _NOW)
    assert save_allowed(entry, at_the_edge, _NOW)
    assert use_allowed(entry, at_the_edge, _NOW)
    past = at_the_edge + timedelta(seconds=1)
    assert is_stale(entry, past, _NOW)
    assert not save_allowed(entry, past, _NOW)
    assert not use_allowed(entry, past, _NOW)


@pytest.mark.parametrize(
    ("text", "microsecond"),
    [
        ("2024-01-01T00:00:00.5Z", 500000),
        ("2024-01-01T00:00:00.12Z", 120000),
        ("2024-01-01T00:00:00.1234Z", 123400),
        ("2024-01-01T00:00:00.12345Z", 123450),
        ("2024-01-01T00:00:00.123456789Z", 123456),
        ("2024-01-01T00:00:00.5+02:00", 500000),
    ],
)
def test_a_go_timestamp_with_any_fraction_length_is_read(text, microsecond):
    parsed = parse_timestamp(text)
    assert parsed.microsecond == microsecond
    assert parsed.tzinfo is not None


def test_a_timestamp_with_no_fraction_is_unchanged():
    assert parse_timestamp("2024-01-01T00:00:00Z") == datetime(
        2024, 1, 1, tzinfo=timezone.utc
    )
