# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An expiration is read against one calendar date across the hour that occurs twice.

Why this file exists
--------------------
``current_date`` is today's date on the host's local clock (``date.today()``),
and an entry stops applying at the start of its expiration date. On the day a
region sets its clocks back, 01:30 happens twice, an hour apart, and a reader of
the rule could wonder whether the two are one day. They are: the date does not
change inside that hour, so an entry expiring that day has expired at both, and
one expiring the next day has not at either. The cases pin that reading for the
US Eastern fall-back of 2026-11-01, with the zone given as a POSIX rule so the
host needs no time-zone database.
"""

import time
from datetime import date

import pytest

from automated_security_helper.models.core import current_date, expiration_has_passed

pytestmark = pytest.mark.unit

#: US Eastern as a POSIX rule: DST from the second Sunday of March to the first
#: Sunday of November.
EASTERN_WITH_FALL_BACK = "EST5EDT,M3.2.0,M11.1.0"
#: 2026-11-01 01:30 EDT (05:30 UTC) and 01:30 EST (06:30 UTC), read with date -u.
FIRST_0130 = 1793511000
SECOND_0130 = 1793514600


@pytest.fixture
def eastern_time(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("the local zone cannot be set on this platform")
    monkeypatch.setenv("TZ", EASTERN_WITH_FALL_BACK)
    time.tzset()
    yield
    # Undone before the zone is read again, so later tests see the host's own.
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize(
    "instant", [FIRST_0130, SECOND_0130], ids=["first-0130-EDT", "second-0130-EST"]
)
def test_the_hour_that_occurs_twice_is_one_date(eastern_time, monkeypatch, instant):
    monkeypatch.setattr(time, "time", lambda: instant)

    assert current_date() == date(2026, 11, 1)
    # On the expiration date itself the entry has expired, at both of them.
    assert expiration_has_passed("2026-11-01") is True
    assert expiration_has_passed("2026-11-02") is False


def test_the_two_instants_are_an_hour_apart_in_the_zone_the_test_sets(eastern_time):
    """The control for the case above: the two instants differ by one hour of
    wall-clock time in the set zone and read the same local time, so a zone
    that was not set (UTC reads 05:30 and 06:30) fails here rather than
    passing the test above for the wrong reason."""
    first = time.localtime(FIRST_0130)
    second = time.localtime(SECOND_0130)

    assert (first.tm_hour, first.tm_min) == (1, 30)
    assert (second.tm_hour, second.tm_min) == (1, 30)
    assert first.tm_isdst == 1
    assert second.tm_isdst == 0
