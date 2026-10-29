# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``content_db_staleness_overrides`` entry expires by the date it validated with.

The entry's ``expiration`` validates with ``strptime("%Y-%m-%d")``, which admits
an unpadded month or day (``2026-1-5``), while ``expires_at`` read it with
``date.fromisoformat``, which does not. An entry that validated was then dropped
at scan time when its expiry raised, a stricter ``fail`` entry included.

Red at the base: ``expires_at`` raised ValueError for an entry the model had
accepted.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from automated_security_helper.config.ash_config import ContentDbStalenessOverride

pytestmark = pytest.mark.unit


def _entry(expiration: str) -> ContentDbStalenessOverride:
    return ContentDbStalenessOverride(
        database="grype-db", policy="fail", expiration=expiration, reason="held"
    )


def test_an_unpadded_date_the_validator_admits_is_read_the_same_way() -> None:
    entry = _entry("2026-1-5")

    assert entry.expires_at == datetime(2026, 1, 5, tzinfo=timezone.utc)
    assert entry.is_expired(datetime(2026, 1, 4, 23, 59, tzinfo=timezone.utc)) is False
    assert entry.is_expired(datetime(2026, 1, 5, tzinfo=timezone.utc)) is True


def test_a_padded_date_reads_as_before() -> None:
    """The control."""
    assert _entry("2026-01-05").expires_at == datetime(2026, 1, 5, tzinfo=timezone.utc)
