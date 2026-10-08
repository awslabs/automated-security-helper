# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""This repository's own scan configs may relax a content database only until a fixed date.

Why this exists
---------------
``.ash/.ash_community_plugins.yaml`` holds trivy-db to ``warn`` while the upstream trivy-db
publisher is failing, through a ``content_db_staleness_overrides`` entry with an expiration
date. At runtime ASH ignores an expired entry, so the gate turns back on by itself. That is
not enough on its own: a dead entry left in the config reads as if the relaxation were still
in force, and the next person to copy it inherits the pattern. So this test fails from 00:00
UTC on the entry's expiration date until the entry is removed.

The date is read from the config entry itself, never restated here, so the two cannot drift.
The test also pins what a relaxation may cover: every repo config keeps the scan-wide
``content_db_staleness: fail``, and only trivy-db may be relaxed. Widening either is a change
to this test, which a reviewer sees.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import pytest
import yaml

from automated_security_helper.config.ash_config import ContentDbStalenessOverride

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_CONFIGS = sorted((REPO_ROOT / ".ash").glob(".ash*.yaml"))
COMMUNITY_CONFIG = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
#: The databases this repository's configs may relax, and why each one may.
RELAXABLE = {
    "trivy-db": "aquasecurity/trivy-db stopped publishing on 2026-10-07",
}


def _overrides(path: Path) -> List[ContentDbStalenessOverride]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        ContentDbStalenessOverride.model_validate(raw)
        for raw in data.get("content_db_staleness_overrides") or []
    ]


def expired_relaxations(paths: List[Path], now: Optional[datetime] = None) -> List[str]:
    """Every override in ``paths`` that has passed its expiration date, as a message."""
    now = now or datetime.now(timezone.utc)
    return [
        f"{path.relative_to(REPO_ROOT).as_posix()}: the content_db_staleness_overrides "
        f"entry for {entry.database} expired at {entry.expires_at.isoformat()} and must "
        f"be removed ({entry.reason})"
        for path in paths
        for entry in _overrides(path)
        if entry.is_expired(now)
    ]


def test_the_repo_configs_are_found():
    assert COMMUNITY_CONFIG in REPO_CONFIGS, REPO_CONFIGS


def test_no_repo_config_keeps_an_expired_relaxation():
    assert expired_relaxations(REPO_CONFIGS) == []


def test_the_expiry_check_can_fail():
    """At the community config's own expiration instant the check reports every entry."""
    entries = _overrides(COMMUNITY_CONFIG)
    if not entries:
        pytest.skip("the community config holds no content_db_staleness_overrides")
    for entry in entries:
        at_expiry = expired_relaxations([COMMUNITY_CONFIG], now=entry.expires_at)
        assert any(entry.database in message for message in at_expiry), at_expiry
        just_before = entry.expires_at - timedelta(seconds=1)
        assert not any(
            entry.database in message
            for message in expired_relaxations([COMMUNITY_CONFIG], now=just_before)
        )


@pytest.mark.parametrize("path", REPO_CONFIGS, ids=lambda p: p.name)
def test_relaxations_stay_narrow(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert data.get("content_db_staleness", "fail") == "fail", path.name
    relaxed = {e.database for e in _overrides(path) if e.policy == "warn"}
    assert relaxed <= set(RELAXABLE), (path.name, relaxed)
