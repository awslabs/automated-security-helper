# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""This repository's own scan configs may relax a content database only until a fixed date.

Why this exists
---------------
A ``content_db_staleness_overrides`` entry in a repo config holds one content database to
``warn`` until its expiration date. At runtime ASH ignores an expired entry, so the gate turns
back on by itself. That is not enough on its own: a dead entry left in the config reads as if
the relaxation were still in force, and the next person to copy it inherits the pattern. So
this test fails from 00:00 UTC on an entry's expiration date until the entry is removed.

The repo configs hold no override today. The last one held trivy-db to ``warn`` from
2026-10-07, while aquasecurity/trivy-db's scheduled publish was failing, and was removed once
the upstream publish had recovered. With no entries, the expiry check is shown to work on a
planted config instead, so it never passes because there was nothing to check.

The date is read from the config entry itself, never restated here, so the two cannot drift.
The test also pins what a relaxation may cover: every repo config keeps the scan-wide
``content_db_staleness: fail``, and only a database named in ``RELAXABLE`` may be relaxed.
``RELAXABLE`` is empty, so adding an override means adding its database, and the reason, here
in the same change, where a reviewer sees it.
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
#: The databases this repository's configs may relax, and why each one may. Empty while no
#: upstream publisher is down.
RELAXABLE: dict = {}


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


def _planted_config(directory: Path) -> Path:
    """A config with one override, so the expiry check is exercised with or without one."""
    planted = directory / ".ash_planted.yaml"
    planted.write_text(
        "content_db_staleness_overrides:\n"
        "  - database: trivy-db\n"
        "    policy: warn\n"
        '    expiration: "2026-10-11"\n'
        "    reason: planted by test_the_expiry_check_can_fail\n",
        encoding="utf-8",
    )
    return planted


@pytest.mark.parametrize("source", ["planted", "community"])
def test_the_expiry_check_can_fail(source, ash_temp_path):
    """At each entry's own expiration instant the check reports it, and not a second before.

    The planted config always holds an entry, so this runs whether or not the community
    config does; the community case checks its own entries too when it has any.
    """
    path = _planted_config(ash_temp_path) if source == "planted" else COMMUNITY_CONFIG
    entries = _overrides(path)
    if source == "planted":
        assert len(entries) == 1, entries
    for entry in entries:
        at_expiry = expired_relaxations([path], now=entry.expires_at)
        assert any(entry.database in message for message in at_expiry), at_expiry
        just_before = entry.expires_at - timedelta(seconds=1)
        assert not any(
            entry.database in message
            for message in expired_relaxations([path], now=just_before)
        )


@pytest.mark.parametrize("path", REPO_CONFIGS, ids=lambda p: p.name)
def test_relaxations_stay_narrow(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert data.get("content_db_staleness", "fail") == "fail", path.name
    relaxed = {e.database for e in _overrides(path) if e.policy == "warn"}
    assert relaxed <= set(RELAXABLE), (path.name, relaxed)
