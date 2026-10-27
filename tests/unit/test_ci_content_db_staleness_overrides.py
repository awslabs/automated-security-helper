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

These configs are inside the tree ASH scans, so a ``policy: warn`` entry in one is ignored with
a warning (``config/staleness_trust.py``) unless the scan's operator sets the same entry, with
``--config-overrides`` or a config outside the tree. The check here still keeps such an entry
from outliving its date.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import yaml

from automated_security_helper.config.ash_config import ContentDbStalenessOverride

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_CONFIGS = sorted((REPO_ROOT / ".ash").glob(".ash*.yaml"))
COMMUNITY_CONFIG = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
#: The databases this repository's configs may relax, and why each one may. Empty while no
#: relaxation is in force: a database is added here in the same change as its config entry,
#: with the upstream state that justifies it, and removed with the entry.
RELAXABLE: Dict[str, str] = {}


def _overrides(path: Path) -> List[ContentDbStalenessOverride]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        ContentDbStalenessOverride.model_validate(raw)
        for raw in data.get("content_db_staleness_overrides") or []
    ]


def _shown(path: Path) -> str:
    """``path`` relative to the checkout when it is inside it, else as given."""
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def expired_relaxations(paths: List[Path], now: Optional[datetime] = None) -> List[str]:
    """Every override in ``paths`` that has passed its expiration date, as a message."""
    now = now or datetime.now(timezone.utc)
    return [
        f"{_shown(path)}: the content_db_staleness_overrides "
        f"entry for {entry.database} expired at {entry.expires_at.isoformat()} and must "
        f"be removed ({entry.reason})"
        for path in paths
        for entry in _overrides(path)
        if entry.is_expired(now)
    ]


def test_the_repo_configs_are_found() -> None:
    assert COMMUNITY_CONFIG in REPO_CONFIGS, REPO_CONFIGS


def test_no_repo_config_keeps_an_expired_relaxation() -> None:
    assert expired_relaxations(REPO_CONFIGS) == []


def test_the_expiry_check_can_fail(tmp_path: Path) -> None:
    """At an entry's own expiration instant the check reports it, and a second before, not.

    Run against an entry this test writes, so the check is exercised while no repo config
    holds one, and against every entry a repo config does hold.
    """
    written = tmp_path / ".ash.yaml"
    written.write_text(
        yaml.safe_dump(
            {
                "content_db_staleness_overrides": [
                    {
                        "database": "trivy-db",
                        "policy": "warn",
                        "expiration": "2026-10-11",
                        "reason": "written by test_the_expiry_check_can_fail",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    checked = 0
    for path in [written, *REPO_CONFIGS]:
        for entry in _overrides(path):
            at_expiry = expired_relaxations([path], now=entry.expires_at)
            assert any(entry.database in message for message in at_expiry), at_expiry
            just_before = entry.expires_at - timedelta(seconds=1)
            assert not any(
                entry.database in message
                for message in expired_relaxations([path], now=just_before)
            )
            checked += 1
    assert checked >= 1


@pytest.mark.parametrize("path", REPO_CONFIGS, ids=lambda p: p.name)
def test_relaxations_stay_narrow(path: Path) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert data.get("content_db_staleness", "fail") == "fail", path.name
    relaxed = {e.database for e in _overrides(path) if e.policy == "warn"}
    assert relaxed <= set(RELAXABLE), (path.name, relaxed)
