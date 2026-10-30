# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The operator's per-database ``policy: fail`` entries survive a repository config.

``confine_content_db_staleness`` keeps a repository's ``content_db_staleness``
when it equals the operator's. With the operator on ``warn`` scan-wide and a
``content_db_staleness_overrides`` entry holding one database to ``fail``, a
repository config that repeats the ``warn`` and leaves the entry out would hold
that database to warn, laxer than the operator's setting for it. The confinement
carries the operator's ``fail`` entries for the databases the config has no entry
for; its ``warn`` entries are not copied in. A config's own ``fail`` entry for the
database stands; an own entry laxer than the operator's (a ``warn`` the operator
did not set) is dropped first, so the operator's ``fail`` entry is carried in its
place.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.staleness_trust import (
    confine_content_db_staleness,
)

pytestmark = pytest.mark.unit

_FAIL_GRYPE = {
    "database": "grype-db",
    "policy": "fail",
    "expiration": "2099-01-01",
    "reason": "held to fail while the scan-wide policy is warn",
}
_WARN_TRIVY = {
    "database": "trivy-db",
    "policy": "warn",
    "expiration": "2099-01-01",
    "reason": "upstream publishing is paused",
}


def _policies(config: AshConfig) -> List[Tuple[str, str]]:
    return [
        (entry.database, entry.policy)
        for entry in config.content_db_staleness_overrides
    ]


def _confine(config: AshConfig, trusted: AshConfig, tmp_path: Path) -> None:
    confine_content_db_staleness(
        config, trusted, [], [tmp_path / "repo" / ".ash" / ".ash.yaml"]
    )


def test_the_operators_fail_entry_is_carried_into_a_config_that_lacks_it(tmp_path):
    trusted = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_FAIL_GRYPE],
        }
    )
    config = AshConfig.model_validate({"content_db_staleness": "warn"})

    _confine(config, trusted, tmp_path)

    assert config.content_db_staleness == "warn"
    assert _policies(config) == [("grype-db", "fail")]


def test_a_dropped_warn_entry_makes_way_for_the_operators_fail_entry(tmp_path):
    trusted = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_FAIL_GRYPE],
        }
    )
    config = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [{**_FAIL_GRYPE, "policy": "warn"}],
        }
    )

    _confine(config, trusted, tmp_path)

    assert _policies(config) == [("grype-db", "fail")]


def test_the_configs_own_fail_entry_for_the_database_stands(tmp_path):
    trusted = AshConfig.model_validate(
        {"content_db_staleness_overrides": [_FAIL_GRYPE]}
    )
    own = {**_FAIL_GRYPE, "reason": "the repository's own reason"}
    config = AshConfig.model_validate({"content_db_staleness_overrides": [own]})

    _confine(config, trusted, tmp_path)

    assert _policies(config) == [("grype-db", "fail")]
    assert config.content_db_staleness_overrides[0].reason == own["reason"]


def test_the_operators_warn_entry_is_not_copied_in(tmp_path):
    trusted = AshConfig.model_validate(
        {"content_db_staleness_overrides": [_WARN_TRIVY]}
    )
    config = AshConfig.model_validate({"content_db_staleness": "fail"})

    _confine(config, trusted, tmp_path)

    assert _policies(config) == []
