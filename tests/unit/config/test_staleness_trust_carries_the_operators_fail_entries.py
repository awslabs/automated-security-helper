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
_EXPIRED_FAIL_GRYPE = {
    **_FAIL_GRYPE,
    "expiration": "2000-01-01",
    "reason": "a hold the repository never removed",
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


def test_only_the_operators_fail_entry_is_carried_when_the_config_holds_neither(
    tmp_path,
):
    """The operator holds one database to fail and another to warn; the config
    has an entry for neither. Only the fail entry narrows the scan-wide warn
    the config repeats, so only it is carried."""
    trusted = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_FAIL_GRYPE, _WARN_TRIVY],
        }
    )
    config = AshConfig.model_validate({"content_db_staleness": "warn"})

    _confine(config, trusted, tmp_path)

    assert _policies(config) == [("grype-db", "fail")]


def test_an_expired_own_fail_entry_makes_way_for_the_operators_fail_entry(tmp_path):
    """At run time an expired entry is ignored and the database returns to the
    scan-wide policy, here the repository's warn, and the run-time read stops at
    the first entry naming the database. The config's own fail entry for grype-db
    has expired, so it holds the database to nothing; kept as written, it blocked
    the carry of the operator's entry, still in force, for the same database.
    It is dropped and the operator's entry is carried in its place."""
    trusted = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_FAIL_GRYPE],
        }
    )
    config = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_EXPIRED_FAIL_GRYPE],
        }
    )

    _confine(config, trusted, tmp_path)

    assert _policies(config) == [("grype-db", "fail")]
    entries = config.content_db_staleness_overrides
    assert [entry.expiration for entry in entries] == [_FAIL_GRYPE["expiration"]]
    assert not entries[0].is_expired()


def test_an_expired_own_fail_entry_stands_where_the_operator_holds_nothing(tmp_path):
    """The control: with no operator entry for the database, the config's own
    expired entry is left as written, for the run-time read to ignore and name
    in its own warning."""
    trusted = AshConfig.model_validate({"content_db_staleness": "warn"})
    config = AshConfig.model_validate(
        {
            "content_db_staleness": "warn",
            "content_db_staleness_overrides": [_EXPIRED_FAIL_GRYPE],
        }
    )

    _confine(config, trusted, tmp_path)

    entries = config.content_db_staleness_overrides
    assert [entry.expiration for entry in entries] == ["2000-01-01"]
