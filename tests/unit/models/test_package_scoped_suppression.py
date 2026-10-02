# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package-scoped suppressions: ``package_name``, ``package_version``, ``package_path``.

Dependency scanners report one result per (advisory, package copy), but before
these fields existed a suppression could only match on rule ID, file path and
line range. grype places every finding at line 1 of the lockfile, so two copies
of one package in the same lockfile -- ``brace-expansion`` 1.1.18 at the top
level and a 5.0.9 bundled inside ``aws-cdk-lib`` -- were identical on every
field a suppression could match. Suppressing one copy suppressed them all.

The package fields narrow a suppression to one package copy. Each one is
optional; a suppression that sets none of them matches exactly as before. A
suppression that sets one never matches a finding that does not carry that
piece of identity, so a scanner that cannot report it fails closed.
"""

from datetime import date, timedelta

import pytest

from automated_security_helper.config.config_linter import ConfigLinter
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

LOCKFILE = "deploy/cdk/package-lock.json"
RULE = "GHSA-6j4f-fj2g-mc7p-brace-expansion"
BUNDLED_PATH = "deploy/cdk/node_modules/aws-cdk-lib/node_modules/brace-expansion"
TOP_LEVEL_PATH = "deploy/cdk/node_modules/brace-expansion"


def _finding(**overrides) -> FlatVulnerability:
    fields = {
        "id": "f",
        "title": RULE,
        "description": "d",
        "severity": "HIGH",
        "scanner": "grype",
        "scanner_type": "SCA",
        "rule_id": RULE,
        "file_path": LOCKFILE,
        "line_start": 1,
        "line_end": 1,
    }
    fields.update(overrides)
    return FlatVulnerability(**fields)


def _bundled() -> FlatVulnerability:
    return _finding(
        package_name="brace-expansion",
        package_version="5.0.9",
        package_path=BUNDLED_PATH,
    )


def _top_level(version: str = "1.1.18") -> FlatVulnerability:
    return _finding(
        package_name="brace-expansion",
        package_version=version,
        package_path=TOP_LEVEL_PATH,
    )


def _suppression(**overrides) -> AshSuppression:
    fields = {"rule_id": RULE, "path": LOCKFILE, "reason": "r"}
    fields.update(overrides)
    return AshSuppression(**fields)


class TestBackwardCompatibility:
    """A suppression that sets no package field behaves exactly as before."""

    @pytest.mark.parametrize(
        "finding",
        [_finding(), _bundled(), _top_level(), _top_level("5.0.9")],
        ids=["no-identity", "bundled", "top-level-1.1.18", "top-level-5.0.9"],
    )
    def test_legacy_suppression_matches_every_copy(self, finding):
        assert _suppression().matches(finding) is True

    def test_legacy_suppression_still_rejects_other_rule(self):
        assert _suppression(rule_id="GHSA-other").matches(_bundled()) is False

    def test_legacy_suppression_still_rejects_other_path(self):
        assert _suppression(path="other/package-lock.json").matches(_bundled()) is False

    def test_legacy_id_is_unchanged(self):
        assert _suppression().id == f"{LOCKFILE}|{RULE}|*|*"

    def test_finding_package_fields_default_to_none(self):
        finding = _finding()
        assert finding.package_name is None
        assert finding.package_version is None
        assert finding.package_path is None


class TestPackageName:
    def test_matches_same_name(self):
        assert _suppression(package_name="brace-expansion").matches(_bundled())

    def test_rejects_other_name(self):
        assert not _suppression(package_name="minimatch").matches(_bundled())

    def test_glob_and_case_insensitive(self):
        assert _suppression(package_name="Brace-*").matches(_bundled())

    def test_fails_closed_when_finding_has_no_name(self):
        assert not _suppression(package_name="brace-expansion").matches(_finding())


class TestPackageVersion:
    def test_matches_same_version_only(self):
        supp = _suppression(package_name="brace-expansion", package_version="5.0.9")
        assert supp.matches(_bundled()) is True
        assert supp.matches(_top_level("1.1.18")) is False

    def test_glob(self):
        supp = _suppression(package_version="5.*")
        assert supp.matches(_bundled()) is True
        assert supp.matches(_top_level("1.1.18")) is False

    def test_fails_closed_when_finding_has_no_version(self):
        finding = _finding(package_name="brace-expansion")
        assert not _suppression(package_version="5.0.9").matches(finding)


class TestPackagePath:
    """Only a dependency path separates two copies with the same name and version."""

    def test_name_and_version_cannot_separate_a_collision(self):
        # The trap: a non-bundled 5.0.9 next to the bundled 5.0.9.
        supp = _suppression(package_name="brace-expansion", package_version="5.0.9")
        assert supp.matches(_bundled()) is True
        assert supp.matches(_top_level("5.0.9")) is True

    def test_path_separates_a_collision(self):
        supp = _suppression(
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path=BUNDLED_PATH,
        )
        assert supp.matches(_bundled()) is True
        assert supp.matches(_top_level("5.0.9")) is False

    def test_recursive_glob_covers_every_tree_but_only_the_bundled_copy(self):
        supp = _suppression(
            path="*",
            package_path="**/node_modules/aws-cdk-lib/node_modules/brace-expansion",
        )
        other_tree = _finding(
            file_path="deploy/cdk-constructs/package-lock.json",
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path=(
                "deploy/cdk-constructs/node_modules/aws-cdk-lib/node_modules/"
                "brace-expansion"
            ),
        )
        assert supp.matches(_bundled()) is True
        assert supp.matches(other_tree) is True
        assert supp.matches(_top_level("5.0.9")) is False
        assert supp.matches(_top_level("1.1.18")) is False

    def test_fails_closed_when_finding_has_no_path(self):
        finding = _finding(package_name="brace-expansion", package_version="5.0.9")
        assert not _suppression(package_path=BUNDLED_PATH).matches(finding)


class TestExpiry:
    """An expired package-scoped suppression matches nothing, like any other."""

    @pytest.mark.parametrize("days_from_today", [0, -1, -365])
    def test_expired_matches_nothing(self, days_from_today):
        supp = _suppression(
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path=BUNDLED_PATH,
            expiration=(date.today() + timedelta(days=days_from_today)).isoformat(),
        )
        assert supp.is_expired is True
        for finding in (_bundled(), _top_level(), _top_level("5.0.9"), _finding()):
            assert supp.matches(finding) is False

    def test_unexpired_still_matches(self):
        supp = _suppression(
            package_path=BUNDLED_PATH,
            expiration=(date.today() + timedelta(days=1)).isoformat(),
        )
        assert supp.matches(_bundled()) is True


class TestIdentity:
    """Two entries that differ only in package fields must not share an id.

    The unused-suppressions report keys on ``id``. If two package-scoped entries
    for the same rule and lockfile collapsed to one id, using one would mark
    the other as used.
    """

    def test_package_fields_distinguish_ids(self):
        a = _suppression(package_version="5.0.9", package_path=BUNDLED_PATH)
        b = _suppression(package_version="1.1.18", package_path=TOP_LEVEL_PATH)
        assert a.id != b.id
        assert a.id.startswith(f"{LOCKFILE}|{RULE}|*|*|")

    def test_linter_id_agrees_with_model_id(self):
        supp = _suppression(
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path=BUNDLED_PATH,
        )
        as_dict = supp.model_dump(exclude_none=True)
        assert ConfigLinter._make_suppression_id(as_dict) == supp.id

    def test_linter_id_agrees_for_legacy_entry(self):
        supp = _suppression()
        as_dict = supp.model_dump(exclude_none=True)
        assert ConfigLinter._make_suppression_id(as_dict) == supp.id
