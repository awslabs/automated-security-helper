# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two time-boxed deepmerge suppressions in .ash/.ash.yaml cover their findings.

Why this exists
---------------
npm-audit reports GHSA-gcqx-w48m-w2h4 (deepmerge 4.2.0 through 4.3.1, no patched
release) once per lockfile that holds deepmerge 4.3.1: deploy/cdk and
deploy/cdk-constructs both reach it through jest-config as a dev dependency. A
package-scoped suppression that sets ``package_path`` covers exactly one install
path, so the repository's config carries two entries, one per lockfile. An entry
with a typo in its path, version or rule id would load fine and match nothing, and
the self-scan would stay red; an entry past its expiration matches nothing either.

What this checks
----------------
The repository's own ``.ash/.ash.yaml``, loaded through the config model, holds two
GHSA-gcqx-w48m-w2h4 entries that match a finding shaped like each of npm-audit's
rows, do not match a different installed version or a copy at another path, and
have not expired.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression, expiration_has_passed
from automated_security_helper.models.flat_vulnerability import FlatVulnerability

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".ash" / ".ash.yaml"

RULE = "GHSA-gcqx-w48m-w2h4"
FILE_PATH = "node_modules/deepmerge/package.json"
PACKAGE_PATHS = (
    "deploy/cdk/node_modules/deepmerge",
    "deploy/cdk-constructs/node_modules/deepmerge",
)


def _deepmerge_entries() -> list[AshSuppression]:
    document = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    config = AshConfig.model_validate(document)
    return [
        entry for entry in config.global_settings.suppressions if entry.rule_id == RULE
    ]


def _finding(**overrides) -> FlatVulnerability:
    """A finding shaped like npm-audit's row for this advisory."""
    fields = {
        "id": "f",
        "title": RULE,
        "description": "deepmerge mergeObject() allows prototype poisoning",
        "severity": "MEDIUM",
        "scanner": "npm-audit",
        "scanner_type": "SCA",
        "rule_id": RULE,
        "file_path": FILE_PATH,
        "line_start": 1,
        "line_end": 1,
        "package_name": "deepmerge",
        "package_version": "4.3.1",
    }
    fields.update(overrides)
    return FlatVulnerability(**fields)


def test_the_config_holds_one_entry_per_lockfile() -> None:
    entries = _deepmerge_entries()
    assert sorted(entry.package_path for entry in entries) == sorted(PACKAGE_PATHS)


@pytest.mark.parametrize("package_path", PACKAGE_PATHS)
def test_each_finding_is_covered_by_exactly_one_entry(package_path: str) -> None:
    finding = _finding(package_path=package_path)
    covering = [entry for entry in _deepmerge_entries() if entry.matches(finding)]
    assert len(covering) == 1, (
        f"{package_path}: covered by {len(covering)} entries; expected exactly one"
    )
    assert covering[0].package_path == package_path


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"package_version": "4.3.2"}, id="other-version"),
        pytest.param(
            {"package_path": "deploy/other/node_modules/deepmerge"}, id="other-path"
        ),
        pytest.param({"package_name": "deepmerge-ts"}, id="other-package"),
        pytest.param({"rule_id": "GHSA-0000-0000-0000"}, id="other-rule"),
    ],
)
def test_a_different_finding_is_not_covered(overrides: dict) -> None:
    # The override replaces the default, so the other-path case carries its own
    # package_path instead of a second value for the same keyword.
    kwargs = {"package_path": PACKAGE_PATHS[0], **overrides}
    finding = _finding(**kwargs)
    assert not any(entry.matches(finding) for entry in _deepmerge_entries())


def test_the_entries_have_not_expired() -> None:
    entries = _deepmerge_entries()
    assert entries, "no GHSA-gcqx-w48m-w2h4 entries in .ash/.ash.yaml"
    for entry in entries:
        assert entry.expiration, f"{entry.package_path}: no expiration"
        assert not expiration_has_passed(entry.expiration), (
            f"{entry.package_path}: expired on {entry.expiration}; re-read the "
            "advisory for a patched release before extending it"
        )
