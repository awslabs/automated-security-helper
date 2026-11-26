# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No `.ash.yaml` suppression matches a minimatch copy the lockfiles no longer carry.

Why this exists
---------------
`.ash.yaml` carried four suppression entries for GHSA-g3hv-75wg-m249 (and its
CVE-2026-118764 / grype spellings) pinning ``package_version: "10.2.5"``, the
minimatch copy bundled inside aws-cdk-lib 2.273.0. The aws-cdk-lib 2.278.0 bump
replaced that bundled copy with minimatch 11.0.9 in both deploy lockfiles, which
is outside the advisory's vulnerable range (``>= 7.0.0, < 11.0.1``, first
patched 11.0.1), so the entries matched no installed copy and were removed.

This pins the removal two ways: the lockfiles hold no minimatch 10.2.5 (the
precondition that makes the entries dead weight; if 10.2.5 ever reappears this
fails loudly and the pin is revisited), and no suppression in `.ash.yaml`
matches a synthetic bundled-minimatch-10.2.5 finding under any of the three
rule-id spellings the removed entries carried. A positive control shows the
synthetic finding is matchable, so an empty answer is the entries' absence,
never a dead matcher.
"""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

LOCKFILES = (
    "deploy/cdk/package-lock.json",
    "deploy/cdk-constructs/package-lock.json",
)

#: The rule-id spellings the removed entries carried: npm-audit's, grype's
#: and trivy's names for the same advisory against the same bundled copy.
RULE_SPELLINGS = (
    "GHSA-g3hv-75wg-m249",
    "GHSA-g3hv-75wg-m249-minimatch",
    "CVE-2026-118764",
)


def _repo_suppressions():
    doc = yaml.safe_load((REPO_ROOT / ".ash.yaml").read_text(encoding="utf-8"))
    entries = (doc.get("global_settings") or {}).get("suppressions") or []
    return [AshSuppression.model_validate(entry) for entry in entries]


def _installed_minimatch_versions():
    versions = {}
    for name in LOCKFILES:
        doc = json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))
        for key, meta in (doc.get("packages") or {}).items():
            if key.split("/")[-1] == "minimatch":
                versions[(name, key)] = meta.get("version")
    return versions


def _bundled_finding(rule_id: str, version: str) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"synthetic-{rule_id}-{version}",
        title="minimatch globparts amplification denial of service",
        description="Synthetic lockfile-located finding for the suppression pin.",
        severity="MEDIUM",
        scanner="npm-audit",
        scanner_type="SCA",
        rule_id=rule_id,
        file_path="deploy/cdk/package-lock.json",
        package_name="minimatch",
        package_version=version,
        package_path="deploy/cdk/node_modules/aws-cdk-lib/node_modules/minimatch",
    )


def test_lockfiles_no_longer_carry_minimatch_10_2_5():
    """The precondition: every installed minimatch copy is 11.x, none 10.2.5."""
    versions = _installed_minimatch_versions()
    assert versions, "no minimatch entry found in either lockfile; vacuous"
    stale = {k: v for k, v in versions.items() if v == "10.2.5"}
    assert not stale, (
        f"minimatch 10.2.5 is installed again ({stale}); re-read "
        "GHSA-g3hv-75wg-m249 and revisit the suppressions this test pinned away"
    )


@pytest.mark.parametrize("rule_id", RULE_SPELLINGS)
@pytest.mark.parametrize("version", ["10.2.5", "11.0.9"])
def test_no_repo_suppression_matches_the_bundled_minimatch_finding(rule_id, version):
    """No `.ash.yaml` entry suppresses the bundled copy, stale or installed.

    At 10.2.5 this is the removal pin (the removed entries matched exactly
    this finding); at 11.0.9 it shows the entries never covered the copy the
    lockfiles install now, which is patched and yields no finding anyway.
    """
    suppressed, hit = should_suppress_finding(
        _bundled_finding(rule_id, version), _repo_suppressions()
    )
    assert not suppressed, (
        f"a .ash.yaml suppression ({hit and hit.rule_id} at {hit and hit.path}) "
        f"still matches bundled minimatch {version} under {rule_id}"
    )


def test_positive_control_a_pinned_entry_does_match_the_synthetic_finding():
    """The synthetic finding is matchable: a 10.2.5 entry shaped like the
    removed ones suppresses it, so the empty answers above are measurements."""
    control = AshSuppression(
        reason="positive control for the stale-suppression pin",
        rule_id="GHSA-g3hv-75wg-m249",
        path="deploy/cdk/package-lock.json",
        package_name="minimatch",
        package_version="10.2.5",
        package_path="deploy/cdk/node_modules/aws-cdk-lib/node_modules/minimatch",
    )
    suppressed, hit = should_suppress_finding(
        _bundled_finding("GHSA-g3hv-75wg-m249", "10.2.5"), [control]
    )
    assert suppressed and hit is control


@pytest.mark.parametrize(
    "rule_id,package_name",
    [
        ("GHSA-0000-0000-0000", "minimatch"),  # other advisory
        ("GHSA-g3hv-75wg-m249", "not-a-real-package"),  # other package
    ],
)
def test_negative_controls_do_not_match_the_control_entry(rule_id, package_name):
    """The control entry is scoped: another GHSA or another package never matches."""
    control = AshSuppression(
        reason="negative control for the stale-suppression pin",
        rule_id="GHSA-g3hv-75wg-m249",
        path="deploy/cdk/package-lock.json",
        package_name="minimatch",
        package_version="10.2.5",
    )
    finding = _bundled_finding(rule_id, "10.2.5")
    finding = finding.model_copy(update={"package_name": package_name})
    suppressed, _ = should_suppress_finding(finding, [control])
    assert not suppressed
