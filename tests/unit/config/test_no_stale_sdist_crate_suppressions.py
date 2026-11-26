# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No `.ash.yaml` suppression matches a crate advisory the locked sdists no longer embed.

Why this exists
---------------
The sdist-lock harvester extracts the Cargo.lock a compiled dependency's PyPI
sdist embeds, and grype and trivy report advisories against the crates it pins.
`.ash.yaml` carried time-boxed entries for three such crates: ten for zip 8.6.0
inside ruff 0.16.10 (CVE-2026-115905 to CVE-2026-115909, trivy's CVE ids and
grype's suffixed GHSA ids), two wildcard entries for pyo3 inside pydantic-core
2.46.5, rpds-py 0.30.0 and rtoml 0.13.0 (GHSA-36hh-v3qg-5jq4,
GHSA-chgr-c6px-7xpp), and a GHSA-c8m5-c952-6cm4 rustls wildcard over every
harvested Cargo.lock that also covered uv 0.13.5. The locked releases now embed
the fixed crates: ruff 0.17.5 embeds zip 9.0.5, pydantic-core 2.50.5 embeds pyo3
0.30.1, rpds-py 2026.9.1 and rtoml 0.14.0 embed pyo3 0.29.3, and uv 0.13.9
embeds rustls 0.23.46, each outside its advisories' ranges. So the zip and pyo3
entries matched nothing and were removed, and the rustls entries were narrowed
to the one lockfile that still needs them, polars-runtime-32's
(``tests/utils/sdist_harvest_oracle.py`` holds those).

This pins the removal two ways. The precondition: `uv.lock` locks each of those
packages at or above the first release whose sdist embeds the fixed crate, so
the entries stay dead weight; a lock below a floor fails here and the
suppressions are revisited. The removal: no `.ash.yaml` suppression matches a
synthetic finding for a removed advisory, under each scanner spelling, at the
parent's harvested lockfile in the converted tree and in the harvest layout, at
the crate version the entries covered and at the fixed one locked now. The
entries are read as if unexpired, so an entry put back with a past `expires`
is caught too. Positive controls show the synthetic findings are matchable:
entries shaped like the removed ones suppress them, and the repository's own
polars rustls entries suppress polars' finding through the same loader, so an
empty answer is the entries' absence, never a dead matcher or an unread file.
"""

import functools
import tomllib
from pathlib import Path

import pytest
import yaml
from packaging.version import Version

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The first release of each parent whose sdist-embedded Cargo.lock carries the
#: fixed crate, measured by harvesting the release's sdist and its predecessor's
#: (the predecessor in parentheses still embeds the vulnerable copy).
FIRST_FIXED_RELEASES = {
    "ruff": "0.17.4",  # zip 9.0.5 (0.17.3 embeds zip 8.6.0)
    "pydantic-core": "2.48.0",  # pyo3 0.29.2 (2.47.0 embeds pyo3 0.28.3)
    "rpds-py": "2026.6.3",  # pyo3 0.29.0 (2026.5.1 embeds pyo3 0.28.3)
    "rtoml": "0.14.0",  # pyo3 0.29.3 (0.13.0 embeds pyo3 0.26.0)
    "uv": "0.13.7",  # rustls 0.23.46 (0.13.6 embeds rustls 0.23.45)
}

ZIP_ADVISORIES = (
    ("CVE-2026-115905", "GHSA-m665-v7pm-7grj"),
    ("CVE-2026-115906", "GHSA-8hxf-qr8p-62x4"),
    ("CVE-2026-115907", "GHSA-9hj8-73fh-9963"),
    ("CVE-2026-115908", "GHSA-hjqx-j4rw-g7xv"),
    ("CVE-2026-115909", "GHSA-q7v9-x93c-xqv3"),
)
PYO3_ADVISORIES = ("GHSA-36hh-v3qg-5jq4", "GHSA-chgr-c6px-7xpp")
RUSTLS_ADVISORY = "GHSA-c8m5-c952-6cm4"

#: The rule-id spellings a removed advisory can arrive under: trivy reports the
#: CVE id when one exists, else the bare GHSA id; grype appends the crate name.
ZIP_SPELLINGS = tuple(
    spelling for cve, ghsa in ZIP_ADVISORIES for spelling in (cve, ghsa, f"{ghsa}-zip")
)
PYO3_SPELLINGS = tuple(
    spelling for ghsa in PYO3_ADVISORIES for spelling in (ghsa, f"{ghsa}-pyo3")
)
RUSTLS_SPELLINGS = (RUSTLS_ADVISORY, f"{RUSTLS_ADVISORY}-rustls")

#: (parent, the parent version the removed entries were written for, crate,
#: the crate version that release embedded, the crate version the locked
#: release embeds, the rule-id spellings).
REMOVED = (
    ("ruff", "0.16.10", "zip", "8.6.0", "9.0.5", ZIP_SPELLINGS),
    ("pydantic-core", "2.46.5", "pyo3", "0.28.3", "0.30.1", PYO3_SPELLINGS),
    ("rpds-py", "0.30.0", "pyo3", "0.27.2", "0.29.3", PYO3_SPELLINGS),
    ("rtoml", "0.13.0", "pyo3", "0.26.0", "0.29.3", PYO3_SPELLINGS),
    ("uv", "0.13.5", "rustls", "0.23.45", "0.23.46", RUSTLS_SPELLINGS),
)

CASES = [
    pytest.param(
        parent, old, crate, vulnerable, fixed, rule_id, id=f"{parent}-{rule_id}"
    )
    for parent, old, crate, vulnerable, fixed, spellings in REMOVED
    for rule_id in spellings
]


@functools.cache
def _repo_suppressions():
    """The `.ash.yaml` suppressions, read as if none had expired.

    An expired entry matches nothing, so an entry put back with a past date
    would pass the removal pin vacuously; reading it unexpired catches it.
    """
    doc = yaml.safe_load((REPO_ROOT / ".ash.yaml").read_text(encoding="utf-8"))
    entries = (doc.get("global_settings") or {}).get("suppressions") or []
    return tuple(
        AshSuppression.model_validate(
            {k: v for k, v in entry.items() if k not in ("expires", "expiration")}
        )
        for entry in entries
    )


@functools.cache
def _lock_packages():
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return tuple(lock.get("package", []))


def _locked_versions(name: str):
    return [p["version"] for p in _lock_packages() if p.get("name") == name]


def _lockfile_paths(parent: str, version: str):
    """The harvested lockfile's path as ASH's converted tree reports it, and as
    the harvest layout under the converted target names it."""
    layout = f"sdist-locks/{parent}/{version}/Cargo.lock"
    return (f".ash/ash_output/converted/sdist-lock-harvester/{layout}", layout)


def _harvested_finding(
    rule_id: str, path: str, crate: str, version: str
) -> FlatVulnerability:
    scanner = "grype" if rule_id.endswith(f"-{crate}") else "trivy"
    return FlatVulnerability(
        id=f"synthetic-{rule_id}-{crate}-{version}",
        title=f"{crate} {version} advisory {rule_id}",
        description="Synthetic harvested-lockfile finding for the suppression pin.",
        severity="MEDIUM",
        scanner=scanner,
        scanner_type="SCA",
        rule_id=rule_id,
        file_path=path,
        package_name=crate,
        package_version=version,
    )


@pytest.mark.parametrize("parent,floor", sorted(FIRST_FIXED_RELEASES.items()))
def test_uv_lock_holds_each_parent_at_or_above_its_first_fixed_release(parent, floor):
    """The precondition that makes the removed entries dead weight."""
    versions = _locked_versions(parent)
    assert versions, f"{parent} is not in uv.lock; vacuous"
    below = [v for v in versions if Version(v) < Version(floor)]
    assert not below, (
        f"uv.lock locks {parent} {below}, below {floor}, whose sdist is the first "
        "to embed the fixed crate; re-measure the embedded Cargo.lock and revisit "
        "the suppressions this test pinned away"
    )


@pytest.mark.parametrize("parent,old,crate,vulnerable,fixed,rule_id", CASES)
def test_no_repo_suppression_matches_a_removed_advisory(
    parent, old, crate, vulnerable, fixed, rule_id
):
    """No `.ash.yaml` entry suppresses the advisory at the parent's lockfile.

    At the vulnerable crate version this is the removal pin (the removed entries
    matched exactly this finding); at the fixed version it shows no entry covers
    the copy the locked release embeds, which yields no finding anyway.
    """
    entries = _repo_suppressions()
    parent_versions = sorted({old, *_locked_versions(parent)})
    for parent_version in parent_versions:
        for path in _lockfile_paths(parent, parent_version):
            for version in (vulnerable, fixed):
                suppressed, hit = should_suppress_finding(
                    _harvested_finding(rule_id, path, crate, version), entries
                )
                assert not suppressed, (
                    f"a .ash.yaml suppression ({hit and hit.rule_id} at "
                    f"{hit and hit.path}) still matches {crate} {version} under "
                    f"{rule_id} at {path}"
                )


def _removed_shape(rule_id: str, path: str, crate: str, version=None):
    return AshSuppression(
        reason="positive control for the stale-suppression pin",
        rule_id=rule_id,
        path=path,
        package_name=crate,
        package_version=version,
    )


def test_positive_control_entries_shaped_like_the_removed_ones_match():
    """Entries shaped like the removed ones suppress the synthetic findings, so
    the empty answers above are measurements."""
    converted_ruff, _ = _lockfile_paths("ruff", "0.16.10")
    zip_entry = _removed_shape(
        "CVE-2026-115905",
        "**/sdist-lock-harvester/sdist-locks/ruff/*/Cargo.lock",
        "zip",
        "8.6.0",
    )
    finding = _harvested_finding("CVE-2026-115905", converted_ruff, "zip", "8.6.0")
    suppressed, hit = should_suppress_finding(finding, [zip_entry])
    assert suppressed and hit is zip_entry

    # The pyo3 and rustls entries were one wildcard per advisory over every
    # harvested Cargo.lock, with no version; each covered both spellings.
    for parent, old, crate, vulnerable, _fixed, spellings in REMOVED[1:]:
        converted, _ = _lockfile_paths(parent, old)
        for rule_id in spellings:
            advisory = rule_id.removesuffix(f"-{crate}")
            wildcard = _removed_shape(
                f"{advisory}*",
                "**/sdist-lock-harvester/sdist-locks/**/Cargo.lock",
                crate,
            )
            suppressed, hit = should_suppress_finding(
                _harvested_finding(rule_id, converted, crate, vulnerable), [wildcard]
            )
            assert suppressed and hit is wildcard, (parent, rule_id)


def test_positive_control_the_repo_polars_rustls_entries_match_through_the_loader():
    """The loader reads the file and the matcher answers on its entries: the kept
    polars-runtime-32 rustls entries suppress polars' finding at its lockfile.
    When polars moves past rustls 0.23.43 and those entries go, point this control
    at another lockfile-located entry the file carries."""
    entries = _repo_suppressions()
    converted, layout = _lockfile_paths("polars-runtime-32", "1.44.2")
    for rule_id in (
        "GHSA-2mjx-qc3c-rqvc",
        "GHSA-2mjx-qc3c-rqvc-rustls",
        "GHSA-c8m5-c952-6cm4",
        "GHSA-c8m5-c952-6cm4-rustls",
    ):
        for path in (converted, layout):
            suppressed, hit = should_suppress_finding(
                _harvested_finding(rule_id, path, "rustls", "0.23.43"), entries
            )
            assert suppressed and hit is not None and hit.rule_id == rule_id, (
                f"{rule_id} at {path} is not suppressed by the repository's entries"
            )


@pytest.mark.parametrize(
    "rule_id,package_name,version",
    [
        ("CVE-2026-000000", "zip", "8.6.0"),  # other advisory
        ("CVE-2026-115905", "not-a-real-crate", "8.6.0"),  # other crate
        ("CVE-2026-115905", "zip", "9.0.5"),  # the fixed version
    ],
)
def test_negative_controls_do_not_match_the_control_entry(
    rule_id, package_name, version
):
    """The control entry is scoped: another advisory, another crate or the
    fixed version never matches."""
    control = _removed_shape(
        "CVE-2026-115905",
        "**/sdist-lock-harvester/sdist-locks/ruff/*/Cargo.lock",
        "zip",
        "8.6.0",
    )
    converted, _ = _lockfile_paths("ruff", "0.16.10")
    finding = _harvested_finding(rule_id, converted, package_name, version)
    suppressed, _ = should_suppress_finding(finding, [control])
    assert not suppressed
