# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every harvested lockfile is held to the crate suppressions its sdists need.

Why this exists
---------------
The sdist-lock harvester extracts the Cargo.lock a compiled dependency's PyPI
sdist embeds, and grype and trivy report advisories against the crates it pins.
It reads every ``uv.lock`` in the scan set that no global ignore path skips, not
only the root one, and lays out the lockfiles embedded in the sdist of each
compiled package a lockfile pins under ``sdist-locks/<package>/<version>/``, so
a package two lockfiles pin at two versions is harvested at both. This
repository has two such lockfiles (``HARVESTED_LOCKFILES``): the root
``uv.lock`` and the agentic-coding transpiler's.

`.ash.yaml` carried time-boxed entries for three such crates: ten for zip 8.6.0
inside ruff 0.16.10 (CVE-2026-115905 to CVE-2026-115909, trivy's CVE ids and
grype's suffixed GHSA ids), two wildcard entries for pyo3 inside pydantic-core
2.46.5, rpds-py 0.30.0 and rtoml 0.13.0 (GHSA-36hh-v3qg-5jq4,
GHSA-chgr-c6px-7xpp), and a GHSA-c8m5-c952-6cm4 rustls wildcard over every
harvested Cargo.lock that also covered uv 0.13.5. The root lock now pins
releases whose sdists embed the fixed crates: ruff 0.17.5 embeds zip 9.0.5,
pydantic-core 2.50.5 embeds pyo3 0.30.1, rpds-py 2026.9.1 and rtoml 0.14.0 embed
pyo3 0.29.3, and uv 0.13.9 embeds rustls 0.23.46, each outside its advisories'
ranges. Those entries were removed, and the rustls entries were narrowed to
polars-runtime-32's lockfile (``tests/utils/sdist_harvest_oracle.py`` holds
those). The transpiler's lock still pins rpds-py 0.30.0, whose sdist embeds pyo3
0.27.2, and the repository's own scan reports both pyo3 advisories against that
lockfile: trivy under the bare GHSA id, grype under the id with ``-pyo3``
appended.

What is held
------------
For each parent in ``FIRST_FIXED_RELEASES`` and each version of it a harvested
lockfile pins:

- At or above the parent's first fixed release, no `.ash.yaml` suppression
  matches a synthetic finding for the parent's removed advisories at that
  version's lockfile, under each scanner spelling and path form, at the crate
  version the removed entries covered or at the fixed one.
- Below it, ``REMOVED`` has a measured row for the version (the crate version
  its sdist embeds), and `.ash.yaml` suppresses each advisory spelling at that
  version's lockfile, at every path form, for that crate version and nothing
  else: not for the fixed crate version, not at another parent's lockfile, and
  not at another version of the same parent.

A ``REMOVED`` row for a version no harvested lockfile pins any more stays a
removal pin: no suppression matches its advisories at that version's lockfile,
at either crate version. A ``uv.lock`` the harvester would read that the
repository gains or loses fails
``test_harvested_lockfiles_are_the_tracked_uv_locks_the_harvester_reads`` until
``HARVESTED_LOCKFILES`` matches, so these rows cannot go stale silently.

The entries are read as if unexpired: a removal pin then catches an entry put
back with a past `expires`, and the below-the-floor check asks only that the
exact entries be written, leaving their time box to the scan. Positive controls
show the synthetic findings are matchable: entries shaped like the removed ones
suppress them, the repository's own polars rustls entries suppress polars'
finding through the same loader, and the below-the-floor check passes on exact
entries and fails on the same set missing one spelling or pinned too loosely.
So an empty answer is the entries' absence, never a dead matcher or an unread
file.
"""

import functools
import subprocess  # nosec B404 - git ls-files over this checkout only
import tomllib
from pathlib import Path, PurePosixPath

import pytest
import yaml
from packaging.version import Version

from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.sdist_harvest import harvest_options_of
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
    should_suppress_finding,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Every ``uv.lock`` the harvester reads in this repository, by path from the
#: root. The harvester takes them from the scan set, a walk of the checkout that
#: a unit test does not make, so they are named here, and
#: ``test_harvested_lockfiles_are_the_tracked_uv_locks_the_harvester_reads``
#: holds the names to the lockfiles git tracks.
HARVESTED_LOCKFILES = (
    "uv.lock",
    "ash-agent-plugins/agentic-coding/transpiler/uv.lock",
)

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

#: The releases below each floor that `.ash.yaml` carried entries for, each
#: measured: (parent, that release, crate, the crate version its sdist embeds,
#: the crate version the root uv.lock's release of the parent embeds, the
#: rule-id spellings). A row no harvested lockfile pins any more is a removal
#: pin; a row a harvested lockfile still pins is held to exact entries.
REMOVED = (
    ("ruff", "0.16.10", "zip", "8.6.0", "9.0.5", ZIP_SPELLINGS),
    ("pydantic-core", "2.46.5", "pyo3", "0.28.3", "0.30.1", PYO3_SPELLINGS),
    ("rpds-py", "0.30.0", "pyo3", "0.27.2", "0.29.3", PYO3_SPELLINGS),
    ("rtoml", "0.13.0", "pyo3", "0.26.0", "0.29.3", PYO3_SPELLINGS),
    ("uv", "0.13.5", "rustls", "0.23.45", "0.23.46", RUSTLS_SPELLINGS),
)


@functools.cache
def _repo_config():
    return yaml.safe_load((REPO_ROOT / ".ash.yaml").read_text(encoding="utf-8"))


def _global_settings():
    return _repo_config().get("global_settings") or {}


@functools.cache
def _repo_suppressions():
    """The `.ash.yaml` suppressions, read as if none had expired.

    An expired entry matches nothing, so an entry put back with a past date
    would pass the removal pin vacuously; reading it unexpired catches it.
    """
    return tuple(
        AshSuppression.model_validate(
            {k: v for k, v in entry.items() if k not in ("expires", "expiration")}
        )
        for entry in _global_settings().get("suppressions") or []
    )


@functools.cache
def _lock_packages(lockfile: str):
    lock = tomllib.loads((REPO_ROOT / lockfile).read_text(encoding="utf-8"))
    return tuple(lock.get("package", []))


def _pinned_versions(name: str):
    """The versions of ``name`` the harvested lockfiles pin, lowest first."""
    return sorted(
        {
            package["version"]
            for lockfile in HARVESTED_LOCKFILES
            for package in _lock_packages(lockfile)
            if package.get("name") == name
        },
        key=Version,
    )


def _lockfiles_pinning(name: str, version: str):
    """The harvested lockfiles that pin ``name`` at ``version``."""
    return [
        lockfile
        for lockfile in HARVESTED_LOCKFILES
        if any(
            package.get("name") == name and package.get("version") == version
            for package in _lock_packages(lockfile)
        )
    ]


def _below_floor(parent: str, version: str) -> bool:
    return Version(version) < Version(FIRST_FIXED_RELEASES[parent])


def _measured_row(parent: str, version: str):
    """The ``REMOVED`` row measured for ``parent`` at ``version``, or None."""
    for row in REMOVED:
        if row[:2] == (parent, version):
            return row
    return None


def _spellings_of(parent: str):
    """The spellings of ``parent``'s removed advisories, in table order."""
    return tuple(
        dict.fromkeys(
            rule_id for row in REMOVED if row[0] == parent for rule_id in row[5]
        )
    )


#: Each (parent, version) a harvested lockfile pins, for the parents above.
PINNED = [
    (parent, version)
    for parent in sorted(FIRST_FIXED_RELEASES)
    for version in _pinned_versions(parent)
]
BELOW_THE_FLOOR = [
    (parent, version) for parent, version in PINNED if _below_floor(parent, version)
]

REMOVAL_CASES = [
    pytest.param(
        parent,
        old,
        crate,
        vulnerable,
        fixed,
        rule_id,
        id=f"{parent}-{old}-{rule_id}",
    )
    for parent, old, crate, vulnerable, fixed, spellings in REMOVED
    if (parent, old) not in PINNED
    for rule_id in spellings
]
PAST_THE_FLOOR_CASES = [
    pytest.param(parent, version, rule_id, id=f"{parent}-{version}-{rule_id}")
    for parent, version in PINNED
    if not _below_floor(parent, version)
    for rule_id in _spellings_of(parent)
]
EXACT_CASES = [
    pytest.param(
        parent,
        version,
        crate,
        vulnerable,
        fixed,
        rule_id,
        id=f"{parent}-{version}-{rule_id}",
    )
    for parent, version, crate, vulnerable, fixed, spellings in REMOVED
    if (parent, version) in BELOW_THE_FLOOR
    for rule_id in spellings
]


def _lockfile_paths(parent: str, version: str):
    """The harvested lockfile's path in the forms a finding can carry.

    As trivy reported it, from the scanned tree through ASH's converted
    directory; as grype reported it, from that converted directory; and as the
    harvest layout names it below the harvester's converted target.
    """
    layout = f"sdist-locks/{parent}/{version}/Cargo.lock"
    return (
        f".ash/ash_output/converted/sdist-lock-harvester/{layout}",
        f"sdist-lock-harvester/{layout}",
        layout,
    )


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


def _suppressing(entries, rule_id: str, path: str, crate: str, version: str):
    """The entry that suppresses a synthetic finding at ``path``, or None."""
    suppressed, hit = should_suppress_finding(
        _harvested_finding(rule_id, path, crate, version), entries
    )
    return hit if suppressed else None


def _removal_problems(entries, parent, version, crate, crate_versions, rule_id):
    """Each match of ``rule_id`` at ``parent`` ``version``'s lockfile, as text.

    At every path form of the lockfile, for each of ``crate_versions``; an empty
    list is the removal pin holding.
    """
    problems = []
    for path in _lockfile_paths(parent, version):
        for crate_version in crate_versions:
            hit = _suppressing(entries, rule_id, path, crate, crate_version)
            if hit is not None:
                problems.append(
                    f"a .ash.yaml suppression ({hit.rule_id} at {hit.path}) still "
                    f"matches {crate} {crate_version} under {rule_id} at {path}"
                )
    return problems


def _other_harvest_locations(parent: str, version: str):
    """The harvested lockfiles, as (package, version), a row's entries leave alone.

    Each parent at every version a harvested lockfile pins, and ``parent`` at its
    first fixed release too, so another version of it is always tried; never
    ``parent`` ``version`` itself.
    """
    locations = {
        (other, pinned)
        for other in FIRST_FIXED_RELEASES
        for pinned in _pinned_versions(other)
    }
    locations.add((parent, FIRST_FIXED_RELEASES[parent]))
    locations.discard((parent, version))
    return sorted(locations)


def _exact_entry_problems(entries, parent, version, crate, vulnerable, fixed, rule_id):
    """Why ``entries`` do not suppress ``rule_id`` at exactly one place.

    The place is ``crate`` ``vulnerable`` in ``parent`` ``version``'s lockfile, at
    every path form, through an entry with that rule id. Each problem is
    ``(kind, (package, version), text)``, the kind being ``not-suppressed`` (not
    suppressed so at a path form), ``fixed-suppressed`` (the ``fixed`` crate
    version is suppressed there) or ``suppressed-elsewhere`` (``vulnerable`` is
    suppressed at another harvested lockfile, ``_other_harvest_locations``). An
    empty list is the entries suppressing that place and no other.
    """
    problems = []
    for path in _lockfile_paths(parent, version):
        hit = _suppressing(entries, rule_id, path, crate, vulnerable)
        if hit is None or (hit.rule_id or "").lower() != rule_id.lower():
            matched = hit and hit.rule_id
            text = (
                f"{crate} {vulnerable} under {rule_id} at {path} is not suppressed "
                f"by an entry for {rule_id} (the matching entry: {matched})"
            )
            problems.append(("not-suppressed", (parent, version), text))
        hit = _suppressing(entries, rule_id, path, crate, fixed)
        if hit is not None:
            text = (
                f"{crate} {fixed}, the fixed version, under {rule_id} at {path} is "
                f"suppressed by {hit.rule_id} at {hit.path}"
            )
            problems.append(("fixed-suppressed", (parent, version), text))
    for location in _other_harvest_locations(parent, version):
        for path in _lockfile_paths(*location):
            hit = _suppressing(entries, rule_id, path, crate, vulnerable)
            if hit is not None:
                text = (
                    f"{crate} {vulnerable} under {rule_id} at {path}, not {parent} "
                    f"{version}'s lockfile, is suppressed by {hit.rule_id} at "
                    f"{hit.path}"
                )
                problems.append(("suppressed-elsewhere", location, text))
    return problems


def _tracked_files_named(names):
    """The files git tracks in this checkout whose name is one of ``names``."""
    command = ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "--"]
    command += [f"*{name}" for name in names]
    listed = subprocess.run(  # nosec B603 B607 - git over this checkout
        command,
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout.decode("utf-8")
    return sorted(
        path
        for path in listed.split(chr(0))
        if path and PurePosixPath(path).name in names
    )


def test_harvested_lockfiles_are_the_tracked_uv_locks_the_harvester_reads():
    """``HARVESTED_LOCKFILES`` names every lockfile the harvester reads here.

    The harvester reads each file of the scan set whose name is one of the syft
    options' ``sdist_harvest.lockfiles`` (``uv.lock`` when `.ash.yaml` sets none,
    ``harvest_options_of``), less those a global ignore path skips
    (``SdistLockHarvester._ignored_by``). The files git tracks stand in for the
    scan set, so a harvested lockfile the repository gains or loses fails here
    until the tuple matches.
    """
    syft = (_repo_config().get("scanners") or {}).get("syft") or {}
    harvest = (syft.get("options") or {}).get("sdist_harvest") or {}
    names = harvest.get("lockfiles", harvest_options_of(None)["lockfiles"])
    ignore_paths = ignore_paths_that_skip_scanning(
        active_ignore_paths(
            [
                IgnorePathWithReason.model_validate(entry)
                for entry in _global_settings().get("ignore_paths") or []
            ]
        ),
        ignore_suppressions=False,
    )
    read = [
        name
        for name in _tracked_files_named(names)
        if not any(ignore_path_matches(name, entry.path) for entry in ignore_paths)
    ]
    assert read == sorted(HARVESTED_LOCKFILES), (
        f"the harvester reads {read} in this repository, and HARVESTED_LOCKFILES "
        f"names {sorted(HARVESTED_LOCKFILES)}; make the tuple match"
    )


@pytest.mark.parametrize("parent", sorted(FIRST_FIXED_RELEASES))
def test_every_parent_is_pinned_by_a_harvested_lockfile(parent):
    """Every parent is pinned by a harvested lockfile, so it has per-version
    rows: a parent no lockfile pins would have none, and only this would say so."""
    assert _pinned_versions(parent), (
        f"no harvested lockfile pins {parent}, so the per-version rows hold nothing "
        "for it; drop it from FIRST_FIXED_RELEASES (its REMOVED rows stay removal "
        "pins)"
    )


@pytest.mark.parametrize("parent,old,crate,vulnerable,fixed,rule_id", REMOVAL_CASES)
def test_no_repo_suppression_matches_a_removed_advisory(
    parent, old, crate, vulnerable, fixed, rule_id
):
    """No `.ash.yaml` entry suppresses the advisory at a removed release's lockfile.

    No harvested lockfile pins that release any more. At the vulnerable crate
    version this is the removal pin (the removed entries matched exactly this
    finding); at the fixed version it shows no entry for the crate is left there
    either.
    """
    problems = _removal_problems(
        _repo_suppressions(), parent, old, crate, (vulnerable, fixed), rule_id
    )
    assert not problems, "; ".join(problems)


@pytest.mark.parametrize("parent,version,rule_id", PAST_THE_FLOOR_CASES)
def test_no_repo_suppression_matches_a_removed_advisory_past_the_floor(
    parent, version, rule_id
):
    """No `.ash.yaml` entry suppresses a removed advisory at a release past the floor.

    A harvested lockfile pins the release at or above the parent's first fixed
    release, which is taken to embed a fixed copy of the crate; this is the
    removal pin at that release's lockfile, at each crate version a ``REMOVED``
    row of the parent names.
    """
    entries = _repo_suppressions()
    problems = []
    for row_parent, _old, crate, vulnerable, fixed, spellings in REMOVED:
        if row_parent == parent and rule_id in spellings:
            problems += _removal_problems(
                entries, parent, version, crate, (vulnerable, fixed), rule_id
            )
    assert not problems, "; ".join(problems)


@pytest.mark.parametrize("parent,version", BELOW_THE_FLOOR)
def test_a_version_pinned_below_the_floor_is_measured(parent, version):
    """A release pinned below its floor has a ``REMOVED`` row naming its crate.

    The exact-entry check reads the crate version the release's sdist embeds from
    that row, so a release a lockfile starts pinning below the floor fails here
    until its embedded Cargo.lock is measured.
    """
    pinning = " and ".join(_lockfiles_pinning(parent, version))
    assert _measured_row(parent, version) is not None, (
        f"{pinning} pins {parent} {version}, below {FIRST_FIXED_RELEASES[parent]}, "
        "the first release whose sdist embeds the fixed crate: measure the crate "
        "version this release's embedded Cargo.lock pins and add its REMOVED row, "
        "which then asks .ash.yaml for exact entries, or lock a release at or "
        "above the floor"
    )


@pytest.mark.parametrize("parent,version,crate,vulnerable,fixed,rule_id", EXACT_CASES)
def test_the_repo_suppresses_a_version_pinned_below_the_floor_exactly(
    parent, version, crate, vulnerable, fixed, rule_id
):
    """`.ash.yaml` suppresses the advisory at the release's lockfile, and only there.

    A harvested lockfile pins the release below its parent's first fixed release,
    so the crate its sdist embeds is reported. The spelling is suppressed at every
    path form of that release's lockfile for the crate version it embeds, through
    an entry for the spelling, and not for the fixed crate version, at another
    parent's lockfile or at another version of the parent.
    """
    problems = _exact_entry_problems(
        _repo_suppressions(), parent, version, crate, vulnerable, fixed, rule_id
    )
    assert not problems, "; ".join(text for _kind, _where, text in problems)


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
    converted_ruff = _lockfile_paths("ruff", "0.16.10")[0]
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
        converted = _lockfile_paths(parent, old)[0]
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
    for rule_id in (
        "GHSA-2mjx-qc3c-rqvc",
        "GHSA-2mjx-qc3c-rqvc-rustls",
        "GHSA-c8m5-c952-6cm4",
        "GHSA-c8m5-c952-6cm4-rustls",
    ):
        for path in _lockfile_paths("polars-runtime-32", "1.44.2"):
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
    converted = _lockfile_paths("ruff", "0.16.10")[0]
    finding = _harvested_finding(rule_id, converted, package_name, version)
    suppressed, _ = should_suppress_finding(finding, [control])
    assert not suppressed


def _exact_entries(parent, version, crate, vulnerable, spellings, **pin):
    """One entry per spelling, as exact as the below-the-floor check asks.

    Each is pinned to ``parent`` ``version``'s lockfile directory and to
    ``crate`` ``vulnerable``, the shape the check asks `.ash.yaml` to carry;
    ``pin`` replaces the path or the crate version, for a control that pins less.
    """
    fields = {
        "path": f"**/sdist-locks/{parent}/{version}/Cargo.lock",
        "package_name": crate,
        "package_version": vulnerable,
        **pin,
    }
    return [
        AshSuppression(
            reason="control for the below-the-floor check", rule_id=rule_id, **fields
        )
        for rule_id in spellings
    ]


def _control_row():
    """The ``REMOVED`` row the below-the-floor check's controls run on."""
    row = _measured_row("rpds-py", "0.30.0")
    assert row is not None, (
        "rpds-py 0.30.0's REMOVED row is gone; point the controls at another row"
    )
    return row


def test_control_the_exact_check_passes_on_exact_entries():
    """One exact entry per spelling passes the check for every spelling."""
    parent, version, crate, vulnerable, fixed, spellings = _control_row()
    entries = _exact_entries(parent, version, crate, vulnerable, spellings)
    for rule_id in spellings:
        problems = _exact_entry_problems(
            entries, parent, version, crate, vulnerable, fixed, rule_id
        )
        assert not problems, "; ".join(text for _kind, _where, text in problems)


@pytest.mark.parametrize("missing", PYO3_SPELLINGS)
def test_control_the_exact_check_fails_on_entries_missing_one_spelling(missing):
    """Without one spelling's entry the check fails for that spelling, and only it."""
    parent, version, crate, vulnerable, fixed, spellings = _control_row()
    assert missing in spellings
    entries = [
        entry
        for entry in _exact_entries(parent, version, crate, vulnerable, spellings)
        if entry.rule_id != missing
    ]
    for rule_id in spellings:
        problems = _exact_entry_problems(
            entries, parent, version, crate, vulnerable, fixed, rule_id
        )
        expected = {"not-suppressed"} if rule_id == missing else set()
        assert {kind for kind, _where, _text in problems} == expected, rule_id


def test_control_the_exact_check_fails_on_entries_with_no_crate_version():
    """Entries that name no crate version suppress the fixed one as well."""
    parent, version, crate, vulnerable, fixed, spellings = _control_row()
    entries = _exact_entries(
        parent, version, crate, vulnerable, spellings, package_version=None
    )
    for rule_id in spellings:
        problems = _exact_entry_problems(
            entries, parent, version, crate, vulnerable, fixed, rule_id
        )
        assert {kind for kind, _where, _text in problems} == {"fixed-suppressed"}


def test_control_the_exact_check_fails_on_entries_over_every_version_of_the_parent():
    """Entries over the parent's lockfile at any version reach its other versions."""
    parent, version, crate, vulnerable, fixed, spellings = _control_row()
    entries = _exact_entries(
        parent,
        version,
        crate,
        vulnerable,
        spellings,
        path=f"**/sdist-locks/{parent}/*/Cargo.lock",
    )
    for rule_id in spellings:
        problems = _exact_entry_problems(
            entries, parent, version, crate, vulnerable, fixed, rule_id
        )
        assert {kind for kind, _where, _text in problems} == {"suppressed-elsewhere"}
        assert {where[0] for _kind, where, _text in problems} == {parent}


def test_control_the_exact_check_fails_on_entries_over_every_harvested_lockfile():
    """Entries over every harvested lockfile reach the other parents' lockfiles."""
    parent, version, crate, vulnerable, fixed, spellings = _control_row()
    entries = _exact_entries(
        parent,
        version,
        crate,
        vulnerable,
        spellings,
        path="**/sdist-locks/**/Cargo.lock",
    )
    for rule_id in spellings:
        problems = _exact_entry_problems(
            entries, parent, version, crate, vulnerable, fixed, rule_id
        )
        assert {kind for kind, _where, _text in problems} == {"suppressed-elsewhere"}
        assert {where[0] for _kind, where, _text in problems} - {parent}
