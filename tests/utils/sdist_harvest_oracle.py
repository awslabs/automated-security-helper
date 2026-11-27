# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The assertions the sdist-harvest oracle makes about a produced SBOM.

One place holds them so the two legs that run them cannot drift apart:

- the online leg (``tests/integration/test_sdist_harvest_self_scan.py``) runs
  the real harvester, then the pinned syft over the harvest, and hands the
  report it produced here;
- the fixture leg (``tests/integration/test_sdist_harvest_sbom_fixture.py``)
  hands the same function a report captured from that run, for the CI jobs
  that do not install syft.

What is held to what:

- the crate the repository's suppressions are written for (``rustls`` 0.23.43,
  statically linked into the polars runtime wheel) is in the SBOM, and it
  carries the polars parent purl and the sdist's sha256 the harvest stamped;
- the four ``global_settings.suppressions`` entries of ``.ash.yaml`` that
  name polars' harvested lockfile each match a finding reported at the path
  syft gives the lockfile, so none of them reads as unused;
- no entry over the harvest layout suppresses a finding there for another
  crate or another rustls version, or the same advisory in a file outside the
  layout (the controls). The layout holds entries for other harvested
  packages too (ruff, pydantic-core, rpds-py, rtoml, uv), so the controls read
  every one of them: a broad entry with no version pin would cover polars'
  lockfile as well and silently undo the four entries' version pin.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

import yaml

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    PROPERTY_PARENT_PURL,
    PROPERTY_SDIST_SHA256,
)
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

LINKED_CRATE = "rustls"
LINKED_CRATE_VERSION = "0.23.43"
LINKED_CRATE_PURL = f"pkg:cargo/{LINKED_CRATE}@{LINKED_CRATE_VERSION}"

#: The suppressions of polars' harvested lockfile: two advisories, each in the
#: trivy and the grype spelling.
EXPECTED_SUPPRESSION_RULE_IDS = (
    "GHSA-2mjx-qc3c-rqvc",
    "GHSA-2mjx-qc3c-rqvc-rustls",
    "GHSA-c8m5-c952-6cm4",
    "GHSA-c8m5-c952-6cm4-rustls",
)

#: The part of a suppression's path that names polars' harvested lockfile.
LINKED_LOCKFILE_DIR = f"{HARVEST_DIR_NAME}/polars-runtime-32/"


def _components(report: Any) -> List[Mapping[str, Any]]:
    """The report's components as plain dicts (a model or a parsed document)."""
    if isinstance(report, Mapping):
        return list(report.get("components") or [])
    dumped = report.model_dump(by_alias=True, exclude_none=True, mode="json")
    return list(dumped.get("components") or [])


def _properties(component: Mapping[str, Any]) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for prop in component.get("properties") or []:
        found.setdefault(prop["name"], []).append(prop["value"])
    return found


def linked_crate_components(report: Any) -> List[Mapping[str, Any]]:
    return [
        component
        for component in _components(report)
        if component.get("purl") == LINKED_CRATE_PURL
    ]


def assert_linked_crate_is_listed_with_its_parent(
    report: Any, parent_purl: str
) -> List[str]:
    """``rustls`` is in the SBOM once, stamped with the polars parent purl.

    Returns the lockfile locations syft gave it (``syft:location:N:path``).
    """
    found = linked_crate_components(report)
    assert found, f"{LINKED_CRATE_PURL} is not in the SBOM"
    assert len(found) == 1, (
        f"{LINKED_CRATE_PURL} is listed {len(found)} times: "
        f"{[c.get('bom-ref') for c in found]}"
    )
    properties = _properties(found[0])
    assert properties.get(PROPERTY_PARENT_PURL) == [parent_purl]
    (sdist_sha256,) = properties[PROPERTY_SDIST_SHA256]
    assert len(sdist_sha256) == 64
    locations = [
        value
        for name, values in properties.items()
        if name.startswith("syft:location:") and name.endswith(":path")
        for value in values
    ]
    assert locations, "syft recorded no lockfile location for the crate"
    assert all(f"/{HARVEST_DIR_NAME}/polars-runtime-32/" in v for v in locations)
    return locations


def harvest_layout_suppressions() -> List[AshSuppression]:
    """Every suppression of the repository whose path names the harvest layout."""
    document = yaml.safe_load(
        REPO_ROOT.joinpath(".ash.yaml").read_text(encoding="utf-8")
    )
    return [
        AshSuppression.model_validate(raw)
        for raw in document["global_settings"]["suppressions"]
        if HARVEST_DIR_NAME in str(raw.get("path", ""))
    ]


def harvest_suppressions() -> List[AshSuppression]:
    """The repository's suppressions that name polars' harvested lockfile."""
    entries = [
        entry
        for entry in harvest_layout_suppressions()
        if LINKED_LOCKFILE_DIR in (entry.path or "")
    ]
    assert sorted(e.rule_id or "" for e in entries) == sorted(
        EXPECTED_SUPPRESSION_RULE_IDS
    ), "the harvested lockfile's suppressions are not the four the oracle holds"
    return entries


def reported_path_forms(location: str) -> List[str]:
    """The spellings a scanner can report for a syft lockfile location.

    syft's location is rooted at the scanned target (``/sdist-locks/...``); a
    scanner run from the converted tree's parent reports the path with the
    converted directory in front, and one given the target reports it
    relative, so each form is matched.
    """
    relative = location.lstrip("/")
    return [
        location,
        relative,
        f"converted/sdist-lock-harvester/{relative}",
        f".ash/ash_output/converted/sdist-lock-harvester/{relative}",
    ]


def _finding(rule_id: str, path: str, name: str, version: str) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"{rule_id}:{path}",
        title=rule_id,
        description=rule_id,
        severity="MEDIUM",
        scanner="grype",
        scanner_type="SCA",
        rule_id=rule_id,
        file_path=path,
        package_name=name,
        package_version=version,
    )


def assert_suppressions_match_reported_paths(locations: Sequence[str]) -> None:
    """Each harvest suppression matches a finding at every reported path form.

    "None unused" is checked by identity: the entries that matched a finding
    are collected and compared with the full list. The controls are findings
    no entry over the harvest layout may cover (another crate, another rustls
    version, a file outside the layout), for each of the four rule ids.
    """
    entries = harvest_suppressions()
    layout_entries = harvest_layout_suppressions()
    used = set()
    for location in locations:
        for path in reported_path_forms(location):
            for entry in entries:
                finding = _finding(
                    entry.rule_id or "", path, LINKED_CRATE, LINKED_CRATE_VERSION
                )
                suppressed, matching = should_suppress_finding(finding, entries)
                assert suppressed and matching is not None, (
                    f"{entry.rule_id} at {path!r} is not suppressed"
                )
                assert matching.rule_id == entry.rule_id
                used.add(entry.id)
    unused = [e.rule_id for e in entries if e.id not in used]
    assert not unused, f"suppressions that match no reported path: {unused}"

    # Every path form, not only syft's own: an entry spelled for the converted
    # tree's path matches the scanners' forms and not syft's.
    controls = [
        _finding(rule_id, "uv.lock", LINKED_CRATE, LINKED_CRATE_VERSION)
        for rule_id in EXPECTED_SUPPRESSION_RULE_IDS
    ]
    for rule_id in EXPECTED_SUPPRESSION_RULE_IDS:
        for path in reported_path_forms(locations[0]):
            controls.append(_finding(rule_id, path, "tokio", LINKED_CRATE_VERSION))
            controls.append(_finding(rule_id, path, LINKED_CRATE, "0.23.99"))
    for control in controls:
        suppressed, matching = should_suppress_finding(control, layout_entries)
        assert not suppressed, (
            f"control finding was suppressed by {matching}: {control.model_dump()}"
        )
