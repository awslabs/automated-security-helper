# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Provenance stamping of harvested SBOM components (A7 row 5).

Every component whose syft location falls under a
``sdist-locks/<package>/<version>/`` directory carries three CycloneDX
properties read from that directory's harvest manifest, so each harvested
component is auditable back to the sdist that produced it; components located
anywhere else are untouched. The merge dedups a component reported by both the
source pass and the harvest by purl, whatever their bom-refs are, so a harvested
crate appears exactly once.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports
from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    PROPERTY_PARENT_PURL,
    PROPERTY_SDIST_SHA256,
    PROPERTY_SOURCE_URL,
    stamp_harvested_components,
)

pytestmark = pytest.mark.unit

SDIST_SHA256 = "a" * 64
SDIST_URL = "https://files.test.invalid/fixturepkg-0.1.0.tar.gz"


def _write_manifest(target: Path) -> None:
    directory = target.joinpath(
        "sdist-lock-harvester", HARVEST_DIR_NAME, "fixturepkg", "0.1.0"
    )
    directory.mkdir(parents=True)
    directory.joinpath("Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    directory.joinpath(HARVEST_MANIFEST_NAME).write_text(
        json.dumps(
            {
                "package": "fixturepkg",
                "version": "0.1.0",
                "parent_purl": "pkg:pypi/fixturepkg@0.1.0",
                "sdist_url": SDIST_URL,
                "sdist_sha256": SDIST_SHA256,
                "lockfiles": ["Cargo.lock"],
            }
        ),
        encoding="utf-8",
    )


#: syft's cargo bom-ref: the purl and a package-id hash that differs between runs.
CRATE_PURL = "pkg:cargo/fixturecrate@0.1.0"


def _report(
    location: str, crate_ref: str = f"{CRATE_PURL}?package-id=bbbb"
) -> CycloneDXReport:
    return CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": crate_ref,
                    "name": "fixturecrate",
                    "version": "0.1.0",
                    "purl": "pkg:cargo/fixturecrate@0.1.0",
                    "properties": [
                        {"name": "syft:package:language", "value": "rust"},
                        {"name": "syft:location:0:path", "value": location},
                    ],
                },
                {
                    "type": "library",
                    "bom-ref": "pkg:pypi/requests@2.32.0",
                    "name": "requests",
                    "version": "2.32.0",
                    "purl": "pkg:pypi/requests@2.32.0",
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/requirements.txt"}
                    ],
                },
            ],
        }
    )


def _properties_of(report: CycloneDXReport, name: str) -> dict[str, str]:
    (component,) = [c for c in report.components or [] if c.name == name]
    return {p.name: p.value for p in component.properties or []}


def test_components_under_a_harvest_dir_gain_the_three_properties(
    tmp_path: Path,
) -> None:
    _write_manifest(tmp_path)
    report = _report(
        f"/work/sdist-lock-harvester/{HARVEST_DIR_NAME}/fixturepkg/0.1.0/Cargo.lock"
    )

    stamped = stamp_harvested_components(report, tmp_path)

    assert stamped == 1
    properties = _properties_of(report, "fixturecrate")
    assert properties[PROPERTY_SDIST_SHA256] == SDIST_SHA256
    assert properties[PROPERTY_PARENT_PURL] == "pkg:pypi/fixturepkg@0.1.0"
    assert properties[PROPERTY_SOURCE_URL] == SDIST_URL


def test_components_outside_a_harvest_dir_are_untouched(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    report = _report(
        f"/work/sdist-lock-harvester/{HARVEST_DIR_NAME}/fixturepkg/0.1.0/Cargo.lock"
    )

    stamp_harvested_components(report, tmp_path)

    properties = _properties_of(report, "requests")
    assert PROPERTY_SDIST_SHA256 not in properties
    assert PROPERTY_PARENT_PURL not in properties


def test_stamping_is_idempotent(tmp_path: Path) -> None:
    _write_manifest(tmp_path)
    report = _report(
        f"/work/sdist-lock-harvester/{HARVEST_DIR_NAME}/fixturepkg/0.1.0/Cargo.lock"
    )

    assert stamp_harvested_components(report, tmp_path) == 1
    assert stamp_harvested_components(report, tmp_path) == 0
    properties = [
        p.name
        for c in report.components or []
        if c.name == "fixturecrate"
        for p in c.properties or []
    ]
    assert properties.count(PROPERTY_SDIST_SHA256) == 1


def test_a_location_under_no_manifest_is_not_stamped(tmp_path: Path) -> None:
    """A path that looks harvested but has no manifest gets no invented provenance."""
    _write_manifest(tmp_path)
    report = _report(f"/work/other/{HARVEST_DIR_NAME}/otherpkg/9.9.9/Cargo.lock")

    assert stamp_harvested_components(report, tmp_path) == 0


def test_merged_sbom_carries_a_harvested_component_exactly_once(
    tmp_path: Path,
) -> None:
    """The source pass and the harvest pass name one crate under bom-refs that
    differ in syft's package-id suffix, as syft writes them; the merge folds the
    harvested one onto the one already listed."""
    _write_manifest(tmp_path)
    harvested = _report(
        f"/work/sdist-lock-harvester/{HARVEST_DIR_NAME}/fixturepkg/0.1.0/Cargo.lock",
        f"{CRATE_PURL}?package-id=bbbb",
    )
    stamp_harvested_components(harvested, tmp_path)
    source_pass = _report("/some/source/Cargo.lock", f"{CRATE_PURL}?package-id=aaaa")

    merged = merge_cyclonedx_reports(source_pass, harvested)

    crates = [c for c in merged.components or [] if c.purl == CRATE_PURL]
    assert len(crates) == 1
    assert crates[0].bom_ref.root == f"{CRATE_PURL}?package-id=aaaa"


def test_suppression_glob_matches_the_harvest_layout() -> None:
    """The ``.ash.yaml`` rustls entries glob over the harvest layout; this
    pins that the glob and the materialized path shape agree, so a polars bump
    (a new version segment) keeps matching (A6, carried limit 4)."""
    from automated_security_helper.utils.suppression_matcher import ignore_path_matches

    layout = (
        "converted/sdist-lock-harvester/"
        f"{HARVEST_DIR_NAME}/polars-runtime-32/1.44.2/Cargo.lock"
    )
    glob = f"**/{HARVEST_DIR_NAME}/polars-runtime-32/*/Cargo.lock"
    assert ignore_path_matches(layout, glob)
    assert not ignore_path_matches(f"{HARVEST_DIR_NAME}/otherpkg/1.0/Cargo.lock", glob)
