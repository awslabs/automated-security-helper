# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A package syft reports in two passes is listed once, whatever its bom-refs are.

Why this exists
---------------
syft writes a package-id suffix into each cargo ``bom-ref``
(``pkg:cargo/x@1?package-id=<hash>``), and the hash differs from one syft run to
the next. A crate that the source pass reads from an artifact and the
sdist-lock-harvester pass reads from the harvested ``Cargo.lock`` therefore has the
same ``purl`` under two different ``bom-ref`` values. The merge keys a component
by its ``bom-ref`` first, so it listed the crate twice, and the dependency tree
carried two nodes for one package.

What the cells pin
------------------
A second-report component that is harvest-stamped (it carries the
``ash:sbom-harvest`` provenance properties) and whose ``purl`` the merged SBOM
already lists is folded onto that component: it is not listed again, and every
reference to its ``bom-ref`` in the second report's ``dependencies`` is redirected
to the listed component's ``bom-ref``. A component that is not harvest-stamped
keeps the module's rule, which is that a different ``bom-ref`` is a different
package.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports
from automated_security_helper.utils.sdist_harvest import PROPERTY_SDIST_SHA256

pytestmark = pytest.mark.unit

PURL = "pkg:cargo/x@1"
SOURCE_REF = f"{PURL}?package-id=aaaa"
HARVEST_REF = f"{PURL}?package-id=bbbb"
ROOT_REF = "pkg:cargo/root@1?package-id=cccc"


def _crate(ref: str, *, harvested: bool, purl: str = PURL) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": ref,
        "name": "x",
        "version": "1",
        "purl": purl,
    }
    if harvested:
        component["properties"] = [
            {"name": PROPERTY_SDIST_SHA256, "value": "a" * 64},
        ]
    return component


def _report(
    components: list[dict[str, Any]], dependencies: list[dict[str, Any]]
) -> CycloneDXReport:
    return CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": components,
            "dependencies": dependencies,
        }
    )


def _root() -> dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": ROOT_REF,
        "name": "root",
        "version": "1",
        "purl": "pkg:cargo/root@1",
    }


def _merged(held: CycloneDXReport, incoming: CycloneDXReport) -> CycloneDXReport:
    result = merge_cyclonedx_reports(held, incoming)
    assert result is not None
    return result


def _depends_on(report: CycloneDXReport) -> dict[str, list[str]]:
    return {
        d.ref.root.root: [r.root.root for r in d.dependsOn or []]
        for d in report.dependencies or []
    }


def test_a_harvested_package_with_another_bom_ref_is_listed_once() -> None:
    held = _report(
        [_crate(SOURCE_REF, harvested=False)],
        [{"ref": SOURCE_REF, "dependsOn": []}],
    )
    incoming = _report(
        [_crate(HARVEST_REF, harvested=True)],
        [{"ref": HARVEST_REF, "dependsOn": []}],
    )

    result = _merged(held, incoming)

    assert [c.purl for c in result.components or []] == [PURL]
    assert [c.bom_ref.root for c in result.components or [] if c.bom_ref] == [
        SOURCE_REF
    ]


def test_dependencies_on_the_folded_ref_follow_the_listed_component() -> None:
    held = _report(
        [_root(), _crate(SOURCE_REF, harvested=False)],
        [{"ref": ROOT_REF, "dependsOn": []}, {"ref": SOURCE_REF, "dependsOn": []}],
    )
    incoming = _report(
        [_crate(HARVEST_REF, harvested=True)],
        [{"ref": ROOT_REF, "dependsOn": [HARVEST_REF]}],
    )

    result = _merged(held, incoming)

    depends_on = _depends_on(result)
    assert depends_on[ROOT_REF] == [SOURCE_REF]
    assert HARVEST_REF not in depends_on
    assert all(HARVEST_REF not in refs for refs in depends_on.values())


def test_the_folded_components_own_dependencies_join_the_listed_ones() -> None:
    held = _report(
        [_crate(SOURCE_REF, harvested=False)],
        [{"ref": SOURCE_REF, "dependsOn": [ROOT_REF]}],
    )
    incoming = _report(
        [_crate(HARVEST_REF, harvested=True)],
        [{"ref": HARVEST_REF, "dependsOn": ["pkg:cargo/y@2?package-id=dddd"]}],
    )

    result = _merged(held, incoming)

    assert _depends_on(result)[SOURCE_REF] == [
        ROOT_REF,
        "pkg:cargo/y@2?package-id=dddd",
    ]
    assert HARVEST_REF not in _depends_on(result)


def test_a_package_that_is_not_harvest_stamped_keeps_its_own_bom_ref() -> None:
    held = _report(
        [_crate(SOURCE_REF, harvested=False)],
        [{"ref": SOURCE_REF, "dependsOn": []}],
    )
    incoming = _report(
        [_crate(HARVEST_REF, harvested=False)],
        [{"ref": HARVEST_REF, "dependsOn": []}],
    )

    result = _merged(held, incoming)

    assert sorted(c.bom_ref.root for c in result.components or [] if c.bom_ref) == [
        SOURCE_REF,
        HARVEST_REF,
    ]


def test_a_harvested_package_the_merge_does_not_list_is_added() -> None:
    held = _report(
        [_crate(SOURCE_REF, harvested=False)],
        [{"ref": SOURCE_REF, "dependsOn": []}],
    )
    other = "pkg:cargo/z@3"
    incoming = _report(
        [_crate(f"{other}?package-id=eeee", harvested=True, purl=other)],
        [{"ref": f"{other}?package-id=eeee", "dependsOn": []}],
    )

    result = _merged(held, incoming)

    assert sorted(c.purl for c in result.components or [] if c.purl) == [PURL, other]


def test_two_harvested_copies_of_one_package_are_listed_once() -> None:
    held = _report([_root()], [{"ref": ROOT_REF, "dependsOn": []}])
    incoming = _report(
        [
            _crate(HARVEST_REF, harvested=True),
            _crate(f"{PURL}?package-id=ffff", harvested=True),
        ],
        [{"ref": ROOT_REF, "dependsOn": [HARVEST_REF, f"{PURL}?package-id=ffff"]}],
    )

    result = _merged(held, incoming)

    assert [c.purl for c in result.components or [] if c.purl == PURL] == [PURL]
