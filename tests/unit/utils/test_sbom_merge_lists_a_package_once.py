# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A merged SBOM lists a package once, wherever its first copy sits.

Why this exists
---------------
The merge compared a component of the second report with the top-level components
of the first one, and it never recorded the components it had just kept. A second
report that lists a package already nested inside a first-report component, or one
that repeats a package within itself, therefore gave the merged SBOM the same
``bom-ref`` twice. CycloneDX requires a ``bom-ref`` to be unique within one BOM,
and the module promises that a repeated component is "listed once". syft writes a
flat list, so a syft report never shows the gap, but the merge also takes every
other scanner's CycloneDX report.

What the cells pin
------------------
The keys of the whole first report count, the components nested in its components
included, and each component the merge keeps counts for the ones after it, the
components nested inside it included. So a top-level component of the second report
that repeats a nested one is dropped, one that shares only its ``bom-ref`` is kept
under a new ref, and a package the second report repeats within itself is listed
once.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Component,
    CycloneDXReport,
)
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports

REQUESTS = "pkg:pypi/requests@2.19.1"
URLLIB3 = "pkg:pypi/urllib3@2.0.0"
FLASK = "pkg:pypi/flask@3.0.0"
JINJA2 = "pkg:pypi/jinja2@3.1.0"


def _component(
    ref: str | None, purl: str | None, *nested: dict[str, Any]
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": purl.split("/")[-1].split("@")[0] if purl else "unnamed",
        "version": "1.0",
    }
    if ref is not None:
        component["bom-ref"] = ref
    if purl is not None:
        component["purl"] = purl
    if nested:
        component["components"] = list(nested)
    return component


def _sbom(*components: dict[str, Any]) -> CycloneDXReport:
    return CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": list(components),
        }
    )


def _walk(components: list[Component] | None) -> Iterator[Component]:
    for component in components or []:
        yield component
        yield from _walk(component.components)


def _refs(report: CycloneDXReport) -> list[str]:
    return [
        component.bom_ref.root
        for component in _walk(report.components)
        if component.bom_ref is not None
    ]


def _purls(report: CycloneDXReport) -> list[str | None]:
    return sorted((c.purl for c in _walk(report.components)), key=str)


def _merged(held: CycloneDXReport, incoming: CycloneDXReport) -> CycloneDXReport:
    result = merge_cyclonedx_reports(held, incoming)
    assert result is not None
    return result


def test_a_package_nested_in_the_first_report_is_not_listed_again():
    held = _sbom(_component("app", None, _component("n1", URLLIB3)))
    incoming = _sbom(_component("n1", URLLIB3))

    result = _merged(held, incoming)

    assert len(result.components) == 1
    assert _refs(result).count("n1") == 1
    assert _purls(result) == [None, URLLIB3]


def test_a_package_nested_in_the_first_report_is_not_listed_again_by_purl():
    held = _sbom(_component("app", None, _component(None, URLLIB3)))
    incoming = _sbom(_component(None, URLLIB3))

    result = _merged(held, incoming)

    assert len(result.components) == 1
    assert _purls(result) == [None, URLLIB3]


def test_a_different_package_with_the_ref_of_a_nested_one_gets_a_ref_of_its_own():
    held = _sbom(_component("app", None, _component("n1", URLLIB3)))
    incoming = _sbom(_component("n1", FLASK))

    result = _merged(held, incoming)

    assert len(result.components) == 2
    assert len(_refs(result)) == len(set(_refs(result))) == 3
    assert _purls(result) == [None, FLASK, URLLIB3]


def test_a_package_the_second_report_repeats_is_listed_once():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(_component("r", FLASK), _component("r", FLASK))

    result = _merged(held, incoming)

    assert _purls(result) == [FLASK, REQUESTS]
    assert _refs(result).count("r") == 1


def test_a_package_the_second_report_repeats_by_purl_is_listed_once():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(_component(None, FLASK), _component(None, FLASK))

    result = _merged(held, incoming)

    assert _purls(result) == [FLASK, REQUESTS]


def test_two_packages_the_second_report_gives_one_ref_do_not_share_it():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(_component("r", FLASK), _component("r", JINJA2))

    result = _merged(held, incoming)

    assert _purls(result) == [FLASK, JINJA2, REQUESTS]
    assert len(_refs(result)) == len(set(_refs(result))) == 3


def test_a_repeated_package_that_also_shares_a_held_ref_is_added_once():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(_component("1", FLASK), _component("1", FLASK))

    result = _merged(held, incoming)

    assert _purls(result) == [FLASK, REQUESTS]
    assert len(_refs(result)) == len(set(_refs(result))) == 2


def test_a_package_nested_in_a_kept_component_counts_for_the_ones_after_it():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(
        _component("app", None, _component("n9", JINJA2)),
        _component("n9", JINJA2),
    )

    result = _merged(held, incoming)

    assert _refs(result).count("n9") == 1
    assert _purls(result) == [None, JINJA2, REQUESTS]


def test_components_with_neither_key_are_still_never_matched():
    held = _sbom(_component(None, None))
    incoming = _sbom(_component(None, None), _component(None, None))

    assert len(_merged(held, incoming).components) == 3
