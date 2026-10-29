# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A merged SBOM checks the components nested inside the second report's components.

Why this exists
---------------
The merge compared only the top-level components of the second report with the
first one's. A component nested inside a second-report component was copied as it
came, in two ways that break the promise that a package is listed once and that a
``bom-ref`` is unique within one BOM:

* A new top-level component that carried a nested child with a ``bom-ref`` the
  first report already used put the same ``bom-ref`` in the merged SBOM twice, and
  a nested child that repeated a package of the first report was listed twice.
* A top-level component that repeated one of the first report was dropped with
  everything nested in it. A nested child the first report did not hold vanished
  from the SBOM while its ``dependencies`` entries stayed.

What the cells pin
------------------
A nested component gets the verdict a top-level one gets: a repeat is dropped, a
package that only shares a ``bom-ref`` is kept under a new ref that the
second report's ``dependencies`` follow, and a new package is kept. The children of
a component that is dropped as a repeat are checked in its place, so the ones the
first report does not hold are added to the list the dropped component was in. The
merge changes neither input and a merged result shares no object with them.
"""

from __future__ import annotations

import uuid
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
DJANGO = "pkg:pypi/django@5.0.0"

HELD_SERIAL = f"urn:uuid:{uuid.UUID(int=1)}"


def _component(
    ref: str | None,
    purl: str | None,
    *nested: dict[str, Any],
    name: str | None = None,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": name or (purl.split("/")[-1].split("@")[0] if purl else "unnamed"),
        "version": "1.0",
    }
    if ref is not None:
        component["bom-ref"] = ref
    if purl is not None:
        component["purl"] = purl
    if nested:
        component["components"] = list(nested)
    return component


def _sbom(
    *components: dict[str, Any],
    dependencies: list[dict[str, Any]] | None = None,
    serial: str | None = None,
) -> CycloneDXReport:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": list(components),
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    if serial is not None:
        document["serialNumber"] = serial
    return CycloneDXReport.model_validate(document)


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


def _refs_by_purl(report: CycloneDXReport) -> dict[str | None, list[str]]:
    by_purl: dict[str | None, list[str]] = {}
    for component in _walk(report.components):
        if component.bom_ref is not None:
            by_purl.setdefault(component.purl, []).append(component.bom_ref.root)
    return by_purl


def _named(report: CycloneDXReport, ref: str) -> Component:
    return next(c for c in _walk(report.components) if c.bom_ref.root == ref)


def _dump(report: CycloneDXReport) -> dict[str, Any]:
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


def _merged(held: CycloneDXReport, incoming: CycloneDXReport) -> CycloneDXReport:
    result = merge_cyclonedx_reports(held, incoming)
    assert result is not None
    return result


def test_a_nested_package_that_shares_a_held_ref_is_given_a_ref_of_its_own():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(_component("app", None, _component("1", FLASK), name="app"))

    result = _merged(held, incoming)

    refs = _refs(result)
    assert len(refs) == len(set(refs)) == 3
    by_purl = _refs_by_purl(result)
    assert by_purl[REQUESTS] == ["1"]
    assert by_purl[FLASK] != ["1"]


def test_a_nested_package_with_no_purl_that_shares_a_held_ref_gets_its_own_ref():
    held = _sbom(_component("1", None, name="libfoo"))
    incoming = _sbom(
        _component("app", None, _component("1", None, name="libbar"), name="app")
    )

    result = _merged(held, incoming)

    refs = _refs(result)
    assert len(refs) == len(set(refs)) == 3
    assert _named(result, "1").name == "libfoo"


def test_the_dependency_entries_follow_a_nested_package_that_was_re_referenced():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(
        _component("app", None, _component("1", FLASK), name="app"),
        dependencies=[{"ref": "app", "dependsOn": ["1"]}],
    )

    result = _merged(held, incoming)

    entry = next(d for d in result.dependencies if d.ref.root.root == "app")
    flask_ref = _refs_by_purl(result)[FLASK][0]
    assert flask_ref != "1"
    assert [ref.root.root for ref in entry.dependsOn] == [flask_ref]


def test_a_nested_package_the_first_report_holds_is_not_listed_again():
    held = _sbom(_component("n1", URLLIB3))
    incoming = _sbom(_component("app", None, _component("n1", URLLIB3), name="app"))

    result = _merged(held, incoming)

    assert _refs(result).count("n1") == 1
    assert not _named(result, "app").components


def test_a_package_repeated_inside_a_new_component_is_listed_once():
    held = _sbom(_component("1", REQUESTS))
    incoming = _sbom(
        _component(
            "app", None, _component("r", FLASK), _component("r", FLASK), name="app"
        )
    )

    result = _merged(held, incoming)

    assert _refs(result).count("r") == 1


def test_a_nested_package_of_a_repeated_component_is_added():
    held = _sbom(_component("app", None, name="app"))
    incoming = _sbom(
        _component("app", None, _component("c1", FLASK), name="app"),
        dependencies=[{"ref": "app", "dependsOn": ["c1"]}, {"ref": "c1"}],
    )

    result = _merged(held, incoming)

    by_purl = _refs_by_purl(result)
    assert FLASK in by_purl
    assert by_purl[FLASK] == ["c1"]
    assert len(result.components) == 2
    assert {d.ref.root.root for d in result.dependencies} <= set(_refs(result))


def test_a_repeated_component_keeps_its_own_children_and_adds_the_new_ones():
    held = _sbom(_component("app", None, _component("n1", URLLIB3), name="app"))
    incoming = _sbom(
        _component(
            "app",
            None,
            _component("n1", URLLIB3),
            _component("n2", FLASK),
            name="app",
        )
    )

    result = _merged(held, incoming)

    refs = _refs(result)
    assert sorted(refs) == ["app", "n1", "n2"]
    assert [c.bom_ref.root for c in _named(result, "app").components] == ["n1"]


def test_a_nested_package_of_a_repeated_component_that_shares_a_held_ref_is_kept():
    held = _sbom(_component("app", None, name="app"), _component("1", REQUESTS))
    incoming = _sbom(
        _component("app", None, _component("1", FLASK), name="app"),
        dependencies=[{"ref": "app", "dependsOn": ["1"]}],
    )

    result = _merged(held, incoming)

    refs = _refs(result)
    assert len(refs) == len(set(refs)) == 3
    by_purl = _refs_by_purl(result)
    assert by_purl[REQUESTS] == ["1"]
    entry = next(d for d in result.dependencies if d.ref.root.root == "app")
    assert [ref.root.root for ref in entry.dependsOn] == by_purl[FLASK]


def test_the_children_of_a_repeat_nested_in_a_new_component_stay_in_that_component():
    held = _sbom(_component("n1", URLLIB3))
    incoming = _sbom(
        _component(
            "app",
            None,
            _component("n1", URLLIB3, _component("n2", FLASK)),
            name="app",
        )
    )

    result = _merged(held, incoming)

    assert sorted(_refs(result)) == ["app", "n1", "n2"]
    assert [c.bom_ref.root for c in _named(result, "app").components] == ["n2"]


def test_a_nested_package_that_is_added_gives_the_merge_a_new_serial():
    held = _sbom(_component("app", None, name="app"), serial=HELD_SERIAL)
    incoming = _sbom(_component("app", None, _component("c1", FLASK), name="app"))

    assert _merged(held, incoming).serialNumber != HELD_SERIAL


def test_nested_packages_the_first_report_holds_leave_the_serial_alone():
    held = _sbom(
        _component("app", None, _component("n1", URLLIB3), name="app"),
        serial=HELD_SERIAL,
    )
    incoming = _sbom(_component("app", None, _component("n1", URLLIB3), name="app"))

    assert _merged(held, incoming).serialNumber == HELD_SERIAL


def test_the_merge_changes_neither_input_and_shares_nothing_with_them():
    held = _sbom(
        _component("app", None, name="app"),
        _component("1", REQUESTS),
        _component("2", URLLIB3),
    )
    incoming = _sbom(
        _component(
            "app",
            None,
            _component("c1", FLASK),
            _component("1", DJANGO),
            name="app",
        ),
        _component("x", None, _component("2", FLASK), name="x"),
        dependencies=[{"ref": "x", "dependsOn": ["2"]}],
    )
    before = (_dump(held), _dump(incoming))

    result = _merged(held, incoming)
    for component in _walk(result.components):
        component.name = "changed"
    for dependency in result.dependencies:
        dependency.ref.root.root = "changed"

    assert (_dump(held), _dump(incoming)) == before
