# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The merged SBOM holds no object that either report it was built from holds.

Why this exists
---------------
``merge_cyclonedx_reports`` is handed the scanner's own report, which the scan goes
on reading, and its result is stored in the scan's results, which later steps read
and change. When the result is an argument, or holds an object an argument holds,
a change to one shows in the other.

It was both. With one side empty or missing it returned the other side itself. With
both sides holding something it copied the held report one level deep, so the
result shared the header, the lists that are not combined, the held components,
the incoming components it kept and the dependency entries with the reports they
came from.

What the tests pin
------------------
Each place the result takes something from an argument has its own tests, so a
copy that is missing shows in the tests for that place and no other:

* the result when only one side holds anything: the held report passed through
  (incoming missing), the incoming report passed through (held missing or empty),
  and the held report passed through (incoming empty);
* the held report's parts in a merged result: its header, a list that is not
  combined, its components and its dependency entries;
* the incoming report's components that a merged result keeps;
* the incoming report's dependency entries, both a ref only it has and its refs
  added to an entry the held report has too.

For each, the inputs are compared before and after the merge, then the result is
changed and the inputs are read again. The changes reach into nested lists and
references, so a copy that stops one level down fails as well. The existing tests
of what the merge contains are in ``tests/unit/core/phases/
test_a_second_sbom_keeps_the_first_ones_components.py``.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
    Dependency,
)
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports

pytestmark = pytest.mark.unit

HELD_SERIAL = "urn:uuid:11111111-1111-4111-8111-111111111111"
INCOMING_SERIAL = "urn:uuid:22222222-2222-4222-8222-222222222222"

#: Different on purpose: ``version`` defaults to 1, so two reports that set none
#: agree and a merge that took the wrong one would pass.
HELD_VERSION = 3
INCOMING_VERSION = 5


def _purl(name: str) -> str:
    return f"pkg:pypi/{name}@1.0"


def _component(name: str) -> dict[str, Any]:
    return {
        "type": "library",
        "name": name,
        "version": "1.0",
        "purl": _purl(name),
        "bom-ref": _purl(name),
        "properties": [
            {"name": "syft:location:0:path", "value": f"/{name}/requirements.txt"}
        ],
    }


def _entry(name: str, *depends_on: str) -> dict[str, Any]:
    return {"ref": _purl(name), "dependsOn": [_purl(other) for other in depends_on]}


def _sbom(
    *,
    components: list[dict[str, Any]],
    subject: str,
    serial: str,
    version: int,
    dependencies: list[dict[str, Any]],
    list_name: str,
) -> CycloneDXReport:
    return CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": serial,
            "version": version,
            "metadata": {
                "component": {
                    "type": "file",
                    "name": subject,
                    "properties": [{"name": "subject-property", "value": "1"}],
                }
            },
            "components": components,
            "dependencies": dependencies,
            "properties": [{"name": list_name, "value": "1"}],
        }
    )


def _held() -> CycloneDXReport:
    """requests -> flask and flask -> urllib3; requests is also in the incoming one."""
    return _sbom(
        components=[_component("requests"), _component("flask")],
        subject="source tree",
        serial=HELD_SERIAL,
        version=HELD_VERSION,
        dependencies=[_entry("requests", "flask"), _entry("flask", "urllib3")],
        list_name="held-list",
    )


def _incoming() -> CycloneDXReport:
    """requests -> django and django -> sqlparse; django is not in the held one."""
    return _sbom(
        components=[_component("requests"), _component("django")],
        subject="converted tree",
        serial=INCOMING_SERIAL,
        version=INCOMING_VERSION,
        dependencies=[_entry("requests", "django"), _entry("django", "sqlparse")],
        list_name="incoming-list",
    )


def _nothing() -> None:
    return None


def _dump(report: CycloneDXReport | None) -> dict[str, Any] | None:
    if report is None:
        return None
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


def _both(
    held: CycloneDXReport | None, incoming: CycloneDXReport | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    return _dump(held), _dump(incoming)


def _named(report: CycloneDXReport, name: str):
    return next(c for c in report.components if c.name == name)


def _entry_for(report: CycloneDXReport, name: str) -> Dependency:
    return next(d for d in report.dependencies if d.ref.root.root == _purl(name))


def _change_component(component) -> None:
    component.name = "changed"
    component.properties[0].value = "changed"


def _change_dependency(dependency: Dependency) -> None:
    dependency.ref.root.root = "changed"
    for ref in dependency.dependsOn or []:
        ref.root.root = "changed"


def _change_everything(report: CycloneDXReport) -> None:
    report.metadata.component.name = "changed"
    report.metadata.component.properties[0].value = "changed"
    report.properties[0].value = "changed"
    for component in report.components:
        _change_component(component)
    for dependency in report.dependencies:
        _change_dependency(dependency)


def _change(result: CycloneDXReport, change: Callable[[CycloneDXReport], None]) -> None:
    """Apply *change* to *result*, and check that it did change the result."""
    before = _dump(result)
    change(result)
    assert _dump(result) != before


#: Where the merge hands one side back: (held, incoming, the side the result copies).
PASS_THROUGH: dict[str, tuple[Callable, Callable, str]] = {
    "held-only-incoming-missing": (_held, _nothing, "held"),
    "incoming-only-held-missing": (_nothing, _incoming, "incoming"),
    "incoming-only-held-empty": (CycloneDXReport, _incoming, "incoming"),
    "held-only-incoming-empty": (_held, CycloneDXReport, "held"),
}

#: Every shape the merge takes, for the tests that hold for all of them.
SHAPES: dict[str, tuple[Callable, Callable]] = {
    **{name: (held, incoming) for name, (held, incoming, _) in PASS_THROUGH.items()},
    "empty-held-incoming-missing": (CycloneDXReport, _nothing),
    "both-hold-components": (_held, _incoming),
}


@pytest.mark.parametrize("shape", SHAPES)
def test_merging_changes_neither_input(shape):
    held_factory, incoming_factory = SHAPES[shape]
    held, incoming = held_factory(), incoming_factory()
    before = _both(held, incoming)

    merge_cyclonedx_reports(held, incoming)

    assert _both(held, incoming) == before


@pytest.mark.parametrize("shape", SHAPES)
def test_the_result_is_not_one_of_the_inputs(shape):
    held_factory, incoming_factory = SHAPES[shape]
    held, incoming = held_factory(), incoming_factory()

    result = merge_cyclonedx_reports(held, incoming)

    assert result is not held
    assert result is not incoming


def test_two_missing_reports_give_nothing():
    assert merge_cyclonedx_reports(None, None) is None


@pytest.mark.parametrize("shape", PASS_THROUGH)
def test_changing_a_passed_through_result_leaves_the_input_alone(shape):
    held_factory, incoming_factory, source = PASS_THROUGH[shape]
    held, incoming = held_factory(), incoming_factory()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    assert _dump(result) == before[0 if source == "held" else 1]
    _change(result, _change_everything)

    assert _both(held, incoming) == before


def test_the_held_reports_header_in_a_merged_result_is_a_copy():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    assert result.version == HELD_VERSION
    assert result.version != INCOMING_VERSION
    _change(result, lambda r: setattr(r.metadata.component, "name", "changed"))
    _change(result, lambda r: setattr(r.metadata.component.properties[0], "value", "x"))

    assert _both(held, incoming) == before


def test_a_list_of_the_held_report_that_is_not_combined_is_a_copy():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    assert [p.name for p in result.properties] == ["held-list"]
    _change(result, lambda r: setattr(r.properties[0], "value", "changed"))

    assert _both(held, incoming) == before


def test_the_held_reports_components_in_a_merged_result_are_copies():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    assert sorted(c.name for c in result.components) == ["django", "flask", "requests"]
    _change(result, lambda r: _change_component(_named(r, "requests")))
    _change(result, lambda r: _change_component(_named(r, "flask")))

    assert _both(held, incoming) == before


def test_the_held_reports_dependency_entries_in_a_merged_result_are_copies():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    _change(result, lambda r: _change_dependency(_entry_for(r, "flask")))
    _change(result, lambda r: setattr(_entry_for(r, "requests").ref.root, "root", "x"))

    assert _both(held, incoming) == before


def test_the_incoming_reports_components_in_a_merged_result_are_copies():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    _change(result, lambda r: _change_component(_named(r, "django")))

    assert _both(held, incoming) == before


def test_an_incoming_dependency_entry_only_it_has_is_a_copy():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    django_entry = _entry_for(result, "django")
    assert [r.root.root for r in django_entry.dependsOn] == [_purl("sqlparse")]
    _change(result, lambda r: _change_dependency(_entry_for(r, "django")))

    assert _both(held, incoming) == before


def test_the_incoming_refs_added_to_a_shared_dependency_entry_are_copies():
    held, incoming = _held(), _incoming()
    before = _both(held, incoming)

    result = merge_cyclonedx_reports(held, incoming)
    requests_entry = _entry_for(result, "requests")
    assert [r.root.root for r in requests_entry.dependsOn] == [
        _purl("flask"),
        _purl("django"),
    ]
    _change(
        result,
        lambda r: setattr(_entry_for(r, "requests").dependsOn[1].root, "root", "x"),
    )

    assert _both(held, incoming) == before
