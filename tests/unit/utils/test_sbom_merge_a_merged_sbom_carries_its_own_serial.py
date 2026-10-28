# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A merged SBOM carries its own serial number.

Why this exists
---------------
The merge started from a copy of the first SBOM, so the result kept that SBOM's
``serialNumber`` while its components and dependencies were no longer the first
SBOM's. A consumer that keys BOMs by serial number and version then treats the
merged document and the first tree's as one.

What the cells pin
------------------
When the merge adds a component or a dependency (or a ref to one), the result has
a new ``urn:uuid`` serial number that conforms to the schema and differs from both
inputs'. When the merge adds nothing, the result keeps the held serial number. The
rest of the header, ``version`` and ``metadata`` included, is still the held
report's.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports

SERIAL_PATTERN = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HELD_SERIAL = f"urn:uuid:{uuid.UUID(int=1)}"
INCOMING_SERIAL = f"urn:uuid:{uuid.UUID(int=2)}"

REQUESTS = "pkg:pypi/requests@2.19.1"
FLASK = "pkg:pypi/flask@3.0.0"


def _component(purl: str) -> dict[str, Any]:
    return {
        "type": "library",
        "name": purl.split("/")[-1].split("@")[0],
        "version": "1.0",
        "purl": purl,
        "bom-ref": purl,
    }


def _sbom(
    components: list[dict[str, Any]],
    *,
    serial: str | None,
    dependencies: list[dict[str, Any]] | None = None,
    version: int | None = None,
    subject: str | None = None,
) -> CycloneDXReport:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    }
    if serial is not None:
        document["serialNumber"] = serial
    if dependencies is not None:
        document["dependencies"] = dependencies
    if version is not None:
        document["version"] = version
    if subject is not None:
        document["metadata"] = {"component": {"type": "file", "name": subject}}
    return CycloneDXReport.model_validate(document)


def _dump(report: CycloneDXReport) -> dict[str, Any]:
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


def _merged(held: CycloneDXReport, incoming: CycloneDXReport) -> CycloneDXReport:
    result = merge_cyclonedx_reports(held, incoming)
    assert result is not None
    return result


def test_a_merge_that_adds_a_component_carries_a_new_serial():
    held = _sbom([_component(REQUESTS)], serial=HELD_SERIAL)
    incoming = _sbom([_component(FLASK)], serial=INCOMING_SERIAL)

    result = _merged(held, incoming)

    assert len(result.components) == 2
    assert result.serialNumber not in (HELD_SERIAL, INCOMING_SERIAL)
    assert SERIAL_PATTERN.fullmatch(result.serialNumber)
    assert CycloneDXReport.model_validate(_dump(result)).serialNumber == (
        result.serialNumber
    )


def test_a_merge_that_adds_only_a_dependency_carries_a_new_serial():
    held = _sbom(
        [_component(REQUESTS)],
        serial=HELD_SERIAL,
        dependencies=[{"ref": REQUESTS}],
    )
    incoming = _sbom(
        [_component(REQUESTS)],
        serial=INCOMING_SERIAL,
        dependencies=[{"ref": REQUESTS}, {"ref": FLASK}],
    )

    result = _merged(held, incoming)

    assert len(result.components) == 1
    assert len(result.dependencies) == 2
    assert result.serialNumber != HELD_SERIAL
    assert SERIAL_PATTERN.fullmatch(result.serialNumber)


@pytest.mark.parametrize("field", ["dependsOn", "provides"])
def test_a_merge_that_adds_only_a_ref_to_a_shared_entry_carries_a_new_serial(field):
    held = _sbom(
        [_component(REQUESTS)],
        serial=HELD_SERIAL,
        dependencies=[{"ref": REQUESTS}],
    )
    incoming = _sbom(
        [_component(REQUESTS)],
        serial=INCOMING_SERIAL,
        dependencies=[{"ref": REQUESTS, field: [FLASK]}],
    )

    result = _merged(held, incoming)

    assert len(result.components) == 1
    assert result.serialNumber != HELD_SERIAL


def test_a_merge_that_re_references_a_package_carries_a_new_serial():
    held = _sbom([{**_component(REQUESTS), "bom-ref": "1"}], serial=HELD_SERIAL)
    incoming = _sbom([{**_component(FLASK), "bom-ref": "1"}], serial=INCOMING_SERIAL)

    result = _merged(held, incoming)

    assert len(result.components) == 2
    assert result.serialNumber != HELD_SERIAL


def test_a_merge_that_adds_nothing_keeps_the_held_serial():
    held = _sbom(
        [_component(REQUESTS), _component(FLASK)],
        serial=HELD_SERIAL,
        dependencies=[{"ref": REQUESTS, "dependsOn": [FLASK]}, {"ref": FLASK}],
    )
    incoming = _sbom(
        [_component(FLASK)],
        serial=INCOMING_SERIAL,
        dependencies=[{"ref": REQUESTS, "dependsOn": [FLASK]}],
    )

    result = _merged(held, incoming)

    assert len(result.components) == 2
    assert result.serialNumber == HELD_SERIAL
    assert _dump(result) == _dump(held)


def test_a_report_with_no_serial_gets_one_only_when_the_merge_adds():
    held = _sbom([_component(REQUESTS)], serial=None, subject="source tree")

    added = _merged(held, _sbom([_component(FLASK)], serial=None))
    unchanged = _merged(held, _sbom([_component(REQUESTS)], serial=None))

    assert SERIAL_PATTERN.fullmatch(added.serialNumber)
    assert unchanged.serialNumber is None


def test_the_rest_of_the_header_is_still_the_held_reports():
    held = _sbom(
        [_component(REQUESTS)],
        serial=HELD_SERIAL,
        version=3,
        subject="source tree",
    )
    incoming = _sbom(
        [_component(FLASK)],
        serial=INCOMING_SERIAL,
        version=7,
        subject="converted tree",
    )

    result = _merged(held, incoming)

    assert result.version == 3
    assert result.specVersion == held.specVersion
    assert _dump(result)["metadata"] == _dump(held)["metadata"]


def test_two_merges_that_add_do_not_share_a_serial():
    held = _sbom([_component(REQUESTS)], serial=HELD_SERIAL)
    incoming = _sbom([_component(FLASK)], serial=INCOMING_SERIAL)

    first = _merged(held, incoming)
    second = _merged(held, incoming)

    assert first.serialNumber != second.serialNumber


def test_the_merge_still_changes_neither_input_when_it_sets_a_serial():
    held = _sbom([_component(REQUESTS)], serial=HELD_SERIAL)
    incoming = _sbom([_component(FLASK)], serial=INCOMING_SERIAL)
    before = (_dump(held), _dump(incoming))

    _merged(held, incoming)

    assert (_dump(held), _dump(incoming)) == before
