# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A default dump of a CycloneDX report re-validates as a CycloneDX report.

``CycloneDXReport`` sets ``serialize_by_alias=True``, but pydantic resolves a
dump's ``by_alias`` per model from each model's own config when the caller
passes none, so a nested ``Component.bom_ref`` was written under its Python
name by ``model_dump()`` and ``model_dump_json()`` with no arguments. Every model
is ``extra="forbid"``, so the document a results file keeps could not be read
back as a CycloneDX report: ``bom_ref`` was an unknown key. Each model that
declares an aliased field now serializes by alias on its own.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Component,
    CycloneDXReport,
)

pytestmark = pytest.mark.unit

BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {
        "component": {"type": "application", "name": "app", "bom-ref": "pkg:app@1"},
        "authors": [{"name": "author", "bom-ref": "author-1"}],
    },
    "components": [
        {
            "type": "library",
            "name": "lib",
            "version": "1.0",
            "bom-ref": "pkg:lib@1.0",
            "externalReferences": [
                {
                    "type": "distribution",
                    "url": "https://example.invalid/lib",
                    "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                }
            ],
        }
    ],
    "dependencies": [{"ref": "pkg:app@1", "dependsOn": ["pkg:lib@1.0"]}],
}


def test_a_default_dump_writes_nested_bom_ref_under_its_alias():
    dumped = CycloneDXReport.model_validate(BOM).model_dump(exclude_none=True)
    assert "bom-ref" in dumped["components"][0]
    assert "bom_ref" not in dumped["components"][0]
    assert "bom-ref" in dumped["metadata"]["component"]
    assert "bom-ref" in dumped["metadata"]["authors"][0]


def test_a_default_dump_re_validates_as_a_report():
    report = CycloneDXReport.model_validate(BOM)
    dumped = report.model_dump(exclude_none=True)
    again = CycloneDXReport.model_validate(dumped)
    assert again.model_dump(exclude_none=True) == dumped
    assert again.model_dump(exclude_none=True)["components"][0]["bom-ref"] == (
        "pkg:lib@1.0"
    )
    from_json = CycloneDXReport.model_validate(
        json.loads(report.model_dump_json(exclude_none=True))
    )
    assert from_json.model_dump(exclude_none=True) == dumped


def test_a_nested_model_dumped_on_its_own_uses_the_alias():
    component = Component.model_validate(
        {"type": "library", "name": "lib", "bom-ref": "pkg:lib@1.0"}
    )
    assert component.model_dump(exclude_none=True)["bom-ref"] == "pkg:lib@1.0"
    assert Component.model_validate(component.model_dump(exclude_none=True))


def test_control_by_alias_false_still_gives_python_names():
    component = Component.model_validate(
        {"type": "library", "name": "lib", "bom-ref": "pkg:lib@1.0"}
    )
    assert "bom_ref" in component.model_dump(by_alias=False, exclude_none=True)
