# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SPDX document states the inventory the SBOM states.

* A name-only CycloneDX license was dropped from ``licenseDeclared``, which
  declared a narrower license than the SBOM; it is now a ``LicenseRef-``
  identifier declared in ``hasExtractedLicensingInfos``.
* Nested components (``component.components``) were left out, so the SPDX and
  CycloneDX reports listed different inventories for one scan.
* With no SBOM the document had the root package only, byte-identical to the
  document of a project with no dependencies; the root package now says so.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    NO_SBOM_COMMENT,
    SpdxReporter,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)

pytestmark = pytest.mark.unit


def _document(context, components=None, cyclonedx=...) -> dict:
    model = AshAggregatedResults()
    model.metadata.project_name = "fixture-project"
    model.metadata.generated_at = "2026-10-01T09:00:00+00:00"
    if cyclonedx is not ...:
        model.cyclonedx = cyclonedx
    else:
        model.cyclonedx = CycloneDXReport.model_validate(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"timestamp": "2026-10-01T09:00:00Z"},
                "components": components or [],
            }
        )
    return json.loads(SpdxReporter(context=context).report(model))


class TestNameOnlyLicenses:
    def test_a_name_only_license_becomes_a_declared_license_ref(
        self, test_plugin_context
    ):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "mystery",
                    "licenses": [{"license": {"name": "Some custom license text"}}],
                }
            ],
        )

        (package,) = document["packages"][1:]
        assert package["licenseDeclared"] == "LicenseRef-Some-custom-license-text"
        assert document["hasExtractedLicensingInfos"] == [
            {
                "licenseId": "LicenseRef-Some-custom-license-text",
                "name": "Some custom license text",
                "extractedText": "NOASSERTION",
            }
        ]

    def test_an_id_and_a_name_are_both_declared(self, test_plugin_context):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "dual",
                    "licenses": [
                        {"license": {"id": "Apache-2.0"}},
                        {"license": {"name": "Vendor Commercial"}},
                    ],
                }
            ],
        )

        (package,) = document["packages"][1:]
        assert (
            package["licenseDeclared"] == "Apache-2.0 AND LicenseRef-Vendor-Commercial"
        )

    def test_two_names_that_sanitize_alike_get_distinct_refs(self, test_plugin_context):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "a",
                    "licenses": [{"license": {"name": "GPL 2"}}],
                },
                {
                    "type": "library",
                    "name": "b",
                    "licenses": [{"license": {"name": "GPL-2"}}],
                },
            ],
        )

        a, b = document["packages"][1:]
        assert a["licenseDeclared"] != b["licenseDeclared"]
        refs = {e["licenseId"] for e in document["hasExtractedLicensingInfos"]}
        assert refs == {a["licenseDeclared"], b["licenseDeclared"]}

    def test_no_extracted_infos_key_without_a_name_only_license(
        self, test_plugin_context
    ):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "x",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ],
        )

        assert "hasExtractedLicensingInfos" not in document


class TestNestedComponents:
    def test_nested_components_are_packages_contained_by_their_parent(
        self, test_plugin_context
    ):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "bundle",
                    "components": [
                        {"type": "library", "name": "inner-a"},
                        {
                            "type": "library",
                            "name": "inner-b",
                            "components": [{"type": "library", "name": "leaf"}],
                        },
                    ],
                }
            ],
        )

        by_name = {p["name"]: p["SPDXID"] for p in document["packages"]}
        assert set(by_name) == {
            "fixture-project",
            "bundle",
            "inner-a",
            "inner-b",
            "leaf",
        }
        contains = {
            (r["spdxElementId"], r["relatedSpdxElement"])
            for r in document["relationships"]
            if r["relationshipType"] == "CONTAINS"
        }
        assert contains == {
            ("SPDXRef-RootPackage", by_name["bundle"]),
            (by_name["bundle"], by_name["inner-a"]),
            (by_name["bundle"], by_name["inner-b"]),
            (by_name["inner-b"], by_name["leaf"]),
        }
        assert len({p["SPDXID"] for p in document["packages"]}) == 5


class TestNoSbom:
    def test_no_model_marks_the_root_package(self, test_plugin_context):
        document = _document(test_plugin_context, cyclonedx=None)

        (root,) = document["packages"]
        assert root["comment"] == NO_SBOM_COMMENT

    def test_the_default_model_marks_the_root_package(self, test_plugin_context):
        document = _document(test_plugin_context, cyclonedx=CycloneDXReport())

        (root,) = document["packages"]
        assert root["comment"] == NO_SBOM_COMMENT

    def test_a_scanner_sbom_with_no_components_is_not_marked(self, test_plugin_context):
        document = _document(test_plugin_context, [])

        (root,) = document["packages"]
        assert "comment" not in root
