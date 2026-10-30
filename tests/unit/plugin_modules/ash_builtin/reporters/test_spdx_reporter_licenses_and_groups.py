# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SPDX document declares what it refers to and keeps the SBOM's distinctions.

* A ``LicenseRef-`` term copied from a CycloneDX ``id`` or ``expression`` was
  referred to and never declared in ``hasExtractedLicensingInfos``.
* A CycloneDX 1.6 license acknowledged as ``concluded`` was written to
  ``licenseDeclared``; it is the SBOM author's conclusion, ``licenseConcluded``.
* The CycloneDX ``group`` was ignored, so same-named components from different
  groups became one SPDX package name.
* A component the CycloneDX report marks as one a delivered client exclusion
  would have dropped carried no such mark here.
"""

import json

import pytest

from automated_security_helper.config.client_scanner_exclusions import SBOM_PROPERTY
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    NOASSERTION,
    SpdxReporter,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)

pytestmark = pytest.mark.unit


def _document(context, components) -> dict:
    model = AshAggregatedResults()
    model.metadata.project_name = "fixture-project"
    model.metadata.generated_at = "2026-10-01T09:00:00+00:00"
    model.cyclonedx = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": "2026-10-01T09:00:00Z"},
            "components": components,
        }
    )
    return json.loads(SpdxReporter(context=context).report(model))


def _packages(document: dict) -> dict:
    return {p["name"]: p for p in document["packages"][1:]}


class TestLicenseRefsAreDeclared:
    def test_a_license_ref_in_an_expression_is_declared(self, test_plugin_context):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "a",
                    "licenses": [{"expression": "MIT AND LicenseRef-syft-unknown"}],
                },
                {
                    "type": "library",
                    "name": "b",
                    "licenses": [{"license": {"id": "LicenseRef-Vendor-EULA"}}],
                },
            ],
        )

        packages = _packages(document)
        assert packages["a"]["licenseDeclared"] == "MIT AND LicenseRef-syft-unknown"
        assert packages["b"]["licenseDeclared"] == "LicenseRef-Vendor-EULA"
        declared = {e["licenseId"]: e for e in document["hasExtractedLicensingInfos"]}
        assert set(declared) == {"LicenseRef-syft-unknown", "LicenseRef-Vendor-EULA"}
        assert declared["LicenseRef-syft-unknown"]["extractedText"] == NOASSERTION

    def test_a_ref_qualified_by_an_external_document_is_left_to_it(
        self, test_plugin_context
    ):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "a",
                    "licenses": [{"expression": "DocumentRef-other:LicenseRef-x"}],
                }
            ],
        )

        assert "hasExtractedLicensingInfos" not in document


class TestConcludedLicenses:
    def test_a_concluded_entry_is_the_concluded_license(self, test_plugin_context):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "a",
                    "licenses": [
                        {"license": {"id": "MIT", "acknowledgement": "concluded"}}
                    ],
                },
                {
                    "type": "library",
                    "name": "b",
                    "licenses": [
                        {"license": {"id": "MIT", "acknowledgement": "declared"}},
                        {"expression": "Apache-2.0", "acknowledgement": "concluded"},
                    ],
                },
            ],
        )

        packages = _packages(document)
        assert packages["a"]["licenseConcluded"] == "MIT"
        assert packages["a"]["licenseDeclared"] == NOASSERTION
        assert packages["b"]["licenseDeclared"] == "MIT"
        assert packages["b"]["licenseConcluded"] == "Apache-2.0"


class TestGroupsAndMarks:
    def test_the_group_qualifies_the_package_name(self, test_plugin_context):
        document = _document(
            test_plugin_context,
            [
                {"type": "library", "name": "core", "group": "@angular"},
                {"type": "library", "name": "core", "group": "@nestjs"},
                {"type": "library", "name": "@angular/core", "group": "@angular"},
            ],
        )

        names = [p["name"] for p in document["packages"][1:]]
        assert names == ["@angular/core", "@nestjs/core", "@angular/core"]
        assert len({p["SPDXID"] for p in document["packages"]}) == 4

    def test_a_client_exclusion_mark_is_carried_as_the_package_comment(
        self, test_plugin_context
    ):
        document = _document(
            test_plugin_context,
            [
                {
                    "type": "library",
                    "name": "left-pad",
                    "properties": [
                        {"name": SBOM_PROPERTY, "value": "exclude_paths: vendor/**"}
                    ],
                },
                {"type": "library", "name": "requests"},
            ],
        )

        packages = _packages(document)
        assert "exclude_paths: vendor/**" in packages["left-pad"]["comment"]
        assert "comment" not in packages["requests"]
