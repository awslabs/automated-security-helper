# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for SpdxReporter.

The reporter used to dump the whole results model as YAML into ``ash.spdx.json``:
neither SPDX nor JSON. ``ash report --format spdx`` exited 1 on it, because the
CLI prints the spdx format with ``print_json`` and the YAML did not parse. These
tests pin the replacement: an SPDX 2.3 JSON document built from the scan's
CycloneDX SBOM.
"""

import json
import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.spdx_reporter import (
    SPDXReporterConfig,
    SpdxReporter,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)

SPDX_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
CREATED = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

COMPONENTS = [
    {
        "type": "library",
        "name": "requests",
        "version": "2.32.3",
        "purl": "pkg:pypi/requests@2.32.3",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
    },
    {
        "type": "library",
        "name": "@scope/left pad",
        "version": "1.0.0",
        "purl": "pkg:npm/%40scope/left%20pad@1.0.0",
        "licenses": [{"expression": "MIT OR Apache-2.0"}],
    },
    {
        "type": "library",
        "name": "mystery",
        "licenses": [{"license": {"name": "Some custom license text"}}],
    },
]


@pytest.fixture
def model() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.metadata.project_name = "fixture-project"
    model.metadata.generated_at = "2026-10-01T09:00:00+00:00"
    model.cyclonedx = CycloneDXReport.model_validate(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": COMPONENTS}
    )
    return model


@pytest.fixture
def document(test_plugin_context, model) -> dict:
    return json.loads(SpdxReporter(context=test_plugin_context).report(model))


class TestSPDXReporterConfig:
    def test_default_config_values(self):
        config = SPDXReporterConfig()
        assert config.name == "spdx"
        assert config.extension == "spdx.json"
        assert config.enabled is False

    def test_model_post_init_sets_default_config(self, test_plugin_context):
        reporter = SpdxReporter(config=None, context=test_plugin_context)
        assert isinstance(reporter.config, SPDXReporterConfig)


class TestSpdxDocument:
    def test_output_is_json_not_a_yaml_model_dump(self, test_plugin_context, model):
        output = SpdxReporter(context=test_plugin_context).report(model)
        document = json.loads(output)
        assert "scanner_results" not in document
        assert "metadata" not in document

    def test_required_document_fields(self, document):
        assert document["spdxVersion"] == "SPDX-2.3"
        assert document["dataLicense"] == "CC0-1.0"
        assert document["SPDXID"] == "SPDXRef-DOCUMENT"
        assert document["name"]
        assert document["documentNamespace"].startswith("https://")
        assert CREATED.match(document["creationInfo"]["created"])
        assert document["creationInfo"]["created"] == "2026-10-01T09:00:00Z"
        assert document["creationInfo"]["creators"][0].startswith(
            "Tool: automated-security-helper-"
        )

    def test_one_package_per_component_plus_the_root(self, document):
        packages = document["packages"]
        assert len(packages) == 1 + len(COMPONENTS)
        names = [p["name"] for p in packages[1:]]
        assert names == [c["name"] for c in COMPONENTS]

    def test_every_package_has_the_required_fields(self, document):
        ids = set()
        for package in document["packages"]:
            assert SPDX_ID.match(package["SPDXID"]), package["SPDXID"]
            ids.add(package["SPDXID"])
            for field in (
                "name",
                "downloadLocation",
                "licenseConcluded",
                "licenseDeclared",
                "copyrightText",
            ):
                assert package[field], (package["SPDXID"], field)
            assert package["filesAnalyzed"] is False
        assert len(ids) == len(document["packages"]), "SPDXIDs must be unique"

    def test_versions_purls_and_licenses_carry_over(self, document):
        by_name = {p["name"]: p for p in document["packages"]}
        requests = by_name["requests"]
        assert requests["versionInfo"] == "2.32.3"
        assert requests["licenseDeclared"] == "Apache-2.0"
        assert requests["externalRefs"] == [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/requests@2.32.3",
            }
        ]
        assert by_name["@scope/left pad"]["licenseDeclared"] == "MIT OR Apache-2.0"
        # A free-text license name is not an SPDX expression; claiming nothing is
        # the valid answer.
        assert by_name["mystery"]["licenseDeclared"] == "NOASSERTION"
        assert "versionInfo" not in by_name["mystery"]

    def test_relationships_describe_the_root_and_contain_each_package(self, document):
        ids = {p["SPDXID"] for p in document["packages"]}
        relationships = document["relationships"]
        assert {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-RootPackage",
        } in relationships
        contained = {
            r["relatedSpdxElement"]
            for r in relationships
            if r["relationshipType"] == "CONTAINS"
        }
        assert contained == ids - {"SPDXRef-RootPackage"}

    def test_the_namespace_is_stable_for_one_scan_and_differs_across_scans(
        self, test_plugin_context, model
    ):
        reporter = SpdxReporter(context=test_plugin_context)
        first = json.loads(reporter.report(model))["documentNamespace"]
        again = json.loads(reporter.report(model))["documentNamespace"]
        model.metadata.generated_at = "2026-10-02T09:00:00+00:00"
        other = json.loads(reporter.report(model))["documentNamespace"]
        assert first == again
        assert first != other

    def test_no_sbom_yields_a_valid_document_with_only_the_root(
        self, test_plugin_context
    ):
        model = AshAggregatedResults()
        model.cyclonedx = None
        document = json.loads(SpdxReporter(context=test_plugin_context).report(model))
        assert [p["SPDXID"] for p in document["packages"]] == ["SPDXRef-RootPackage"]


def test_ash_report_format_spdx_exits_zero_and_prints_the_document(tmp_path, model):
    """The CLI symptom: before the fix this exited 1 with a JSON decode error."""
    (tmp_path / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    result = CliRunner().invoke(
        app,
        ["report", "--format", "spdx", "--output-dir", str(tmp_path), "--no-color"],
    )
    assert result.exit_code == 0, result.output
    # rich's print_json highlights regardless of --no-color; compare plain text.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    assert '"spdxVersion": "SPDX-2.3"' in plain
