# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""gitlab-cyclonedx says when the inventory is unknown, and honors overrides.

* With no CycloneDX model (no SBOM scanner produced an inventory) the minimal
  document was byte-identical to the one a dependency-free repository gets. It
  now carries ``compositions`` with aggregate ``unknown``, as the ``cyclonedx``
  reporter does for the same case.
* When no component mapped to a known ecosystem, every metadata-level source
  property was omitted, the category and the operator's overrides included,
  which is exactly the repository the overrides exist for.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
    GitLabCycloneDXReporterConfigOptions,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()

UNKNOWN_ECOSYSTEM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"timestamp": "2026-10-29T00:00:00Z"},
    "components": [
        {"type": "library", "name": "zlib", "purl": "pkg:conan/zlib@1.3"},
    ],
}


def _reporter(tmp_path, **options) -> GitLabCycloneDXReporter:
    ctx = PluginContext(source_dir=Path("."), output_dir=tmp_path)
    config = GitLabCycloneDXReporterConfig(
        options=GitLabCycloneDXReporterConfigOptions(**options)
    )
    return GitLabCycloneDXReporter(context=ctx, config=config)


def _props(doc: dict) -> dict:
    return {p["name"]: p["value"] for p in doc["metadata"]["properties"]}


class TestAnUnknownInventoryIsMarked:
    def test_no_model_emits_an_unknown_composition(self, tmp_path):
        model = AshAggregatedResults()
        model.cyclonedx = None

        doc = json.loads(_reporter(tmp_path).report(model))

        assert doc["components"] == []
        assert doc["compositions"] == [{"aggregate": "unknown"}]

    def test_the_default_model_emits_an_unknown_composition(self, tmp_path):
        """No SBOM scanner ran: the default model has no metadata, serial or
        components."""
        doc = json.loads(_reporter(tmp_path).report(AshAggregatedResults()))

        assert doc["components"] == []
        assert doc["compositions"] == [{"aggregate": "unknown"}]

    def test_a_scanner_sbom_with_no_components_is_not_marked_unknown(self, tmp_path):
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"timestamp": "2026-10-29T00:00:00Z"},
                "components": [],
            }
        )

        doc = json.loads(_reporter(tmp_path).report(model))

        assert doc["components"] == []
        assert "compositions" not in doc


class TestOverridesReachTheMetadataWithNoDominantEcosystem:
    def test_the_category_and_overrides_are_emitted(self, tmp_path):
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(UNKNOWN_ECOSYSTEM)
        reporter = _reporter(
            tmp_path,
            category="development",
            package_manager_override="conan",
            language_override="C++",
            input_file_path_override="conanfile.txt",
        )

        props = _props(json.loads(reporter.report(model)))

        assert props["gitlab:dependency_scanning:category"] == "development"
        assert props["gitlab:dependency_scanning:package_manager:name"] == "conan"
        assert props["gitlab:dependency_scanning:language:name"] == "C++"
        assert props["gitlab:dependency_scanning:input_file:path"] == "conanfile.txt"

    def test_the_category_alone_is_emitted_without_overrides(self, tmp_path):
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(UNKNOWN_ECOSYSTEM)

        props = _props(json.loads(_reporter(tmp_path).report(model)))

        assert props["gitlab:dependency_scanning:category"] == "production"
        assert "gitlab:dependency_scanning:package_manager:name" not in props
        assert "gitlab:dependency_scanning:language:name" not in props
