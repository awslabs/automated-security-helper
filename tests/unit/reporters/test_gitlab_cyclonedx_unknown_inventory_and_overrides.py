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
    # The scratch directory, never the working directory: this repository's
    # root holds pyproject.toml and uv.lock, so a reporter that ever read
    # source_dir would answer differently depending on where pytest ran.
    ctx = PluginContext(source_dir=tmp_path, output_dir=tmp_path)
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

    def test_a_metadata_less_empty_sbom_is_marked_unknown(self, tmp_path):
        """No metadata, no serial number, no components is the default model's
        own shape, so it reads as "no scanner produced an inventory"; every SBOM
        a scanner writes carries metadata or a serial number."""
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        )

        doc = json.loads(_reporter(tmp_path).report(model))

        assert doc["components"] == []
        assert doc["compositions"] == [{"aggregate": "unknown"}]


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
        # conan is in neither GitLab table, so no default lockfile is drawn
        assert "gitlab:dependency_scanning:input_file:path" not in props


def _component(name: str, purl: str, location: str) -> dict:
    return {
        "type": "library",
        "name": name,
        "purl": purl,
        "properties": [{"name": "syft:location:0:path", "value": location}],
    }


class TestVendoredComponentsDoNotVote:
    """A Python repository whose .venv holds a documentation toolchain: three npm
    components inside the virtual environment, one declared Python dependency.
    The majority vote labelled it an npm project with input file yarn.lock."""

    VENDORED_HEAVY = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"timestamp": "2026-10-29T00:00:00Z"},
        "components": [
            _component("requests", "pkg:pypi/requests@2.32.3", "/requirements.txt"),
            _component(
                "left-pad",
                "pkg:npm/left-pad@1.3.0",
                "/.venv/lib/python3.12/site-packages/docs/node_modules/yarn.lock",
            ),
            _component(
                "lodash",
                "pkg:npm/lodash@4.17.21",
                "/.venv/lib/python3.12/site-packages/docs/node_modules/yarn.lock",
            ),
            _component(
                "chalk",
                "pkg:npm/chalk@5.3.0",
                "/.venv/lib/python3.12/site-packages/docs/node_modules/yarn.lock",
            ),
        ],
    }

    def test_the_declared_dependency_decides_the_source(self, tmp_path):
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(self.VENDORED_HEAVY)

        props = _props(json.loads(_reporter(tmp_path).report(model)))

        assert props["gitlab:dependency_scanning:package_manager:name"] == "pip"
        assert props["gitlab:dependency_scanning:language:name"] == "Python"
        assert props["gitlab:dependency_scanning:input_file:path"] == "requirements.txt"

    def test_an_all_vendored_inventory_still_votes(self, tmp_path):
        only_vendored = dict(self.VENDORED_HEAVY)
        only_vendored["components"] = self.VENDORED_HEAVY["components"][1:]
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(only_vendored)

        props = _props(json.loads(_reporter(tmp_path).report(model)))

        # The vendored components still vote, and their lockfile, yarn.lock,
        # names the manager that declared them.
        assert props["gitlab:dependency_scanning:package_manager:name"] == "yarn"
        assert props["gitlab:dependency_scanning:input_file:path"] == "yarn.lock"

    @pytest.mark.parametrize(
        "location",
        [
            "/src/myvendor/package-lock.json",
            "/src/myvenv/package-lock.json",
            "/tools/vendored/package-lock.json",
            "/vendor",
        ],
    )
    def test_a_directory_that_only_contains_a_vendored_name_votes(
        self, tmp_path, location
    ):
        """``vendor/`` names a directory, not a substring: ``src/myvendor/`` is
        the repository's own code and keeps its vote; a file named ``vendor``
        at the root is not inside a vendored tree either."""
        declared_under_a_lookalike = dict(self.VENDORED_HEAVY)
        declared_under_a_lookalike["components"] = [
            _component("left-pad", "pkg:npm/left-pad@1.3.0", location),
            _component("lodash", "pkg:npm/lodash@4.17.21", location),
            _component("requests", "pkg:pypi/requests@2.32.3", "/requirements.txt"),
        ]
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(declared_under_a_lookalike)

        props = _props(json.loads(_reporter(tmp_path).report(model)))

        assert props["gitlab:dependency_scanning:package_manager:name"] == "npm"

    @pytest.mark.parametrize(
        "location",
        ["/vendor/package-lock.json", "/src/vendor/deep/package-lock.json"],
    )
    def test_a_real_vendor_directory_at_any_depth_does_not_vote(
        self, tmp_path, location
    ):
        vendored = dict(self.VENDORED_HEAVY)
        vendored["components"] = [
            _component("left-pad", "pkg:npm/left-pad@1.3.0", location),
            _component("lodash", "pkg:npm/lodash@4.17.21", location),
            _component("requests", "pkg:pypi/requests@2.32.3", "/requirements.txt"),
        ]
        model = AshAggregatedResults()
        model.cyclonedx = CycloneDXReport.model_validate(vendored)

        props = _props(json.loads(_reporter(tmp_path).report(model)))

        assert props["gitlab:dependency_scanning:package_manager:name"] == "pip"
