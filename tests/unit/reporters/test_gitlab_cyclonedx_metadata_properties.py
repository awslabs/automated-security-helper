# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for gitlab-cyclonedx reporter metadata-level properties.

Validates that the reporter produces output matching GitLab's requirements:
- gitlab:meta:schema_version at metadata.properties
- gitlab:dependency_scanning:{category,package_manager:name,language:name,input_file:path}
  at metadata.properties (required for GitLab to resolve a report-level source)
- Per-component enrichment still present

Without metadata-level dependency_scanning properties, GitLab fires:
"Required GitLab CycloneDX properties are missing"
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
    GitLabCycloneDXReporterConfigOptions,
    GITLAB_SCHEMA_VERSION,
)
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.plugin_context import PluginContext

AshAggregatedResults.model_rebuild()


@pytest.fixture
def model():
    fixture_path = Path("tests/test_data/outputs/ash_aggregated_results.json")
    with open(fixture_path) as f:
        raw = json.load(f)
    return AshAggregatedResults.model_validate(raw)


@pytest.fixture
def reporter(tmp_path):
    ctx = PluginContext(source_dir=Path("."), output_dir=tmp_path)
    return GitLabCycloneDXReporter(context=ctx, config=GitLabCycloneDXReporterConfig())


@pytest.fixture
def report_doc(reporter, model):
    """Parse the reporter output into a dict for assertions."""
    result = reporter.report(model)
    assert result is not None
    return json.loads(result)


class TestMetadataLevelProperties:
    """Validate that metadata.properties contains all required GitLab properties."""

    def test_schema_version_present(self, report_doc):
        """gitlab:meta:schema_version must be at metadata.properties."""
        meta_props = report_doc["metadata"]["properties"]
        schema_props = [
            p for p in meta_props if p["name"] == "gitlab:meta:schema_version"
        ]
        assert len(schema_props) == 1
        assert schema_props[0]["value"] == GITLAB_SCHEMA_VERSION

    def test_dependency_scanning_category_present(self, report_doc):
        """gitlab:dependency_scanning:category must be at metadata.properties."""
        meta_props = report_doc["metadata"]["properties"]
        cat_props = [
            p for p in meta_props if p["name"] == "gitlab:dependency_scanning:category"
        ]
        assert len(cat_props) == 1
        assert cat_props[0]["value"] == "production"

    def test_dependency_scanning_package_manager_present(self, report_doc):
        """gitlab:dependency_scanning:package_manager:name must be at metadata.properties."""
        meta_props = report_doc["metadata"]["properties"]
        pm_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:package_manager:name"
        ]
        assert len(pm_props) == 1
        # The fixture is npm-dominant
        assert pm_props[0]["value"] == "npm"

    def test_dependency_scanning_language_present(self, report_doc):
        """gitlab:dependency_scanning:language:name must be at metadata.properties."""
        meta_props = report_doc["metadata"]["properties"]
        lang_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:language:name"
        ]
        assert len(lang_props) == 1
        assert lang_props[0]["value"] == "JavaScript"

    def test_dependency_scanning_input_file_path_present(self, report_doc):
        """gitlab:dependency_scanning:input_file:path must be at metadata.properties.

        This is the critical property — without it, GitLab's parser returns nil
        for the source and fires the 'Required properties are missing' error.
        """
        meta_props = report_doc["metadata"]["properties"]
        path_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:input_file:path"
        ]
        assert len(path_props) == 1
        # Should be a non-empty string (the dominant input file or fallback)
        assert path_props[0]["value"]
        assert len(path_props[0]["value"]) > 0

    def test_all_required_properties_present_together(self, report_doc):
        """All 5 required properties must be present for GitLab to accept the report."""
        meta_props = report_doc["metadata"]["properties"]
        prop_names = {p["name"] for p in meta_props}

        required = {
            "gitlab:meta:schema_version",
            "gitlab:dependency_scanning:category",
            "gitlab:dependency_scanning:package_manager:name",
            "gitlab:dependency_scanning:language:name",
            "gitlab:dependency_scanning:input_file:path",
        }
        missing = required - prop_names
        assert not missing, f"Missing required metadata properties: {missing}"


class TestMetadataWithConfigOverrides:
    """Validate that config overrides are reflected in metadata properties."""

    def test_package_manager_override_in_metadata(self, tmp_path, model):
        """Config override for package_manager should appear in metadata."""
        ctx = PluginContext(source_dir=Path("."), output_dir=tmp_path)
        config = GitLabCycloneDXReporterConfig(
            options=GitLabCycloneDXReporterConfigOptions(
                package_manager_override="yarn",
                language_override="TypeScript",
            )
        )
        reporter = GitLabCycloneDXReporter(context=ctx, config=config)
        result = reporter.report(model)
        doc = json.loads(result)

        meta_props = doc["metadata"]["properties"]
        pm_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:package_manager:name"
        ]
        lang_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:language:name"
        ]
        assert pm_props[0]["value"] == "yarn"
        assert lang_props[0]["value"] == "TypeScript"

    def test_input_file_path_override_in_metadata(self, tmp_path, model):
        """Config override for input_file_path should appear in metadata."""
        ctx = PluginContext(source_dir=Path("."), output_dir=tmp_path)
        config = GitLabCycloneDXReporterConfig(
            options=GitLabCycloneDXReporterConfigOptions(
                input_file_path_override="custom/package-lock.json",
            )
        )
        reporter = GitLabCycloneDXReporter(context=ctx, config=config)
        result = reporter.report(model)
        doc = json.loads(result)

        meta_props = doc["metadata"]["properties"]
        path_props = [
            p
            for p in meta_props
            if p["name"] == "gitlab:dependency_scanning:input_file:path"
        ]
        assert path_props[0]["value"] == "custom/package-lock.json"

    def test_category_override_in_metadata(self, tmp_path, model):
        """Config override for category should appear in metadata."""
        ctx = PluginContext(source_dir=Path("."), output_dir=tmp_path)
        config = GitLabCycloneDXReporterConfig(
            options=GitLabCycloneDXReporterConfigOptions(
                category="development",
            )
        )
        reporter = GitLabCycloneDXReporter(context=ctx, config=config)
        result = reporter.report(model)
        doc = json.loads(result)

        meta_props = doc["metadata"]["properties"]
        cat_props = [
            p for p in meta_props if p["name"] == "gitlab:dependency_scanning:category"
        ]
        assert cat_props[0]["value"] == "development"


class TestPerComponentEnrichmentStillPresent:
    """Verify per-component properties are still injected alongside metadata."""

    def test_components_still_have_category(self, report_doc):
        """Per-component category should still be present."""
        for component in report_doc["components"][:5]:
            cats = [
                p
                for p in component.get("properties", [])
                if p["name"] == "gitlab:dependency_scanning:category"
            ]
            assert len(cats) >= 1, f"Component {component.get('name')} missing category"

    def test_components_still_have_package_manager(self, report_doc):
        """Per-component package_manager should still be present for components with PURLs."""
        components_with_purl = [c for c in report_doc["components"] if c.get("purl")]
        assert len(components_with_purl) > 0

        for component in components_with_purl[:5]:
            pms = [
                p
                for p in component.get("properties", [])
                if p["name"] == "gitlab:dependency_scanning:package_manager:name"
            ]
            assert len(pms) >= 1, (
                f"Component {component.get('name')} missing package_manager"
            )


class TestOutputFormat:
    """Validate the overall output format is valid CycloneDX-like JSON."""

    def test_output_is_valid_json(self, reporter, model):
        """Output must be parseable JSON."""
        result = reporter.report(model)
        doc = json.loads(result)
        assert isinstance(doc, dict)

    def test_output_has_bom_format(self, report_doc):
        """Output should retain the CycloneDX bomFormat field."""
        assert report_doc.get("bomFormat") == "CycloneDX"

    def test_output_has_spec_version(self, report_doc):
        """Output should retain the CycloneDX specVersion field."""
        assert report_doc.get("specVersion") in ("1.4", "1.5", "1.6")

    def test_output_has_components(self, report_doc):
        """Output should have a non-empty components array."""
        assert len(report_doc.get("components", [])) > 0

    def test_output_has_metadata(self, report_doc):
        """Output should have metadata with properties."""
        assert "metadata" in report_doc
        assert "properties" in report_doc["metadata"]
        assert len(report_doc["metadata"]["properties"]) >= 5  # at least the 5 required

    def test_compact_json_output(self, reporter, model):
        """Output should use compact JSON (no extra whitespace)."""
        result = reporter.report(model)
        # Compact JSON uses separators=(",", ":") — no spaces after , or :
        assert ", " not in result[:200]  # Check first 200 chars for spaces after comma
