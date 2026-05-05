"""Smoke tests for the gitlab-cyclonedx reporter."""

import json
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
    _extract_purl_type,
    _normalize_input_file_path,
    _resolve_package_manager_and_language,
    GitLabCycloneDXReporterConfigOptions,
)
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


def test_report_produces_output(reporter, model):
    result = reporter.report(model)
    assert result is not None


def test_schema_version_injected(reporter, model):
    result = reporter.report(model)
    doc = json.loads(result)
    meta_props = doc["metadata"]["properties"]
    schema_props = [p for p in meta_props if p["name"] == "gitlab:meta:schema_version"]
    assert len(schema_props) == 1
    assert schema_props[0]["value"] == "1"


def test_components_have_category(reporter, model):
    result = reporter.report(model)
    doc = json.loads(result)
    first = doc["components"][0]
    cats = [
        p
        for p in first["properties"]
        if p["name"] == "gitlab:dependency_scanning:category"
    ]
    assert len(cats) == 1
    assert cats[0]["value"] == "production"


def test_components_have_package_manager(reporter, model):
    result = reporter.report(model)
    doc = json.loads(result)
    first = doc["components"][0]
    pms = [
        p
        for p in first["properties"]
        if p["name"] == "gitlab:dependency_scanning:package_manager:name"
    ]
    assert len(pms) == 1
    assert pms[0]["value"] == "npm"


def test_components_have_input_file_path(reporter, model):
    result = reporter.report(model)
    doc = json.loads(result)
    first = doc["components"][0]
    paths = [
        p
        for p in first["properties"]
        if p["name"] == "gitlab:dependency_scanning:input_file:path"
    ]
    assert len(paths) == 1
    assert paths[0]["value"] == "yarn.lock"


def test_returns_none_when_no_components(reporter):
    model = AshAggregatedResults()
    result = reporter.report(model)
    assert result is None


def test_extract_purl_type():
    assert _extract_purl_type("pkg:npm/%40antfu/install-pkg@1.0.0") == "npm"
    assert _extract_purl_type("pkg:pypi/requests@2.31.0") == "pypi"
    assert _extract_purl_type("pkg:golang/github.com/foo/bar@v1.0.0") == "golang"
    assert _extract_purl_type(None) is None
    assert _extract_purl_type("") is None
    assert _extract_purl_type("not-a-purl") is None


def test_normalize_input_file_path():
    assert (
        _normalize_input_file_path(
            "/.venv/lib/python3.12/site-packages/jupyterlab/staging/yarn.lock"
        )
        == "yarn.lock"
    )
    assert _normalize_input_file_path("/app/go.sum") == "app/go.sum"
    assert _normalize_input_file_path(None) is None
    assert _normalize_input_file_path("") is None


def test_resolve_package_manager_syft_type():
    component = {
        "properties": [{"name": "syft:package:type", "value": "python"}],
        "purl": "pkg:pypi/requests@2.31.0",
    }
    options = GitLabCycloneDXReporterConfigOptions()
    pm, lang = _resolve_package_manager_and_language(component, options)
    assert pm == "pip"
    assert lang == "Python"


def test_resolve_package_manager_purl_fallback():
    component = {"properties": [], "purl": "pkg:cargo/serde@1.0.0"}
    options = GitLabCycloneDXReporterConfigOptions()
    pm, lang = _resolve_package_manager_and_language(component, options)
    assert pm == "cargo"
    assert lang == "Rust"


def test_resolve_package_manager_override():
    component = {
        "properties": [{"name": "syft:package:type", "value": "npm"}],
        "purl": "pkg:npm/foo@1.0.0",
    }
    options = GitLabCycloneDXReporterConfigOptions(
        package_manager_override="yarn", language_override="TypeScript"
    )
    pm, lang = _resolve_package_manager_and_language(component, options)
    assert pm == "yarn"
    assert lang == "TypeScript"
