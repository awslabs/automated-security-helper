# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitlab-cyclonedx report names the source GitLab can act on.

* ``package_manager:name`` came from the ecosystem alone, so a yarn.lock
  component was ``npm`` and a poetry.lock one ``pip``; the lockfile says which.
* The report-level ``input_file:path`` was the most common path over every
  component while the package manager came from the dominant ecosystem, so the
  metadata could pair ``pip`` with ``package-lock.json``.
* The dominant-ecosystem vote counted Syft and PURL type keys apart, so one
  ecosystem's components split across two keys.
* A vendored path was reported by its basename whatever it was (``METADATA``,
  an installed dependency's own ``package.json``); only a manifest name is.
* Several mapped types had no default lockfile, and the minimal document for an
  empty inventory carried no source properties even when an operator had set
  the overrides that name them.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    _DEFAULT_LOCKFILES,
    GITLAB_SCHEMA_VERSION,
    PURL_TYPE_TO_GITLAB,
    SYFT_TYPE_TO_GITLAB,
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
    GitLabCycloneDXReporterConfigOptions,
    _normalize_input_file_path,
    _resolve_package_manager_and_language,
    _walk_components,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


def _reporter(tmp_path, **options) -> GitLabCycloneDXReporter:
    context = PluginContext(source_dir=tmp_path / "src", output_dir=tmp_path / "out")
    config = GitLabCycloneDXReporterConfig(
        options=GitLabCycloneDXReporterConfigOptions(**options)
    )
    return GitLabCycloneDXReporter(context=context, config=config)


def _component(name: str, location: str, purl: str | None = None, syft_type=None):
    properties = [{"name": "syft:location:0:path", "value": location}]
    if syft_type:
        properties.append({"name": "syft:package:type", "value": syft_type})
    component = {"type": "library", "name": name, "properties": properties}
    if purl:
        component["purl"] = purl
    return component


def _report(reporter, components) -> dict:
    model = AshAggregatedResults()
    model.cyclonedx = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": "2026-10-29T00:00:00Z"},
            "components": components,
        }
    )
    return json.loads(reporter.report(model))


def _metadata_props(doc: dict) -> dict:
    return {p["name"]: p["value"] for p in doc["metadata"]["properties"]}


def _component_props(doc: dict, name: str) -> dict:
    (component,) = [c for c in doc["components"] if c["name"] == name]
    return {p["name"]: p["value"] for p in component["properties"]}


class TestLockfileNamesTheManager:
    def test_a_yarn_lock_component_is_yarns(self):
        pm, lang = _resolve_package_manager_and_language(
            _component("left-pad", "/yarn.lock", purl="pkg:npm/left-pad@1.3.0"),
            GitLabCycloneDXReporterConfigOptions(),
        )
        assert (pm, lang) == ("yarn", "JavaScript")

    def test_a_poetry_lock_component_is_poetrys(self):
        pm, lang = _resolve_package_manager_and_language(
            _component("requests", "/poetry.lock", purl="pkg:pypi/requests@2.32.3"),
            GitLabCycloneDXReporterConfigOptions(),
        )
        assert (pm, lang) == ("poetry", "Python")

    def test_a_requirements_component_stays_pips(self):
        pm, _ = _resolve_package_manager_and_language(
            _component(
                "requests", "/requirements.txt", purl="pkg:pypi/requests@2.32.3"
            ),
            GitLabCycloneDXReporterConfigOptions(),
        )
        assert pm == "pip"

    def test_a_python_component_at_a_yarn_lock_stays_pip(self):
        pm, lang = _resolve_package_manager_and_language(
            _component("requests", "/yarn.lock", purl="pkg:pypi/requests@2.32.3"),
            GitLabCycloneDXReporterConfigOptions(),
        )
        assert (pm, lang) == ("pip", "Python")

    def test_a_javascript_component_at_a_poetry_lock_stays_npm(self):
        pm, lang = _resolve_package_manager_and_language(
            _component("left-pad", "/poetry.lock", purl="pkg:npm/left-pad@1.3.0"),
            GitLabCycloneDXReporterConfigOptions(),
        )
        assert (pm, lang) == ("npm", "JavaScript")

    def test_the_report_level_manager_ignores_another_ecosystems_lockfile(
        self, tmp_path
    ):
        """A Python inventory with an operator-set input file named yarn.lock is
        still pip: the lockfile is not a Python one."""
        doc = _report(
            _reporter(tmp_path, input_file_path_override="docs/yarn.lock"),
            [
                _component("a", "/requirements.txt", purl="pkg:pypi/a@1.0.0"),
                _component("b", "/requirements.txt", purl="pkg:pypi/b@1.0.0"),
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "pip"
        assert props["gitlab:dependency_scanning:input_file:path"] == "docs/yarn.lock"

    def test_the_report_level_manager_follows_the_report_level_lockfile(self, tmp_path):
        doc = _report(
            _reporter(tmp_path),
            [
                _component("a", "/pnpm-lock.yaml", purl="pkg:npm/a@1.0.0"),
                _component("b", "/pnpm-lock.yaml", purl="pkg:npm/b@1.0.0"),
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "pnpm"
        assert props["gitlab:dependency_scanning:input_file:path"] == "pnpm-lock.yaml"


class TestTheReportLevelSourceIsOneEcosystem:
    def test_the_input_file_belongs_to_the_dominant_ecosystem(self, tmp_path):
        """Three Python components with a PURL and no location, two JavaScript
        components declared by package-lock.json: Python wins the vote, no
        Python component has a location, so the report names pip with the pip
        default, requirements.txt, never pip with package-lock.json."""
        doc = _report(
            _reporter(tmp_path),
            [
                {"type": "library", "name": "requests", "purl": "pkg:pypi/requests@2"},
                {"type": "library", "name": "flask", "purl": "pkg:pypi/flask@3.0.0"},
                {"type": "library", "name": "click", "purl": "pkg:pypi/click@8.1.7"},
                _component(
                    "left-pad", "/package-lock.json", purl="pkg:npm/left-pad@1.3.0"
                ),
                _component(
                    "lodash", "/package-lock.json", purl="pkg:npm/lodash@4.17.21"
                ),
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "pip"
        assert props["gitlab:dependency_scanning:language:name"] == "Python"
        assert props["gitlab:dependency_scanning:input_file:path"] == "requirements.txt"

    def test_a_larger_javascript_ecosystem_names_its_own_lockfile(self, tmp_path):
        """Two Python components declared by requirements.txt, three JavaScript
        components declared by package-lock.json: the larger ecosystem wins and
        the file is its own."""
        doc = _report(
            _reporter(tmp_path),
            [
                _component(
                    "requests", "/requirements.txt", purl="pkg:pypi/requests@2.32.3"
                ),
                _component("flask", "/requirements.txt", purl="pkg:pypi/flask@3.0.0"),
                _component(
                    "left-pad", "/package-lock.json", purl="pkg:npm/left-pad@1.3.0"
                ),
                _component(
                    "lodash", "/package-lock.json", purl="pkg:npm/lodash@4.17.21"
                ),
                _component("chalk", "/package-lock.json", purl="pkg:npm/chalk@5.3.0"),
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "npm"
        assert (
            props["gitlab:dependency_scanning:input_file:path"] == "package-lock.json"
        )

    def test_a_syft_type_and_a_purl_type_of_one_ecosystem_vote_together(self, tmp_path):
        """Two Python components typed by Syft, two by PURL, three npm ones:
        Python wins four to three once the two keys are one ecosystem."""
        doc = _report(
            _reporter(tmp_path),
            [
                _component("a", "/requirements.txt", syft_type="python"),
                _component("b", "/requirements.txt", syft_type="python"),
                _component("c", "/requirements.txt", purl="pkg:pypi/c@1"),
                _component("d", "/requirements.txt", purl="pkg:pypi/d@1"),
                _component("e", "/package-lock.json", purl="pkg:npm/e@1"),
                _component("f", "/package-lock.json", purl="pkg:npm/f@1"),
                _component("g", "/package-lock.json", purl="pkg:npm/g@1"),
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "pip"
        assert props["gitlab:dependency_scanning:language:name"] == "Python"
        assert props["gitlab:dependency_scanning:input_file:path"] == "requirements.txt"

    def test_nested_components_vote(self, tmp_path):
        parent = _component("bundle", "/package-lock.json", purl="pkg:npm/bundle@1")
        parent["components"] = [
            _component("x", "/poetry.lock", purl="pkg:pypi/x@1"),
            _component("y", "/poetry.lock", purl="pkg:pypi/y@1"),
        ]

        doc = _report(_reporter(tmp_path), [parent])

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "poetry"
        assert props["gitlab:dependency_scanning:input_file:path"] == "poetry.lock"


class TestTheWalkVisitsEveryComponentOnceInDocumentOrder:
    """Control for the linear walk: the order and the set are what the list-copying
    walk returned, so the dominant-type tie-break is unchanged."""

    def test_nested_components_follow_their_parent_depth_first(self):
        c = {"name": "c"}
        b = {"name": "b", "components": [c]}
        d = {"name": "d"}
        a = {"name": "a", "components": [b, d]}
        e = {"name": "e"}

        walked = _walk_components([a, e])

        assert [x["name"] for x in walked] == ["a", "b", "c", "d", "e"]

    def test_entries_that_are_not_components_are_skipped(self):
        child = {"name": "child"}
        parent = {"name": "parent", "components": ["text", child, 3, None]}

        walked = _walk_components([parent, "text", None])

        assert [x["name"] for x in walked] == ["parent", "child"]

    def test_a_deep_chain_is_walked_whole(self):
        depth = 3000
        root: dict = {"name": "0"}
        tip = root
        for level in range(1, depth):
            nested = {"name": str(level)}
            tip["components"] = [nested]
            tip = nested

        walked = _walk_components([root])

        assert [x["name"] for x in walked] == [str(n) for n in range(depth)]


class TestVendoredPathsNameManifestsOnly:
    @pytest.mark.parametrize(
        "location",
        [
            "/.venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA",
            "/node_modules/left-pad/package.json",
            "/vendor/tool/t32.exe",
        ],
    )
    def test_a_file_that_is_not_a_manifest_names_no_input_file(self, location):
        assert _normalize_input_file_path(location) is None

    def test_a_lockfile_inside_a_vendored_tree_is_named(self):
        assert _normalize_input_file_path("/node_modules/pkg/yarn.lock") == "yarn.lock"

    def test_a_component_found_in_a_wheels_metadata_carries_no_input_file(
        self, tmp_path
    ):
        doc = _report(
            _reporter(tmp_path),
            [
                _component(
                    "requests", "/requirements.txt", purl="pkg:pypi/requests@2.32.3"
                ),
                _component(
                    "urllib3",
                    "/.venv/lib/python3.12/site-packages/urllib3-2.2.0.dist-info/METADATA",
                    purl="pkg:pypi/urllib3@2.2.0",
                ),
            ],
        )

        assert "gitlab:dependency_scanning:input_file:path" not in _component_props(
            doc, "urllib3"
        )
        assert (
            _component_props(doc, "requests")[
                "gitlab:dependency_scanning:input_file:path"
            ]
            == "requirements.txt"
        )


class TestDefaultsAndTheMinimalDocument:
    def test_every_mapped_type_has_a_default_lockfile(self):
        for type_key in list(SYFT_TYPE_TO_GITLAB) + list(PURL_TYPE_TO_GITLAB):
            assert type_key in _DEFAULT_LOCKFILES, type_key

    def test_a_java_archive_inventory_without_locations_names_pom_xml(self, tmp_path):
        doc = _report(
            _reporter(tmp_path),
            [
                {
                    "type": "library",
                    "name": "guava",
                    "properties": [
                        {"name": "syft:package:type", "value": "java-archive"}
                    ],
                }
            ],
        )

        props = _metadata_props(doc)
        assert props["gitlab:dependency_scanning:package_manager:name"] == "maven"
        assert props["gitlab:dependency_scanning:input_file:path"] == "pom.xml"

    def test_the_minimal_document_carries_the_category_and_the_overrides(
        self, tmp_path
    ):
        reporter = _reporter(
            tmp_path,
            category="development",
            package_manager_override="conan",
            language_override="C++",
            input_file_path_override="conanfile.txt",
        )
        model = AshAggregatedResults()
        model.cyclonedx = None

        props = _metadata_props(json.loads(reporter.report(model)))

        assert props["gitlab:meta:schema_version"] == GITLAB_SCHEMA_VERSION
        assert props["gitlab:dependency_scanning:category"] == "development"
        assert props["gitlab:dependency_scanning:package_manager:name"] == "conan"
        assert props["gitlab:dependency_scanning:language:name"] == "C++"
        assert props["gitlab:dependency_scanning:input_file:path"] == "conanfile.txt"

    def test_the_minimal_document_without_overrides_names_the_category_only(
        self, tmp_path
    ):
        model = AshAggregatedResults()
        model.cyclonedx = None

        props = _metadata_props(json.loads(_reporter(tmp_path).report(model)))

        assert props["gitlab:dependency_scanning:category"] == "production"
        assert "gitlab:dependency_scanning:package_manager:name" not in props
