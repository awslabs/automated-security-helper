# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The report-level source votes of the gitlab-cyclonedx reporter, pinned.

``_resolve_dominant_type`` and ``_dominant_input_file`` pick one ecosystem and
one manifest path by counting components. This module holds a verbatim copy of
the ``Counter``-based bodies they had before the votes moved onto a polars frame,
and runs both over hand-built cases (ties, vendored-only inventories, a Syft and
a PURL type naming one ecosystem, a lone surrogate in a path) and over seeded
random inventories. A difference is a change of behavior, not of the oracle.
"""

from __future__ import annotations

import random
from collections import Counter
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter import (
    PURL_TYPE_TO_GITLAB,
    SYFT_TYPE_TO_GITLAB,
    GitLabCycloneDXReporter,
    GitLabCycloneDXReporterConfig,
    GitLabCycloneDXReporterConfigOptions,
    _declared_components,
    _ecosystem_of,
    _get_component_property,
    _normalize_input_file_path,
    _type_key_for_manager,
)

pytestmark = pytest.mark.unit


def _oracle_dominant_type(components, options):
    if options.package_manager_override:
        override_type = _type_key_for_manager(options.package_manager_override)
        if override_type is not None:
            return override_type
    pairs: Counter = Counter()
    for component in _declared_components(components):
        pm, lang = _ecosystem_of(component)
        if pm is not None:
            pairs[(pm, lang or "")] += 1
    if not pairs:
        return None
    pm, _ = pairs.most_common(1)[0][0]
    return _type_key_for_manager(pm)


def _oracle_dominant_input_file(components, dominant_type=None):
    dominant_pm = None
    if dominant_type in PURL_TYPE_TO_GITLAB:
        dominant_pm = PURL_TYPE_TO_GITLAB[dominant_type][0]
    elif dominant_type in SYFT_TYPE_TO_GITLAB:
        dominant_pm = SYFT_TYPE_TO_GITLAB[dominant_type][0]
    declared = _declared_components(components)
    if dominant_pm is not None:
        voters = [c for c in declared if _ecosystem_of(c)[0] == dominant_pm]
    else:
        voters = declared
    files: Counter = Counter()
    for component in voters:
        raw_path = _get_component_property(component, "syft:location:0:path")
        normalized = _normalize_input_file_path(raw_path)
        if normalized:
            files[normalized] += 1
    if files:
        return files.most_common(1)[0][0]
    return None


def _component(path=None, syft_type=None, purl=None):
    properties = []
    if path is not None:
        properties.append({"name": "syft:location:0:path", "value": path})
    if syft_type is not None:
        properties.append({"name": "syft:package:type", "value": syft_type})
    component = {"type": "library", "name": "c", "properties": properties}
    if purl is not None:
        component["purl"] = purl
    return component


def _reporter(**options) -> GitLabCycloneDXReporter:
    return GitLabCycloneDXReporter(
        context=PluginContext(source_dir=Path("src"), output_dir=Path("out")),
        config=GitLabCycloneDXReporterConfig(
            options=GitLabCycloneDXReporterConfigOptions(**options)
        ),
    )


HAND_CASES = {
    "empty": [],
    "tie_first_seen_wins": [
        _component("yarn.lock", "npm"),
        _component("poetry.lock", "python"),
    ],
    "tie_reversed": [
        _component("poetry.lock", "python"),
        _component("yarn.lock", "npm"),
    ],
    "syft_and_purl_name_one_ecosystem": [
        _component("a/requirements.txt", "python"),
        _component("b/requirements.txt", None, purl="pkg:pypi/x@1"),
        _component("c/yarn.lock", "npm"),
    ],
    "go_both_spellings": [
        _component("go.sum", "go-module"),
        _component("go.sum", None, purl="pkg:golang/x@1"),
        _component("package-lock.json", "npm"),
    ],
    "all_vendored": [
        _component("/.venv/lib/yarn.lock", "npm"),
        _component("/node_modules/x/package.json", "npm"),
    ],
    "vendored_ignored_when_declared_exist": [
        _component("/.venv/a/yarn.lock", "npm"),
        _component("/.venv/b/yarn.lock", "npm"),
        _component("requirements.txt", "python"),
    ],
    "no_ecosystem": [_component("x.lock", None), _component("y.lock", "unknown")],
    "no_paths": [_component(None, "npm"), _component(None, "npm")],
    "slash_only_path_is_empty": [_component("/", "npm"), _component("/", "npm")],
    "same_ecosystem_other_manager_tie": [
        _component("a.lock", "npm"),
        _component("b.lock", "npm"),
        _component("b.lock", "npm"),
        _component("a.lock", "npm"),
    ],
    "os_packages_empty_language": [
        _component("lib/apk/db/installed", "apk"),
        _component("lib/apk/db/installed", "apk"),
        _component("package-lock.json", "npm"),
    ],
    "lone_surrogate_path": [
        _component("src/\udcff/requirements.txt", "python"),
        _component("src/\udcff/requirements.txt", "python"),
        _component("src/ok/requirements.txt", "python"),
    ],
    "non_ascii_paths": [
        _component("src/é/Pipfile.lock", "python"),
        _component("src/日本/Pipfile.lock", "python"),
        _component("src/日本/Pipfile.lock", "python"),
    ],
    "vendor_only_substring_not_vendored": [
        _component("src/myvendor/yarn.lock", "npm"),
        _component("src/vendor/yarn.lock", "npm"),
    ],
}


def _every_dominant_type(components):
    keys = [None, "npm", "pypi", "python", "golang", "go-module", "apk", "nope"]
    return keys + list(PURL_TYPE_TO_GITLAB) + list(SYFT_TYPE_TO_GITLAB)


@pytest.mark.parametrize("name", sorted(HAND_CASES))
@pytest.mark.parametrize("override", [None, "yarn", "poetry", "npm", "bogus"])
def test_dominant_type_matches_the_counter_oracle(name, override):
    components = HAND_CASES[name]
    options = GitLabCycloneDXReporterConfigOptions(package_manager_override=override)
    assert _reporter()._resolve_dominant_type(
        components, options
    ) == _oracle_dominant_type(components, options)


@pytest.mark.parametrize("name", sorted(HAND_CASES))
def test_dominant_input_file_matches_the_counter_oracle(name):
    components = HAND_CASES[name]
    reporter = _reporter()
    for dominant_type in _every_dominant_type(components):
        assert reporter._dominant_input_file(
            components, dominant_type
        ) == _oracle_dominant_input_file(components, dominant_type), dominant_type
    assert reporter._dominant_input_file(components) == _oracle_dominant_input_file(
        components
    )


_PATHS = [
    None,
    "yarn.lock",
    "package-lock.json",
    "requirements.txt",
    "poetry.lock",
    "go.sum",
    "/.venv/lib/yarn.lock",
    "/node_modules/a/package.json",
    "/vendor/Gemfile.lock",
    "src/vendor/go.sum",
    "src/a/requirements.txt",
    "src/b/requirements.txt",
    "src/\udcfe/uv.lock",
    "/",
    "",
]
_TYPES = [None, "npm", "python", "go-module", "gem", "apk", "deb", "mystery"]
_PURLS = [None, "pkg:npm/a@1", "pkg:pypi/a@1", "pkg:golang/a@1", "pkg:gem/a@1", "x"]


@pytest.mark.parametrize("seed", range(60))
def test_random_inventories_match_the_counter_oracle(seed):
    rng = random.Random(seed)
    components = [
        _component(
            rng.choice(_PATHS),
            rng.choice(_TYPES),
            rng.choice(_PURLS),
        )
        for _ in range(rng.randint(0, 25))
    ]
    reporter = _reporter()
    for override in (None, "pip", "yarn"):
        options = GitLabCycloneDXReporterConfigOptions(
            package_manager_override=override
        )
        assert reporter._resolve_dominant_type(
            components, options
        ) == _oracle_dominant_type(components, options)
    dominant = _oracle_dominant_type(components, GitLabCycloneDXReporterConfigOptions())
    for dominant_type in (None, dominant):
        assert reporter._dominant_input_file(
            components, dominant_type
        ) == _oracle_dominant_input_file(components, dominant_type)
