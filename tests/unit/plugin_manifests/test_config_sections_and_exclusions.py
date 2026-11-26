# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config layer names no plugin: sections and exclusion options come from manifests.

The root config model's typed plugin sections (``scanners.bandit``,
``reporters.sarif``, ``converters.archive``) and the client-exclusion option table
are built from data the plugins declare (``ScannerManifest.config_section`` and
``exclusion_options``, and the reporter/converter rows in
``plugin_manifests.option_sections``). These tests bind that data to the classes
it names, fail closed, and pin the shape the generated config schema had when the
sections were written out by hand.
"""

from __future__ import annotations

import typing

import pytest
from pydantic import ValidationError

from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_manifest import (
    ConfigSection,
    ExclusionOption,
    resolve_ref,
)
from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.ash_config import (
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
from automated_security_helper.config.client_scanner_exclusions import (
    SCANNER_EXCLUSION_OPTIONS,
)
from automated_security_helper.plugin_manifests import (
    exclusion_options,
    plugin_config_sections,
    scanner_manifests,
)

pytestmark = pytest.mark.unit

#: The scanner sections as the config schema listed them before they were derived.
SCANNER_SECTION_FIELDS = {
    "actionlint": None,
    "bandit": None,
    "cdk_nag": "cdk-nag",
    "cfn_guard": "cfn-guard",
    "cfn_lint": "cfn-lint",
    "cfn_nag": "cfn-nag",
    "checkov": None,
    "detect_secrets": "detect-secrets",
    "gitleaks": None,
    "grype": None,
    "mcp_config": "mcp-config",
    "npm_audit": "npm-audit",
    "opengrep": None,
    "semgrep": None,
    "syft": None,
    "trivy": None,
    "zizmor": None,
}
REPORTER_SECTION_FIELDS = {
    "csv": None,
    "cyclonedx": None,
    "gitlab_cyclonedx": "gitlab-cyclonedx",
    "html": None,
    "flat_json": "flat-json",
    "gitlab_sast": "gitlab-sast",
    "github_ghas": "github-ghas",
    "junitxml": None,
    "markdown": None,
    "asff": None,
    "ocsf": None,
    "sarif": None,
    "spdx": None,
    "text": None,
    "unused_suppressions": "unused-suppressions",
    "yaml": None,
}
CONVERTER_SECTION_FIELDS = {"archive": None, "jupyter": None, "mcp_config": None}


def _fields_and_aliases(segment) -> dict:
    return {name: info.alias for name, info in segment.model_fields.items()}


@pytest.mark.parametrize(
    "segment,expected",
    [
        (ScannerConfigSegment, SCANNER_SECTION_FIELDS),
        (ReporterConfigSegment, REPORTER_SECTION_FIELDS),
        (ConverterConfigSegment, CONVERTER_SECTION_FIELDS),
    ],
    ids=["scanners", "reporters", "converters"],
)
def test_a_segment_has_the_sections_it_had_and_in_the_same_order(segment, expected):
    assert _fields_and_aliases(segment) == expected
    assert list(segment.model_fields) == list(expected), "schema order moved"


@pytest.mark.parametrize(
    "kind,base",
    [
        ("scanners", ScannerPluginConfigBase),
        ("reporters", ReporterPluginConfigBase),
        ("converters", ConverterPluginConfigBase),
    ],
)
def test_every_section_names_a_config_class_of_its_kind(kind, base):
    rows = plugin_config_sections(kind)
    assert rows, f"control: no {kind} sections were read"
    for plugin_name, section in rows:
        config_class = resolve_ref(section.model)
        assert issubclass(config_class, base), plugin_name
        assert section.description.startswith("Configure the options for "), plugin_name


def test_a_scanner_section_is_the_scanners_own_config_and_options_model():
    manifests = {m.name: m for m in scanner_manifests()}
    rows = plugin_config_sections("scanners")
    assert {name for name, _ in rows} == {
        name for name, m in manifests.items() if m.config_section is not None
    }
    for name, section in rows:
        config_class = resolve_ref(section.model)
        assert config_class.model_fields["name"].default == name
        options_field = config_class.model_fields["options"]
        wanted = resolve_ref(manifests[name].options_model)
        annotation = options_field.annotation
        candidates = [annotation, *typing.get_args(annotation)]
        assert wanted in candidates, (
            f"{name}: the section's options field is {annotation}, "
            f"the manifest says {wanted}"
        )


def test_only_the_builtin_scanners_have_typed_sections():
    with_section = {m.name for m in scanner_manifests() if m.config_section}
    builtin = {m.name for m in scanner_manifests() if m.default_enabled}
    assert with_section == builtin, "an alpha scanner is configured through extras"
    assert len(builtin) == 17, "control: the builtin set shrank"


def test_the_section_class_is_built_into_the_default_config():
    from automated_security_helper.config.ash_config import AshConfig

    config = AshConfig(project_name="sections")
    bandit_class = resolve_ref(
        next(s.model for n, s in plugin_config_sections("scanners") if n == "bandit")
    )
    assert type(config.scanners.bandit) is bandit_class
    assert config.scanners.model_fields["bandit"].description == (
        "Configure the options for Bandit"
    )


# -- exclusion options ------------------------------------------------------------


def test_the_exclusion_table_is_what_the_manifests_declare():
    assert {
        (s.scanner, s.option, s.kind, s.default) for s in SCANNER_EXCLUSION_OPTIONS
    } == {
        ("bandit", "excluded_paths", "bandit", ()),
        ("checkov", "skip_path", "checkov", ()),
        ("opengrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")),
        ("semgrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")),
        ("syft", "exclude", "glob", ()),
        ("ferret-scan", "exclude_patterns", "glob", ()),
        ("guarddog", "excluded_paths", "guarddog-path", ()),
        ("trivy-repo", "ignore_file", "trivy-ignore-file", ()),
        ("trivy", "ignore_file", "trivy-ignore-file", ()),
    }
    # A number, not ``len(exclusion_options())``: the table is built one-to-one from
    # that function, so comparing the two could not fail.
    assert len(SCANNER_EXCLUSION_OPTIONS) == 9


def test_a_manifest_listing_an_exclusion_option_twice_is_refused():
    manifest = next(m for m in scanner_manifests() if m.name == "bandit")
    data = manifest.model_dump()
    data["exclusion_options"] = list(data["exclusion_options"]) * 2

    with pytest.raises(ValidationError, match="lists an option twice"):
        type(manifest).model_validate(data)


def test_a_glob_builder_outside_the_plugin_module_is_refused():
    manifest = next(m for m in scanner_manifests() if m.name == "bandit")
    data = manifest.model_dump()
    data["exclusion_options"] = [
        {
            **dict(data["exclusion_options"][0]),
            "glob_builder": "automated_security_helper.config.ash_config:AshConfig",
        }
    ]

    with pytest.raises(ValidationError, match="lies outside plugin_module"):
        type(manifest).model_validate(data)


def test_an_exclusion_option_is_an_option_of_its_scanners_model():
    manifests = {m.name: m for m in scanner_manifests()}
    for scanner, option in exclusion_options():
        model = resolve_ref(manifests[scanner].options_model)
        assert option.option in model.model_fields, (scanner, option.option)


def test_ferret_scan_splits_its_entries_on_commas_and_no_other_scanner_does():
    splitting = {
        scanner for scanner, option in exclusion_options() if option.split_commas
    }
    assert splitting == {"ferret-scan"}


def test_the_glob_builder_is_the_scanners_function():
    builders = [
        option.glob_builder
        for _, option in exclusion_options()
        if option.glob_builder is not None
    ]
    assert builders == [
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "bandit_scanner:bandit_excluded_path_globs"
        )
    ]
    assert callable(resolve_ref(builders[0]))


def test_the_bandit_kind_needs_a_glob_builder_and_no_other_kind_takes_one():
    with pytest.raises(ValidationError, match="glob builder"):
        ExclusionOption(option="excluded_paths", kind="bandit")
    with pytest.raises(ValidationError, match="glob builder"):
        ExclusionOption(option="exclude", kind="glob", glob_builder="pkg.mod:build")


def test_only_plugins_that_do_not_load_by_default_declare_denied_option_defaults():
    from automated_security_helper.config.client_config_policy import (
        PLUGIN_OPTION_DEFAULTS,
    )

    declaring = {m.name for m in scanner_manifests() if m.denied_option_defaults}
    assert declaring == {m.name for m in scanner_manifests() if not m.default_enabled}
    assert {scanner for scanner, _ in PLUGIN_OPTION_DEFAULTS} == declaring
    assert len(PLUGIN_OPTION_DEFAULTS) == 48, "control: the table lost rows"
    assert PLUGIN_OPTION_DEFAULTS[("trivy-repo", "scanners")] == [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]


def test_a_denied_option_default_is_an_option_of_its_scanners_model():
    for manifest in scanner_manifests():
        model = resolve_ref(manifest.options_model)
        for option in manifest.denied_option_defaults:
            assert option in model.model_fields, (manifest.name, option)


def test_a_section_model_outside_the_plugin_is_refused():
    manifest = scanner_manifests()[0]
    data = manifest.model_dump()
    data["config_section"] = ConfigSection(
        model="automated_security_helper.config.ash_config:AshConfig",
        description="Configure the options for x",
    ).model_dump()
    with pytest.raises(ValidationError, match="lies outside plugin_module"):
        type(manifest).model_validate(data)


def test_resolve_ref_refuses_what_is_not_a_reference():
    with pytest.raises(ValueError, match="reference"):
        resolve_ref("not a reference")
    with pytest.raises(AttributeError):
        resolve_ref("automated_security_helper.base.plugin_manifest:NoSuchName")
