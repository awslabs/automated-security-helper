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

import importlib
import pkgutil
import typing

import pytest
from pydantic import BaseModel, ValidationError
from pydantic_core import to_jsonable_python

from automated_security_helper.base.converter_plugin import ConverterPluginConfigBase
from automated_security_helper.base.plugin_config import plugin_config_key
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
from automated_security_helper.config.plugin_option_check import (
    _config_class,
    _options_class,
)
from automated_security_helper.config.plugin_section_names import (
    declared_section_names,
    folded_section_name,
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
    assert len(PLUGIN_OPTION_DEFAULTS) == 42, "control: the table lost rows"
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


# -- list defaults of the plugins whose section the config does not type ------------

#: Where a plugin package lists the plugins of each kind it ships, by config segment.
_PLUGIN_LISTS = {
    "scanners": "ASH_SCANNERS",
    "reporters": "ASH_REPORTERS",
    "converters": "ASH_CONVERTERS",
}

#: One row of the table: (config segment, plugin name, option path under its section).
_Row = tuple[str, str, tuple[str, ...]]


def _untyped_list_option_table():
    """``UNTYPED_LIST_OPTION_DEFAULTS``, imported here so that this module still
    collects where the table does not exist, and fails these tests with a message."""
    try:
        from automated_security_helper.plugin_manifests import (
            UNTYPED_LIST_OPTION_DEFAULTS,
        )
    except ImportError:
        pytest.fail(
            "automated_security_helper.plugin_manifests has no "
            "UNTYPED_LIST_OPTION_DEFAULTS: --config-overrides KEY+=VALUE has no "
            "default list to add to for a plugin whose section the config does "
            "not type"
        )
    return UNTYPED_LIST_OPTION_DEFAULTS


def _table_rows(table) -> dict[_Row, tuple]:
    return {
        (segment, plugin, path): tuple(items)
        for segment, plugins in table.items()
        for plugin, options in plugins.items()
        for path, items in options.items()
    }


def _table_plugins(table) -> set[tuple[str, str]]:
    """``(segment, plugin)`` for every plugin the table names, one whose row is empty
    included: ``_table_rows`` has no entry for it."""
    return {
        (segment, plugin) for segment, plugins in table.items() for plugin in plugins
    }


def _shipped_plugin_packages() -> list:
    """The plugin packages ASH ships: ``ash_builtin`` and each ``ash_*_plugins``
    package under ``plugin_modules``, found by walking it, together with every
    ``plugin_module`` a scanner manifest names. The union, so a package whose name
    does not fit the pattern is not missed, and one added later is covered without
    being listed."""
    import automated_security_helper.plugin_modules as plugin_modules

    names = {
        f"{plugin_modules.__name__}.{info.name}"
        for info in pkgutil.iter_modules(plugin_modules.__path__)
        if info.name == "ash_builtin"
        or (info.name.startswith("ash_") and info.name.endswith("_plugins"))
    }
    names.update(manifest.plugin_module for manifest in scanner_manifests())
    return [importlib.import_module(name) for name in sorted(names)]


def _list_defaults(
    options_class: type[BaseModel], path: tuple[str, ...]
) -> typing.Iterator[tuple[tuple[str, ...], tuple]]:
    """``(path, items)`` for each field of the options model whose default is a list
    or a tuple, the items as JSON values (``to_jsonable_python``, which writes a
    model as its dump, an enum as its value and a path as its text), descending
    into a field whose default is a model of its own. A field is keyed by its alias
    when it has one, as a config file spells it."""
    for name, field in options_class.model_fields.items():
        key = field.alias or name
        default = field.get_default(call_default_factory=True)
        if isinstance(default, (list, tuple)):
            yield ((*path, key), tuple(to_jsonable_python(default)))
        elif isinstance(default, BaseModel):
            yield from _list_defaults(type(default), (*path, key))


def _untyped_plugin_classes() -> list[tuple[str, str, type]]:
    """``(segment, plugin name, plugin class)`` for every plugin the shipped packages
    list whose section is not a typed field of its segment, one with no list option
    included."""
    found: list[tuple[str, str, type]] = []
    for package in _shipped_plugin_packages():
        for segment, attribute in _PLUGIN_LISTS.items():
            for plugin_class in getattr(package, attribute, None) or ():
                plugin = plugin_config_key(plugin_class)
                if folded_section_name(plugin) in declared_section_names(segment):
                    continue
                found.append((segment, plugin, plugin_class))
    return found


def _declared_plugins() -> set[tuple[str, str]]:
    """``(segment, plugin)`` for every shipped plugin whose section is not a typed
    field of its segment, whether or not it has a list option."""
    return {(segment, plugin) for segment, plugin, _ in _untyped_plugin_classes()}


def _declared_rows() -> dict[_Row, tuple]:
    """The rows the plugins' own option models give: every list option of every
    shipped plugin whose section is not a typed field of its segment."""
    rows: dict[_Row, tuple] = {}
    for segment, plugin, plugin_class in _untyped_plugin_classes():
        config_class = _config_class(plugin_class)
        options_class = (
            _options_class(config_class) if config_class is not None else None
        )
        if options_class is None:
            continue
        for path, items in _list_defaults(options_class, ("options",)):
            row = (segment, plugin, path)
            assert row not in rows, (
                f"{segment}.{plugin}.{'.'.join(path)} is declared by two plugin "
                "classes that share the key, so one row would overwrite the other"
            )
            rows[row] = items
    return rows


def test_the_walk_reaches_the_plugin_packages_it_is_meant_to_read():
    """Control: a walk that listed no package would find no row, and the table, if
    it held none either, would equal it."""
    names = {
        package.__name__.rpartition(".")[2] for package in _shipped_plugin_packages()
    }
    assert {"ash_builtin", "ash_aws_plugins", "ash_guarddog_plugins"} <= names


def test_the_untyped_list_option_table_is_what_the_plugins_declare():
    """``resolve_config`` imports no plugin package, so the list defaults it adds a
    ``+=`` to are mirrored as data; this holds them equal to the option models. It
    holds the plugins the table names equal to the shipped plugins whose section
    the config does not type as well, those with no list option included: the rows
    alone cannot name a plugin whose row is empty."""
    untyped_table = _untyped_list_option_table()
    table = _table_rows(untyped_table)
    declared = _declared_rows()

    assert declared, "control: the walk found no list option of an untyped plugin"
    listed_plugins = _table_plugins(untyped_table)
    declared_plugins = _declared_plugins()
    unlisted = sorted(declared_plugins - listed_plugins)
    unshipped = sorted(listed_plugins - declared_plugins)
    assert (unlisted, unshipped) == ([], []), (
        "UNTYPED_LIST_OPTION_DEFAULTS and the shipped plugins disagree about which "
        "plugins have a section the config does not type, each of which needs a "
        "row, empty when it has no list option: plugins with no row "
        f"{unlisted}, rows for plugins that are not shipped or have a typed "
        f"section {unshipped}"
    )

    missing = sorted(declared.keys() - table.keys())
    extra = sorted(table.keys() - declared.keys())
    changed = sorted(
        (key, table[key], declared[key])
        for key in declared.keys() & table.keys()
        if table[key] != declared[key]
    )
    assert (missing, extra, changed) == ([], [], []), (
        "UNTYPED_LIST_OPTION_DEFAULTS and the plugins' option models disagree: "
        f"options the table lacks {missing}, rows for options no untyped plugin "
        f"declares {extra}, rows whose default differs {changed}"
    )


def test_every_row_of_the_untyped_list_option_table_names_an_untyped_plugin():
    table = _untyped_list_option_table()
    assert table, "control: the table has no rows"

    for segment, plugins in table.items():
        assert segment in _PLUGIN_LISTS, segment
        typed = declared_section_names(segment)
        for plugin in plugins:
            assert folded_section_name(plugin) not in typed, (
                f"{segment}.{plugin} is a typed section of the config, whose "
                "default the document already holds"
            )
