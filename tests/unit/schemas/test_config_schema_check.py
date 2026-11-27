"""The config schema checker finds each rule's breaches, and only those.

``fixtures/improper_scanner_models.py`` holds one config model per breach of one
rule, and a few proper models. The tests here pin, model by model, which rule the
checker reports and at which JSON pointer; that the proper models report nothing;
and that the baseline and the author command say what they should. A rule that
could no longer fail would pass every other test of the suite, so each rule has a
model that must trip it.

The tests of the author command's ``--path`` mode run it in a child process. The
command imports the package it is given, which can register plugins, and a child
keeps that out of this process.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import subprocess  # nosec B404 - the test's own interpreter, fixed argv
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from automated_security_helper.base.plugin_provisioning import tool_versions
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.plugin_manifests import scanner_manifests
from automated_security_helper.schemas import config_schema_check as checker
from automated_security_helper.schemas.config_schema_check import (
    ROOT_SCANNER,
    ROOT_WORKSPACE_SCANNER,
    RULES,
    BaselineLine,
    GeneratedModule,
    Problem,
    RouteSources,
    body_sha256,
    check_bounded,
    check_closed,
    check_config_model,
    check_declared,
    check_declared_class,
    check_declared_manifest,
    check_defaulted,
    check_described,
    check_generates,
    check_keys,
    check_published,
    check_registry,
    check_root_keys,
    check_route,
    check_scanner,
    check_typed,
    compare_baseline,
    enumerate_scanners,
    format_problem,
    load_published,
    main,
    options_model_of,
    own_option_fields,
    read_baseline,
    split_generated_module,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS, REPO_ROOT, checkout_env

FIXTURE_NAME = "ash_config_schema_fixture_models"
FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "improper_scanner_models.py"
)


def _key(options: str, name: str) -> str:
    """The pointer of a key of an options model, in the schema of its section."""
    return f"/$defs/{options}/properties/{name}"


#: Each broken section: the one rule it breaks, and the pointers of its problems.
BROKEN: dict[str, tuple[str, frozenset[str]]] = {
    "CallableConfig": ("P2", frozenset({"", "/properties/options"})),
    "OpenNestedConfig": ("P3", frozenset({"/$defs/OpenNested"})),
    "DroppingNestedConfig": ("P3", frozenset({"/$defs/DroppingNested"})),
    "WrongTypedMapConfig": (
        "P3",
        frozenset({_key("WrongTypedMapOptions", "wrong")}),
    ),
    "AnyFieldConfig": ("P4", frozenset({_key("AnyFieldOptions", "anything")})),
    "UntypedDictConfig": ("P4", frozenset({_key("UntypedDictOptions", "bag")})),
    "UntypedListConfig": (
        "P4",
        frozenset({_key("UntypedListOptions", "listing") + "/items"}),
    ),
    "UndescribedFieldConfig": (
        "P5",
        frozenset({_key("UndescribedFieldOptions", "limit")}),
    ),
    "BareSectionConfig": (
        "P5",
        frozenset({"/properties/name", "/properties/enabled"}),
    ),
    "RequiredFieldConfig": (
        "P6",
        frozenset({"", "/properties/options", "/$defs/RequiredFieldOptions"}),
    ),
    "RequiredNestedConfig": ("P6", frozenset({"/$defs/NeedsKey"})),
    "BadDefaultConfig": ("P6", frozenset({_key("BadDefaultOptions", "limit")})),
    "UnboundedConfig": (
        "P7",
        frozenset(
            _key("UnboundedOptions", name) for name in ("retries", "ratio", "maybe")
        ),
    ),
    "KebabAliasConfig": ("P8", frozenset({_key("KebabAliasOptions", "skip-dirs")})),
    "FoldCollisionConfig": (
        "P8",
        frozenset({_key("FoldCollisionOptions", "skip_dirs")}),
    ),
    "TrailingUnderscoreConfig": (
        "P8",
        frozenset({_key("TrailingUnderscoreOptions", "limit_")}),
    ),
    "KebabFirstChoiceConfig": (
        "P8",
        frozenset({_key("KebabFirstChoiceOptions", "ignore-unfixed")}),
    ),
    "ByNameAliasConfig": (
        "P8",
        frozenset({_key("ByNameAliasOptions", "skip_dirs")}),
    ),
}

#: Sections that break nothing.
PROPER = (
    "ProperConfig",
    "ProperTypedMapConfig",
    "ProperTypedExtrasConfig",
    "ReservedNamesConfig",
    "AliasChoicesConfig",
)

#: Sections whose scanner classes are there for the checks of P1 alone.
DECLARATION_ONLY = frozenset({"GenericOptionsConfig", "NoNameConfig"})


@pytest.fixture(scope="module")
def models() -> Iterator[ModuleType]:
    """The fixtures module, loaded once by file path under a name of its own.

    The name is registered before the module runs, so the references the fixtures
    build (``<name>:<class>``) resolve like any manifest's.
    """
    spec = importlib.util.spec_from_file_location(FIXTURE_NAME, FIXTURE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[FIXTURE_NAME] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(FIXTURE_NAME, None)


def _loads(source: str, root: Any) -> Callable[[str, str], GeneratedModule | None]:
    """A ``load_module`` that answers every request with one generated module."""

    def load(dotted: str, root_class: str) -> GeneratedModule | None:
        return GeneratedModule(source, root)

    return load


def _sources(models: ModuleType, **overrides: Any) -> RouteSources:
    """Route sources that hold the stand-in pin, tool pin, license entry and
    operator sentence, each overridable."""
    fields: dict[str, Any] = {
        "pins": {"fixture-pin": models.pin()},
        "tool_pins": {"fixture-tool": "v1.2.3"},
        "license_versions": {"fixture-key": "1.2.3"},
        "load_module": _loads(models.generated_source(), models.GeneratedRoot),
        "operator_sentence": models.OPERATOR_SENTENCE,
    }
    fields.update(overrides)
    return RouteSources(**fields)


def _scenario(
    models: ModuleType,
    options: str = "OwnFieldOptions",
    *,
    route: Callable[..., Any] | None = None,
    pinned: bool = False,
    sources: dict[str, Any] | None = None,
    **fields: Any,
) -> tuple[Any, type, dict[str, Any]]:
    """A manifest with a route, the options class it is checked against, and the
    route sources to override. ``pinned`` gives its provisioning a tool pin."""
    build = route or models.route
    manifest = models.manifest(
        tool_config=build(**fields),
        provisioning=SimpleNamespace(tool_pins=(models.tool_pin(),) if pinned else ()),
    )
    return manifest, getattr(models, options), sources or {}


#: Routes that hold: each yields (manifest, options class, route source overrides).
PROPER_ROUTES = [
    pytest.param(lambda m: _scenario(m), id="ash route, version from a constant"),
    pytest.param(
        lambda m: _scenario(m, version="v1.2.3"), id="a leading v on the version"
    ),
    pytest.param(
        lambda m: _scenario(
            m, "BareOptions", no_options_reason="The tool takes no setting from ASH."
        ),
        id="bare options with a reason",
    ),
    pytest.param(
        lambda m: _scenario(m, pinned=True, version_source="toolpin:fixture-tool"),
        id="version from a tool pin",
    ),
    pytest.param(
        lambda m: _scenario(m, version_source="third_party_licenses:fixture-key"),
        id="version from a license entry",
    ),
    pytest.param(
        lambda m: _scenario(
            m, version_source="unpinned", unpinned_reason="Nothing pins this tool."
        ),
        id="unpinned, with a reason",
    ),
    pytest.param(
        lambda m: _scenario(m, "UpstreamOptions", route=m.upstream_route),
        id="upstream route",
    ),
]

#: Routes that each break one claim: the scenario, and the one pointer reported.
ROUTE_CONTROLS = [
    pytest.param(
        lambda m: (m.manifest(), m.OwnFieldOptions, {}),
        "/tool_config",
        id="no route",
    ),
    pytest.param(
        lambda m: _scenario(m, "BareOptions"),
        "/tool_config/no_options_reason",
        id="bare options and no reason",
    ),
    pytest.param(
        lambda m: _scenario(m, no_options_reason="The tool takes no setting."),
        "/tool_config/no_options_reason",
        id="own fields and a reason",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            pinned=True,
            version_source="toolpin:fixture-tool",
            version="1.2.4",
            read_at="owner/tool@v1.2.4",
        ),
        "/tool_config/version",
        id="version differs from its tool pin",
    ),
    pytest.param(
        lambda m: _scenario(m, read_at="owner/tool@v9.9.9"),
        "/tool_config/read_at",
        id="version absent from the tag read",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            pinned=True,
            version_source="toolpin:fixture-tool",
            read_at="owner/tool@v2.0.0",
        ),
        "/tool_config/read_at",
        id="tag read differs from the tool pin",
    ),
    pytest.param(
        lambda m: _scenario(m, version_source="unpinned"),
        "/tool_config/unpinned_reason",
        id="unpinned with no reason",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            pinned=True,
            version_source="unpinned",
            unpinned_reason="Nothing pins this tool.",
        ),
        "/tool_config/version_source",
        id="unpinned where provisioning names a tool pin",
    ),
    pytest.param(
        lambda m: _scenario(m, version_source=f"module:{m.__name__}:NO_SUCH_CONSTANT"),
        "/tool_config/version_source",
        id="module source naming a missing constant",
    ),
    pytest.param(
        lambda m: _scenario(m, version_source="toolpin:no-such-tool"),
        "/tool_config/version_source",
        id="tool pin that does not exist",
    ),
    pytest.param(
        lambda m: _scenario(m, version_source="somewhere"),
        "/tool_config/version_source",
        id="version source in no known form",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            version_source="third_party_licenses:fixture-key",
            sources={"license_versions": {"fixture-key": "2.0.0"}},
        ),
        "/tool_config/version",
        id="version differs from its license entry",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            version_source="third_party_licenses:fixture-key",
            sources={"license_versions": {}},
        ),
        "/tool_config/version_source",
        id="license entry that does not exist",
    ),
    pytest.param(
        lambda m: _scenario(m, version=""), "/tool_config/version", id="empty version"
    ),
    pytest.param(
        lambda m: _scenario(m, read_at="not a reference"),
        "/tool_config/read_at",
        id="malformed read_at",
    ),
    pytest.param(
        lambda m: _scenario(m, kind="other"),
        "/tool_config/kind",
        id="kind that is neither upstream nor ash",
    ),
    pytest.param(
        lambda m: _scenario(m, reason=""),
        "/tool_config/reason",
        id="ash route with no reason",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            "EmptyRootOptions",
            route=m.upstream_route,
            sources={"load_module": _loads(m.generated_source(), m.EmptyRoot)},
        ),
        "/tool_config/pin",
        id="upstream root class with no field",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            "UpstreamOptions",
            route=m.upstream_route,
            sources={
                "load_module": _loads(m.generated_source("b" * 64), m.GeneratedRoot)
            },
        ),
        "/tool_config/pin",
        id="header source hash differs from the pin",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            "UpstreamOptions",
            route=m.upstream_route,
            sources={
                "load_module": _loads(
                    m.generated_source(body_sha="d" * 64), m.GeneratedRoot
                )
            },
        ),
        "/tool_config/pin",
        id="body hash differs from its header",
    ),
    pytest.param(
        lambda m: _scenario(
            m,
            "UpstreamOptions",
            route=m.upstream_route,
            sources={"load_module": lambda dotted, root_class: None},
        ),
        "/tool_config/pin",
        id="generated module that does not exist",
    ),
    pytest.param(
        lambda m: _scenario(
            m, "UpstreamOptions", route=m.upstream_route, pin="no-such-pin"
        ),
        "/tool_config/pin",
        id="pin that does not exist",
    ),
    pytest.param(
        lambda m: _scenario(
            m, "UpstreamOptions", route=m.upstream_route, read_at="owner/other@v1.2.3"
        ),
        "/tool_config/read_at",
        id="upstream read_at differs from the pin",
    ),
    pytest.param(
        lambda m: _scenario(
            m, "UpstreamOptions", route=m.upstream_route, option="no_such_field"
        ),
        "/tool_config/option",
        id="upstream option that is no field",
    ),
    pytest.param(
        lambda m: _scenario(m, "UnconfinedOptions", route=m.upstream_route),
        "/tool_config/option",
        id="upstream option not confined to the operator",
    ),
]


class TestRules:
    pytestmark = pytest.mark.unit

    def test_the_rule_table_names_p1_to_p10(self) -> None:
        assert list(RULES) == [f"P{number}" for number in range(1, 11)]
        assert all(sentence.strip() for sentence in RULES.values())

    def test_the_root_labels_cannot_be_a_manifest_name(self) -> None:
        for label in (ROOT_SCANNER, ROOT_WORKSPACE_SCANNER):
            assert label.startswith("(")
        assert {manifest.name for manifest in scanner_manifests()}.isdisjoint(
            {ROOT_SCANNER, ROOT_WORKSPACE_SCANNER}
        )

    def test_problems_sort_by_rule_number_then_path(self) -> None:
        rows = [
            Problem("P10", "/a", "t"),
            Problem("P2", "/b", "t"),
            Problem("P2", "/a", "t"),
        ]
        ordered = sorted(rows, key=Problem.sort_key)
        assert [(row.rule, row.path) for row in ordered] == [
            ("P2", "/a"),
            ("P2", "/b"),
            ("P10", "/a"),
        ]

    def test_a_problem_is_one_line_of_output(self) -> None:
        assert format_problem("scan", Problem("P5", "/a", "text")) == (
            "scan\tP5\t/a\ttext"
        )

    @pytest.mark.parametrize(
        ("check", "argument", "rule"),
        [
            (check_declared_class, 42, "P1"),
            (check_described, 42, "P5"),
            (check_typed, 42, "P4"),
            (check_bounded, 42, "P7"),
        ],
    )
    def test_a_check_that_cannot_run_comes_back_as_a_row_of_its_rule(
        self, check: Callable[[Any], list[Problem]], argument: Any, rule: str
    ) -> None:
        (row,) = check(argument)
        assert row.rule == rule
        assert row.text.startswith("the check could not run")


class TestEachModelTripsOneRule:
    pytestmark = pytest.mark.unit

    @pytest.mark.parametrize("name", sorted(BROKEN))
    def test_a_broken_section_trips_its_rule_and_no_other(
        self, models: ModuleType, name: str
    ) -> None:
        rule, paths = BROKEN[name]
        rows = check_config_model(getattr(models, name))
        assert {row.rule for row in rows} == {rule}, rows
        assert {row.path for row in rows} == paths, rows
        assert len(rows) == len(paths), rows

    @pytest.mark.parametrize("name", PROPER)
    def test_a_proper_section_trips_nothing(
        self, models: ModuleType, name: str
    ) -> None:
        assert check_config_model(getattr(models, name)) == []

    def test_every_section_in_the_fixtures_is_covered(self, models: ModuleType) -> None:
        sections = {
            name
            for name, value in vars(models).items()
            if isinstance(value, type)
            and issubclass(value, ScannerPluginConfigBase)
            and value.__module__ == FIXTURE_NAME
            and name.endswith("Config")
        }
        assert sections == set(BROKEN) | set(PROPER) | DECLARATION_ONLY

    @pytest.mark.parametrize(
        "check", [check_generates, check_closed, check_defaulted, check_keys]
    )
    def test_each_rule_on_a_class_is_clean_for_the_proper_section(
        self, models: ModuleType, check: Callable[[Any], list[Problem]]
    ) -> None:
        assert check(models.ProperConfig) == []

    @pytest.mark.parametrize("check", [check_typed, check_described, check_bounded])
    def test_each_rule_on_a_schema_is_clean_for_the_proper_section(
        self, models: ModuleType, check: Callable[[Any], list[Problem]]
    ) -> None:
        assert check(models.ProperConfig.model_json_schema()) == []


class TestDeclared:
    pytestmark = pytest.mark.unit

    def test_a_scanner_that_declares_its_config_and_options_is_clean(
        self, models: ModuleType
    ) -> None:
        assert check_declared_class(models.ProperScanner) == []

    def test_a_scanner_with_no_config_class_is_reported(
        self, models: ModuleType
    ) -> None:
        (row,) = check_declared_class(models.UndeclaredScanner)
        assert (row.rule, row.path) == ("P1", "/config")

    def test_generic_options_are_the_missing_schema(self, models: ModuleType) -> None:
        (row,) = check_declared_class(models.GenericOptionsScanner)
        assert (row.rule, row.path) == ("P1", "/config/options")
        assert "generic ScannerOptionsBase" in row.text

    def test_a_config_with_no_name_default_is_reported(
        self, models: ModuleType
    ) -> None:
        (row,) = check_declared_class(models.NoNameScanner)
        assert (row.rule, row.path) == ("P1", "/config/name")

    def test_a_manifest_that_agrees_with_its_scanner_is_clean(
        self, models: ModuleType
    ) -> None:
        assert check_declared_manifest(models.manifest(), models.ProperScanner) == []

    def test_an_options_model_that_does_not_resolve_is_reported(
        self, models: ModuleType
    ) -> None:
        manifest = models.manifest(options_model="no_such_fixture_module:Missing")
        (row,) = check_declared_manifest(manifest, models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/options_model")
        assert "does not resolve" in row.text

    def test_an_options_model_that_is_no_model_is_reported(
        self, models: ModuleType
    ) -> None:
        manifest = models.manifest(options_model=f"{FIXTURE_NAME}:FIXTURE_TOOL_VERSION")
        (row,) = check_declared_manifest(manifest, models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/options_model")
        assert "is not a model class" in row.text

    def test_an_options_model_that_is_another_class_is_reported(
        self, models: ModuleType
    ) -> None:
        manifest = models.manifest(options_model=f"{FIXTURE_NAME}:OwnFieldOptions")
        (row,) = check_declared_manifest(manifest, models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/options_model")
        assert "config types options as" in row.text

    def test_an_entry_point_naming_another_class_is_reported(
        self, models: ModuleType
    ) -> None:
        other = SimpleNamespace(scanner=f"{FIXTURE_NAME}:UndeclaredScanner")
        manifest = models.manifest(entry_points=other)
        (row,) = check_declared_manifest(manifest, models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/entry_points/scanner")
        assert "the registered class is" in row.text

    def test_a_name_that_differs_from_the_name_default_is_reported(
        self, models: ModuleType
    ) -> None:
        manifest = models.manifest(name="other-name")
        (row,) = check_declared_manifest(manifest, models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/name")
        assert "name default" in row.text

    def test_a_manifest_that_no_registered_class_answers_to_is_reported(
        self, models: ModuleType
    ) -> None:
        (row,) = check_declared_manifest(models.manifest(), None)
        assert (row.rule, row.path) == ("P1", "/entry_points/scanner")
        assert "no plugin package registers" in row.text

    def test_the_missing_schema_control_trips_both_halves(
        self, models: ModuleType
    ) -> None:
        manifest = models.manifest(
            entry_points=SimpleNamespace(
                scanner=f"{FIXTURE_NAME}:GenericOptionsScanner"
            ),
            options_model="no_such_fixture_module:Missing",
        )
        rows = check_declared(models.GenericOptionsScanner, manifest)
        assert {(row.rule, row.path) for row in rows} == {
            ("P1", "/config/options"),
            ("P1", "/options_model"),
        }

    def test_a_scanner_with_no_manifest_is_reported_unless_none_is_expected(
        self, models: ModuleType
    ) -> None:
        (row,) = check_scanner(models.ProperScanner)
        assert (row.rule, row.path) == ("P1", "/entry_points/scanner")
        assert check_scanner(models.ProperScanner, require_manifest=False) == []

    def test_the_options_class_of_a_config_is_read_from_its_options_field(
        self, models: ModuleType
    ) -> None:
        assert options_model_of(models.ProperConfig) is models.ProperOptions
        assert options_model_of(models.OwnFieldOptions) is None

    def test_an_option_a_generic_base_declares_is_not_the_scanners_own(
        self, models: ModuleType
    ) -> None:
        assert own_option_fields(models.BareOptions) == []
        assert own_option_fields(models.OwnFieldOptions) == ["own_setting"]


class TestGenerates:
    pytestmark = pytest.mark.unit

    def test_a_section_with_a_schema_reports_nothing(self, models: ModuleType) -> None:
        assert check_generates(models.ProperConfig) == []

    def test_a_field_with_no_json_schema_is_reported_for_the_section_and_options(
        self, models: ModuleType
    ) -> None:
        rows = check_generates(models.CallableConfig)
        assert {row.path for row in rows} == {"", "/properties/options"}
        assert all("cannot be generated" in row.text for row in rows)


class TestClosed:
    pytestmark = pytest.mark.unit

    def test_a_nested_model_that_keeps_undeclared_keys_fails_both_halves(
        self, models: ModuleType
    ) -> None:
        (row,) = check_closed(models.OpenNestedConfig)
        assert row.path == "/$defs/OpenNested"
        assert "additionalProperties is true" in row.text
        assert "keeps it as an extra" in row.text

    def test_a_nested_model_that_drops_undeclared_keys_fails_both_halves(
        self, models: ModuleType
    ) -> None:
        (row,) = check_closed(models.DroppingNestedConfig)
        assert row.path == "/$defs/DroppingNested"
        assert "additionalProperties is absent" in row.text
        assert "drops it silently" in row.text

    def test_a_map_that_types_values_only_in_its_schema_is_reported(
        self, models: ModuleType
    ) -> None:
        (row,) = check_closed(models.WrongTypedMapConfig)
        assert row.path == _key("WrongTypedMapOptions", "wrong")
        assert "accepts values of the wrong type" in row.text

    @pytest.mark.parametrize(
        "name", ["ProperTypedMapConfig", "ProperTypedExtrasConfig"]
    )
    def test_a_typed_map_that_refuses_a_wrong_value_is_closed(
        self, models: ModuleType, name: str
    ) -> None:
        assert check_closed(getattr(models, name)) == []

    def test_a_node_the_tools_own_schema_leaves_open_can_be_listed(
        self, models: ModuleType
    ) -> None:
        rows = check_closed(models.OpenNestedConfig, open_nodes=["/$defs/OpenNested"])
        assert rows == []

    def test_a_section_that_does_not_construct_is_not_probed(
        self, models: ModuleType
    ) -> None:
        assert check_closed(models.RequiredFieldConfig) == []


class TestSchemaRules:
    pytestmark = pytest.mark.unit

    def test_an_empty_property_schema_has_no_type(self) -> None:
        rows = check_typed({"type": "object", "properties": {"a": {}}})
        assert [(row.rule, row.path) for row in rows] == [("P4", "/properties/a")]

    def test_an_array_with_no_items_is_reported(self) -> None:
        schema = {"type": "object", "properties": {"a": {"type": "array"}}}
        (row,) = check_typed(schema)
        assert row.path == "/properties/a"
        assert "declares no items" in row.text

    def test_a_map_is_typed_by_a_value_schema_or_by_a_key_pattern(self) -> None:
        untyped = {
            "type": "object",
            "properties": {"a": {"type": "object", "additionalProperties": True}},
        }
        (row,) = check_typed(untyped)
        assert row.path == "/properties/a"
        assert "no typed value schema" in row.text
        by_pattern = {
            "type": "object",
            "properties": {
                "a": {
                    "type": "object",
                    "patternProperties": {"^E[0-9]+$": {"type": "string"}},
                }
            },
        }
        assert check_typed(by_pattern) == []

    def test_a_union_is_typed_when_each_arm_is(self) -> None:
        typed = {"anyOf": [{"type": "string"}, {"type": "null"}]}
        untyped = {"anyOf": [{"type": "string"}, {}]}
        schema = {"type": "object", "properties": {"a": typed, "b": untyped}}
        assert [row.path for row in check_typed(schema)] == ["/properties/b/anyOf/1"]

    def test_a_node_listed_as_open_is_not_read(self) -> None:
        schema = {"type": "object", "properties": {"a": {}}}
        assert check_typed(schema, open_nodes=["/properties/a"]) == []

    def test_a_property_with_no_or_a_blank_description_is_reported(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string", "description": "  "},
                "c": {"type": "string", "description": "What it does."},
            },
        }
        assert [row.path for row in check_described(schema)] == [
            "/properties/a",
            "/properties/b",
        ]

    def test_a_number_needs_a_lower_bound_not_an_upper_one(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer", "minimum": 0},
                "c": {"type": "number", "exclusiveMinimum": 0},
                "d": {"type": "integer", "maximum": 5},
                "e": {"type": "integer", "enum": [1, 2]},
                "f": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
                "g": {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
            },
        }
        assert [row.path for row in check_bounded(schema)] == [
            "/properties/a",
            "/properties/d",
            "/properties/f",
        ]

    def test_a_definition_generated_from_a_tools_schema_is_exempt(self) -> None:
        schema = {
            "$defs": {
                "Generated": {
                    "type": "object",
                    "properties": {"x": {"type": "integer"}},
                },
                "Written": {
                    "type": "object",
                    "properties": {"y": {"type": "integer"}},
                },
            }
        }
        assert [row.path for row in check_bounded(schema)] == [
            "/$defs/Generated/properties/x",
            "/$defs/Written/properties/y",
        ]
        exempt = check_bounded(schema, generated=["/$defs/Generated"])
        assert [row.path for row in exempt] == ["/$defs/Written/properties/y"]


class TestDefaulted:
    pytestmark = pytest.mark.unit

    def test_a_section_that_does_not_construct_says_the_probe_is_skipped(
        self, models: ModuleType
    ) -> None:
        rows = {
            row.path: row.text for row in check_defaulted(models.RequiredFieldConfig)
        }
        assert "does not construct" in rows["/properties/options"]
        assert "skipped" not in rows["/properties/options"]
        assert "does not construct" in rows[""]
        assert "undeclared-key probe of P3" in rows[""]
        assert "so it is skipped" in rows[""]
        assert (
            "lists required properties (limit)" in rows["/$defs/RequiredFieldOptions"]
        )

    def test_a_required_key_of_a_nested_model_is_reported_at_the_model(
        self, models: ModuleType
    ) -> None:
        (row,) = check_defaulted(models.RequiredNestedConfig)
        assert row.path == "/$defs/NeedsKey"
        assert "lists required properties (token)" in row.text

    def test_a_default_that_fails_its_field_is_reported_at_its_key_in_the_options(
        self, models: ModuleType
    ) -> None:
        (row,) = check_defaulted(models.BadDefaultConfig)
        assert row.path == _key("BadDefaultOptions", "limit")
        assert "does not validate against its own field" in row.text

    def test_the_proper_section_and_its_typed_extras_round_trip(
        self, models: ModuleType
    ) -> None:
        assert check_defaulted(models.ProperConfig) == []
        assert check_defaulted(models.ProperTypedExtrasConfig) == []


class TestKeys:
    pytestmark = pytest.mark.unit

    def test_each_key_problem_says_what_is_wrong(self, models: ModuleType) -> None:
        (kebab,) = check_keys(models.KebabAliasConfig)
        assert "not snake_case" in kebab.text
        (fold,) = check_keys(models.FoldCollisionConfig)
        assert "'skip_dirs', 'skipdirs'" in fold.text
        assert "differ only in" in fold.text
        (underscore,) = check_keys(models.TrailingUnderscoreConfig)
        assert "ends in an underscore" in underscore.text
        (by_name,) = check_keys(models.ByNameAliasConfig)
        assert "validates by name only" in by_name.text

    def test_the_first_alias_choice_is_the_published_key(
        self, models: ModuleType
    ) -> None:
        assert check_keys(models.AliasChoicesConfig) == []
        (row,) = check_keys(models.KebabFirstChoiceConfig)
        assert row.path == _key("KebabFirstChoiceOptions", "ignore-unfixed")

    def test_a_trailing_underscore_is_allowed_on_a_reserved_name_only(
        self, models: ModuleType
    ) -> None:
        assert check_keys(models.ReservedNamesConfig) == []
        (row,) = check_keys(models.TrailingUnderscoreConfig)
        assert row.path == _key("TrailingUnderscoreOptions", "limit_")

    def test_the_root_check_reads_the_keys_outside_the_plugin_sections(
        self, models: ModuleType
    ) -> None:
        assert check_root_keys(models.ProperRoot) == []
        (row,) = check_root_keys(models.KebabRoot)
        assert (row.rule, row.path) == ("P8", "/properties/mcp-resource-management")

    def test_a_plugin_segment_is_entered_only_when_the_root_check_is_told_to(
        self, models: ModuleType
    ) -> None:
        assert check_root_keys(models.SegmentedRoot) == []
        (row,) = check_root_keys(models.SegmentedRoot, plugin_segments=())
        assert row.path == "/$defs/KebabSegment/properties/cfn-lint"

    def test_a_planted_key_in_the_published_config_is_found(self) -> None:
        published = load_published()
        before = {row.path for row in check_root_keys(published)}
        planted = copy.deepcopy(published)
        planted["$defs"]["AshConfig"]["properties"]["planted-key"] = {
            "type": "string",
            "description": "A key planted to see that the root check reads it.",
        }
        after = {row.path for row in check_root_keys(planted)}
        assert after - before == {"/$defs/AshConfig/properties/planted-key"}
        assert before <= after

    def test_a_planted_key_in_the_workspace_config_is_found(self) -> None:
        published = load_published("AshWorkspaceConfig.json")
        before = {row.path for row in check_root_keys(published)}
        planted = copy.deepcopy(published)
        planted["properties"]["planted-key"] = {
            "type": "string",
            "description": "A key planted to see that the root check reads it.",
        }
        after = {row.path for row in check_root_keys(planted)}
        assert after - before == {"/properties/planted-key"}


class TestPublished:
    pytestmark = pytest.mark.unit

    def test_a_section_that_refers_to_the_config_class_is_clean(
        self, models: ModuleType
    ) -> None:
        published = models.published_schema()
        assert check_published(published, "fixture-scanner", models.ProperConfig) == []

    def test_the_target_may_carry_a_module_prefix(self, models: ModuleType) -> None:
        section = {"$ref": "#/$defs/some_module__ProperConfig", "description": "d"}
        published = models.published_schema({"fixture-scanner": section})
        assert check_published(published, "fixture-scanner", models.ProperConfig) == []

    def test_the_target_is_not_compared_when_no_class_is_given(
        self, models: ModuleType
    ) -> None:
        section = {"$ref": "#/$defs/Anything", "description": "d"}
        published = models.published_schema({"fixture-scanner": section})
        assert check_published(published, "fixture-scanner") == []

    @pytest.mark.parametrize(
        ("section", "said"),
        [
            (None, "has no section for 'fixture-scanner'"),
            ({"$ref": "#/$defs/ProperConfig"}, "has no description"),
            (
                {"$ref": "#/$defs/ProperConfig", "description": " "},
                "has no description",
            ),
            ({"description": "d"}, "does not refer to a model"),
            (
                {"$ref": "#/$defs/OtherConfig", "description": "d"},
                "not to the scanner's config class",
            ),
        ],
        ids=[
            "missing section",
            "no description",
            "blank description",
            "no reference",
            "another class",
        ],
    )
    def test_each_fault_of_a_section_is_one_problem_at_the_section(
        self, models: ModuleType, section: dict[str, Any] | None, said: str
    ) -> None:
        sections = {} if section is None else {"fixture-scanner": section}
        published = models.published_schema(sections)
        (row,) = check_published(published, "fixture-scanner", models.ProperConfig)
        assert row.rule == "P9"
        assert row.path == "/$defs/ScannerConfigSegment/properties/fixture-scanner"
        assert said in row.text

    def test_a_schema_with_no_scanners_segment_is_reported_once(self) -> None:
        (row,) = check_published({}, "fixture-scanner")
        assert (row.rule, row.path) == ("P9", "")
        assert "no scanners segment" in row.text

    def test_the_committed_file_has_a_section_for_a_builtin_scanner(self) -> None:
        assert check_published(load_published(), "bandit") == []

    def test_the_published_control_is_the_committed_file_with_one_section_removed(
        self,
    ) -> None:
        published = copy.deepcopy(load_published())
        del published["$defs"]["ScannerConfigSegment"]["properties"]["bandit"]
        (row,) = check_published(published, "bandit")
        assert (row.rule, row.path) == (
            "P9",
            "/$defs/ScannerConfigSegment/properties/bandit",
        )


class TestRoute:
    pytestmark = pytest.mark.unit

    @pytest.mark.parametrize("build", PROPER_ROUTES)
    def test_a_route_whose_claims_hold_has_no_problem(
        self, models: ModuleType, build: Callable[[ModuleType], Any]
    ) -> None:
        manifest, options, overrides = build(models)
        sources = _sources(models, **overrides)
        assert check_route(manifest, options, sources=sources) == []

    @pytest.mark.parametrize(("build", "path"), ROUTE_CONTROLS)
    def test_a_route_that_breaks_one_claim_is_one_problem_at_that_claim(
        self, models: ModuleType, build: Callable[[ModuleType], Any], path: str
    ) -> None:
        manifest, options, overrides = build(models)
        sources = _sources(models, **overrides)
        rows = check_route(manifest, options, sources=sources)
        assert [(row.rule, row.path) for row in rows] == [("P10", path)], rows

    def test_a_manifest_with_no_tool_config_field_has_no_route(
        self, models: ModuleType
    ) -> None:
        manifest = SimpleNamespace(name="fixture-scanner")
        (row,) = check_route(manifest, models.OwnFieldOptions)
        assert (row.rule, row.path) == ("P10", "/tool_config")

    def test_the_header_of_a_generated_module_is_its_leading_comment_lines(
        self, models: ModuleType
    ) -> None:
        source = models.generated_source()
        fields, body = split_generated_module(source)
        assert fields["source sha256"] == models.pin().sha256
        assert body == models.GENERATED_BODY
        assert fields["body sha256"] == body_sha256(body)
        assert body_sha256(body) == hashlib.sha256(body.encode("utf-8")).hexdigest()

    def test_a_generated_module_with_crlf_line_ends_is_read_as_lf(
        self, models: ModuleType
    ) -> None:
        source = models.generated_source()
        assert split_generated_module(source.replace("\n", "\r\n")) == (
            split_generated_module(source)
        )

    def test_the_default_sources_read_this_installation(self) -> None:
        sources = RouteSources()
        versions = tool_versions()
        assert versions
        tool, version = next(iter(versions.items()))
        assert sources.tool_version(tool) == version
        assert sources.tool_version("no-such-tool") is None
        assert sources.license_version("no-such-key") is None
        assert sources.pin("no-such-pin") is None
        assert sources.operator_only_sentence()


class TestScanner:
    pytestmark = pytest.mark.unit

    @staticmethod
    def _arguments(models: ModuleType) -> dict[str, Any]:
        return {
            "manifest": models.manifest(tool_config=models.route()),
            "published": models.published_schema(),
            "sources": _sources(models),
        }

    def test_a_proper_scanner_has_no_problem_under_any_rule(
        self, models: ModuleType
    ) -> None:
        given = self._arguments(models)
        rows = check_scanner(
            models.ProperScanner,
            given["manifest"],
            published=given["published"],
            sources=given["sources"],
        )
        assert rows == []

    @pytest.mark.parametrize(
        ("fault", "rule"),
        [
            pytest.param(
                lambda m: {"published": m.published_schema({})}, "P9", id="no section"
            ),
            pytest.param(
                lambda m: {
                    "manifest": m.manifest(tool_config=m.route(version="9.9.9"))
                },
                "P10",
                id="wrong route",
            ),
            pytest.param(
                lambda m: {
                    "manifest": m.manifest(
                        tool_config=m.route(),
                        options_model=f"{m.__name__}:OwnFieldOptions",
                    )
                },
                "P1",
                id="wrong options model",
            ),
        ],
    )
    def test_one_fault_trips_only_its_rule(
        self, models: ModuleType, fault: Callable[[ModuleType], Any], rule: str
    ) -> None:
        given = self._arguments(models)
        given.update(fault(models))
        rows = check_scanner(
            models.ProperScanner,
            given["manifest"],
            published=given["published"],
            sources=given["sources"],
        )
        assert rows
        assert {row.rule for row in rows} == {rule}


class TestEnumeration:
    pytestmark = pytest.mark.unit

    def test_every_manifest_has_a_registered_class(self) -> None:
        enumeration = enumerate_scanners()
        names = {subject.name for subject in enumeration.subjects}
        assert enumeration.failures == {}
        assert names == {manifest.name for manifest in scanner_manifests()}
        assert [subject.name for subject in enumeration.subjects] == sorted(names)
        for subject in enumeration.subjects:
            assert subject.scanner_class is not None, subject.name
            assert subject.manifest is not None, subject.name
        assert {"cdk-nag", "semgrep", "opengrep", "trivy-repo", "snyk-code"} <= names

    def test_a_manifest_that_no_class_registers_is_a_subject_of_its_own(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ghost = SimpleNamespace(
            name="ghost-scanner",
            entry_points=SimpleNamespace(scanner="no_such_module:Ghost"),
        )
        shipped = list(scanner_manifests())
        monkeypatch.setattr(
            "automated_security_helper.plugin_manifests.scanner_manifests",
            lambda: [*shipped, ghost],
        )
        subjects = {subject.name: subject for subject in enumerate_scanners().subjects}
        assert subjects["ghost-scanner"].scanner_class is None
        assert subjects["ghost-scanner"].manifest is ghost
        rows = check_scanner(None, ghost)
        assert ("P1", "/entry_points/scanner") in {(r.rule, r.path) for r in rows}

    def test_a_class_that_no_manifest_names_is_a_subject_of_its_own(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        kept = [m for m in scanner_manifests() if m.name != "bandit"]
        monkeypatch.setattr(
            "automated_security_helper.plugin_manifests.scanner_manifests",
            lambda: kept,
        )
        subjects = {subject.name: subject for subject in enumerate_scanners().subjects}
        subject = subjects["bandit"]
        assert subject.manifest is None
        assert subject.scanner_class is not None
        rows = check_scanner(subject.scanner_class, subject.manifest)
        assert ("P1", "/entry_points/scanner") in {(r.rule, r.path) for r in rows}

    def test_the_registry_check_covers_every_scanner_and_both_roots(self) -> None:
        findings = check_registry()
        names = {manifest.name for manifest in scanner_manifests()}
        assert set(findings) == names | {ROOT_SCANNER, ROOT_WORKSPACE_SCANNER}
        for rows in findings.values():
            assert isinstance(rows, list)
            assert all(isinstance(row, Problem) for row in rows)
            assert {row.rule for row in rows} <= set(RULES)


FINDINGS = {
    "alpha-scanner": [Problem("P5", "/$defs/A/properties/limit", "has no description")],
    "beta-scanner": [],
}
LISTED = "alpha-scanner\tP5\t/$defs/A/properties/limit\tfix-limit"


def _write_baseline(path: Path, *lines: str) -> Path:
    """A baseline file with LF line ends on every platform."""
    path.write_text(
        "".join(f"{line}\n" for line in lines), encoding="utf-8", newline="\n"
    )
    return path


class TestBaseline:
    pytestmark = pytest.mark.unit

    def test_a_baseline_line_has_four_tab_separated_fields(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "baseline.tsv"
        path.write_text(
            "a\tP1\t/x\tfix-1\n\nb\tP9\t\tfix-2\n", encoding="utf-8", newline="\n"
        )
        assert read_baseline(path) == [
            BaselineLine("a", "P1", "/x", "fix-1"),
            BaselineLine("b", "P9", "", "fix-2"),
        ]

    @pytest.mark.parametrize(
        "line", ["a\tP1\t/x", "a\tP1\t/x\tfix\textra", "a\tP1\t/x\t", "\tP1\t/x\tfix"]
    )
    def test_a_line_that_is_not_four_fields_is_refused_with_its_number(
        self, tmp_path: Path, line: str
    ) -> None:
        path = _write_baseline(tmp_path / "baseline.tsv", "a\tP1\t/x\tfix", line)
        with pytest.raises(ValueError) as refusal:
            read_baseline(path)
        assert ":2:" in str(refusal.value)

    def test_the_comparison_names_the_new_problems_and_the_stale_lines(self) -> None:
        listed = BaselineLine("alpha-scanner", "P5", "/$defs/A/properties/limit", "f")
        gone = BaselineLine("beta-scanner", "P1", "/config", "g")
        new, stale = compare_baseline(FINDINGS, [listed, gone])
        assert new == []
        assert stale == [gone]
        new, stale = compare_baseline(FINDINGS, [])
        assert [(scanner, row.rule) for scanner, row in new] == [
            ("alpha-scanner", "P5")
        ]
        assert stale == []

    def test_a_problem_is_matched_by_scanner_rule_and_pointer_not_by_its_text(
        self,
    ) -> None:
        reworded = {"alpha-scanner": [Problem("P5", "/$defs/A/properties/limit", "x")]}
        new, stale = compare_baseline(reworded, [BaselineLine(*LISTED.split("\t"))])
        assert (new, stale) == ([], [])


class TestCommand:
    pytestmark = pytest.mark.unit

    @pytest.fixture
    def fixed_registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(checker, "check_registry", lambda: FINDINGS)

    def test_with_no_baseline_every_problem_is_printed_and_the_exit_is_one(
        self, fixed_registry: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = io.StringIO()
        assert main([], out=out) == 1
        assert out.getvalue() == (
            "alpha-scanner\tP5\t/$defs/A/properties/limit\thas no description\n"
        )
        summary = capsys.readouterr().err
        assert "checked 2 scanner(s) or root surface(s): 1 problem(s)" in summary

    def test_with_nothing_to_print_the_exit_is_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(checker, "check_registry", lambda: {"a-scanner": []})
        out = io.StringIO()
        assert main([], out=out) == 0
        assert out.getvalue() == ""

    def test_a_problem_the_baseline_lists_is_not_printed(
        self, fixed_registry: None, tmp_path: Path
    ) -> None:
        baseline = _write_baseline(tmp_path / "baseline.tsv", LISTED)
        out = io.StringIO()
        assert main(["--baseline", str(baseline)], out=out) == 0
        assert out.getvalue() == ""

    def test_a_problem_the_baseline_does_not_list_is_printed_as_new(
        self, fixed_registry: None, tmp_path: Path
    ) -> None:
        other = "alpha-scanner\tP5\t/$defs/A/properties/other\tfix-other"
        baseline = _write_baseline(tmp_path / "baseline.tsv", other)
        out = io.StringIO()
        assert main(["--baseline", str(baseline)], out=out) == 1
        lines = out.getvalue().splitlines()
        assert lines[0] == (
            "new\talpha-scanner\tP5\t/$defs/A/properties/limit\thas no description"
        )
        assert lines[1:] == ["stale\t" + other]

    def test_a_line_that_no_longer_occurs_is_printed_as_stale(
        self, fixed_registry: None, tmp_path: Path
    ) -> None:
        gone = "beta-scanner\tP1\t/config\tfix-config"
        baseline = _write_baseline(tmp_path / "baseline.tsv", LISTED, gone)
        out = io.StringIO()
        assert main(["--baseline", str(baseline)], out=out) == 1
        assert out.getvalue() == "stale\t" + gone + "\n"

    def test_a_baseline_that_cannot_be_read_is_an_error_not_a_pass(
        self, fixed_registry: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        malformed = _write_baseline(tmp_path / "bad.tsv", "alpha-scanner\tP5")
        out = io.StringIO()
        assert main(["--baseline", str(malformed)], out=out) == 2
        assert out.getvalue() == ""
        assert "expected scanner, rule, JSON pointer and fix id" in (
            capsys.readouterr().err
        )
        absent = tmp_path / "absent.tsv"
        assert main(["--baseline", str(absent)], out=io.StringIO()) == 2
        assert capsys.readouterr().err.startswith("error:")

    def test_output_is_ascii(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = "caf" + chr(0xE9)
        monkeypatch.setattr(
            checker, "check_registry", lambda: {"s": [Problem("P5", "/p", text)]}
        )
        out = io.StringIO()
        assert main([], out=out) == 1
        assert out.getvalue().isascii()
        assert ascii(text)[1:-1] in out.getvalue()

    def test_a_directory_that_is_no_package_is_one_problem_without_importing_it(
        self, tmp_path: Path
    ) -> None:
        empty = tmp_path / "ash_check_fixture_no_package"
        empty.mkdir()
        out = io.StringIO()
        assert main(["--path", str(empty)], out=out) == 1
        (line,) = out.getvalue().splitlines()
        scanner, rule, pointer, text = line.split("\t")
        assert (scanner, rule, pointer) == ("ash_check_fixture_no_package", "P1", "")
        assert "not a plugin package" in text

    def test_the_help_lists_the_rules_and_both_modes(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as stopped:
            main(["--help"])
        assert stopped.value.code == 0
        printed = capsys.readouterr().out
        assert "--path" in printed
        assert "--baseline" in printed
        assert all(rule in printed for rule in RULES)

    def test_a_usage_error_exits_with_two(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as stopped:
            main(["--no-such-option"])
        assert stopped.value.code == 2
        assert "--no-such-option" in capsys.readouterr().err


#: A plugin package with one scanner: ``{description}`` is the description of the
#: one options field, left out to make the field a problem.
PLUGIN_PACKAGE = """\
from typing import Annotated, Literal

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)


class FixtureOptions(ScannerOptionsBase):
    limit: Annotated[int, Field(ge=1{description})] = 1


class FixtureConfig(ScannerPluginConfigBase):
    name: Annotated[
        Literal["pkg-scanner"], Field(description="The scanner's name.")
    ] = "pkg-scanner"
    enabled: Annotated[bool, Field(description="Whether it runs.")] = True
    options: Annotated[FixtureOptions, Field(description="Its options.")] = (
        FixtureOptions()
    )


class FixtureScanner(ScannerPluginBase[FixtureConfig]):
    pass


ASH_SCANNERS = [FixtureScanner]
"""
DESCRIBED = ', description="How many."'
LIMIT = "/$defs/FixtureOptions/properties/limit"


def _plugin_package(root: Path, name: str, source: str) -> Path:
    """A package directory ``name`` under ``root`` whose ``__init__.py`` is ``source``."""
    directory = root / name
    directory.mkdir()
    (directory / "__init__.py").write_text(source, encoding="utf-8", newline="\n")
    return directory


def _author_command(*arguments: str) -> subprocess.CompletedProcess[str]:
    """The author command in a child process that imports this checkout."""
    return subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-B",
            "-m",
            "automated_security_helper.schemas.config_schema_check",
            *arguments,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=REPO_ROOT,
        env=checkout_env(),
        timeout=CHILD_TIMEOUT_SECONDS,
        check=False,
    )


class TestPathInAChildProcess:
    pytestmark = pytest.mark.integration

    def test_an_undescribed_field_is_one_p5_line(self, tmp_path: Path) -> None:
        source = PLUGIN_PACKAGE.format(description="")
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_a", source)
        done = _author_command("--path", str(package))
        assert done.returncode == 1, done.stderr
        (line,) = done.stdout.splitlines()
        scanner, rule, pointer, text = line.split("\t")
        assert (scanner, rule, pointer) == ("pkg-scanner", "P5", LIMIT)
        assert "has no description" in text
        assert "1 problem(s)" in done.stderr

    def test_the_same_package_with_the_field_described_is_clean(
        self, tmp_path: Path
    ) -> None:
        source = PLUGIN_PACKAGE.format(description=DESCRIBED)
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_b", source)
        done = _author_command("--path", str(package))
        assert done.returncode == 0, done.stdout + done.stderr
        assert done.stdout == ""

    def test_a_package_that_fails_to_import_is_one_p1_line(
        self, tmp_path: Path
    ) -> None:
        source = 'raise RuntimeError("the package cannot be imported")\n'
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_c", source)
        done = _author_command("--path", str(package))
        assert done.returncode == 1, done.stderr
        (line,) = done.stdout.splitlines()
        scanner, rule, pointer, text = line.split("\t")
        assert (scanner, rule, pointer) == ("ash_check_fixture_pkg_c", "P1", "")
        assert text.startswith("importing ash_check_fixture_pkg_c failed")
        assert "the package cannot be imported" in text

    def test_a_package_that_exports_no_scanners_is_one_p1_line(
        self, tmp_path: Path
    ) -> None:
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_d", "VALUE = 1\n")
        done = _author_command("--path", str(package))
        assert done.returncode == 1, done.stderr
        (line,) = done.stdout.splitlines()
        assert line.split("\t")[:3] == ["ash_check_fixture_pkg_d", "P1", ""]
        assert "exports no ASH_SCANNERS" in line

    def test_a_baseline_that_lists_the_problem_suppresses_it(
        self, tmp_path: Path
    ) -> None:
        source = PLUGIN_PACKAGE.format(description="")
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_e", source)
        listed = f"pkg-scanner\tP5\t{LIMIT}\tfix-limit"
        baseline = _write_baseline(tmp_path / "baseline.tsv", listed)
        done = _author_command("--path", str(package), "--baseline", str(baseline))
        assert done.returncode == 0, done.stdout + done.stderr
        assert done.stdout == ""

    def test_a_problem_the_baseline_does_not_list_is_printed_as_new(
        self, tmp_path: Path
    ) -> None:
        source = PLUGIN_PACKAGE.format(description="")
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_f", source)
        baseline = _write_baseline(tmp_path / "baseline.tsv")
        done = _author_command("--path", str(package), "--baseline", str(baseline))
        assert done.returncode == 1, done.stderr
        (line,) = done.stdout.splitlines()
        assert line.split("\t")[:4] == ["new", "pkg-scanner", "P5", LIMIT]

    def test_a_listed_problem_that_no_longer_occurs_is_printed_as_stale(
        self, tmp_path: Path
    ) -> None:
        source = PLUGIN_PACKAGE.format(description=DESCRIBED)
        package = _plugin_package(tmp_path, "ash_check_fixture_pkg_g", source)
        gone = f"pkg-scanner\tP5\t{LIMIT}\tfix-limit"
        baseline = _write_baseline(tmp_path / "baseline.tsv", gone)
        done = _author_command("--path", str(package), "--baseline", str(baseline))
        assert done.returncode == 1, done.stderr
        assert done.stdout.splitlines() == ["stale\t" + gone]
