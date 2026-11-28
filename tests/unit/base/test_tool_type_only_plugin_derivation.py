"""A plugin that names only the legacy ``tool_type`` still gets one category.

A scanner plugin written before scan categories existed says what it is through
``tool_type`` alone: on its operational row's ``targets``, as a class-level field
default, or by setting ``self.tool_type`` in its own ``model_post_init`` (an enum
member, or a string such as ``"SAST"``). Each of those gives the plugin the one
category ``CATEGORY_OF_TOOL_TYPE`` maps that type to, with a ``DeprecationWarning``
that says deriving categories from ``tool_type`` is removed in 4.0, and the category
is answered by name (``scanner_categories``) in the same process: from the row, from
the class, or from the first instance. A plugin that says neither derives no category
and is warned that a category scope reads it as ``other``. A plugin whose row
declares its categories is warned nothing, and the row's ``tool_type`` is the one the
instance ends up with, whatever its own ``model_post_init`` set.

These are the paths a third-party plugin takes first, so each has a test of its own.
The by-name records and the warnings are process-wide and de-duplicated (once per
scanner name for a row, once per class otherwise), and xdist runs the tests in any
order, so every row, class and config name here belongs to one test, and each warning
is asserted in the test that builds the thing raising it.
"""

import contextlib
import importlib
import importlib.util
import sys
import warnings
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar, Literal

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core import enums
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

pytestmark = pytest.mark.unit

SCAN_CATEGORIES = "automated_security_helper.utils.scan_categories"

#: The conformance fixture plugin, whose operational row names only ``tool_type``.
FIXTURE_PLUGIN = (
    Path(__file__).resolve().parents[1] / "plugin_conformance" / "fixture_plugin"
)

#: The stable parts of the scan-category warning texts: the three derivation
#: warnings and the warning for a plugin that derives no category.
CATEGORY_WARNING_PHRASES = (
    "derived from tool_type",
    "derived from its class-level tool_type",
    "derived from its tool_type",
    "meets a category scope as 'other'",
    "removed in 4.0",
)


@contextlib.contextmanager
def _recording() -> Iterator[list[warnings.WarningMessage]]:
    """Every warning raised inside the block, none filtered out or de-duplicated."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        yield caught


def _category_warnings(
    caught: list[warnings.WarningMessage],
) -> list[warnings.WarningMessage]:
    """The recorded warnings whose text is one of the scan-category warnings."""
    return [
        warning
        for warning in caught
        if any(phrase in str(warning.message) for phrase in CATEGORY_WARNING_PHRASES)
    ]


def _shown(found: list[warnings.WarningMessage]) -> list[str]:
    return [f"{warning.category.__name__}: {warning.message}" for warning in found]


def _the_one_deprecation(caught: list[warnings.WarningMessage], what: str) -> str:
    """The text of the one scan-category warning that *what* raised."""
    found = _category_warnings(caught)
    assert len(found) == 1, (
        f"{what} raised {len(found)} scan-category warnings, not one: {_shown(found)}"
    )
    assert issubclass(found[0].category, DeprecationWarning), (
        f"{what} warned with the wrong category: {_shown(found)}"
    )
    return str(found[0].message)


def _no_category_warning(caught: list[warnings.WarningMessage], what: str) -> None:
    found = _category_warnings(caught)
    assert found == [], f"{what} raised scan-category warnings: {_shown(found)}"


def _scan_category() -> Any:
    found = getattr(enums, "ScanCategory", None)
    assert found is not None, "automated_security_helper.core.enums has no ScanCategory"
    return found


def _scan_categories_module() -> ModuleType:
    assert importlib.util.find_spec(SCAN_CATEGORIES) is not None, (
        f"{SCAN_CATEGORIES} does not exist"
    )
    return importlib.import_module(SCAN_CATEGORIES)


def _named(module: ModuleType, name: str) -> Any:
    found = getattr(module, name, None)
    assert found is not None, f"{module.__name__} has no {name}"
    return found


def _targets(**fields: Any) -> opsf.TargetsFacet:
    """A targets facet over source code; *fields* add to or replace its values."""
    values: dict[str, Any] = {
        "kinds": (opsf.TargetKind.SOURCE_CODE,),
        "selection": "every python file in the scan set",
    }
    values.update(fields)
    return opsf.TargetsFacet(**values)


def _operational_row(
    name: str, targets: opsf.TargetsFacet
) -> opsf.ScannerOperationalFacets:
    """A whole operational row named *name*: the fixture plugin's, with *targets*."""
    return opsf.ScannerOperationalFacets(
        scanner_name=name,
        network=opsf.NetworkFacet(
            fetch_kind=opsf.FetchKind.NONE,
            fetches=(),
            prefetch=(),
            offline_outcome=opsf.OfflineOutcome.UNCHANGED,
            offline_strategy=OfflineStrategy.BUNDLED,
            sandbox_network=opsf.SandboxNetwork.NONE,
            source="tests/unit/base/test_tool_type_only_plugin_derivation.py",
        ),
        output=opsf.OutputFacet(
            native_formats=(opsf.OutputFormat.SARIF,),
            side_reports=(),
            non_finding_artifacts=(),
            note="one SARIF file",
        ),
        targets=targets,
        runtime=opsf.RuntimeFacet(
            kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
            external_programs=(),
            invocations=opsf.Invocations.ONE,
            python_only=False,
            use_uv_tool=False,
        ),
        runtime_compat=opsf.RuntimeCompatFacet(rows=()),
        platforms=opsf.PlatformsFacet(
            provisionable=(),
            note="installed by the user; ASH provisions nothing",
        ),
        image=opsf.ImageFacet(
            route=opsf.ImageRoute.NOT_IN_IMAGE,
            reason="a test double; the user installs its CLI",
        ),
        severity=opsf.SeverityFacet(
            severity_class=opsf.SeverityClass.DERIVED,
            note="the native level through one table",
        ),
        silencing=opsf.SilencingFacet(
            tool_side=(),
            none_reason="the test double has no tool, so no tool-side layer",
        ),
        identity=opsf.IdentityFacet(
            fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
            note="identity is file and line through the shared floor",
        ),
        extensibility=opsf.ExtensibilityFacet(
            custom_rules=opsf.CustomRules.NONE,
            env_prefixes=(),
            options_surface="none: the test double has no options",
        ),
        exit_codes=opsf.ExitCodesFacet(
            success_exit_codes=(0,),
            semantics="0 is the only status a completed run gives",
        ),
        provenance=opsf.ProvenanceFacet(
            source=opsf.ProvenanceSource.USER_INSTALLED,
            selection_surfaces=("a test double in this module",),
            upstream_license="not applicable (source: a test double with no upstream)",
        ),
        prerequisites=opsf.PrerequisitesFacet(
            kinds=(opsf.Prerequisite.NONE,),
            note="nothing: the test double is never run",
        ),
    )


class _RunsNoTool:
    """What a concrete scanner class needs beside its config: these tests build
    scanners and never scan."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(
        self, target: Path, target_type: Any, global_ignore_paths: list[Any]
    ) -> tuple[list[str], Path, dict[str, str] | None]:
        raise NotImplementedError("these tests run no scan")


def _fixture_plugin_modules() -> list[str]:
    return [name for name in sys.modules if name.split(".")[0] == "ash_fixture_plugin"]


@pytest.fixture
def fresh_fixture_plugin(monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    """The fixture plugin's scanner module, imported fresh so that its row is built,
    and recorded by name, inside the test; its modules are gone again afterwards, as
    tests/unit/plugin_conformance/conftest.py leaves them."""
    monkeypatch.syspath_prepend(str(FIXTURE_PLUGIN))
    for name in _fixture_plugin_modules():
        monkeypatch.delitem(sys.modules, name)
    yield importlib.import_module("ash_fixture_plugin.scanner")
    for name in _fixture_plugin_modules():
        sys.modules.pop(name, None)


def test_a_tool_type_only_row_derives_its_category_and_warns_once_per_name() -> None:
    """The row names ``tool_type`` SAST and no ``categories``: it derives ``sast``,
    says so in one DeprecationWarning, and answers by name; a second row of the same
    name is not warned again."""
    name = "category-fixture-derive-row"
    with _recording() as caught:
        row = _operational_row(name, _targets(tool_type=ScannerToolType.SAST))
    message = _the_one_deprecation(caught, f"building the {name} row")
    assert "derived from tool_type" in message, message
    assert "removed in 4.0" in message and name in message, message

    category = _scan_category()
    row_categories = _named(opsf, "row_categories")
    assert row.targets.categories == (category.SAST,)
    assert "categories" not in row.targets.model_fields_set
    assert row_categories(name) == (category.SAST,)

    with _recording() as again:
        _operational_row(name, _targets(tool_type=ScannerToolType.SAST))
    _no_category_warning(again, f"building a second {name} row")
    assert row_categories(name) == (category.SAST,)


def test_the_fixture_plugins_tool_type_only_row_answers_by_name_after_a_fresh_import(
    fresh_fixture_plugin: ModuleType,
) -> None:
    """The conformance fixture plugin is a pre-category plugin of the first kind:
    its row names only ``tool_type`` SAST, and once imported it answers ``sast`` by
    name though it is no ScannerPluginBase subclass and no table names it."""
    category = _scan_category()
    scanner_categories = _named(_scan_categories_module(), "scanner_categories")
    targets = fresh_fixture_plugin.FixtureScanner.operational_facets.targets
    assert targets.categories == (category.SAST,)
    assert scanner_categories("fixture-lint") == (category.SAST,)


def test_a_class_level_tool_type_warns_when_the_class_is_defined_and_answers_by_name(
    plugin_context: PluginContext,
) -> None:
    """A class-level ``tool_type`` default of SAST and no row: the class warns once
    when it is defined, answers ``sast`` by name before any instance exists, and its
    instance is not warned again."""
    name = "category-fixture-derive-class-field"

    class DeriveClassFieldScannerConfig(ScannerPluginConfigBase):
        name: Literal["category-fixture-derive-class-field"] = (
            "category-fixture-derive-class-field"
        )

    with _recording() as defined:

        class DeriveClassFieldScanner(
            _RunsNoTool, ScannerPluginBase[DeriveClassFieldScannerConfig]
        ):
            tool_type: ScannerToolType = ScannerToolType.SAST
            config: DeriveClassFieldScannerConfig | None = None

    message = _the_one_deprecation(defined, "defining DeriveClassFieldScanner")
    assert "derived from its class-level tool_type" in message, message
    assert "removed in 4.0" in message, message
    assert "DeriveClassFieldScanner" in message, message

    category = _scan_category()
    scanner_categories = _named(_scan_categories_module(), "scanner_categories")
    assert scanner_categories(name) == (category.SAST,)

    with _recording() as built:
        scanner = DeriveClassFieldScanner(
            config=DeriveClassFieldScannerConfig(), context=plugin_context
        )
    _no_category_warning(built, "building the first DeriveClassFieldScanner")
    assert scanner.declared_categories() == (category.SAST,)


def test_a_tool_type_set_in_post_init_warns_at_the_first_instance_and_is_recorded(
    plugin_context: PluginContext,
) -> None:
    """``model_post_init`` sets ``tool_type`` to the string ``"SAST"`` before the base
    runs: nothing is known by name until the first instance, which warns once and
    records ``sast`` under its config name; a second instance is not warned."""
    name = "category-fixture-derive-post-init"

    class DerivePostInitScannerConfig(ScannerPluginConfigBase):
        name: Literal["category-fixture-derive-post-init"] = (
            "category-fixture-derive-post-init"
        )

    with _recording() as defined:

        class DerivePostInitScanner(
            _RunsNoTool, ScannerPluginBase[DerivePostInitScannerConfig]
        ):
            config: DerivePostInitScannerConfig | None = None

            def model_post_init(self, context: Any) -> None:
                self.tool_type = "SAST"
                super().model_post_init(context)

    _no_category_warning(defined, "defining DerivePostInitScanner")

    category = _scan_category()
    scanner_categories = _named(_scan_categories_module(), "scanner_categories")
    assert scanner_categories(name) == ()

    with _recording() as first:
        scanner = DerivePostInitScanner(
            config=DerivePostInitScannerConfig(), context=plugin_context
        )
    message = _the_one_deprecation(first, f"building the first {name} instance")
    assert "derived from its tool_type" in message, message
    assert "removed in 4.0" in message and name in message, message
    assert scanner.declared_categories() == (category.SAST,)
    assert scanner_categories(name) == (category.SAST,)

    with _recording() as second:
        DerivePostInitScanner(
            config=DerivePostInitScannerConfig(), context=plugin_context
        )
    _no_category_warning(second, f"building a second {name} instance")


def test_a_scanner_that_declares_nothing_warns_once_and_meets_a_scope_as_other(
    plugin_context: PluginContext,
) -> None:
    """No row, no class-level ``tool_type`` and none set at construction: the scanner
    can serve nothing and will serve nothing, its first instance says that a category
    scope reads it as ``other``, and an empty set does meet the scope as ``other``."""
    name = "category-fixture-derive-nothing"

    class DeriveNothingScannerConfig(ScannerPluginConfigBase):
        name: Literal["category-fixture-derive-nothing"] = (
            "category-fixture-derive-nothing"
        )

    with _recording() as defined:

        class DeriveNothingScanner(
            _RunsNoTool, ScannerPluginBase[DeriveNothingScannerConfig]
        ):
            config: DeriveNothingScannerConfig | None = None

    _no_category_warning(defined, "defining DeriveNothingScanner")

    with _recording() as first:
        scanner = DeriveNothingScanner(
            config=DeriveNothingScannerConfig(), context=plugin_context
        )
    message = _the_one_deprecation(first, f"building the first {name} instance")
    assert "meets a category scope as 'other'" in message and name in message, message

    category = _scan_category()
    module = _scan_categories_module()
    scanner_categories = _named(module, "scanner_categories")
    scope_categories = _named(module, "scope_categories")
    assert scanner.declared_categories() == ()
    assert scanner.categories_for_run() == frozenset()
    assert scanner_categories(name) == ()
    assert scope_categories(scanner.categories_for_run()) == frozenset({category.OTHER})

    with _recording() as second:
        DeriveNothingScanner(
            config=DeriveNothingScannerConfig(), context=plugin_context
        )
    _no_category_warning(second, f"building a second {name} instance")


def test_a_declared_row_is_the_last_writer_of_tool_type_and_warns_nothing(
    plugin_context: PluginContext,
) -> None:
    """The row declares ``tool_type`` SCA and ``categories`` (sca,); the scanner's own
    ``model_post_init`` sets SAST before the base runs. The instance ends up SCA, and
    neither the class nor the instance warns."""
    category = _scan_category()
    name = "category-fixture-derive-row-wins"

    class DeriveRowWinsScannerConfig(ScannerPluginConfigBase):
        name: Literal["category-fixture-derive-row-wins"] = (
            "category-fixture-derive-row-wins"
        )

    with _recording() as caught:

        class DeriveRowWinsScanner(
            _RunsNoTool, ScannerPluginBase[DeriveRowWinsScannerConfig]
        ):
            config: DeriveRowWinsScannerConfig | None = None
            operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
                _operational_row(
                    name,
                    _targets(
                        kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                        tool_type=ScannerToolType.SCA,
                        categories=(category.SCA,),
                        selection="every lockfile in the scan set",
                    ),
                )
            )

            def model_post_init(self, context: Any) -> None:
                self.tool_type = ScannerToolType.SAST
                super().model_post_init(context)

        scanner = DeriveRowWinsScanner(
            config=DeriveRowWinsScannerConfig(), context=plugin_context
        )

    _no_category_warning(caught, f"defining and building {name}")
    assert scanner.tool_type is ScannerToolType.SCA, scanner.tool_type
    assert scanner.declared_categories() == (category.SCA,)
