"""The scanner-name tables of ``utils/scanner_names.py``.

``SCANNER_CATEGORIES`` states each shipped scanner's can-serve categories by config
name, beside the legacy ``SCANNER_TOOL_TYPES``, so a reader that has only a name (a
stored result, a report, the MCP server) answers without importing a scanner class.
Its rows are written out here value by value, in canonical order: they are the
can-serve table each scanner's operational row declares, and
tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py binds each
row to the register. ``SCANNER_TAG_NAMES`` is built from the category table's names,
so it does not lean on the legacy table that is removed with the tool type.

Two controls hold what must not move. The module still imports nothing from ASH but
``core/enums.py``: ``models/flat_vulnerability.py`` reaches it, and the module
docstring measures the import cycle a wider import would close. And ``utils`` adds
no import of a plugin package: the layer ratchet's count for that edge stays at the
two statements it records (tests/unit/test_layer_dag_boundaries.py).
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.utils import scanner_names
from tests.unit.test_layer_dag_boundaries import _imported_modules, import_edges

pytestmark = pytest.mark.unit

_PACKAGE = "automated_security_helper"

#: Each shipped scanner's can-serve categories, by config name, as category values
#: in canonical order.
_SHIPPED_CATEGORIES: dict[str, tuple[str, ...]] = {
    "actionlint": ("secrets", "ci", "quality"),
    "bandit": ("sast",),
    "betterleaks": ("secrets",),
    "cdk-nag": ("iac",),
    "cfn-guard": ("iac",),
    "cfn-lint": ("iac",),
    "cfn-nag": ("iac",),
    "checkov": ("secrets", "iac", "ci", "api"),
    "detect-secrets": ("secrets",),
    "ferret-scan": ("secrets", "pii"),
    "gitleaks": ("secrets",),
    "grype": ("sca", "container"),
    "guarddog": ("supply-chain", "malware"),
    "hadolint": ("iac", "quality"),
    "mcp-config": ("secrets", "supply-chain", "agent"),
    "npm-audit": ("sca",),
    "opengrep": ("sast", "secrets", "iac", "ci", "quality"),
    "semgrep": ("sast", "secrets", "iac", "ci", "quality"),
    "snyk-code": ("sast", "secrets"),
    "syft": ("sbom",),
    "trivy": ("secrets", "sca", "container", "iac", "license"),
    "trivy-repo": ("secrets", "sca", "iac", "license"),
    "zizmor": ("secrets", "sca", "ci", "supply-chain", "quality"),
}


def _scan_category() -> Any:
    """``core.enums.ScanCategory``, read when the test runs rather than at import."""
    enums = importlib.import_module(f"{_PACKAGE}.core.enums")
    found = getattr(enums, "ScanCategory", None)
    assert found is not None, "core.enums has no ScanCategory"
    return found


def _scanner_categories() -> Mapping[str, Any]:
    """``SCANNER_CATEGORIES``, read when the test runs rather than at import."""
    found = getattr(scanner_names, "SCANNER_CATEGORIES", None)
    assert found is not None, "utils/scanner_names has no SCANNER_CATEGORIES"
    return found


def _source_tree() -> ast.Module:
    path = Path(scanner_names.__file__)
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _assigned_value(tree: ast.Module, name: str) -> ast.expr:
    """The value a module-level statement of *tree* assigns to *name*."""
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        ):
            return statement.value
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == name
            and statement.value is not None
        ):
            return statement.value
    raise AssertionError(f"utils/scanner_names.py assigns no {name} at module level")


def test_scanner_names_imports_nothing_from_ash_but_core_enums() -> None:
    """One import statement from ASH, of ``core.enums``, whatever names it takes;
    lazy imports count too."""
    from_ash = [
        module
        for module in _imported_modules(_source_tree(), (_PACKAGE, "utils"))
        if module.partition(".")[0] == _PACKAGE
    ]

    assert from_ash == [f"{_PACKAGE}.core.enums"], from_ash


def test_utils_reaches_plugin_modules_in_its_two_known_statements() -> None:
    """The category readers answer by name from tables, so they add no import of a
    plugin package to ``utils``."""
    count = import_edges()[("utils", "plugin_modules")]

    assert count == 2, (
        f"utils imports plugin_modules in {count} statement(s); the layer ratchet "
        "records 2"
    )


def test_the_category_table_names_the_scanners_of_the_tool_type_table() -> None:
    table = _scanner_categories()
    names = set(scanner_names.SCANNER_TOOL_TYPES)

    assert isinstance(table, Mapping)
    assert set(table) == names, (
        f"only in SCANNER_CATEGORIES: {sorted(set(table) - names)}; "
        f"only in SCANNER_TOOL_TYPES: {sorted(names - set(table))}"
    )


def test_each_scanners_categories_are_a_canonical_tuple_without_repeats() -> None:
    table = _scanner_categories()
    category = _scan_category()
    canonical = list(category)

    for name, categories in table.items():
        assert isinstance(categories, tuple), f"{name}: {categories!r} is no tuple"
        assert categories, f"{name} serves no category"
        assert all(isinstance(member, category) for member in categories), (
            f"{name}: {categories!r} holds a value that is no ScanCategory member"
        )
        assert len(set(categories)) == len(categories), (
            f"{name} names a category twice: {categories!r}"
        )
        assert list(categories) == sorted(categories, key=canonical.index), (
            f"{name}: {[member.value for member in categories]} is not in "
            "canonical order"
        )


def test_the_category_table_is_the_can_serve_table() -> None:
    table = _scanner_categories()

    found = {
        name: tuple(member.value for member in categories)
        for name, categories in table.items()
    }

    assert found == _SHIPPED_CATEGORIES


def test_the_tag_names_are_built_from_the_category_table() -> None:
    table = _scanner_categories()
    tag_names = scanner_names.SCANNER_TAG_NAMES
    named = {
        node.id
        for node in ast.walk(_assigned_value(_source_tree(), "SCANNER_TAG_NAMES"))
        if isinstance(node, ast.Name)
    }

    assert isinstance(tag_names, frozenset)
    assert set(tag_names) == set(table)
    assert "SCANNER_CATEGORIES" in named, sorted(named)
    assert "SCANNER_TOOL_TYPES" not in named, sorted(named)
