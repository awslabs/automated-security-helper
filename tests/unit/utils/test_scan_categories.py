"""The category readers of ``utils/scan_categories.py``.

``normalize_category`` is where a category name typed by an operator, a plugin or a
stored tag is read, so it takes each value in any case and with surrounding space,
and refuses an unknown one with the nearest value and the whole list;
``normalize_categories`` folds several into canonical order, each once.
``scope_categories`` reads an empty set as ``other``, which is how a plugin that
declares no category meets a category scope. ``scanner_categories`` answers by config
name with no scanner import, from the shipped table first. ``result_categories``
reads a result's ``category::`` tags, and for an untagged result only the one
category of a shipped single-category scanner: an untagged result of a scanner that
serves several stays unclassified, and a legacy ``tool_type::`` tag is never read as
a category.

The module is imported in each test's body, so on a tree without it every test
fails there with ``ModuleNotFoundError`` and this file still collects. Each scanner
name a test makes up is used by that test alone, because the by-name records the
readers consult are kept for the whole process.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any

import pytest

from automated_security_helper.utils import scanner_names

pytestmark = pytest.mark.unit

#: The twenty category values, in canonical order.
_CATEGORY_VALUES: tuple[str, ...] = (
    "sast",
    "secrets",
    "pii",
    "sca",
    "container",
    "iac",
    "ci",
    "supply-chain",
    "malware",
    "maintenance",
    "license",
    "quality",
    "complexity",
    "api",
    "agent",
    "binary",
    "posture",
    "dast",
    "sbom",
    "other",
)

#: How a refusal of an unknown category ends.
_THE_CATEGORIES_ARE = "; the categories are: " + ", ".join(_CATEGORY_VALUES)


def _scan_categories() -> Any:
    """``utils/scan_categories``, imported when the test runs rather than at import."""
    return importlib.import_module("automated_security_helper.utils.scan_categories")


def _scan_category() -> Any:
    """``core.enums.ScanCategory``, read when the test runs rather than at import."""
    enums = importlib.import_module("automated_security_helper.core.enums")
    found = getattr(enums, "ScanCategory", None)
    assert found is not None, "core.enums has no ScanCategory"
    return found


def _scanner_categories() -> Mapping[str, Any]:
    """``SCANNER_CATEGORIES``, read when the test runs rather than at import."""
    found = getattr(scanner_names, "SCANNER_CATEGORIES", None)
    assert found is not None, "utils/scanner_names has no SCANNER_CATEGORIES"
    return found


def _result(
    scanner_name: str | None = None, tags: list[str] | None = None
) -> dict[str, Any]:
    """A SARIF result as JSON, its scanner name and tags in its property bag."""
    properties: dict[str, Any] = {}
    if scanner_name is not None:
        properties["scanner_name"] = scanner_name
    if tags is not None:
        properties["tags"] = tags
    return {"properties": properties}


@pytest.mark.parametrize("value", _CATEGORY_VALUES)
def test_a_category_is_read_from_its_member_or_value_in_any_case(value: str) -> None:
    module = _scan_categories()
    member = _scan_category()(value)

    for spelling in (member, value, value.upper(), f"  {value.title()}\t"):
        assert module.normalize_category(spelling) is member, repr(spelling)


def test_an_unknown_category_is_refused_with_the_nearest_value_and_the_list() -> None:
    module = _scan_categories()

    with pytest.raises(ValueError) as refusal:
        module.normalize_category("supply_chain")

    message = str(refusal.value)
    assert message.startswith("unknown scan category 'supply_chain'"), message
    assert " (did you mean 'supply-chain'?)" in message, message
    assert message.endswith(_THE_CATEGORIES_ARE), message


def test_an_unknown_category_with_no_near_value_is_refused_without_a_guess() -> None:
    module = _scan_categories()

    with pytest.raises(ValueError) as refusal:
        module.normalize_category("qqzzqq")

    message = str(refusal.value)
    assert message.startswith("unknown scan category 'qqzzqq'"), message
    assert "did you mean" not in message, message
    assert message.endswith(_THE_CATEGORIES_ARE), message


def test_categories_are_folded_into_canonical_order_each_once() -> None:
    module = _scan_categories()
    category = _scan_category()

    folded = module.normalize_categories(
        ["SECRETS", "sast", category.SECRETS, " Sast "]
    )

    assert isinstance(folded, tuple)
    assert folded == (category.SAST, category.SECRETS)
    assert module.normalize_categories(iter(["ci", "iac"])) == (
        category.IAC,
        category.CI,
    )
    assert module.normalize_categories(()) == ()


def test_one_string_is_one_category_and_not_a_run_of_letters() -> None:
    module = _scan_categories()
    category = _scan_category()

    assert module.normalize_categories("sast") == (category.SAST,)
    assert module.normalize_categories("supply-chain") == (category.SUPPLY_CHAIN,)


def test_an_unknown_value_among_categories_is_refused() -> None:
    module = _scan_categories()

    with pytest.raises(ValueError, match="^unknown scan category 'supply_chain'"):
        module.normalize_categories(["sast", "supply_chain"])


def test_an_empty_scope_meets_as_other() -> None:
    module = _scan_categories()
    category = _scan_category()

    for empty in ((), [], iter(())):
        scope = module.scope_categories(empty)
        assert isinstance(scope, frozenset), repr(empty)
        assert scope == frozenset({category.OTHER}), repr(empty)


def test_a_scope_is_its_categories_as_a_set() -> None:
    module = _scan_categories()
    category = _scan_category()

    scope = module.scope_categories(["sca", "container"])

    assert isinstance(scope, frozenset)
    assert scope == frozenset({category.SCA, category.CONTAINER})
    assert module.scope_categories(["SECRETS", category.SECRETS]) == frozenset(
        {category.SECRETS}
    )


@pytest.mark.parametrize("name", sorted(scanner_names.SCANNER_TOOL_TYPES))
def test_a_shipped_scanner_answers_with_its_row_in_the_name_table(name: str) -> None:
    module = _scan_categories()
    table = _scanner_categories()

    answer = module.scanner_categories(name)

    assert name in table, f"SCANNER_CATEGORIES has no row for {name}"
    assert isinstance(answer, tuple)
    assert answer == table[name]


def test_a_name_that_is_empty_or_not_text_has_no_categories() -> None:
    module = _scan_categories()

    for name in ("", None, 7, ["bandit"], ("bandit",)):
        assert module.scanner_categories(name) == (), repr(name)


def test_a_name_nothing_declares_has_no_categories() -> None:
    module = _scan_categories()

    assert module.scanner_categories("categories-test-unknown-scanner") == ()


def test_category_tags_name_the_categories_and_an_unknown_one_is_skipped() -> None:
    module = _scan_categories()
    category = _scan_category()
    result = _result(
        "categories-test-tagged-scanner",
        ["category::secrets", "category::no-such-category", "tool_name::any"],
    )

    found = module.result_categories(result)

    assert module.CATEGORY_TAG_PREFIX == "category::"
    assert isinstance(found, frozenset)
    assert found == frozenset({category.SECRETS})


def test_category_tags_are_read_in_any_case_and_together() -> None:
    module = _scan_categories()
    category = _scan_category()
    result = _result(
        "categories-test-two-tag-scanner", ["category::SCA", "category::container"]
    )

    found = module.result_categories(result)

    assert found == frozenset({category.SCA, category.CONTAINER})


def test_a_results_category_tags_outrank_its_scanners_name() -> None:
    module = _scan_categories()
    category = _scan_category()

    found = module.result_categories(_result("bandit", ["category::secrets"]))

    assert found == frozenset({category.SECRETS})


def test_an_untagged_result_of_a_single_category_scanner_takes_its_category() -> None:
    module = _scan_categories()
    category = _scan_category()

    found = module.result_categories(_result("bandit"))

    assert found == frozenset({category.SAST})


def test_an_untagged_result_of_a_multi_category_scanner_is_unclassified() -> None:
    module = _scan_categories()

    assert module.result_categories(_result("trivy")) == frozenset()


def test_a_tool_type_tag_is_not_a_category() -> None:
    module = _scan_categories()
    result = _result("categories-test-tool-type-scanner", ["tool_type::SAST"])

    assert module.result_categories(result) == frozenset()


def test_a_result_with_nothing_to_read_is_unclassified() -> None:
    module = _scan_categories()

    assert module.result_categories({}) == frozenset()
    assert module.result_categories(_result()) == frozenset()
