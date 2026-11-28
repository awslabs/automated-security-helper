"""The scan-category vocabulary of ``core/enums.py``.

``ScanCategory`` is the vocabulary a scanner declares what it can serve in, and its
declaration order is the canonical order every category tuple is written in, so the
order is pinned here value by value. ``CATEGORY_KIND`` marks ``sbom`` as the one
artifact category. ``CATEGORY_OF_TOOL_TYPE`` and the two helpers beside it read a
legacy ``tool_type`` as a category until the type is removed. A tool type arrives in
several spellings (a member, its value in any case, the ``ScannerToolType.X`` text
some results carry, the retired ``SECRET``), and each spelling is read here, so the
derivation a row without categories falls back on gives one answer for all of them.

The category names are reached inside each test, so this module collects on a tree
that predates them. The last test is a control that holds on such a tree too:
``core/enums.py`` stays a leaf that imports only ``enum`` and ``typing``.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.core import enums
from automated_security_helper.core.enums import ScannerToolType

pytestmark = pytest.mark.unit

#: Every category, member name and value, in declaration order.
_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("SAST", "sast"),
    ("SECRETS", "secrets"),
    ("PII", "pii"),
    ("SCA", "sca"),
    ("CONTAINER", "container"),
    ("IAC", "iac"),
    ("CI", "ci"),
    ("SUPPLY_CHAIN", "supply-chain"),
    ("MALWARE", "malware"),
    ("MAINTENANCE", "maintenance"),
    ("LICENSE", "license"),
    ("QUALITY", "quality"),
    ("COMPLEXITY", "complexity"),
    ("API", "api"),
    ("AGENT", "agent"),
    ("BINARY", "binary"),
    ("POSTURE", "posture"),
    ("DAST", "dast"),
    ("SBOM", "sbom"),
    ("OTHER", "other"),
)

#: Each tool type, by member name, and the value of the category it stands for.
_CATEGORY_OF_TOOL_TYPE: tuple[tuple[str, str | None], ...] = (
    ("SAST", "sast"),
    ("DAST", "dast"),
    ("SCA", "sca"),
    ("IAC", "iac"),
    ("SECRETS", "secrets"),
    ("CONTAINER", "container"),
    ("SBOM", "sbom"),
    ("CUSTOM", "other"),
    ("UNKNOWN", None),
)


def _enums_name(name: str) -> Any:
    """``core.enums.<name>``, read when the test runs rather than at import."""
    found = getattr(enums, name, None)
    assert found is not None, f"core.enums has no {name}"
    return found


def test_the_categories_are_the_twenty_in_canonical_order() -> None:
    category = _enums_name("ScanCategory")

    assert issubclass(category, str)
    assert [(member.name, member.value) for member in category] == list(_CATEGORIES)


def test_a_category_prints_as_its_value() -> None:
    category = _enums_name("ScanCategory")

    for member in category:
        assert str(member) == member.value, member.name
        assert f"{member}" == member.value, member.name


def test_a_category_is_found_by_its_value() -> None:
    category = _enums_name("ScanCategory")

    assert category("supply-chain") is category.SUPPLY_CHAIN
    for name, value in _CATEGORIES:
        assert category(value) is category[name], value


def test_sbom_is_the_one_artifact_category() -> None:
    category = _enums_name("ScanCategory")
    kind = _enums_name("CategoryKind")
    category_kind = _enums_name("CATEGORY_KIND")

    assert issubclass(kind, str)
    assert [(member.name, member.value) for member in kind] == [
        ("FINDING", "finding"),
        ("ARTIFACT", "artifact"),
    ]
    assert [str(member) for member in kind] == ["finding", "artifact"]
    assert set(category_kind) == set(category)
    assert category_kind[category.SBOM] is kind.ARTIFACT
    assert [
        member for member in category if category_kind[member] is not kind.FINDING
    ] == [category.SBOM]


def test_each_tool_type_stands_for_one_category_and_unknown_for_none() -> None:
    category = _enums_name("ScanCategory")
    of_tool_type = _enums_name("CATEGORY_OF_TOOL_TYPE")

    assert {name for name, _ in _CATEGORY_OF_TOOL_TYPE} == {
        member.name for member in ScannerToolType
    }, "this file's table no longer names every ScannerToolType member"
    assert set(of_tool_type) == set(ScannerToolType)
    for name, value in _CATEGORY_OF_TOOL_TYPE:
        found = of_tool_type[ScannerToolType[name]]
        expected = None if value is None else category(value)
        assert found is expected, f"{name} stands for {found!r}, not {expected!r}"


@pytest.mark.parametrize(
    ("value", "member"),
    [
        pytest.param(ScannerToolType.SAST, "SAST", id="member"),
        pytest.param("SAST", "SAST", id="value"),
        pytest.param("sast", "SAST", id="lower-case"),
        pytest.param(" Sast ", "SAST", id="padded-mixed-case"),
        pytest.param("ScannerToolType.SAST", "SAST", id="enum-qualified"),
        pytest.param("SECRET", "SECRETS", id="retired-SECRET"),
        pytest.param("lint", "UNKNOWN", id="names-no-member"),
        pytest.param("", "UNKNOWN", id="empty"),
        pytest.param(None, "UNKNOWN", id="None"),
    ],
)
def test_a_tool_type_spelling_reads_as_its_member(value: object, member: str) -> None:
    tool_type_member = _enums_name("tool_type_member")

    assert tool_type_member(value) is ScannerToolType[member]


@pytest.mark.parametrize(
    "member", list(ScannerToolType), ids=lambda member: member.name
)
def test_a_tool_type_member_is_read_as_itself(member: ScannerToolType) -> None:
    tool_type_member = _enums_name("tool_type_member")

    assert tool_type_member(member) is member


@pytest.mark.parametrize(
    ("value", "categories"),
    [
        pytest.param("SAST", ("sast",), id="SAST"),
        pytest.param("CUSTOM", ("other",), id="CUSTOM"),
        pytest.param(None, (), id="None"),
        pytest.param("SECRET", ("secrets",), id="retired-SECRET"),
        pytest.param("lint", (), id="names-no-member"),
    ],
)
def test_a_tool_type_spelling_derives_its_category(
    value: object, categories: tuple[str, ...]
) -> None:
    categories_of_tool_type = _enums_name("categories_of_tool_type")
    category = _enums_name("ScanCategory")

    derived = categories_of_tool_type(value)

    assert isinstance(derived, tuple)
    assert derived == tuple(category(each) for each in categories)


@pytest.mark.parametrize(
    ("name", "value"),
    _CATEGORY_OF_TOOL_TYPE,
    ids=[name for name, _ in _CATEGORY_OF_TOOL_TYPE],
)
def test_each_tool_type_derives_its_category_or_none(
    name: str, value: str | None
) -> None:
    categories_of_tool_type = _enums_name("categories_of_tool_type")
    category = _enums_name("ScanCategory")
    expected = () if value is None else (category(value),)

    assert categories_of_tool_type(ScannerToolType[name]) == expected
    assert categories_of_tool_type(name) == expected


def test_core_enums_imports_only_enum_and_typing() -> None:
    """The vocabulary module stays a leaf: every import statement it holds, lazy
    ones included, takes from ``enum`` or ``typing`` and from nothing else."""
    path = Path(enums.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." * node.level + (node.module or "").partition(".")[0])

    assert imported == {"enum", "typing"}, sorted(imported)
