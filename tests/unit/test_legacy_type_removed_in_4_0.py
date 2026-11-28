"""The legacy tool-type names leave in 4.0, and this checks it by name.

Scan categories replace the legacy tool type. The type stays through 3.x, so that a
third-party plugin and a stored result keep working, and goes in 4.0. The names that
go are listed once, in ``utils/scan_categories.REMOVED_IN_4_0``, each with its kind:
an identifier the package source defines or names, an attribute of a class, or a
result tag prefix. This file pins that list, and fails once ``__version__`` reaches
4.0 while any listed name is still in the package source, naming each one and where
it is. It follows the alias-window test of
tests/unit/test_community_spellings_stay_aliases_of_the_alpha_tier.py, and checks by
name rather than by module path, because a name that moved to another module is as
present as one that stayed.

The finder reads every ``.py`` file under the package with ``ast``, so a docstring,
a comment or a string that only mentions a name is not a use of it. Controls keep
the version check from passing on nothing: a planted package where each kind is
found and each near miss is not, and the real package, where the legacy names are
still found before 4.0.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

import automated_security_helper

pytestmark = pytest.mark.unit

#: The names that leave in 4.0, and the kind of each, in the list's order.
_REMOVED_IN_4_0: tuple[tuple[str, str], ...] = (
    ("ScannerToolType", "name"),
    ("CATEGORY_OF_TOOL_TYPE", "name"),
    ("tool_type_member", "name"),
    ("categories_of_tool_type", "name"),
    ("TargetsFacet.tool_type", "attribute"),
    ("TargetsFacet.tool_type_note", "attribute"),
    ("SCANNER_TOOL_TYPES", "name"),
    ("scanner_tool_type", "name"),
    ("result_tool_types", "name"),
    ("normalize_tool_type", "name"),
    ("tool_type::", "tag"),
    ("scanner_type", "name"),
    ("exclude_scanner_types", "name"),
)

_KINDS = ("name", "attribute", "tag")

_REMOVAL_VERSION = "4.0.0"


def _scan_categories() -> Any:
    """``utils/scan_categories``, imported when the test runs rather than at import."""
    return importlib.import_module("automated_security_helper.utils.scan_categories")


def _package_root() -> Path:
    return Path(automated_security_helper.__file__).resolve().parent


def _identifiers(node: ast.AST) -> set[str]:
    """The identifiers *node* defines or names: a def or class, a name, an
    attribute, a keyword argument, a parameter or an imported name."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, (ast.keyword, ast.arg)) and node.arg is not None:
        return {node.arg}
    if isinstance(node, ast.alias):
        names = {node.name.rpartition(".")[2]}
        if node.asname:
            names.add(node.asname)
        return names
    return set()


def _fields(statement: ast.stmt) -> set[str]:
    """The names one statement of a class body defines in the class."""
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return {statement.target.id}
    if isinstance(statement, ast.Assign):
        return {
            target.id for target in statement.targets if isinstance(target, ast.Name)
        }
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {statement.name}
    return set()


def find_legacy_names(
    root: Path, entries: Iterable[tuple[str, str]]
) -> dict[tuple[str, str], list[str]]:
    """Where each ``(name, kind)`` entry is in the Python source under *root*.

    Each place is ``"<path from root>:<line>"``, once, in path and line order. The
    kinds:

    - ``name``: an identifier the source defines or names: a def, a class, an
      assignment target, an annotated field, an attribute, a keyword argument, a
      parameter or an imported name. A docstring, a comment or a string that only
      mentions it is not counted.
    - ``attribute``: ``Class.field``, the field defined in the body of a class
      called ``Class``, by an annotated or plain assignment or as a method.
    - ``tag``: a string constant that starts with the prefix, a literal part of an
      f-string included.

    A file that does not parse fails the call: a check that skipped it would pass
    over the one file it could not read.
    """
    wanted = list(entries)
    unknown = [entry for entry in wanted if entry[1] not in _KINDS]
    if unknown:
        raise ValueError(f"entries of no known kind ({', '.join(_KINDS)}): {unknown}")
    names = {name for name, kind in wanted if kind == "name"}
    fields_by_class: dict[str, set[str]] = {}
    for name, kind in wanted:
        if kind == "attribute":
            owner, _, field = name.partition(".")
            if not owner or not field or "." in field:
                raise ValueError(f"{name!r} is not a Class.field attribute")
            fields_by_class.setdefault(owner, set()).add(field)
    prefixes = [name for name, kind in wanted if kind == "tag"]
    places: dict[tuple[str, str], set[tuple[str, int]]] = {
        entry: set() for entry in wanted
    }
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            raise AssertionError(
                f"{relative} does not parse ({exc.msg}, line {exc.lineno}); the "
                "removal check cannot read its names"
            ) from exc
        for node in ast.walk(tree):
            line = getattr(node, "lineno", 0)
            for name in _identifiers(node) & names:
                places[(name, "name")].add((relative, line))
            if isinstance(node, ast.ClassDef) and node.name in fields_by_class:
                for statement in node.body:
                    for field in _fields(statement) & fields_by_class[node.name]:
                        entry = (f"{node.name}.{field}", "attribute")
                        places[entry].add((relative, statement.lineno))
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for prefix in prefixes:
                    if node.value.startswith(prefix):
                        places[(prefix, "tag")].add((relative, line))
    return {
        entry: [f"{path}:{line}" for path, line in sorted(found)]
        for entry, found in places.items()
    }


def remaining_report(places: dict[tuple[str, str], list[str]], shown: int = 20) -> str:
    """One line per entry that is still found: its name, its kind and its places."""
    lines: list[str] = []
    for (name, kind), found in places.items():
        if not found:
            continue
        listed = ", ".join(found[:shown])
        more = f" and {len(found) - shown} more" if len(found) > shown else ""
        lines.append(f"{name} ({kind}): {listed}{more}")
    return "\n".join(lines)


def test_the_removal_list_names_the_thirteen_legacy_names_in_order() -> None:
    module = _scan_categories()
    removed = module.REMOVED_IN_4_0

    assert isinstance(removed, tuple)
    assert module.RemovedName._fields == ("name", "kind", "what")
    assert all(isinstance(entry, module.RemovedName) for entry in removed)
    assert [(entry.name, entry.kind) for entry in removed] == list(_REMOVED_IN_4_0)
    for entry in removed:
        assert entry.kind in _KINDS, entry
        assert isinstance(entry.what, str), entry
        assert entry.what.strip(), f"{entry.name}: its what is blank"
        assert "\n" not in entry.what, f"{entry.name}: its what is not one line"


#: A planted package: each kind of use, and a near miss of each.
_PLANTED = {
    "names.py": (
        "def legacy_helper() -> None:\n"
        "    return None\n"
        "\n"
        "\n"
        "class LegacyKind:\n"
        "    legacy_field: int = 0\n"
        "\n"
        "\n"
        "LEGACY_TABLE: dict[str, int] = {}\n"
        "\n"
        "\n"
        "def use(holder: object) -> object:\n"
        "    call(legacy_kw=1)\n"
        "    return holder.legacy_attr\n"
    ),
    "mentions.py": (
        '"""legacy_helper, LegacyKind and LEGACY_TABLE, named in prose."""\n'
        "\n"
        "# legacy_kw, in a comment\n"
        'SPELLED = ["legacy_helper", "legacy_kw", "Facet.legacy_note"]\n'
    ),
    "facets.py": (
        "class Facet:\n"
        '    legacy_note: str = ""\n'
        "\n"
        "    def legacy_method(self) -> None:\n"
        "        return None\n"
        "\n"
        "\n"
        "class Other:\n"
        '    legacy_other: str = ""\n'
        "\n"
        "\n"
        "legacy_module_level = 1\n"
    ),
    "tags.py": (
        'PREFIX = "legacy::"\n'
        "\n"
        "\n"
        "def tag(value: str) -> str:\n"
        '    return f"legacy::{value}"\n'
        "\n"
        "\n"
        'NOT_A_TAG = "not legacy::"\n'
    ),
}

#: Where the finder must find each planted entry, and must find nothing.
_PLANTED_PLACES: dict[tuple[str, str], list[str]] = {
    ("legacy_helper", "name"): ["names.py:1"],
    ("LegacyKind", "name"): ["names.py:5"],
    ("legacy_field", "name"): ["names.py:6"],
    ("LEGACY_TABLE", "name"): ["names.py:9"],
    ("legacy_kw", "name"): ["names.py:13"],
    ("legacy_attr", "name"): ["names.py:14"],
    ("Facet.legacy_note", "attribute"): ["facets.py:2"],
    ("Facet.legacy_method", "attribute"): ["facets.py:4"],
    ("Facet.legacy_other", "attribute"): [],
    ("Other.legacy_note", "attribute"): [],
    ("Facet.legacy_module_level", "attribute"): [],
    ("legacy::", "tag"): ["tags.py:1", "tags.py:5"],
}


def test_the_finder_finds_each_kind_and_passes_over_a_mention(tmp_path: Path) -> None:
    for name, text in _PLANTED.items():
        (tmp_path / name).write_text(text, encoding="utf-8")

    found = find_legacy_names(tmp_path, _PLANTED_PLACES)

    assert found == _PLANTED_PLACES


def test_the_finder_refuses_an_unknown_kind_and_an_unreadable_file(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="no known kind"):
        find_legacy_names(tmp_path, [("legacy_helper", "label")])
    with pytest.raises(ValueError, match="not a Class.field attribute"):
        find_legacy_names(tmp_path, [("legacy_note", "attribute")])
    (tmp_path / "broken.py").write_text("def f(:\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="broken.py does not parse"):
        find_legacy_names(tmp_path, [("legacy_helper", "name")])


def test_the_report_names_each_entry_still_found_and_where() -> None:
    report = remaining_report(
        {
            ("legacy_helper", "name"): ["names.py:1"],
            ("LegacyKind", "name"): [],
            ("legacy::", "tag"): ["tags.py:1", "tags.py:5", "more.py:3"],
        },
        shown=2,
    )

    assert report == (
        "legacy_helper (name): names.py:1\n"
        "legacy:: (tag): tags.py:1, tags.py:5 and 1 more"
    )
    assert remaining_report({("LegacyKind", "name"): []}) == ""


def test_the_finder_sees_the_legacy_names_in_the_package_before_4_0() -> None:
    from packaging.version import Version

    version = automated_security_helper.__version__
    if Version(version) >= Version(_REMOVAL_VERSION):
        pytest.skip(f"ASH {version} is past {_REMOVAL_VERSION}: the names are gone")
    defined_in = {
        ("ScannerToolType", "name"): "core/enums.py",
        ("TargetsFacet.tool_type", "attribute"): "base/scanner_operational_facets.py",
        ("tool_type::", "tag"): "utils/scanner_tool_types.py",
    }

    found = find_legacy_names(_package_root(), defined_in)

    for entry, path in defined_in.items():
        paths = {place.rpartition(":")[0] for place in found[entry]}
        assert path in paths, f"{entry[0]} ({entry[1]}) is found only in {paths}"


def test_no_listed_name_is_left_once_the_version_reaches_4_0() -> None:
    """Before 4.0 the names stay, so this waits for the version; the controls above
    keep the finder honest until then."""
    from packaging.version import Version

    removed = _scan_categories().REMOVED_IN_4_0
    version = automated_security_helper.__version__
    if Version(version) < Version(_REMOVAL_VERSION):
        return

    report = remaining_report(
        find_legacy_names(
            _package_root(), [(entry.name, entry.kind) for entry in removed]
        )
    )

    assert not report, (
        f"ASH {version} reached {_REMOVAL_VERSION}, and these names on the removal "
        "list (utils/scan_categories.REMOVED_IN_4_0) are still in the package "
        f"source; remove each where it is named:\n{report}"
    )
