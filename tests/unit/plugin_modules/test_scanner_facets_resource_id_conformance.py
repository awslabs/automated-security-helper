# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Conformance of the register's ``resource_id`` cells to the code and fixtures.

The register (automated_security_helper/base/scanner_facets.py) validates the
SHAPE of a declaration and the totality test checks that one exists; neither
reads what a declaration claims. Without this module a wrong ``resource_id``
cell passes every test, and the register is etiquette, not a contract. Each
state gets the check that can fail:

- N/A or DROPPED means the adapter never writes ``ash_resource_id`` (the key
  that binds resource-scoped suppressions; a wrong value there binds a
  suppression to a finding it was not written for). The must-NOT row parses
  the source of the scanner class and every plugin-package base it inherits
  from and fails on any write of the key, whichever spelling.
- MAPPED means a writer exists and the declared example is a value a committed
  fixture really carries. The must-attach row pins the writer module per
  MAPPED scanner (so a new MAPPED cell forces a registered writer) and checks
  the example against the fixture.
- DROPPED means the native output carries the field. The rot guard reads the
  committed fixture and fails when the declared native field is gone from it
  (a tool upgrade that renamed it, a fixture replaced by one without it).

Scope, said plainly: this covers the ``resource_id`` facet, the one whose
wrong value does damage downstream. The other facets are shape-validated
only. The must-NOT row is a static read of plugin-package sources: a write
made through a module outside plugin_modules (a shared utility) is invisible
to it, which the planted controls below bound but do not close. A value that
arrives in a tool's own passed-through property bag is a different route and is
closed at the flatten boundary (models/flat_vulnerability.py); the last rows
of this module pin it.
"""

from __future__ import annotations

import ast
import csv
import importlib
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.utils.package_identity import ASH_RESOURCE_ID_KEY
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _REPO_ROOT / "tests" / "test_data" / "scanners"

#: The shared enumeration (tests/utils/scanner_enumeration.py).
SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()


def _declaration(cls: type) -> Any:
    """The class's own register row, or None for a scanner that declares none.

    Read with ``.get`` so that ONE undeclared scanner is not an unnamed
    KeyError at collection time that silences every control in this module:
    the registry totality test owns that failure and names the scanner.
    """
    return vars(cls).get(SCANNER_FACETS_ATTR)


def _resource_id_state(cls: type) -> FacetState | None:
    declaration = _declaration(cls)
    return None if declaration is None else declaration.resource_id.state


def _classes_in(state: FacetState, classes: list[type] | None = None) -> list[type]:
    pool = SCANNER_CLASSES if classes is None else classes
    return [c for c in pool if _resource_id_state(c) is state]


def test_an_undeclared_scanner_is_skipped_not_a_collection_error() -> None:
    """Planted: the totality test names a missing row; this module must not die."""

    class Undeclared:
        pass

    class Declared:
        facets = SimpleNamespace(
            resource_id=SimpleNamespace(state=FacetState.NA, example=None)
        )

    assert _resource_id_state(Undeclared) is None
    assert _classes_in(FacetState.NA, [Undeclared, Declared]) == [Declared]


# --------------------------------------------------------------------------
# The writer detector, and its planted controls.
# --------------------------------------------------------------------------


def _key_writes(source: str) -> list[int]:
    """Line numbers where the source writes the resource-id key.

    A write is any of: a subscript whose index is the key (``bag["k"] = v``),
    a dict display with the key, a call keyword named for the key
    (``PropertyBag(ash_resource_id=...)``), the key as a string-literal call
    argument (``props.setdefault("k", v)``, ``props.update(...)`` through a
    helper that takes the key), an import that renames the constant
    (``from ... import ASH_RESOURCE_ID_KEY as RID``, after which ``RID`` is a
    different Name), or any use of the ``ASH_RESOURCE_ID_KEY`` constant by
    name. A string that merely mentions the key (a docstring, a ``reason=``
    text) is not a write.
    """
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Subscript):
            index = node.slice
            if isinstance(index, ast.Constant) and index.value == ASH_RESOURCE_ID_KEY:
                lines.append(node.lineno)
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and key.value == ASH_RESOURCE_ID_KEY:
                    lines.append(key.lineno)
        elif isinstance(node, ast.keyword):
            if node.arg == ASH_RESOURCE_ID_KEY:
                lines.append(node.value.lineno)
        elif isinstance(node, ast.Call):
            for argument in node.args:
                if (
                    isinstance(argument, ast.Constant)
                    and argument.value == ASH_RESOURCE_ID_KEY
                ):
                    lines.append(argument.lineno)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "ASH_RESOURCE_ID_KEY" and alias.asname:
                    lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id == "ASH_RESOURCE_ID_KEY":
            lines.append(node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr == "ASH_RESOURCE_ID_KEY":
            lines.append(node.lineno)
    return sorted(set(lines))


@pytest.mark.parametrize(
    "source",
    [
        'props["ash_resource_id"] = secret_hash\n',
        'bag = {"ash_resource_id": h}\n',
        "PropertyBag(ash_resource_id=h)\n",
        "props[ASH_RESOURCE_ID_KEY] = h\n",
        "props[package_identity.ASH_RESOURCE_ID_KEY] = h\n",
        'props.setdefault("ash_resource_id", h)\n',
        'props.pop("ash_resource_id", None)\n',
        (
            "from automated_security_helper.utils.package_identity import (\n"
            "    ASH_RESOURCE_ID_KEY as RID,\n"
            ")\n"
        ),
    ],
    ids=[
        "subscript",
        "dict",
        "keyword",
        "constant",
        "attribute",
        "call-argument-setdefault",
        "call-argument-pop",
        "aliased-import",
    ],
)
def test_the_writer_detector_flags_every_spelling(source: str) -> None:
    """Planted must-flag: a detector that sees nothing proves nothing."""
    assert _key_writes(source), source


def test_the_writer_detector_ignores_prose_mentions() -> None:
    """Planted must-not-flag: docstrings and reason texts are not writes."""
    source = (
        '"""Never writes ash_resource_id."""\n'
        "# ash_resource_id stays unset\n"
        'x = FacetDecl(reason="writes no ash_resource_id")\n'
        'log("the ash_resource_id key is never written")\n'
        "from automated_security_helper.utils.package_identity import "
        "ASH_RESOURCE_ID_KEY\n"
    )
    assert _key_writes(source) == []


def test_the_enumeration_is_not_vacuous() -> None:
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert len(SCANNER_CLASSES) >= 20, sorted(c.__name__ for c in SCANNER_CLASSES)
    assert _classes_in(FacetState.MAPPED), "no scanner declares a mapped resource_id"
    assert _classes_in(FacetState.NA), "no scanner declares an n/a resource_id"


# --------------------------------------------------------------------------
# Must-NOT: an N/A or DROPPED resource_id is never written.
# --------------------------------------------------------------------------


def _imported_names(source: str) -> set[str]:
    """Every dotted module name a source's import statements could name.

    ``from pkg.mod import helper`` names ``pkg.mod`` and, for the ``from pkg
    import mod`` form, ``pkg.mod.helper`` too; the caller keeps only the names
    that are real loaded modules, so a function or a class is not mistaken for
    one.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def _loaded_module_source(module: str) -> str | None:
    """The source of a loaded, non-package module, else None.

    A package ``__init__`` is skipped: it re-exports its siblings (ash_builtin
    imports every builtin scanner), so following it would charge one scanner
    with every other scanner's writes.
    """
    loaded = sys.modules.get(module)
    if loaded is None or getattr(loaded, "__path__", None) is not None:
        return None
    return inspect.getsource(loaded)


def _reachable_sources(
    roots: list[str], read_source: Any = _loaded_module_source
) -> Iterator[tuple[str, str]]:
    """The sources of ``roots`` and of the plugin_modules modules they import.

    Followed to a fixed point, breadth first. ``read_source`` maps a dotted name
    to its source, or None for a name that is not a readable module.
    """
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        module = pending.pop(0)
        if not module.startswith(plugin_modules.__name__) or module in seen:
            continue
        seen.add(module)
        source = read_source(module)
        if source is None:
            continue
        yield module, source
        pending.extend(sorted(_imported_names(source)))


def _plugin_sources(cls: type) -> Iterator[tuple[str, str]]:
    """The module sources the class can reach inside plugin_modules.

    The modules of the class and of every base in its MRO, and the plugin_modules
    modules those import: a helper module the class calls but does not inherit
    from is a route to the key too. Scope, said plainly: bases and helpers
    OUTSIDE plugin_modules (base/scanner_plugin.py, utils/) are not read here; a
    value they attach arrives through the result's property bag and is closed at
    the flatten boundary by the passthrough rows below.
    """
    yield from _reachable_sources([base.__module__ for base in cls.__mro__])


def test_the_source_walk_follows_a_helper_the_class_only_imports() -> None:
    """Planted: a write in a module the scanner imports but does not inherit."""
    root = f"{plugin_modules.__name__}.planted_scanner"
    helper = f"{plugin_modules.__name__}.planted_helper"
    package = f"{plugin_modules.__name__}.planted_pkg"
    sources = {
        root: f"from {helper} import attach\nfrom {package} import everything\n",
        helper: 'def attach(bag, v):\n    bag.setdefault("ash_resource_id", v)\n',
        package: "from x import y\n",
    }

    def read(name: str) -> str | None:
        # the package __init__ answers None, as _loaded_module_source does
        return None if name == package else sources.get(name)

    reached = dict(_reachable_sources([root], read))
    assert set(reached) == {root, helper}
    assert _key_writes(reached[helper]) and not _key_writes(reached[root])
    # outside plugin_modules, and a name that is not a module, are not followed
    assert dict(_reachable_sources(["json"], read)) == {}
    assert dict(_reachable_sources([f"{plugin_modules.__name__}.nope"], read)) == {}


@pytest.mark.parametrize(
    "scanner_cls",
    _classes_in(FacetState.NA) + _classes_in(FacetState.DROPPED),
    ids=lambda cls: cls.__name__,
)
def test_an_na_or_dropped_resource_id_is_never_written(scanner_cls: type) -> None:
    for module, source in _plugin_sources(scanner_cls):
        writes = _key_writes(source)
        assert not writes, (
            f"{scanner_cls.__name__} declares resource_id "
            f"{_resource_id_state(scanner_cls).value} but {module} writes "
            f"{ASH_RESOURCE_ID_KEY} at line(s) {writes}. Either the "
            "declaration is wrong (mapped, with an example from a real read) "
            "or the write is: a value under this key binds resource-scoped "
            "suppressions."
        )


# --------------------------------------------------------------------------
# Must-attach: a MAPPED resource_id has a writer and a real example.
# --------------------------------------------------------------------------

#: scanner class -> (module that writes the key, committed fixture holding the
#: declared example). A MAPPED cell without a row here fails the totality test.
_MAPPED_WRITERS: dict[str, tuple[str, str]] = {
    "CdkNagScanner": (
        "automated_security_helper.utils.cdk_nag_wrapper",
        "cdk/test.yaml_cdk_nag_results/AwsSolutions-test-yaml-NagReport.csv",
    ),
    "CheckovScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            ".checkov_scanner"
        ),
        "checkov/src.test.yaml.json",
    ),
    # DERIVED: the id is parsed from message prose, so the example is read as
    # a path segment of the committed SARIF text. The parse itself and its
    # rot guard are in test_cfn_guard_scanner.py.
    "CfnLintScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            ".cfn_lint_scanner"
        ),
        "cfn_lint_guard/captured/cfn-lint-1.61.0-m0-bad-property.json",
    ),
    # trivy and trivy-repo share one writer (the base module), and the example
    # is the Resource cell of the captured trivy JSON report.
    "TrivyScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            "._trivy_scanner_base"
        ),
        "trivy/captured/trivy-0.76.2-misconfig-terraform.json",
    ),
    "TrivyRepoScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            "._trivy_scanner_base"
        ),
        "trivy/captured/trivy-0.76.2-misconfig-terraform.json",
    ),
    "CfnNagScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners"
            ".cfn_nag_scanner"
        ),
        "cfn_nag/captured/cfn_nag-0.8.10-two-buckets.sarif",
    ),
    "CfnGuardScanner": (
        (
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner"
        ),
        "cfn_lint_guard/captured/cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif",
    ),
}


def _fixture_cells(path: Path) -> set[str]:
    """The candidate example values a committed fixture carries.

    A ``.json`` fixture's cells are every string value anywhere in the
    document; any other fixture is read as CSV and its cells are the fields.
    """
    if path.suffix in (".json", ".sarif"):
        with open(path, encoding="utf-8") as handle:
            return set(_string_values(json.load(handle)))
    with open(path, newline="", encoding="utf-8") as handle:
        return {cell for row in csv.reader(handle) for cell in row}


def _string_values(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _string_values(item)


def test_every_mapped_resource_id_has_a_registered_writer() -> None:
    mapped = {c.__name__ for c in _classes_in(FacetState.MAPPED)}
    assert mapped == set(_MAPPED_WRITERS), (
        "a MAPPED resource_id needs a row in _MAPPED_WRITERS (the module that "
        f"writes the key, and the fixture carrying its example): mapped={sorted(mapped)} "
        f"registered={sorted(_MAPPED_WRITERS)}"
    )


@pytest.mark.parametrize("name", sorted(_MAPPED_WRITERS))
def test_a_mapped_resource_id_is_written_and_its_example_is_in_the_fixture(
    name: str,
) -> None:
    cls = next(c for c in SCANNER_CLASSES if c.__name__ == name)
    writer_module, fixture = _MAPPED_WRITERS[name]
    source = inspect.getsource(importlib.import_module(writer_module))
    assert _key_writes(source), (
        f"{name} declares resource_id mapped but {writer_module} never writes "
        f"{ASH_RESOURCE_ID_KEY}"
    )
    example = vars(cls)[SCANNER_FACETS_ATTR].resource_id.example
    assert example, f"{name}: a mapped resource_id carries its example"
    if fixture.endswith(".sarif") and name == "CfnGuardScanner":
        with open(_FIXTURES / fixture, encoding="utf-8") as handle:
            fixture_text = handle.read()
        example_probe = f"Path=/Resources/{example}/"
        assert example_probe in fixture_text, (
            f"{name}: the declared example {example!r} is not a Path= segment "
            f"of the committed fixture {fixture}"
        )
        return
    cells = _fixture_cells(_FIXTURES / fixture)
    assert example in cells, (
        f"{name}: the declared example {example!r} is not a cell of the "
        f"committed fixture {fixture}; an example comes from a real read"
    )


# --------------------------------------------------------------------------
# DROPPED rot guard: the fixture still carries the declared native field.
# --------------------------------------------------------------------------

#: scanner class -> (committed fixture, JSON key holding the id, a value that
#: key carries in that fixture). A DROPPED cell without a row here fails the
#: totality test, so the claim "the native output carries it" is always read.
#: A key of ``None`` means the id lives in message prose (cfn-guard), so the
#: value is read as a substring of the fixture text instead of under a key.
#: Empty since cfn-lint, cfn-nag, trivy and trivy-repo moved to MAPPED (their
#: native-field example is read from the same fixtures by the must-attach rows
#: above); the machinery stays for the next cell declared DROPPED.
_DROPPED_FIXTURES: dict[str, tuple[str, str | None, str]] = {
    "KicsScanner": (
        "kics/captured/positive.json",
        "search_key",
        "aws_s3_bucket[b].acl=public-read",
    ),
    # Kyverno's native output is the policy report as YAML, which the JSON
    # reader cannot parse, so the object it names under "resources" is read as
    # a substring of the captured report's text (the key-None reading).
    "KyvernoScanner": (
        "kyverno/captured/kyverno-1.19.2-high.report.yaml",
        None,
        "    kind: Pod\n    name: bad-pod\n    namespace: default\n",
    ),
}


def _values_under_key(node: Any, key: str) -> Iterator[Any]:
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                yield value
            yield from _values_under_key(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _values_under_key(item, key)


def _flatten(value: Any) -> Iterator[str]:
    """The string leaves under a value; a dict or a number is not a candidate.

    A nested dict yielded whole made the caller's set comprehension raise
    TypeError (an unhashable dict), and a number can never equal the declared
    string example.
    """
    if isinstance(value, list):
        for item in value:
            yield from _flatten(item)
    elif isinstance(value, str):
        yield value


def test_the_rot_guard_finds_a_planted_value_and_misses_an_absent_one() -> None:
    document = [{"a": {"Path": ["Resources", "Bucket"], "other": 1}}]
    found = {v for hit in _values_under_key(document, "Path") for v in _flatten(hit)}
    assert "Bucket" in found
    assert "Missing" not in found
    assert not list(_values_under_key(document, "Absent"))


def test_the_rot_guard_survives_a_dict_under_the_key() -> None:
    """Planted: a dict value under the key must not crash the set build."""
    document = {"Path": {"nested": "Bucket"}, "other": {"Path": ["Bucket", 3]}}
    found = {v for hit in _values_under_key(document, "Path") for v in _flatten(hit)}
    assert found == {"Bucket"}


def _declared_names_key(native_field: str | None, key: str | None) -> bool:
    """True when a declaration's native_field names the fixture key it rests on.

    A row of ``_DROPPED_FIXTURES`` reads the committed fixture under ``key``;
    nothing else ties that key to the cell, so a row for the wrong key would
    keep the rot guard green while guarding a field the cell does not claim.
    A ``None`` key means the id lives in message prose and has no key to name.
    """
    return key is None or key in (native_field or "")


def test_the_key_tie_flags_a_row_whose_key_is_not_in_the_declaration() -> None:
    assert _declared_names_key('Results[].CauseMetadata."Resource"', "Resource")
    assert not _declared_names_key('Results[].CauseMetadata."Resource"', "Path")
    assert not _declared_names_key(None, "Resource")
    assert _declared_names_key(None, None)


@pytest.mark.parametrize("name", sorted(_DROPPED_FIXTURES))
def test_a_dropped_row_names_a_key_its_declaration_names(name: str) -> None:
    cls = next(c for c in SCANNER_CLASSES if c.__name__ == name)
    _fixture, key, _value = _DROPPED_FIXTURES[name]
    native_field = vars(cls)[SCANNER_FACETS_ATTR].resource_id.native_field
    assert _declared_names_key(native_field, key), (
        f"{name}: the rot-guard row reads key {key!r} but the declared "
        f"native_field {native_field!r} does not name it"
    )


def test_every_dropped_resource_id_has_a_fixture_row() -> None:
    dropped = {c.__name__ for c in _classes_in(FacetState.DROPPED)}
    assert dropped == set(_DROPPED_FIXTURES), (
        "a DROPPED resource_id needs a row in _DROPPED_FIXTURES (a committed "
        f"fixture carrying the native field): dropped={sorted(dropped)} "
        f"registered={sorted(_DROPPED_FIXTURES)}"
    )


@pytest.mark.parametrize("name", sorted(_DROPPED_FIXTURES))
def test_a_dropped_resource_id_is_still_in_its_fixture(name: str) -> None:
    fixture, key, value = _DROPPED_FIXTURES[name]
    with open(_FIXTURES / fixture, encoding="utf-8") as handle:
        text = handle.read()
    if key is None:
        assert value in text, (
            f"{name}: {value!r} no longer appears in {fixture}; the dropped "
            "cell's evidence rotted, so re-read the tool output and "
            "re-declare the cell"
        )
        return
    document = json.loads(text)
    found = {v for hit in _values_under_key(document, key) for v in _flatten(hit)}
    assert value in found, (
        f"{name}: the declared native field {key!r} no longer carries "
        f"{value!r} in {fixture}; the dropped cell's evidence rotted, so "
        "re-read the tool output and re-declare the cell"
    )


# --------------------------------------------------------------------------
# Passthrough: a tool's own property bag cannot attach a resource id.
# --------------------------------------------------------------------------

_BAG_VALUE = "tool/controlled/path"


def _flatten_with_bag_key(scanner_name: str):
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability
    from automated_security_helper.schemas.sarif_schema_model import (
        Message,
        Message1,
        PropertyBag,
        Result,
    )

    result = Result(
        ruleId="TOOL-RULE-1",
        message=Message(root=Message1(text="a finding")),
        properties=PropertyBag(**{ASH_RESOURCE_ID_KEY: _BAG_VALUE}),
    )
    return FlatVulnerability.from_sarif_result(result, scanner_name, "SAST")


def _config_name(cls: type) -> str | None:
    from automated_security_helper.utils.scanner_tool_types import (
        _class_config_name,
    )

    return _class_config_name(cls)


@pytest.mark.parametrize(
    "scanner_cls",
    _classes_in(FacetState.NA) + _classes_in(FacetState.DROPPED),
    ids=lambda cls: cls.__name__,
)
def test_a_tool_bag_resource_id_never_attaches_for_an_na_or_dropped_scanner(
    scanner_cls: type,
) -> None:
    name = _config_name(scanner_cls)
    assert name, f"{scanner_cls.__name__}: no config name to flatten under"
    assert _flatten_with_bag_key(name).resource_id is None, (
        f"{scanner_cls.__name__} declares resource_id "
        f"{_resource_id_state(scanner_cls).value}, yet a {ASH_RESOURCE_ID_KEY} "
        "arriving in the tool's own property bag attached to the finding"
    )


@pytest.mark.parametrize(
    "scanner_cls",
    _classes_in(FacetState.MAPPED),
    ids=lambda cls: cls.__name__,
)
def test_a_mapped_scanner_keeps_its_resource_id(scanner_cls: type) -> None:
    name = _config_name(scanner_cls)
    assert name, f"{scanner_cls.__name__}: no config name to flatten under"
    assert _flatten_with_bag_key(name).resource_id == _BAG_VALUE


def test_an_unknown_scanner_is_left_as_read() -> None:
    assert _flatten_with_bag_key("no-such-scanner").resource_id == _BAG_VALUE


def test_a_state_the_drop_does_not_know_never_keeps_a_tool_bag_resource_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drop is fail-closed: any declared state but MAPPED drops the value.

    A state added to the vocabulary later is not named in the drop, and a
    pass-through resource id would bind resource-scoped suppressions to a value
    the tool, not ASH, wrote. ``None`` (an unknown scanner) stays left as read.
    """
    from automated_security_helper.utils import scanner_tool_types

    monkeypatch.setattr(
        scanner_tool_types, "scanner_resource_id_state", lambda _name: "a-future-state"
    )
    assert _flatten_with_bag_key("any-scanner").resource_id is None
