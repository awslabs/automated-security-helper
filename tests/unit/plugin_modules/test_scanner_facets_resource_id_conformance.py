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
import pkgutil
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.plugin_modules import ash_builtin
from automated_security_helper.utils.package_identity import ASH_RESOURCE_ID_KEY

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _REPO_ROOT / "tests" / "test_data" / "scanners"

_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()


def _registered_scanner_classes() -> list[type]:
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


SCANNER_CLASSES = _registered_scanner_classes()


def _resource_id_state(cls: type) -> FacetState:
    return vars(cls)[SCANNER_FACETS_ATTR].resource_id.state


def _classes_in(state: FacetState) -> list[type]:
    return [c for c in SCANNER_CLASSES if _resource_id_state(c) is state]


# --------------------------------------------------------------------------
# The writer detector, and its planted controls.
# --------------------------------------------------------------------------


def _key_writes(source: str) -> list[int]:
    """Line numbers where the source writes the resource-id key.

    A write is any of: a subscript whose index is the key (``bag["k"] = v``),
    a dict display with the key, a call keyword named for the key
    (``PropertyBag(ash_resource_id=...)``), or any use of the
    ``ASH_RESOURCE_ID_KEY`` constant by name. A string that merely mentions the
    key (a docstring, a ``reason=`` text) is not a write.
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
    ],
    ids=["subscript", "dict", "keyword", "constant", "attribute"],
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
    )
    assert _key_writes(source) == []


def test_the_enumeration_is_not_vacuous() -> None:
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert len(SCANNER_CLASSES) >= 20, sorted(c.__name__ for c in SCANNER_CLASSES)
    assert _classes_in(FacetState.MAPPED), "no scanner declares a mapped resource_id"
    assert _classes_in(FacetState.DROPPED), "no scanner declares a dropped resource_id"
    assert _classes_in(FacetState.NA), "no scanner declares an n/a resource_id"


# --------------------------------------------------------------------------
# Must-NOT: an N/A or DROPPED resource_id is never written.
# --------------------------------------------------------------------------


def _plugin_sources(cls: type) -> Iterator[tuple[str, str]]:
    """The module sources of the class and its bases inside plugin_modules."""
    seen: set[str] = set()
    for base in cls.__mro__:
        module = base.__module__
        if not module.startswith(plugin_modules.__name__) or module in seen:
            continue
        seen.add(module)
        yield module, inspect.getsource(sys.modules[module])


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
}


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
    with open(_FIXTURES / fixture, newline="", encoding="utf-8") as handle:
        cells = {cell for row in csv.reader(handle) for cell in row}
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
_DROPPED_FIXTURES: dict[str, tuple[str, str | None, str]] = {
    "CfnGuardScanner": (
        ("cfn_lint_guard/captured/cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif"),
        None,
        "Path=/Resources/LegacyFunction",
    ),
    "CfnLintScanner": (
        "cfn_lint_guard/captured/cfn-lint-1.61.0-m0-bad-property.json",
        "Path",
        "M0FixtureBucket",
    ),
    "CfnNagScanner": (
        "cfn_nag/src.test.yaml.json",
        "logical_resource_ids",
        "S3Bucket3",
    ),
    "CheckovScanner": (
        "checkov/src.test.yaml.json",
        "resource",
        "AWS::S3::Bucket.S3Bucket3",
    ),
    "TrivyScanner": (
        "trivy/captured/trivy-0.76.2-misconfig-terraform.json",
        "Resource",
        "aws_s3_bucket.m0_fixture_bucket",
    ),
    "TrivyRepoScanner": (
        "trivy/captured/trivy-0.76.2-misconfig-terraform.json",
        "Resource",
        "aws_s3_bucket.m0_fixture_bucket",
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


def _flatten(value: Any) -> Iterator[Any]:
    if isinstance(value, list):
        for item in value:
            yield from _flatten(item)
    else:
        yield value


def test_the_rot_guard_finds_a_planted_value_and_misses_an_absent_one() -> None:
    document = [{"a": {"Path": ["Resources", "Bucket"], "other": 1}}]
    found = {v for hit in _values_under_key(document, "Path") for v in _flatten(hit)}
    assert "Bucket" in found
    assert "Missing" not in found
    assert not list(_values_under_key(document, "Absent"))


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
