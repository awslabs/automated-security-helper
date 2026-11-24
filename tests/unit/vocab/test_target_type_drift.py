# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The drift gate and wire pins for ``TargetType`` (the source/converted label).

Gate mode: ``source`` and ``converted`` are short, ordinary words that appear in
unrelated places (``"source"`` as a dict key or a directory name), so a tree-wide
scan would drown in false positives. The gate is therefore scoped to the files
this vocabulary has been cured in (the SCOPE below, which grows as later units
land: the scanner modules, ``finding_identity`` and the rest are not in it yet) and
scans those files with ``ast`` for any string constant equal to a member value,
outside docstrings. An allowlist entry needs a reason. A planted-positive control
proves the scan can fail.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.models.vocab import TargetType

REPO = Path(__file__).resolve().parents[3]
PKG = REPO / "automated_security_helper"

# Files cured for TargetType. Not yet in scope (named so nobody reads the gate as
# whole-tree): the scanner modules under plugin_modules/ (they spell the Literal
# 36 times), utils/finding_identity.py (CONVERTED_TREE), core/phases/scan_phase.py
# (task dicts) and core/resource_management/scan_tracking.py.
SCOPE = (
    "base/scanner_plugin.py",
    "base/plugin_base.py",
    "models/scan_results_container.py",
    "utils/scan_targets.py",
    "utils/cfn_template_discovery.py",
    "utils/cfn_template_model.py",
)

# (relative path, reason). Empty: no in-scope file may spell a member value.
ALLOWLIST: dict[str, str] = {}

MEMBER_VALUES = frozenset(m.value for m in TargetType)


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def stray_spellings(source: str, values: frozenset[str] = MEMBER_VALUES) -> list[int]:
    """Line numbers of string constants equal to a member value, docstrings skipped."""
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in values
        and id(node) not in skip
    )


@pytest.mark.parametrize("rel", SCOPE)
def test_no_stray_target_type_spelling_in_scope(rel):
    if rel in ALLOWLIST:
        pytest.skip(ALLOWLIST[rel])
    assert (PKG / rel).is_file(), f"{rel} is in the gate's scope but does not exist"
    lines = stray_spellings((PKG / rel).read_text(encoding="utf-8"))
    assert lines == [], f"{rel} spells a TargetType value at lines {lines}"


def test_the_scan_flags_a_planted_stray_spelling():
    planted = (
        '"""doc mentioning "source" is fine."""\n'
        "from typing import Literal\n"
        'def f(t: Literal["source", "converted"]):\n'
        '    return t == "converted"\n'
    )
    assert stray_spellings(planted) == [3, 3, 4]
    assert stray_spellings("x = 1\n") == []


def test_the_scan_reads_a_real_scope_file():
    # A control that the scan sees real files: the enum module itself spells both.
    lines = stray_spellings((PKG / "models/vocab.py").read_text(encoding="utf-8"))
    assert len(lines) == 2


# --- the vocabulary and its wire spellings -------------------------------------


def test_members_and_order_are_the_wire_spellings():
    assert [m.value for m in TargetType] == ["source", "converted"]
    assert TargetType("source") is TargetType.SOURCE
    assert TargetType.SOURCE == "source" and TargetType.CONVERTED == "converted"


def test_a_member_renders_as_its_value_in_text():
    for member in TargetType:
        assert str(member) == member.value
        assert f"{member}" == member.value
        assert "%s" % member == member.value
        assert json.dumps({"t": member}) == json.dumps({"t": member.value})


def test_an_unknown_label_is_not_a_member():
    with pytest.raises(ValueError):
        TargetType("file")


def test_the_container_field_validates_and_dumps_the_wire_string():
    c = ScanResultsContainer(scanner_name="s", target_type="converted")
    assert c.target_type is TargetType.CONVERTED
    assert json.loads(c.model_dump_json())["target_type"] == "converted"
    assert c.model_dump(mode="json")["target_type"] == "converted"
    assert ScanResultsContainer(scanner_name="s").target_type is None
    with pytest.raises(ValueError):
        ScanResultsContainer(scanner_name="s", target_type="file")


def test_scan_targets_hand_out_members(tmp_path):
    from automated_security_helper.utils.scan_targets import scan_targets

    class _Ctx:
        source_dir = tmp_path / "src"
        work_dir = tmp_path / "work"

    _Ctx.source_dir.mkdir()
    _Ctx.work_dir.mkdir()
    (_Ctx.work_dir / "a.txt").write_text("x")
    got = scan_targets(_Ctx())
    assert [t for t, _ in got] == [TargetType.SOURCE, TargetType.CONVERTED]
    assert all(isinstance(t, TargetType) for t, _ in got)
