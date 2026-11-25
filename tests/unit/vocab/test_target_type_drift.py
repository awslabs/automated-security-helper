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

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
PKG = REPO / "automated_security_helper"

# Files cured for TargetType by the string-spelling scan. Not in this scan (named so
# nobody reads the gate as whole-tree): the scanner modules under plugin_modules/
# (SCANNER_SCOPE below, a context-aware scan because "source" is an ordinary word
# there), core/phases/scan_phase.py (task dicts) and
# core/resource_management/scan_tracking.py. A file a later change cures is added
# to SCOPE by that change; this list does not decide it.
SCOPE = (
    "utils/finding_identity.py",
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


# --- the scanner modules ---------------------------------------------------------

#: The scanner modules whose ``target_type`` parameter is the enum. In these files
#: "source" and "converted" are ordinary words (dict keys, directory names), so the
#: scan reads context instead of every constant: a ``Literal`` naming a member, a
#: comparison against a ``target_type`` expression, a ``target_type=`` keyword
#: handed text, and a collection holding only member text (a hand-made tree list).
SCANNER_SCOPE = (
    "plugin_modules/ash_betterleaks_plugins/betterleaks_scanner.py",
    "plugin_modules/ash_builtin/scanners/_grep_scanner_base.py",
    "plugin_modules/ash_builtin/scanners/actionlint_scanner.py",
    "plugin_modules/ash_builtin/scanners/bandit_scanner.py",
    "plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_guard_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_lint_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
    "plugin_modules/ash_builtin/scanners/checkov_scanner.py",
    "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
    "plugin_modules/ash_builtin/scanners/gitleaks_scanner.py",
    "plugin_modules/ash_builtin/scanners/grype_scanner.py",
    "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
    "plugin_modules/ash_builtin/scanners/syft_scanner.py",
    "plugin_modules/ash_builtin/scanners/trivy_scanner.py",
    "plugin_modules/ash_builtin/scanners/zizmor_scanner.py",
    "plugin_modules/ash_ferret_plugins/ferret_scanner.py",
    "plugin_modules/ash_guarddog_plugins/guarddog_scanner.py",
    "plugin_modules/ash_hadolint_plugins/hadolint_scanner.py",
    "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
    "plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
)


def _is_member_text(node: ast.AST, values: frozenset[str] = MEMBER_VALUES) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in values
    )


def _callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def scanner_spellings(source: str, values: frozenset[str] = MEMBER_VALUES) -> list[int]:
    """Lines where a scanner module spells the source/converted label as text."""
    tree = ast.parse(source)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _callee_name(node.value) == "Literal":
            if any(_is_member_text(c, values) for c in ast.walk(node.slice)):
                lines.add(node.lineno)
        elif isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            texts = [o for o in operands if _is_member_text(o, values)]
            others = [o for o in operands if not _is_member_text(o, values)]
            if texts and any("target_type" in ast.unparse(o) for o in others):
                lines.add(node.lineno)
        elif isinstance(node, ast.keyword):
            if node.arg == "target_type" and _is_member_text(node.value, values):
                lines.add(node.value.lineno)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            strings = [e for e in node.elts if isinstance(e, ast.Constant)]
            if strings and all(_is_member_text(e, values) for e in strings):
                if len(strings) == len(node.elts):
                    lines.add(node.lineno)
    return sorted(lines)


@pytest.mark.parametrize("rel", SCANNER_SCOPE)
def test_no_scanner_module_spells_the_target_label_as_text(rel):
    assert (PKG / rel).is_file(), f"{rel} is in the gate's scope but does not exist"
    lines = scanner_spellings((PKG / rel).read_text(encoding="utf-8"))
    assert lines == [], f"{rel} spells a TargetType value at lines {lines}"


def test_the_scanner_scan_flags_each_planted_shape():
    planted = (
        "from typing import Literal\n"
        'def f(target_type: Literal["source", "converted"]):\n'  # 2
        '    if target_type == "converted":\n'  # 3
        "        pass\n"
        '    g(target_type="source")\n'  # 5
        '    return ["source"]\n'  # 6
    )
    assert scanner_spellings(planted) == [2, 3, 5, 6]
    clean = (
        "from automated_security_helper.models.vocab import TargetType\n"
        "def f(target_type: TargetType):\n"
        "    if target_type == TargetType.CONVERTED:\n"
        "        pass\n"
        '    return {"source": 1, "other": 2}\n'
        '    x = ("analysis", "converted")\n'
        '    y = response.get("source") == "source"\n'
    )
    assert scanner_spellings(clean) == []


def test_every_scanner_method_takes_the_enum():
    import importlib
    import inspect
    import typing

    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    seen = 0
    for rel in SCANNER_SCOPE:
        module = importlib.import_module(
            "automated_security_helper." + rel[: -len(".py")].replace("/", ".")
        )
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__ or not issubclass(
                cls, ScannerPluginBase
            ):
                continue
            for name, member in list(vars(cls).items()):
                func = getattr(member, "__func__", member)
                if not inspect.isfunction(func):
                    continue
                if "target_type" not in inspect.signature(func).parameters:
                    continue
                hints = typing.get_type_hints(func)
                if "target_type" not in hints:
                    continue
                seen += 1
                assert hints["target_type"] in (TargetType, TargetType | None), (
                    f"{cls.__name__}.{name} types target_type as "
                    f"{hints['target_type']!r}"
                )
    assert seen >= len(SCANNER_SCOPE), f"only {seen} target_type methods were read"


def test_the_scan_reads_a_real_scope_file():
    # A control that the scan sees real files: the enum module itself spells all three.
    lines = stray_spellings((PKG / "models/vocab.py").read_text(encoding="utf-8"))
    assert len(lines) == 3


# --- the vocabulary and its wire spellings -------------------------------------


def test_members_and_order_are_the_wire_spellings():
    assert [m.value for m in TargetType] == ["source", "converted", "image"]
    assert TargetType("source") is TargetType.SOURCE
    assert TargetType.SOURCE == "source" and TargetType.CONVERTED == "converted"
    assert TargetType("image") is TargetType.IMAGE


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
