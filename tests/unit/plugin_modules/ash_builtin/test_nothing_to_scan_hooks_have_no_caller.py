# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Nothing in ASH calls ``nothing_to_scan_reason`` yet, so the hooks change no result.

actionlint, zizmor, cfn-lint, cfn-guard, gitleaks and trivy define the hook, and
test_nothing_to_scan_reason.py pins what each answers. No code in the
``automated_security_helper`` package asks it, and ``ScannerPluginBase`` does not
define it, so no scanner status depends on it.

This file only pins that. It fails, naming the references it found, as soon as ASH
gains a caller or a base-class definition. Then the hook's answers reach scanner
statuses, and this file is to be deleted: the behavior tests stay.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

import pytest

import automated_security_helper
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    NO_WORKFLOW_FILE,
    ActionlintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    NO_ZIZMOR_INPUT,
    ZizmorScanner,
)
from automated_security_helper.utils.cfn_template_discovery import (
    NO_CLOUDFORMATION_TEMPLATE,
)

HOOK = "nothing_to_scan_reason"
PACKAGE = Path(automated_security_helper.__file__).resolve().parent
THIS_FILE = (
    "tests/unit/plugin_modules/ash_builtin/test_nothing_to_scan_hooks_have_no_caller.py"
)
DELETE_ME = (
    f"This test only pinned that ASH had no caller of {HOOK}. Now that it has one, "
    f"the hook's answers decide scanner statuses: delete {THIS_FILE}, and keep "
    "test_nothing_to_scan_reason.py."
)


def references_to_the_hook(path: Path, root: Path) -> List[str]:
    """``path:line``, relative to *root*, for each reference to ``HOOK`` in *path*.

    A call (``scanner.nothing_to_scan_reason()``) and a lookup
    (``getattr(scanner, "nothing_to_scan_reason", None)``) both count. A
    definition does not, and neither does a longer name that contains it, such
    as ``cloudformation_templates_nothing_to_scan_reason``.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    shown = path.relative_to(root).as_posix()
    return sorted(
        f"{shown}:{node.lineno}"
        for node in ast.walk(tree)
        if (isinstance(node, ast.Attribute) and node.attr == HOOK)
        or (isinstance(node, ast.Constant) and node.value == HOOK)
    )


def test_nothing_in_ash_calls_the_hook():
    references = [
        reference
        for path in sorted(PACKAGE.rglob("*.py"))
        for reference in references_to_the_hook(path, PACKAGE.parent)
    ]

    assert references == [], f"Found {', '.join(references)}. {DELETE_ME}"


def test_the_scanner_base_class_does_not_define_the_hook():
    assert not hasattr(ScannerPluginBase, HOOK), (
        f"ScannerPluginBase now defines {HOOK}. {DELETE_ME}"
    )


def test_the_check_finds_a_caller_written_either_way(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def ask(scanner):\n"
        f"    getattr(scanner, {HOOK!r}, None)\n"
        f"    return scanner.{HOOK}()\n"
        f"def cloudformation_templates_{HOOK}():\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert references_to_the_hook(probe, tmp_path) == ["probe.py:2", "probe.py:3"]


@pytest.mark.parametrize(
    ("scanner_class", "expected"),
    [
        pytest.param(ActionlintScanner, NO_WORKFLOW_FILE, id="actionlint"),
        pytest.param(ZizmorScanner, NO_ZIZMOR_INPUT, id="zizmor"),
        pytest.param(CfnLintScanner, NO_CLOUDFORMATION_TEMPLATE, id="cfn-lint"),
        pytest.param(CfnGuardScanner, NO_CLOUDFORMATION_TEMPLATE, id="cfn-guard"),
        pytest.param(GitleaksScanner, None, id="gitleaks"),
        pytest.param(TrivyScanner, None, id="trivy"),
    ],
)
def test_each_hook_answers_on_a_tree_with_nothing_to_scan(
    tmp_path, scanner_class, expected
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "README.md").write_text("# app\n", encoding="utf-8")
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )

    assert scanner_class(context=context).nothing_to_scan_reason() == expected
