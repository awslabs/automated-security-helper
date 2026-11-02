# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_plugin()`` has no caller inside the package; this names them.

The failure this pins
---------------------
``ScannerPluginBase.validate_plugin`` logs a scanner's dependency reason and
sets ``dependencies_satisfied``. A scan never calls it: ``_pre_scan`` asks
``validate_plugin_dependencies`` and records its own failure after it clears
``errors``. A method nothing calls is easy to remove by mistake or to rely on
by mistake, so the set of callers is written down here. The set is empty
today. A new call site under ``automated_security_helper/`` fails this test
until its author reads ``validate_plugin`` against the scan path (the two
differ in what they log and in what they leave in ``errors``) and lists the
call here with its reason.

Scope, stated precisely: the walk reads the AST of every ``*.py`` under the
package and collects calls spelled ``<expr>.validate_plugin(...)`` or
``validate_plugin(...)``. It does not see ``getattr(plugin, name)()`` or a
call from outside the package; those stay review's to catch. The definitions
are listed too, so a second class that grows a method of the same name is a
decision someone makes on purpose.
"""

import ast
from pathlib import Path

import pytest

import automated_security_helper

pytestmark = pytest.mark.unit

_PACKAGE_DIR = Path(automated_security_helper.__file__).parent

# Reviewed call sites, as (module, enclosing function) -> reason. Empty: no
# code in the package calls validate_plugin().
_ALLOWED_CALLERS: dict = {}

# Reviewed definitions, as (module, dotted class and def name) -> reason.
_ALLOWED_DEFINITIONS = {
    (
        "base/scanner_plugin.py",
        "ScannerPluginBase.validate_plugin",
    ): "the standalone check; a scan asks validate_plugin_dependencies",
}


def _validate_plugin_sites(root):
    """Return (calls, definitions) of validate_plugin under root.

    Each entry is ``(relpath, dotted enclosing name, line)``. The enclosing
    name is the stack of class and def names; module-level code is
    ``<module>``.
    """
    calls = []
    definitions = []
    for path in sorted(root.rglob("*.py")):
        relpath = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        stack = []

        class _Walker(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                if node.name == "validate_plugin":
                    definitions.append(
                        (relpath, ".".join([*stack, node.name]), node.lineno)
                    )
                stack.append(node.name)
                self.generic_visit(node)
                stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node):
                stack.append(node.name)
                self.generic_visit(node)
                stack.pop()

            def visit_Call(self, node):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name == "validate_plugin":
                    calls.append((relpath, ".".join(stack) or "<module>", node.lineno))
                self.generic_visit(node)

        _Walker().visit(tree)
    return calls, definitions


def _write_module(root, relpath, text):
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_no_code_in_the_package_calls_validate_plugin():
    calls, _ = _validate_plugin_sites(_PACKAGE_DIR)
    stray = [
        f"{relpath}:{line} (in {where})"
        for relpath, where, line in calls
        if (relpath, where) not in _ALLOWED_CALLERS
    ]
    assert stray == [], (
        "a call of validate_plugin() inside the package -- a scan reports "
        "through validate_plugin_dependencies and _pre_scan; read the two "
        "against each other, then list this call in the guard's reviewed "
        f"callers with its reason: {stray}"
    )


def test_validate_plugin_is_defined_only_where_it_is_reviewed():
    _, definitions = _validate_plugin_sites(_PACKAGE_DIR)
    found = {(relpath, name) for relpath, name, _ in definitions}
    assert found == set(_ALLOWED_DEFINITIONS), (
        "validate_plugin() is defined somewhere other than the reviewed "
        f"set (or not at all): found {sorted(found)}"
    )


def test_every_reviewed_caller_names_a_live_call_site():
    calls, _ = _validate_plugin_sites(_PACKAGE_DIR)
    live = {(relpath, where) for relpath, where, _ in calls}
    stale = sorted(key for key in _ALLOWED_CALLERS if key not in live)
    assert stale == [], f"reviewed callers that name no call in the package: {stale}"


def test_a_call_in_any_module_is_named(tmp_path):
    _write_module(
        tmp_path,
        "core/phases/some_phase.py",
        "def run(plugin):\n    return plugin.validate_plugin()\n",
    )
    calls, definitions = _validate_plugin_sites(tmp_path)
    assert calls == [("core/phases/some_phase.py", "run", 2)]
    assert definitions == []


def test_a_bare_call_and_a_method_call_inside_a_class_are_named(tmp_path):
    _write_module(
        tmp_path,
        "utils/other.py",
        "class Runner:\n"
        "    def launch(self, plugin):\n"
        "        validate_plugin(plugin)\n"
        "        return self.plugin.validate_plugin()\n",
    )
    calls, _ = _validate_plugin_sites(tmp_path)
    assert calls == [
        ("utils/other.py", "Runner.launch", 3),
        ("utils/other.py", "Runner.launch", 4),
    ]


def test_a_definition_is_not_a_call_and_is_named_with_its_class(tmp_path):
    _write_module(
        tmp_path,
        "base/other_plugin.py",
        "class OtherPlugin:\n    def validate_plugin(self):\n        return True\n",
    )
    calls, definitions = _validate_plugin_sites(tmp_path)
    assert calls == []
    assert definitions == [("base/other_plugin.py", "OtherPlugin.validate_plugin", 2)]


def test_the_name_validate_plugin_dependencies_is_not_a_match(tmp_path):
    _write_module(
        tmp_path,
        "core/phases/scan_like.py",
        "def run(plugin):\n    return plugin.validate_plugin_dependencies()\n",
    )
    calls, definitions = _validate_plugin_sites(tmp_path)
    assert calls == []
    assert definitions == []
