"""Scanners use ``_operator_gated`` for an operator-only option that falls back.

``ScannerPluginBase._operator_gated`` owns the shape "the operator's value, else
the safe default with one warning per option per instance". A scanner that
calls ``set_by_operator`` itself and logs its own once-flag copies that shape,
so this counts the direct calls left in the scanner modules and pins them to the
sites whose shape differs from the base method's.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import automated_security_helper.plugin_modules as plugin_modules

pytestmark = pytest.mark.unit

PLUGIN_ROOT = Path(plugin_modules.__file__).parent

# Direct ``set_by_operator(...)`` calls that are not the base method's shape:
# the refusal swaps in the operator's own value (not a fixed default), raises, or
# returns a pair. (file relative to plugin_modules, enclosing function) -> why.
KEPT = {
    ("ash_builtin/scanners/actionlint_scanner.py", "_integration_executable"): (
        "raises _RefusedIntegration on refusal"
    ),
    ("ash_builtin/scanners/cfn_guard_scanner.py", "_operator_rule_sets"): (
        "refusal substitutes the operator's own value"
    ),
    ("ash_builtin/scanners/cfn_lint_scanner.py", "_operator_option"): (
        "refusal substitutes the operator's own value"
    ),
    ("ash_guarddog_plugins/guarddog_scanner.py", "_hit_limit"): (
        "returns (value, may_lower); warns only for a truthy value"
    ),
}


def direct_calls(source: str) -> list[str]:
    """Names of the functions that call ``set_by_operator`` directly."""
    found: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(node):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "set_by_operator"
            ):
                found.append(node.name)
                break
    return found


def test_the_scan_finds_a_planted_direct_call():
    planted = (
        "def _online(self):\n"
        "    if not set_by_operator(config, 'k', True):\n"
        "        return False\n"
    )
    assert direct_calls(planted) == ["_online"]
    assert (
        direct_calls("def f(self):\n    return self._operator_gated(1, 2, 3, 4)\n")
        == []
    )


def test_only_the_recorded_shapes_still_call_set_by_operator_directly():
    seen: set[tuple[str, str]] = set()
    for path in sorted(PLUGIN_ROOT.rglob("*.py")):
        relative = path.relative_to(PLUGIN_ROOT).as_posix()
        for name in direct_calls(path.read_text(encoding="utf-8")):
            seen.add((relative, name))
    assert seen == set(KEPT), (
        "A scanner calls set_by_operator for a fall-back-to-default option: use "
        "self._operator_gated(key, wanted, default, refusal) (docs/content/plugins/"
        f"write-a-scanner.md). Unexpected: {sorted(seen - set(KEPT))}; "
        f"gone: {sorted(set(KEPT) - seen)}"
    )


@pytest.mark.parametrize("site", sorted(KEPT))
def test_each_kept_site_names_why(site):
    assert KEPT[site]
