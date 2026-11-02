# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No converter or reporter module but the jupyter converter launches a program.

The jupyter converter launches nbconvert once, through uv or a copy its dependency
check verified, and never another copy in uv's place (see
converters/test_notebook_conversion_launches_one_tool.py). Every other module that
defines a converter or a reporter launches nothing itself: it names none of the
helpers a program is started with, so no uv run with a fallback by name, and no
rerun after a non-zero exit, can be in one. A module that comes to need a tool
fails here, and has to follow the jupyter converter's rule before it is added.
"""

from __future__ import annotations

import ast
import importlib.util
import pkgutil
from pathlib import Path
from typing import List, Tuple

import pytest

import automated_security_helper.plugin_modules as plugin_modules

pytestmark = pytest.mark.unit

#: The decorators that register a converter or a reporter.
DECORATORS = {"ash_converter_plugin", "ash_reporter_plugin"}

#: The names a program is started with: ASH's launchers, uv's runner, the base
#: plugin's runners, and the standard library's.
LAUNCHERS = {
    "spawn_run",
    "run_ended_with_the_server",
    "run_command",
    "run_command_with_output_handling",
    "run_tool",
    "_run_subprocess",
    "_try_uv_tool_execution",
    "Popen",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
    "create_subprocess_exec",
    "create_subprocess_shell",
    "posix_spawn",
    "posix_spawnp",
}

#: ``os``'s, counted only as attributes of ``os``: a reporter's model prompt is a
#: ``system`` variable, not a launch.
OS_LAUNCHERS = {
    "system",
    "popen",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnv",
    "spawnvp",
}

#: The one module that launches a tool, under its own rule.
LAUNCHES_A_TOOL = {
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
}


def _plugin_modules() -> List[Tuple[str, Path]]:
    """Every module under plugin_modules that defines a converter or a reporter."""
    found = []
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, prefix=f"{plugin_modules.__name__}."
    ):
        if info.ispkg:
            continue
        spec = importlib.util.find_spec(info.name)
        if spec is None or not spec.origin or not spec.origin.endswith(".py"):
            continue
        tree = ast.parse(Path(spec.origin).read_text(encoding="utf-8"))
        if any(_registers(node) for node in ast.walk(tree)):
            found.append((info.name, Path(spec.origin)))
    return sorted(found)


def _registers(node: ast.AST) -> bool:
    if not isinstance(node, ast.ClassDef):
        return False
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = (
            target.attr
            if isinstance(target, ast.Attribute)
            else getattr(target, "id", "")
        )
        if name in DECORATORS:
            return True
    return False


def _launches(path: Path) -> List[str]:
    """The launcher names ``path`` refers to, with their lines."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    named = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in LAUNCHERS:
            named.append(f"{node.id}:{node.lineno}")
        elif isinstance(node, ast.Attribute) and node.attr in LAUNCHERS:
            named.append(f"{node.attr}:{node.lineno}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "subprocess" and node.attr in ("run", "call"):
                named.append(f"subprocess.{node.attr}:{node.lineno}")
            elif node.value.id == "os" and node.attr in OS_LAUNCHERS:
                named.append(f"os.{node.attr}:{node.lineno}")
        elif isinstance(node, ast.alias) and node.name.split(".")[-1] in LAUNCHERS:
            named.append(f"import {node.name}:{getattr(node, 'lineno', 0)}")
    return named


MODULES = _plugin_modules()


def test_the_converter_and_reporter_modules_are_found():
    """Control: the walk finds the built-in ones and the jupyter converter."""
    names = [name for name, _ in MODULES]
    assert len(names) >= 20, names
    assert LAUNCHES_A_TOOL <= set(names)
    assert any(name.endswith(".sarif_reporter") for name in names), names


@pytest.mark.parametrize(
    ("name", "path"),
    [m for m in MODULES if m[0] not in LAUNCHES_A_TOOL],
    ids=[name.rsplit(".", 1)[-1] for name, _ in MODULES if name not in LAUNCHES_A_TOOL],
)
def test_the_module_launches_no_program(name, path):
    assert _launches(path) == []


def test_control_the_check_sees_the_jupyter_converters_launches():
    """The one module that launches a tool is seen to, so a pass above means the
    check looked, not that it cannot see a launch."""
    (path,) = [p for n, p in MODULES if n in LAUNCHES_A_TOOL]
    assert _launches(path) != []
