"""Every runtime change to ``os.environ`` must go through ``utils.process_env``.

A write to ``os.environ`` outside ``ENVIRON_LOCK`` can land while another
scanner thread is copying the environment for a spawn, or while a vfork child
is reading the live array, which is the EFAULT race ``process_env`` documents.
This test walks the package source and fails on any direct mutation outside
that module, so a new one cannot slip in unnoticed.
"""

import ast
from pathlib import Path
from typing import List

import automated_security_helper

PACKAGE_ROOT = Path(automated_security_helper.__file__).parent
ALLOWED = {PACKAGE_ROOT / "utils" / "process_env.py"}

MUTATING_METHODS = {
    "__setitem__",
    "__delitem__",
    "clear",
    "pop",
    "popitem",
    "setdefault",
    "update",
}
MUTATING_OS_FUNCTIONS = {"putenv", "unsetenv"}


def _is_os_environ(node: ast.AST, environ_aliases: set) -> bool:
    """``os.environ``, or a bare name bound by ``from os import environ``."""
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    ):
        return True
    return isinstance(node, ast.Name) and node.id in environ_aliases


def find_mutations(source: str) -> List[int]:
    """Line numbers in ``source`` that mutate ``os.environ`` directly."""
    tree = ast.parse(source)
    environ_aliases = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "os"
        for alias in node.names
        if alias.name == "environ"
    }
    lines = []
    for node in ast.walk(tree):
        targets: List[ast.AST] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        for target in targets:
            if isinstance(target, ast.Subscript) and _is_os_environ(
                target.value, environ_aliases
            ):
                lines.append(node.lineno)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func = node.func
            if func.attr in MUTATING_METHODS and _is_os_environ(
                func.value, environ_aliases
            ):
                lines.append(node.lineno)
            if (
                func.attr in MUTATING_OS_FUNCTIONS
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                lines.append(node.lineno)
    return sorted(lines)


def test_no_unlocked_environ_mutation_in_the_package():
    offenders = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path in ALLOWED:
            continue
        for line in find_mutations(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(PACKAGE_ROOT.parent)}:{line}")
    assert offenders == [], (
        "Mutate the environment through automated_security_helper.utils."
        "process_env (set_environ, environ_overrides, setdefault_environ), "
        "not os.environ directly: " + ", ".join(offenders)
    )


def test_the_walk_actually_reads_the_package():
    # The allowed module mutates os.environ on purpose. If the walk stopped
    # finding it, the test above would pass without having looked at anything.
    found = find_mutations((PACKAGE_ROOT / "utils" / "process_env.py").read_text())
    assert found, "find_mutations no longer sees process_env's own writes"


def test_each_mutation_form_is_detected():
    source = """\
import os
from os import environ as env
os.environ['A'] = '1'
del os.environ['A']
os.environ['A'] += 'x'
os.environ.pop('A', None)
os.environ.update({'A': '1'})
os.environ.setdefault('A', '1')
os.environ.clear()
os.putenv('A', '1')
os.unsetenv('A')
env['A'] = '1'
os.environ.get('A')
x = dict(os.environ)
"""
    assert find_mutations(source) == list(range(3, 13))
