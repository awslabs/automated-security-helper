# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's ``missing_dependency_reason()`` is read through one function.

The scan's MISSING row, the executor's reason for a scan that found its
dependencies unavailable, and ``ash dependencies install``'s check-refused
line all quote that hook. Each kept its own copy of the read (a getattr, a
call, a type check, a DEBUG line for a hook that raises), and copies drift.
They ask ``base.scanner_plugin.plugin_missing_dependency_reason`` instead.

The guard reads each module's syntax tree, not its text: a read is an
attribute of that name, or a getattr/hasattr of it by a constant name.
A quoted-string grep missed ``getattr(p, 'missing_dependency_reason')`` and a
direct ``plugin.missing_dependency_reason()``, the likeliest copies, and would
have failed on a log line that only names the hook.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.base import scanner_plugin
from automated_security_helper.cli import dependencies
from automated_security_helper.core.phases import scan_phase, scanner_executor

pytestmark = pytest.mark.unit

HOOK = "missing_dependency_reason"

#: The one module that reads the hook: the reader and the base hook itself.
READER = Path(inspect.getfile(scanner_plugin)).resolve()


def _is_super_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "super"
    )


def _reads_of_the_hook(source: str) -> list:
    """Line numbers where *source* reads the hook outside the reader.

    An attribute of the hook's name, except ``super().missing_dependency_reason``
    inside an override, which is the hook's own chain; and a getattr, hasattr,
    setattr or delattr naming it by a constant. A string that only mentions the
    name is not a read, and neither is a method that defines the hook.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == HOOK
            and not _is_super_call(node.value)
        ):
            found.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "hasattr", "setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == HOOK
        ):
            found.append(node.lineno)
    return found


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("getattr(p, 'missing_dependency_reason')", id="getattr-single"),
        pytest.param(
            'getattr(p, "missing_dependency_reason", None)()', id="getattr-default"
        ),
        pytest.param("hasattr(p, 'missing_dependency_reason')", id="hasattr"),
        pytest.param("plugin.missing_dependency_reason()", id="direct-call"),
        pytest.param("reason = outcome.missing_dependency_reason", id="attribute"),
    ],
)
def test_the_guard_flags_a_read(source) -> None:
    """Must-flag controls, read by the same walk as the package."""
    assert _reads_of_the_hook(source) == [1], source


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            'log("missing_dependency_reason() raised")', id="a-string-naming-it"
        ),
        pytest.param(
            "class S:\n"
            "    def missing_dependency_reason(self):\n"
            "        return super().missing_dependency_reason()\n",
            id="an-override-calling-super",
        ),
        pytest.param("outcome.shown_refusal_reason", id="another-name"),
        pytest.param("plugin_missing_dependency_reason(p)", id="the-reader"),
    ],
)
def test_the_guard_passes_what_is_not_a_read(source) -> None:
    """Must-not-flag controls."""
    assert _reads_of_the_hook(source) == [], source


def _package_modules():
    root = Path(inspect.getfile(automated_security_helper)).resolve().parent
    return sorted(path for path in root.rglob("*.py") if path.resolve() != READER)


def test_no_other_module_reads_the_hook_itself() -> None:
    modules = _package_modules()
    # The control: the walk covers the package, the three callers among it.
    names = {path.name for path in modules}
    assert {"scan_phase.py", "scanner_executor.py", "dependencies.py"} <= names
    reads = {
        str(path): lines
        for path in modules
        if (lines := _reads_of_the_hook(path.read_text(encoding="utf-8")))
    }
    assert reads == {}, reads


def test_the_reader_module_is_where_the_hook_is_read() -> None:
    """The control for the walk: the reader's own module does read it."""
    assert _reads_of_the_hook(READER.read_text(encoding="utf-8")), READER


@pytest.mark.parametrize(
    "module", [scan_phase, scanner_executor, dependencies], ids=lambda m: m.__name__
)
def test_each_caller_binds_the_reader_itself(module) -> None:
    """The name each caller reads is the reader function, not a copy. A
    source-text check of the name was satisfied by a comment; this reads the
    binding, and the behavioral checks below drive the calls."""
    assert (
        module.plugin_missing_dependency_reason
        is scanner_plugin.plugin_missing_dependency_reason
    ), module.__name__


def test_the_scan_phase_s_missing_reason_asks_the_one_reader(monkeypatch) -> None:
    asked = []

    def reader(plugin, values=(), **_kwargs):
        asked.append((plugin, tuple(values)))
        return "the plugin's own reason"

    monkeypatch.setattr(scan_phase, "plugin_missing_dependency_reason", reader)
    plugin = object()

    reason = scan_phase._missing_dependency_reason(plugin, values=("a-value",))

    assert reason == "the plugin's own reason"
    assert asked == [(plugin, ("a-value",))]


def test_the_install_command_s_refusal_reason_asks_the_one_reader(
    monkeypatch,
) -> None:
    asked = []

    def reader(plugin, values=(), **_kwargs):
        asked.append((plugin, tuple(values)))
        return "the plugin's own reason"

    monkeypatch.setattr(dependencies, "plugin_missing_dependency_reason", reader)
    monkeypatch.setattr(
        dependencies, "plugin_explains_its_own_refusal", lambda _plugin, _reason: True
    )
    plugin = object()

    reason = dependencies._refusal_reason(plugin, values=("a-value",))

    assert reason == "the plugin's own reason"
    assert len(asked) == 1 and asked[0][0] is plugin, asked
    assert "a-value" in asked[0][1], asked


def test_the_executor_s_reason_after_a_scan_asks_the_one_reader(monkeypatch) -> None:
    asked = []

    def reader(plugin, values=(), **_kwargs):
        asked.append((plugin, tuple(values)))
        return "the plugin's own reason"

    monkeypatch.setattr(scanner_executor, "plugin_missing_dependency_reason", reader)
    plugin = object()

    reason = scanner_executor._missing_reason_after_scan(
        plugin, "a-scanner", "source", values=("a-value",)
    )

    assert reason == "the plugin's own reason"
    assert asked == [(plugin, ("a-value",))]
