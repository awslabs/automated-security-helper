# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two reads of ``ash dependencies install`` that follow the rest of the CLI.

Locals in a traceback. The command's typer app enabled pretty exceptions and
left typer's default for the locals panel, which is on: an unhandled exception
printed every frame's local variables, and this module's frames hold the values
the configuration read from the environment, the very values every line it
prints is redacted with. The app now decides the panel as the other command
apps do, with ``utils.log.show_debug_locals`` (off unless asked for, and never
on a CI runner).

The bin-path hint. The install ends by saying how to make a later scan search
its bin directory, and says nothing when ``ASH_BIN_PATH`` already names it. That
"already" was decided with ``os.path.isabs``, which on Windows before Python
3.13 accepts a drive-less rooted path such as ``\\tools``; the lookup a scan
runs requires an anchored path (a drive or share) and does not search such a
value, so the hint was owed and withheld. The hint now asks
``core.constants.is_anchored``, the lookup's own rule.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.utils.log import show_debug_locals

pytestmark = pytest.mark.unit


def _typer_keywords() -> dict[str, ast.expr]:
    """The keyword arguments of the ``typer.Typer(...)`` call bound to dependencies_app."""
    tree = ast.parse(Path(dependencies_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "dependencies_app"
            for target in node.targets
        ):
            return {kw.arg: kw.value for kw in node.value.keywords if kw.arg}
    raise AssertionError("dependencies_app is not assigned from a call")


def test_the_locals_panel_follows_show_debug_locals():
    keywords = _typer_keywords()
    value = keywords.get("pretty_exceptions_show_locals")
    assert isinstance(value, ast.Call), keywords.keys()
    assert ast.unparse(value.func) == "show_debug_locals", ast.unparse(value)
    # And the live app agrees with the one rule.
    assert dependencies_app.pretty_exceptions_show_locals == show_debug_locals()


def test_the_bin_path_hint_is_given_for_an_unanchored_ash_bin_path(
    tmp_path, monkeypatch
):
    """A value the lookup does not search, however isabs reads it, gets the hint."""
    target = tmp_path / "tools"
    monkeypatch.setattr(dependencies_module, "is_anchored", lambda path: False)

    hint = dependencies_module._bin_path_hint(target, str(target))

    assert hint is not None
    assert "ASH_BIN_PATH" in hint, hint


def test_the_bin_path_hint_is_withheld_for_the_anchored_ash_bin_path(tmp_path):
    """The control: an anchored ASH_BIN_PATH naming the directory needs no hint."""
    target = tmp_path / "tools"

    assert dependencies_module._bin_path_hint(target, str(target)) is None
