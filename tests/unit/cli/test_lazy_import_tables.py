# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The lazy-import tables stay in step with what reads them.

Two drift guards for the startup laziness:

- cli/main.py's ``_COMMAND_ORDER`` is a hand-kept listing order; a command
  registered eagerly or added to ``_LAZY_SUBCOMMANDS`` but left out of it would
  silently move in ``--help`` and the generated CLI docs.
- cli/scan.py's ``_deferred("name")`` calls are string-keyed; a misspelled key,
  or a name renamed in its source module, would only fail at runtime on the one
  path that reads it, and some of those are rare refusal paths.
"""

import ast
import importlib
from pathlib import Path

import pytest

from automated_security_helper.cli import main as cli_main
from automated_security_helper.cli import scan as cli_scan

pytestmark = pytest.mark.unit


def test_command_order_names_exactly_the_registered_and_lazy_commands():
    eager = {command.name for command in cli_main.app.registered_commands}
    lazy = set(cli_main._LAZY_SUBCOMMANDS)
    assert set(cli_main._COMMAND_ORDER) == eager | lazy
    assert len(cli_main._COMMAND_ORDER) == len(eager) + len(lazy)


def test_every_deferred_entry_resolves():
    for name, (module_path, attribute) in cli_scan._DEFERRED_IMPORTS.items():
        value = getattr(importlib.import_module(module_path), attribute, None)
        assert value is not None, f"{name} -> {module_path}.{attribute}"


def test_every_deferred_call_site_names_a_table_key():
    tree = ast.parse(Path(cli_scan.__file__).read_text(encoding="utf-8"))
    keys = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "_deferred"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert keys, "the scan found no _deferred call sites; the shape moved"
    assert keys <= set(cli_scan._DEFERRED_IMPORTS), keys - set(
        cli_scan._DEFERRED_IMPORTS
    )
