# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin guides' code samples pass ``_plugin_log`` a numeric level.

The defect
----------
``PluginBase._plugin_log`` takes ``level: int`` and hands it to the logger, which
compares it with each handler's level. A string such as ``level="ERROR"`` raises
TypeError there, so a plugin copied from a sample that passed one failed in its own
error path, hiding the error it meant to log. The converter guide's notebook
example passed ``level="ERROR"`` twice.

What the test does
------------------
Parses every ``python`` block of the guides below and fails on a ``_plugin_log``
call whose level, by keyword or as the second argument, is a string literal. The
second test shows the call raises.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

import pytest

GUIDES = Path(__file__).resolve().parents[3] / "docs" / "content" / "plugins"
PAGES = (
    "write-a-converter.md",
    "write-a-reporter.md",
    "write-a-scanner.md",
)
PYTHON_BLOCK = re.compile(r"^```python\n(.*?)^```", re.DOTALL | re.MULTILINE)


def string_levels(text: str):
    """(block number, line) of each _plugin_log call given a string level."""
    found = []
    for number, block in enumerate(PYTHON_BLOCK.findall(text), start=1):
        for node in ast.walk(ast.parse(block)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", None)
            )
            if name != "_plugin_log":
                continue
            levels = [kw.value for kw in node.keywords if kw.arg == "level"]
            levels += node.args[1:2]
            if any(
                isinstance(level, ast.Constant) and isinstance(level.value, str)
                for level in levels
            ):
                found.append((number, node.lineno))
    return sorted(found)


@pytest.mark.parametrize("page", PAGES)
def test_the_guide_passes_plugin_log_a_numeric_level(page):
    text = (GUIDES / page).read_text(encoding="utf-8")
    assert PYTHON_BLOCK.findall(text), f"{page} has no python block to check"

    assert string_levels(text) == [], (
        f"{page}: _plugin_log given a string level at (block, line) "
        f"{string_levels(text)}; pass logging.ERROR and the like"
    )


def test_the_checker_finds_a_string_level():
    """Control: both spellings are caught, and a numeric level is not."""
    sample = (
        "```python\n"
        'self._plugin_log("a", level="ERROR")\n'
        'self._plugin_log("b", "WARNING")\n'
        'self._plugin_log("c", level=logging.ERROR)\n'
        "```\n"
    )
    assert string_levels(sample) == [(1, 1), (1, 2)]


def test_a_string_level_raises_in_plugin_log(tmp_path):
    """Why it matters: the logger compares the level with each handler's."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        ArchiveConverter,
    )
    from automated_security_helper.utils.log import ASH_LOGGER

    converter = ArchiveConverter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(project_name="guide-log-levels"),
        )
    )
    handler = logging.NullHandler()
    ASH_LOGGER.addHandler(handler)
    try:
        converter._plugin_log("numeric", level=logging.ERROR)
        with pytest.raises(TypeError):
            converter._plugin_log("string", level="ERROR")
    finally:
        ASH_LOGGER.removeHandler(handler)
