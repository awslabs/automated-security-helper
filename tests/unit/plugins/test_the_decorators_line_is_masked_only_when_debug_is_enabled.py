# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The decorators' "Auto-registering" line is masked only when DEBUG is enabled.

The plugin decorator writes the module path it registers a class under at DEBUG.
The line is passed through the failure line's masking
(``plugin_manager.without_masked_modules``), which redacts the text with the
forms of every masked module in scope. The f-string and the masking were
evaluated on every decoration even when the logger would drop the line, so a
process at INFO paid for the redaction of text nobody saw. Both now run only
when the logger is enabled for DEBUG, as the loader's own traceback is.

Cells: the masking is not called at INFO; at DEBUG it is called once and the
line names the module by its mask.
"""

from __future__ import annotations

import logging
from typing import Callable, List

import pytest

from automated_security_helper.plugins import ash_plugin_manager, decorators
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

MASK = "<value>"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def at_level():
    """A function that sets the ash logger's level and returns the messages
    the logger passes to its handlers from then on."""
    sink = _Sink()
    saved = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)

    def use(level: int) -> List[str]:
        ASH_LOGGER.setLevel(level)
        return sink.messages

    yield use
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(saved)


@pytest.fixture
def masking_calls(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """The texts the decorators module passed to ``without_masked_modules``."""
    original: Callable[[str], str] = decorators.without_masked_modules
    calls: List[str] = []

    def counting(text: str) -> str:
        calls.append(text)
        return original(text)

    monkeypatch.setattr(decorators, "without_masked_modules", counting)
    return calls


def _masked(name: str):
    from automated_security_helper.plugins.loader import masked_module_scope
    from automated_security_helper.plugins.plugin_manager import masked_module_names

    return masked_module_names(masked_module_scope({name: MASK}))


def _decorated(name: str, module: str) -> type:
    plugin = type(name, (), {})
    plugin.__module__ = module
    return plugin


def test_the_decorators_line_is_not_masked_when_debug_is_off(at_level, masking_calls):
    messages = at_level(logging.INFO)
    module = "kqdbgoff_ash_plugins"
    plugin = _decorated("KqDbgOff", module)
    try:
        with _masked(module):
            ash_scanner_plugin(plugin)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqDbgOff")

    assert masking_calls == [], masking_calls
    assert [m for m in messages if "Auto-registering" in m] == [], messages


def test_the_decorators_line_is_masked_when_debug_is_enabled(at_level, masking_calls):
    """Control: the line is written, once, with the module named by its mask."""
    messages = at_level(logging.DEBUG)
    module = "kqdbgon_ash_plugins"
    plugin = _decorated("KqDbgOn", module)
    try:
        with _masked(module):
            ash_scanner_plugin(plugin)
    finally:
        ash_plugin_manager.remove_plugin_module_registration("scanner", "KqDbgOn")

    assert len(masking_calls) == 1, masking_calls
    registering = [m for m in messages if "Auto-registering" in m]
    assert registering == [f"Auto-registering scanner plugin KqDbgOn from {MASK}"], (
        messages
    )
