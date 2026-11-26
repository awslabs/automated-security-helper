"""A plugin with no tool, no context or no results directory stops with a named
error or a plain answer, and a tool's text is not shown when the values to hide
could not be read.

These cover the paths the type declarations on the plugin bases take for
granted: the runtime fields still default to ``None``.
"""

from types import SimpleNamespace

import pytest

from automated_security_helper.base import scanner_plugin
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.base.uv_tool_mixin import UVToolMixin, tool_name
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    _shown_tool_text,
)


class _NoToolPlugin(UVToolMixin):
    """A plugin that names no tool and no package."""

    command = None
    uv_tool_package_name = None

    def _get_tool_package_extras(self):
        return None

    def _get_tool_version_constraint(self):
        return None


def test_tool_text_is_not_shown_when_the_values_could_not_be_read():
    text = "npm ERR! token=hunter2-abcdef at https://user:secret@registry.example/"

    shown = _shown_tool_text(text, None)

    assert shown == "(not shown)"
    assert "hunter2" not in shown
    assert "secret" not in shown


def test_tool_text_is_still_redacted_when_the_values_were_read():
    shown = _shown_tool_text("npm ERR! token=hunter2 at https://u:p@host/", ["hunter2"])

    assert "hunter2" not in shown
    assert "u:p@" not in shown


def test_a_plugin_with_no_tool_and_no_package_has_no_uv_spec():
    plugin = _NoToolPlugin()

    assert plugin._uv_from_spec() is None
    assert plugin._uv_probe_from_spec() is None


def test_a_scanner_with_no_command_is_not_looked_up(monkeypatch):
    def _never(_name):
        raise AssertionError("find_executable was handed a name")

    monkeypatch.setattr(scanner_plugin, "find_executable", _never)
    # The base method consults the forced --binary-path record before the PATH
    # probe; a stand-in with no record answers False there, as a scanner with
    # nothing forced does.
    stand_in = SimpleNamespace(
        command=None,
        dependency_unavailable_reason=None,
        _forced_binary_satisfies=lambda: False,
    )

    assert ScannerPluginBase.validate_plugin_dependencies(stand_in) is False


def test_a_stand_in_that_carries_only_a_command_is_looked_up_by_it(monkeypatch):
    looked_up = []
    monkeypatch.setattr(
        scanner_plugin,
        "find_executable",
        lambda name: looked_up.append(name) or "/usr/bin/sometool",
    )
    stand_in = SimpleNamespace(
        command="sometool",
        dependency_unavailable_reason=None,
        _forced_binary_satisfies=lambda: False,
    )

    assert ScannerPluginBase.validate_plugin_dependencies(stand_in) is True
    assert looked_up == ["sometool"]


def test_the_tool_name_has_one_spelling():
    assert not hasattr(UVToolMixin, "_tool_command")
    assert tool_name(SimpleNamespace(command="bandit")) == "bandit"
    assert tool_name(SimpleNamespace(command=None)) == ""


def test_a_scanner_with_no_results_directory_raises_a_named_error():
    stand_in = SimpleNamespace(results_dir=None)

    with pytest.raises(ScannerError, match="has no results directory"):
        ScannerPluginBase._require_results_dir(stand_in)


def test_a_plugin_with_no_context_raises_a_named_error():
    stand_in = SimpleNamespace(context=None)

    with pytest.raises(ScannerError, match="No context provided"):
        PluginBase._require_context(stand_in)
