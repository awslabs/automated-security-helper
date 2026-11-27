"""The two helpers that keep the recorded tool version with the route that runs.

They are module-level functions because the mixin's arms are also run against
duck-typed stand-ins that carry only the plugin's fields.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.uv_tool_mixin import (
    _record_direct_route_version,
    _restore_uv_route,
)

pytestmark = pytest.mark.unit


def _plugin(**fields):
    base = {
        "command": "tool",
        "use_uv_tool": False,
        "tool_version": "1.0",
        "_deferred_tool_version_probe": None,
    }
    base.update(fields)
    return SimpleNamespace(**base)


def test_restoring_the_uv_route_drops_the_copys_version_and_owes_the_probe():
    plugin = _plugin()

    _restore_uv_route(plugin)

    assert plugin.use_uv_tool is True
    assert plugin.tool_version is None
    assert plugin._deferred_tool_version_probe == ("tool", None)


def test_restoring_the_uv_route_keeps_a_probe_already_owed():
    plugin = _plugin(_deferred_tool_version_probe=("tool", "tool>=2"))

    _restore_uv_route(plugin)

    assert plugin.use_uv_tool is True
    assert plugin._deferred_tool_version_probe == ("tool", "tool>=2")


def test_restoring_the_uv_route_leaves_a_plugin_on_the_uv_route_alone():
    plugin = _plugin(use_uv_tool=True, tool_version="3.0")

    _restore_uv_route(plugin)

    assert plugin.use_uv_tool is True
    assert plugin.tool_version == "3.0"
    assert plugin._deferred_tool_version_probe is None


def test_recording_a_direct_route_version_drops_the_owed_probe():
    plugin = _plugin(_deferred_tool_version_probe=("tool", None))

    _record_direct_route_version(plugin, "2.0")

    assert plugin.tool_version == "2.0"
    assert plugin._deferred_tool_version_probe is None


@pytest.mark.parametrize("answered", [None, ""], ids=["none", "empty"])
def test_a_copy_that_answered_no_version_records_none(answered):
    plugin = _plugin(tool_version="9.9")

    _record_direct_route_version(plugin, answered)

    assert plugin.tool_version is None
    assert plugin._deferred_tool_version_probe is None
