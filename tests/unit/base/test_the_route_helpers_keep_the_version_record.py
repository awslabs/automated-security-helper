"""The route helpers: the check that reads a resolver answer's route, and the
two that keep the recorded tool version with the route that runs.

They are module-level functions because the mixin's arms are also run against
duck-typed stand-ins that carry only the plugin's fields.
"""

from __future__ import annotations

from pathlib import Path
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


def _is_uv_form(command):
    """The shared route check, imported here so that a tree without it fails
    these tests alone, not the module."""
    from automated_security_helper.base.uv_tool_mixin import is_uv_form

    return is_uv_form(command)


@pytest.mark.parametrize(
    "command",
    [
        ["uv", "tool", "run", "checkov"],
        ["uv", "tool", "run", "--from", "checkov>=3.2", "checkov"],
        ["/opt/uv/bin/uv", "tool", "run", "checkov"],
        ["C:\\Users\\me\\.local\\bin\\uv.exe", "tool", "run", "checkov"],
        ["C:/tools/UV.EXE", "tool", "run", "checkov"],
        ["D:\\scoop\\shims\\uv.cmd", "tool", "run", "checkov"],
        ["D:\\bin\\uv.bat", "tool", "run", "checkov"],
        [Path("/opt/uv/bin/uv"), "tool", "run", "checkov"],
        ("uv", "tool", "run", "checkov"),
        "/opt/uv/bin/uv",
    ],
    ids=[
        "bare",
        "from-spec",
        "posix-path",
        "windows-exe",
        "upper-case-exe",
        "windows-cmd-shim",
        "windows-bat-shim",
        "path-object",
        "tuple",
        "one-string",
    ],
)
def test_a_resolver_answer_naming_uv_is_the_uv_form(command):
    """uv by the names it can be found under: bare, by its path on either
    separator, as uv.exe in any letter case, and as the uv.cmd and uv.bat names a
    Windows PATH lookup tries."""
    assert _is_uv_form(command) is True


@pytest.mark.parametrize(
    "command",
    [
        ["/opt/bin/checkov"],
        ["C:\\tools\\checkov.exe"],
        ["uvx", "checkov"],
        ["/opt/tools/uvicorn"],
        ["/opt/tools/uv-wrapper", "tool", "run", "checkov"],
        ["/opt/tools/myuv"],
        ["/opt/tools/uv.exe.bak"],
        ["/opt/tools/uv.sh"],
        ["/opt/uv/bin/checkov"],
        ["/opt/bin/checkov", "uv"],
        "/opt/bin/checkov",
        [""],
        [None],
        [],
        None,
    ],
    ids=[
        "binary",
        "windows-binary",
        "uvx",
        "starts-with-uv",
        "uv-prefixed-name",
        "ends-with-uv",
        "uv-exe-backup",
        "other-suffix",
        "uv-only-in-a-directory",
        "uv-not-first",
        "one-string-binary",
        "empty-word",
        "non-text-word",
        "empty",
        "none",
    ],
)
def test_any_other_answer_is_not_the_uv_form(command):
    """A binary found on PATH, uvx (the resolver never answers with it), a name
    that only starts or ends with uv, uv only in a directory name, and answers
    with no usable first word."""
    assert _is_uv_form(command) is False
