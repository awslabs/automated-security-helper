# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An env-read pin in the install requirement stays out of the debug log.

The plugin's install call hands the runner its environment-read values, and
the runner's install failure arm redacts uv's stderr with them before the
debug line. uv quotes the requirement back in its own canonical spelling, and
a resolver conflict names the pinned version again in a RANGE ("only
stub-tool<9.9.9rc777 is available"), a spelling of the value that no
plugin-built input carries. Only the value layer, fed the values the install
call passes, hides it there; the input-origin layer alone leaves it in clear.

The cells drive the mixin's real install path into the real runner, with the
value coming from the scan config's environment-read set and only uv's
process replaced.
"""

import logging
import subprocess  # nosec B404
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from tests.unit.base.test_uv_tool_mixin import FakePlugin

pytestmark = pytest.mark.unit

_PIN = "9.9.9-RC777"

_RESOLVER_STDERR = (
    "  × No solution found when resolving dependencies:\n"
    "  ╰─▶ Because only stub-tool<9.9.9rc777 is available and you require "
    "stub-tool==9.9.9rc777, we can conclude that your requirements are "
    "unsatisfiable.\n"
    # A second line that quotes the requirement as the install call spelled it.
    # Both spellings of the pin have to be in the text the redaction reads, or
    # the parameter for the as-given one has nothing to hide and passes with
    # the redaction removed.
    f"  help: the requirement stub-tool=={_PIN} came from the install call\n"
)


def _install_with_a_failing_resolver(monkeypatch, caplog):
    plugin = FakePlugin(command="stub-tool", use_uv_tool=True)
    plugin.context = SimpleNamespace(config=SimpleNamespace(_environment_values=[_PIN]))

    def _spawn_run(command, **kwargs):
        raise subprocess.CalledProcessError(
            1, command, output="", stderr=_RESOLVER_STDERR
        )

    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    monkeypatch.setattr(runner, "is_tool_installed", lambda *a, **k: False)
    monkeypatch.setattr(runner, "get_cache_info", lambda: {"cache_available": False})
    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )
    monkeypatch.delenv("UV_OFFLINE", raising=False)

    with (
        patch.object(plugin, "_is_offline_mode", return_value=False),
        patch.object(plugin, "_get_tool_version_constraint", return_value=f"=={_PIN}"),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=runner,
        ),
        caplog.at_level(logging.DEBUG, logger="ash"),
    ):
        installed = plugin._install_uv_tool()

    plugin_lines = [
        " ".join(str(part) for part in message) for message in plugin._log_messages
    ]
    return installed, list(caplog.messages), plugin_lines


def test_the_install_debug_line_hides_a_pin_uv_respells_in_a_range(monkeypatch, caplog):
    installed, messages, _ = _install_with_a_failing_resolver(monkeypatch, caplog)

    assert installed is False
    line = next((text for text in messages if "stderr (redacted" in text), None)
    # The control: the failure arm logged uv's stderr, and the line still
    # carries uv's conclusion, so the redaction did not empty it.
    assert line is not None, messages
    assert "we can conclude" in line, line
    assert "9.9.9rc777" not in line, line
    assert "9.9.9-RC777" not in line, line


@pytest.mark.parametrize("spelling", ["9.9.9rc777", "9.9.9-RC777"])
def test_no_install_record_carries_the_pin(monkeypatch, caplog, spelling):
    # The premise: uv's stderr carries this spelling, so a record without it
    # was hidden, not never given it.
    assert spelling in _RESOLVER_STDERR
    _, messages, plugin_lines = _install_with_a_failing_resolver(monkeypatch, caplog)

    # The control: the install reached uv and both record streams were written.
    assert any("stderr (redacted" in text for text in messages), messages
    assert any("[INSTALLATION_ATTEMPT]" in text for text in plugin_lines), plugin_lines
    assert not any(spelling in text for text in messages), messages
    assert not any(spelling in text for text in plugin_lines), plugin_lines
