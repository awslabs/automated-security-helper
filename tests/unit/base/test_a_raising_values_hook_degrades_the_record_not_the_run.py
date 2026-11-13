"""A raising ``_values_to_redact`` hook degrades records, never the run.

The hook is overridable, and its guarding rule (its own docstring) says a
record or best-effort path reads it once, guarded, and on a raise degrades to
a value-free note -- never to an empty value set, which would print what the
values would have hidden. Before this, the install's attempt lines and its
error arms, and the uv dispatch's error arms, each read the hook again bare,
so one raising hook turned a degraded record into the plugin call's own
crash.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.unit.base.test_uv_tool_mixin import FakePlugin

pytestmark = pytest.mark.unit


class _HookBroke(RuntimeError):
    pass


def _raising_hook(*_args, **_kwargs):
    raise _HookBroke("hook broke on '/opt/qz4b/config'")


def _logged(plugin):
    return "\n".join(
        " ".join(str(part) for part in msg) for msg in plugin._log_messages
    )


def test_an_install_with_a_raising_hook_still_installs():
    """The guard's own comment: a raising hook loses the dict, never the
    install. Every record line degrades to its value-free form, and the
    runner is told nothing about input origins (values=None), which hides
    every plugin-built argument from its debug line."""
    plugin = FakePlugin(command="bandit", use_uv_tool=True)
    with (
        patch.object(plugin, "_is_offline_mode", return_value=False),
        patch.object(plugin, "_values_to_redact", side_effect=_raising_hook),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner,
        patch(
            "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
        ),
    ):
        mock_runner = MagicMock()
        mock_runner.is_uv_available.return_value = True
        mock_runner.get_cache_info.return_value = {"cache_available": False}
        mock_runner.is_tool_installed.return_value = False
        mock_runner.install_tool_with_version.return_value = True
        mock_runner.get_installed_tool_version.return_value = "1.7.0"
        mock_get_runner.return_value = mock_runner

        assert plugin._install_uv_tool() is True

        assert (
            mock_runner.install_tool_with_version.call_args.kwargs["values"] is None
        ), "a raising hook must mean values=None, not an empty set"

    logged = _logged(plugin)
    assert "(not shown)" in logged, logged
    assert "[INSTALLATION_ATTEMPT]" in logged, logged


def test_an_install_error_arm_with_a_raising_hook_still_returns_false():
    """A failure after the guarded read reports through the degraded arm:
    the install answers False instead of re-raising the hook's error from
    inside the handler."""
    plugin = FakePlugin(command="bandit", use_uv_tool=True)
    with (
        patch.object(plugin, "_is_offline_mode", return_value=False),
        patch.object(plugin, "_values_to_redact", side_effect=_raising_hook),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner,
    ):
        mock_runner = MagicMock()
        mock_runner.is_uv_available.return_value = True
        mock_runner.get_cache_info.return_value = {"cache_available": False}
        mock_runner.is_tool_installed.return_value = False
        mock_runner.install_tool_with_version.side_effect = OSError(
            "spawn failed for '/opt/qz4b/config'"
        )
        mock_get_runner.return_value = mock_runner

        assert plugin._install_uv_tool() is False

    logged = _logged(plugin)
    assert "[INSTALLATION_ERROR]" in logged, logged
    assert "qz4b" not in logged, "the arm printed an unredacted error text"


def test_a_uv_run_with_a_raising_hook_reports_a_refusal_not_a_crash():
    """The dispatch's records cannot be redacted without the hook's values,
    so the uv route reports a failure of its own -- the shape 'uv is not
    available' takes -- instead of launching unrecorded or crashing in an
    error arm's second read."""
    plugin = FakePlugin(command="bandit", use_uv_tool=True)
    with (
        patch.object(plugin, "_values_to_redact", side_effect=_raising_hook),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner,
    ):
        mock_runner = MagicMock()
        mock_runner.is_uv_available.return_value = True
        mock_get_runner.return_value = mock_runner

        result = plugin._try_uv_tool_execution(["bandit", "-r", "."], Path("."))

        mock_runner.run_tool.assert_not_called()

    assert result is None
    assert plugin._uv_run_failure, "the refusal must be recorded for the report"
    assert "qz4b" not in _logged(plugin)
