# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PluginBase's own records of a run hold when the plugin or its hooks are odd.

Each case below is a small gap in what ``_plugin_log`` and ``_run_subprocess``
record:

- a plugin built without a config has no ``config.name`` to log under;
- a CRITICAL message is as much the plugin's error as an ERROR one;
- a failed spawn is recorded inside the handler that records it, even when
  ASH's own handling of that response raises;
- a post-run error the handler adds is recorded once, even when the
  post-run recorder ran earlier as a no-op on the unflagged response;
- an interpreter the caller named in ``env`` is the child's, not ASH's;
- the timeout limit prints no number when the values hook cannot be read;
- the carried stderr log is trimmed against a uv run's inputs only for a
  plugin that runs through uv, and an inputs accessor that answers None or
  raises leaves the carry intact.
"""

from __future__ import annotations

import logging
import sys

import pytest

from automated_security_helper.base import plugin_base
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE

pytestmark = pytest.mark.unit


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


class _Plugin(PluginBase):
    """A plugin that adds nothing to the base class."""


def _named(plugin_class, plugin_context, **fields):
    return plugin_class(
        context=plugin_context, config=PluginConfigBase(name="probe"), **fields
    )


def _runner_returns(monkeypatch, response):
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda *args, **kwargs: dict(response),
    )


def _runner_refuses(monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("no such tool")

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", refuse)


# -- the plugin's name and the level of its error lines ---------------------------


def test_a_plugin_without_a_config_logs_under_its_class_name(plugin_context):
    plugin = _Plugin(context=plugin_context)
    assert plugin.config is None

    plugin._plugin_log("starting", level=logging.ERROR)

    assert plugin.errors == ["(_Plugin) starting"]


def test_a_failed_spawn_is_recorded_for_a_plugin_without_a_config(
    plugin_context, monkeypatch
):
    plugin = _Plugin(context=plugin_context, command="probe-tool")
    _runner_refuses(monkeypatch)

    response = plugin._run_subprocess(["probe-tool"])

    assert response["spawn_failed"] is True
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
    assert plugin.scan_spawn_failure


@pytest.mark.parametrize("level", [logging.ERROR, logging.CRITICAL])
def test_errors_hold_every_message_at_error_or_above(plugin_context, level):
    plugin = _named(_Plugin, plugin_context)

    plugin._plugin_log("it broke", level=level)

    assert plugin.errors == ["(probe) it broke"]


def test_a_message_below_error_is_not_an_error(plugin_context):
    plugin = _named(_Plugin, plugin_context)

    plugin._plugin_log("it slowed", level=logging.WARNING)

    assert plugin.errors == []


# -- handling that raises inside the handler -------------------------------------


class _RecordHookBreaks(_Plugin):
    """An override of the seam the handler calls to record the failure.

    The text-shaping hook is not the stand-in: ``_process_command_response``
    guards it and leaves a value-free note, so a raise there never reaches the
    handler this test is about (see the raising-shaping-hook tests).
    """

    def _process_command_response(self, response):
        raise RuntimeError("the record hook broke")


def test_handling_that_raises_after_a_failed_spawn_stays_in_the_handler(
    plugin_context, monkeypatch
):
    plugin = _named(_RecordHookBreaks, plugin_context, command="probe-tool")
    _runner_refuses(monkeypatch)

    response = plugin._run_subprocess(["probe-tool"])

    assert response["spawn_failed"] is True
    assert "the record hook broke" in response["error"], response["error"]
    assert plugin.exit_code == SPAWN_FAILURE_RETURNCODE
    assert plugin.scan_spawn_failure


class _KeptFlagRecorderBreaks(_Plugin):
    def _record_kept_flag(self, response):
        raise RuntimeError("the kept-flag recorder broke")


def test_a_post_run_error_the_handler_adds_is_recorded(plugin_context, monkeypatch):
    plugin = _named(_KeptFlagRecorderBreaks, plugin_context)
    _runner_returns(monkeypatch, {"stdout": "", "stderr": "", "returncode": 0})

    response = plugin._run_subprocess(["probe-tool"])

    assert response["post_run_error"] is True
    assert plugin.scan_post_run_error is not None
    assert any(
        "ran, but ASH could not record its tool's output" in line
        for line in plugin.errors
    ), plugin.errors


# -- the interpreter of a uv child -----------------------------------------------


def _capture_env(monkeypatch):
    seen = {}

    def run(*args, **kwargs):
        seen.update(kwargs)
        return {"stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", run)
    return seen


def test_an_interpreter_the_caller_named_in_env_is_kept(plugin_context, monkeypatch):
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    seen = _capture_env(monkeypatch)
    plugin = _Plugin(context=plugin_context)

    plugin._run_subprocess(
        ["uv", "run", "probe"],
        env={"PATH": "/usr/bin", "UV_PYTHON": "/opt/caller/python"},
    )

    assert seen["env"]["UV_PYTHON"] == "/opt/caller/python"
    assert seen["env"]["UV_NO_PROJECT"] == "1"


def test_the_interpreter_is_ash_s_when_nobody_named_one(plugin_context, monkeypatch):
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    seen = _capture_env(monkeypatch)
    plugin = _Plugin(context=plugin_context)

    plugin._run_subprocess(["uv", "run", "probe"], env={"PATH": "/usr/bin"})

    assert seen["env"]["UV_PYTHON"] == sys.executable
    assert seen["env"]["UV_NO_PROJECT"] == "1"


@pytest.mark.parametrize("false_word", ["0", "false", "no", "off", ""])
def test_a_system_python_switch_read_as_false_names_no_interpreter(
    plugin_context, monkeypatch, false_word
):
    # uv reads these values of UV_SYSTEM_PYTHON as false, so the caller chose
    # nothing and ASH's interpreter still keeps uv out of the tree's .venv.
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    seen = _capture_env(monkeypatch)
    plugin = _Plugin(context=plugin_context)

    plugin._run_subprocess(
        ["uv", "run", "probe"],
        env={"PATH": "/usr/bin", "UV_SYSTEM_PYTHON": false_word},
    )

    assert seen["env"]["UV_PYTHON"] == sys.executable


def test_a_system_python_switch_read_as_true_is_the_callers_choice(
    plugin_context, monkeypatch
):
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    seen = _capture_env(monkeypatch)
    plugin = _Plugin(context=plugin_context)

    plugin._run_subprocess(
        ["uv", "run", "probe"],
        env={"PATH": "/usr/bin", "UV_SYSTEM_PYTHON": "1"},
    )

    assert "UV_PYTHON" not in seen["env"]


# -- the timeout limit token -----------------------------------------------------


class _HookRaises(_Plugin):
    def _values_to_redact(self):
        raise RuntimeError("the values hook broke")


class _HookAnswersNone(_Plugin):
    def _values_to_redact(self):
        return None


@pytest.mark.parametrize("plugin_class", [_HookRaises, _HookAnswersNone])
def test_a_values_hook_that_fails_leaves_the_limit_unprinted(
    plugin_context, plugin_class
):
    plugin = plugin_class(context=plugin_context)

    token = plugin._timeout_limit_token(67.0)

    assert token == "the configured scan_timeout"
    assert "67" not in token


def test_the_limit_prints_whole_when_the_hook_answers(plugin_context):
    plugin = _Plugin(context=plugin_context)

    assert plugin._timeout_limit_token(67.0) == "'67' s"


# -- the carried stderr log ------------------------------------------------------


class _InputsNamedAfterTheCommand(_Plugin):
    def _uv_run_inputs_for_records(self):
        return ("probe-tool==1.0",)


@pytest.mark.parametrize(
    ("uses_uv", "carried_head"),
    [(True, "x" * 60), (False, "x" * 60 + "prob")],
    ids=["uv-run-trims-against-its-inputs", "other-plugin-keeps-its-tail"],
)
def test_the_carried_log_trims_against_inputs_only_for_a_uv_run(
    plugin_context, tmp_path, monkeypatch, uses_uv, carried_head
):
    monkeypatch.setattr(plugin_base, "_STDERR_LOG_READ_LIMIT", 64)
    log = tmp_path / "Probe.stderr.log"
    log.write_text("x" * 60 + "prob" + "e-tool==1.0 and more", encoding="utf-8")
    plugin = _named(_InputsNamedAfterTheCommand, plugin_context, use_uv_tool=uses_uv)
    post_run = {"error": "the response could not be read"}

    plugin._carry_stderr_log(post_run, log, ())

    assert post_run["stderr"] == carried_head + " ...[truncated]"


class _InputsAnswerNone(_Plugin):
    def _uv_run_inputs_for_records(self):
        return None


class _InputsRaise(_Plugin):
    def _uv_run_inputs_for_records(self):
        raise RuntimeError("the inputs hook broke")


@pytest.mark.parametrize("plugin_class", [_InputsAnswerNone, _InputsRaise])
def test_an_inputs_accessor_that_fails_leaves_the_carry_intact(
    plugin_context, tmp_path, plugin_class
):
    log = tmp_path / "Probe.stderr.log"
    # Bytes, not write_text: on Windows write_text turns the newline into "\r\n",
    # and the carried text is what the file holds.
    log.write_bytes(b"tool said no\n")
    plugin = _named(plugin_class, plugin_context, use_uv_tool=True)
    post_run = {"error": "the response could not be read"}

    plugin._carry_stderr_log(post_run, log, ())

    assert post_run["stderr"] == "tool said no\n"
