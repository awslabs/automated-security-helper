# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uv run's response is processed once, however ``_process_command_response`` is overridden.

``_run_subprocess`` folds a uv response into ``exit_code`` and ``errors`` exactly once:
the uv path processes a run that returned, and the dispatcher processes it only when
that mark is missing. The mark was set INSIDE ``_process_command_response``, which is a
documented extension seam, so a subclass overriding it without calling ``super()`` left
the response unmarked and the dispatcher processed it a second time. A response whose
handling raised after the processing was handed back as a copy that was not marked, and
was processed twice the same way. The caller now owns the mark: the uv mixin sets it
after its own call returned, and marks the copy it hands back for a response it had
processed.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

TOOL_SAID = "the tool said this once"


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


def _a_uv_run(self, *_args, **_kwargs):
    """What ``_try_uv_tool_execution`` hands back for a run that returned."""
    result = SimpleNamespace(stdout="", stderr=TOOL_SAID, returncode=1)
    return self._uv_response(result, None)


def _scanner_run_through_uv(plugin_context):
    scanner = _scanner(plugin_context)
    scanner.use_uv_tool = True
    scanner.command = "stub-tool"
    return scanner


def test_an_override_that_never_calls_super_is_called_once(plugin_context, tmp_path):
    scanner = _scanner_run_through_uv(plugin_context)

    with (
        patch.object(type(scanner), "_try_uv_tool_execution", _a_uv_run),
        patch.object(type(scanner), "_process_command_response") as override,
    ):
        scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert override.call_count == 1, override.call_args_list


def test_the_real_accumulator_records_the_tools_line_once(plugin_context, tmp_path):
    scanner = _scanner_run_through_uv(plugin_context)

    with patch.object(type(scanner), "_try_uv_tool_execution", _a_uv_run):
        scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert scanner.errors.count(TOOL_SAID) == 1, scanner.errors


def test_a_response_whose_handling_raised_after_processing_is_not_processed_again(
    plugin_context, tmp_path, monkeypatch
):
    scanner = _scanner_run_through_uv(plugin_context)
    real_log = type(scanner)._plugin_log

    def _log(self, *messages, **kwargs):
        # The line _uv_response writes after the processing and the explainer:
        # raising here sends the processed response into the handler, which hands
        # back a copy.
        if messages and str(messages[0]).startswith("UV tool execution completed"):
            raise RuntimeError("the log broke")
        return real_log(self, *messages, **kwargs)

    monkeypatch.setattr(type(scanner), "_plugin_log", _log)

    with patch.object(type(scanner), "_try_uv_tool_execution", _a_uv_run):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert response["post_run_error"] is True, response
    assert scanner.errors.count(TOOL_SAID) == 1, scanner.errors
    assert scanner._processed_responses == [], scanner._processed_responses


def test_a_response_whose_processing_raised_is_processed_once_by_the_dispatcher(
    plugin_context, tmp_path
):
    """The control: a call that raised sets no mark, so the dispatcher's own call
    is the one that records the run."""
    scanner = _scanner_run_through_uv(plugin_context)
    real_process = type(scanner)._process_command_response
    calls = []

    def _process(self, response):
        calls.append(response)
        if len(calls) == 1:
            raise RuntimeError("could not record the response")
        return real_process(self, response)

    with (
        patch.object(type(scanner), "_try_uv_tool_execution", _a_uv_run),
        patch.object(type(scanner), "_process_command_response", _process),
    ):
        scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert len(calls) == 2, calls
    assert scanner.errors.count(TOOL_SAID) == 1, scanner.errors
