# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uv run's response is processed exactly once by ``_run_subprocess``.

The uv path hands a run that returned to ``_process_command_response`` itself,
but a failure after its child started, or a response whose building raised,
comes back unprocessed, and ``_run_subprocess`` only recorded it. The child's
exit code and stderr then never reached ``exit_code`` and ``errors``: a scanner
reading those judged the run accepted and reported none of the tool's text.
The response is processed when the uv path did not, and never a second time
when it did.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

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


def _after_the_start() -> dict:
    return {
        "stdout": "",
        "stderr": "the tool said why it failed",
        "returncode": 3,
        "post_run_error": True,
        "spawn_failed": False,
        "error": "the wait for the child failed",
    }


def test_an_unprocessed_uv_response_reaches_exit_code_and_errors(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context, use_uv_tool=True)
    scanner.exit_code = 0

    def _unprocessed(self, *args, **kwargs):
        return _after_the_start()

    with patch.object(type(scanner), "_try_uv_tool_execution", _unprocessed):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert response["returncode"] == 3
    assert scanner.exit_code == 3, scanner.exit_code
    assert any("the tool said why it failed" in line for line in scanner.errors), (
        scanner.errors
    )
    assert scanner._processed_responses == [], scanner._processed_responses


def test_a_processed_uv_response_is_not_processed_twice(plugin_context, tmp_path):
    scanner = _scanner(plugin_context, use_uv_tool=True)
    scanner.exit_code = 0

    def _processed(self, *args, **kwargs):
        response = _after_the_start()
        self._process_command_response(response)
        # The caller that processed the response owns the mark (the uv mixin
        # sets it the same way); the accumulator sets none.
        self._mark_processed(response)
        return response

    with patch.object(type(scanner), "_try_uv_tool_execution", _processed):
        scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    said = [line for line in scanner.errors if "the tool said why it failed" in line]
    assert len(said) == 1, scanner.errors
    assert scanner.exit_code == 3
    assert scanner._processed_responses == [], scanner._processed_responses
