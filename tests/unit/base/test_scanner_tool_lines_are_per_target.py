# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The template scan resets the tool lines per target, as it resets the exit code.

``_process_command_response`` appends every run's stdout and stderr to
``output`` and ``errors``, and the executor records them, and the failure
message quotes them, as the current target's. One plugin instance scans the
source target and then the converted one, so a failed converted-target run's
record led with the source target's lines and the quoted stderr described the
wrong run.
"""

from __future__ import annotations

import contextlib
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from tests.unit.base.test_scanner_plugin_coverage import (
    _execute_writing,
    _populated_target,
    _scanner,
)

pytestmark = pytest.mark.unit

_RUNNER = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)


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


def test_a_new_target_starts_with_no_lines_from_the_previous_one(
    plugin_context, tmp_path
):
    scanner = _scanner(plugin_context)
    scanner.errors = ["stderr carried from the source target"]
    scanner.output = ["stdout carried from the source target"]
    empty = tmp_path / "converted"
    empty.mkdir()

    scanner.scan(empty, "converted")

    assert "stderr carried from the source target" not in scanner.errors, scanner.errors
    assert "stdout carried from the source target" not in scanner.output, scanner.output


def test_the_new_targets_own_lines_are_recorded_and_the_carried_ones_are_not(
    plugin_context, tmp_path
):
    """A reset at the end of ``scan()`` or after the output was recorded would
    pass the test above and wipe the current target's own lines. The target here
    is populated, so the tool runs, and what it says is in the record."""
    scanner = _scanner(plugin_context, execute_scan=_execute_writing(None))
    scanner.use_uv_tool = False
    scanner.errors = ["stderr carried from the source target"]
    scanner.output = ["stdout carried from the source target"]
    target = _populated_target(tmp_path, "converted")

    with (
        patch(
            _RUNNER,
            return_value={
                "returncode": 0,
                "stdout": "new-target stdout line",
                "stderr": "new-target stderr line",
            },
        ),
        contextlib.suppress(ScannerError),
    ):
        scanner.scan(target=target, target_type="converted")

    assert "new-target stdout line" in scanner.output, scanner.output
    assert "new-target stderr line" in scanner.errors, scanner.errors
    assert "stdout carried from the source target" not in scanner.output
    assert "stderr carried from the source target" not in scanner.errors
