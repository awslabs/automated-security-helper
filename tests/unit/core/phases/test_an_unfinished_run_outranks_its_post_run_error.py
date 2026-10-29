# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run that did not finish is reported for that, not for its record failure.

A tool that timed out often fails its post-run step BECAUSE it was killed:
the output ASH would record was never finished. The executor's grading gates
each name a way scan() may have misread the run, and when both states are
recorded the raised reason has to lead with the cause (the run did not
finish) rather than the consequence (its output could not be recorded).
The order matches the run recorder's own flag order, where the unfinished
flags come before the post-run error.

A spawn failure still gates first: a tool that never started has no run to
leave unfinished and no post-run step to fail.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: A timed-out run whose post-run record step failed too: the accumulated
#: error carries the timeout first and the record failure after it, as the
#: runner accumulates them.
_TIMED_OUT_AND_UNRECORDED = {
    "stdout": "",
    "stderr": "",
    "returncode": 124,
    "timed_out": True,
    "post_run_error": True,
    "error": (
        "Command timed out after 5s: tool; its stderr log could not be read: boom"
    ),
}

#: The control: the record step failed on a run that finished normally.
_FINISHED_BUT_UNRECORDED = {
    "stdout": "",
    "stderr": "",
    "returncode": 0,
    "post_run_error": True,
    "error": "its stderr log could not be read: boom",
}


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _Scanner(ScannerPluginBase):
    tool: str = sys.executable

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=[self.tool, "-c", "pass"],
            results_dir=self.results_dir,
            timeout=5,
        )
        return {"severity_counts": {}}


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _row(tmp_path, monkeypatch, response):
    """One executor row for a scanner whose single run answers ``response``."""
    context = _context(tmp_path)
    scanner = _Scanner(config=_Config(), context=context)
    scanner.use_uv_tool = False
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: dict(response),
    )
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "watched", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return row


def _row_errors(row):
    raw = row.raw_results if isinstance(row.raw_results, dict) else {}
    return [str(error) for error in [*(raw.get("errors") or []), *(row.errors or [])]]


def test_a_timed_out_run_with_a_record_failure_is_reported_as_timed_out(
    tmp_path, monkeypatch
):
    """Both states recorded: the raised reason leads with the timeout, and the
    record failure's detail still rides in it as the reason text."""
    row = _row(tmp_path, monkeypatch, _TIMED_OUT_AND_UNRECORDED)

    errors = _row_errors(row)
    timed_out = [error for error in errors if "watched timed out" in error]
    assert timed_out, errors
    # The cause's detail is not lost: the recorded reason carries it.
    assert any("could not be read" in error for error in timed_out), timed_out


def test_a_finished_run_with_a_record_failure_keeps_the_record_reason(
    tmp_path, monkeypatch
):
    """The control: with nothing unfinished, the record failure is the story."""
    row = _row(tmp_path, monkeypatch, _FINISHED_BUT_UNRECORDED)

    errors = _row_errors(row)
    assert any("could not record" in error for error in errors), errors
    assert not any("timed out" in error for error in errors), errors
