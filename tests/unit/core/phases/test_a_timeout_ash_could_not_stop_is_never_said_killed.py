# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A timeout whose stop failed is never reported as "was killed".

"Was killed" tells the operator the tool is gone. When ASH's stop did not
end the tool, that is the one thing the message must not claim: the process
may still be running, holding files and burning time, and the operator may
need to end it. The executor's two timeout texts -- the failed-scan lead
and the per-target line -- say so from the recorded could-not-stop state,
never from any text match; a timeout whose stop worked keeps "was killed".
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_MARKER

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: The runner's response for a timeout whose stop did not end the child: the
#: flag kept, no exit code, the reason naming the pid. Built from the
#: constant the runner emits, never hand-written.
_STOP_FAILED = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "timed_out": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4242,
    "error": (
        "Command timed out after 5s: tool; "
        f"{COULD_NOT_STOP_MARKER} 4242), which may still be running"
    ),
}

#: The control: the same timeout, stopped at the limit, the tool gone.
_STOPPED_AT_THE_LIMIT = {
    "stdout": "",
    "stderr": "",
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _Scanner(ScannerPluginBase):
    tool: str = sys.executable
    #: What scan() does after its one tool run: "raise" stands in for the
    #: missing results file a killed tool never wrote (the executor's failed-
    #: scan lead), "return" for a scanner that handled the miss itself (the
    #: grading block's per-target line).
    after_run: str = "raise"

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
        if self.after_run == "raise":
            raise FileNotFoundError(
                "[Errno 2] No such file or directory: 'results.sarif'"
            )
        self.clear_scan_kept_flag()
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


def _row(tmp_path, monkeypatch, response, after_run):
    context = _context(tmp_path)
    scanner = _Scanner(config=_Config(), context=context, after_run=after_run)
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


def _executor_lines(row):
    """The executor's own timeout texts: the ones naming the target type."""
    return [error for error in _row_errors(row) if "on source" in error]


def test_the_failed_scan_lead_says_it_may_still_be_running(tmp_path, monkeypatch):
    """A could-not-stop timeout whose scan then failed on the missing results
    file: the lead says the tool may still be running, and nothing in the
    row claims it was killed."""
    row = _row(tmp_path, monkeypatch, _STOP_FAILED, after_run="raise")

    lines = _executor_lines(row)
    assert any("may still be running" in line for line in lines), lines
    killed = [error for error in _row_errors(row) if "was killed" in error]
    assert killed == [], killed


def test_the_per_target_line_says_it_may_still_be_running(tmp_path, monkeypatch):
    """The same recorded state on a scan that returned: the grading block's
    per-target line carries the same contract."""
    row = _row(tmp_path, monkeypatch, _STOP_FAILED, after_run="return")

    lines = _executor_lines(row)
    assert any("may still be running" in line for line in lines), lines
    killed = [error for error in _row_errors(row) if "was killed" in error]
    assert killed == [], killed


def test_a_stopped_timeout_keeps_was_killed_in_the_lead(tmp_path, monkeypatch):
    """The control: a timeout whose stop worked IS a killed tool, and the
    lead keeps saying so."""
    row = _row(tmp_path, monkeypatch, _STOPPED_AT_THE_LIMIT, after_run="raise")

    lines = _executor_lines(row)
    assert any("was killed" in line for line in lines), lines
    assert not any("may still be running" in line for line in _row_errors(row)), (
        _row_errors(row)
    )


def test_a_stopped_timeout_keeps_was_killed_in_the_per_target_line(
    tmp_path, monkeypatch
):
    row = _row(tmp_path, monkeypatch, _STOPPED_AT_THE_LIMIT, after_run="return")

    lines = _executor_lines(row)
    assert any("was killed" in line for line in lines), lines
    assert not any("may still be running" in line for line in _row_errors(row)), (
        _row_errors(row)
    )
