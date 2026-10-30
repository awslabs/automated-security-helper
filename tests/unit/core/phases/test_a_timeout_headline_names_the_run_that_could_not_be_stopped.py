# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A timeout headline does not pin another run's failed stop on the timed-out tool.

``scan_could_not_stop`` is one record for the whole plugin, set by any run whose
stop failed and kept across the launches of one ``scan()``. The executor's two
timeout texts read it alone, so a scan whose first launch timed out and was killed
and whose second launch was cancelled and could not be stopped said the timed-out
tool "may still be running": the wrong tool. The kept flag names the most recent
run that did not finish; when it is not the timeout, the headline now says a later
run's tool could not be stopped, and still never says the timed-out tool was killed.

The two controls are the single-launch shapes the sibling test pins: a stop that
failed keeps the timeout's own could-not-stop ending; a stop that worked keeps
"was killed".
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import (
    UNSTOPPED_LATER_RUN_ENDING,
    ScannerExecutor,
    _timeout_ending,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    COULD_NOT_STOP_MARKER,
    WAS_KILLED_ENDING,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: Launch 1: a timeout stopped at the limit, the tool gone.
_TIMED_OUT_AND_KILLED = {
    "stdout": "",
    "stderr": "",
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}

#: Launch 2: a cancel whose stop did not end the child.
_CANCELLED_AND_UNSTOPPED = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "cancelled": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4343,
    "error": (
        f"Command cancelled: tool; {COULD_NOT_STOP_MARKER} 4343), which may still "
        "be running"
    ),
}

#: A single timeout whose stop failed (the sibling test's shape).
_TIMED_OUT_AND_UNSTOPPED = {
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


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _Scanner(ScannerPluginBase):
    """Runs one tool command per entry of ``responses``, then raises as a scanner
    whose killed tool wrote no results file does."""

    tool: str = sys.executable
    launches: int = 1

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        for _ in range(self.launches):
            self._run_subprocess(
                command=[self.tool, "-c", "pass"],
                results_dir=self.results_dir,
                timeout=5,
            )
        raise FileNotFoundError("[Errno 2] No such file or directory: 'results.sarif'")


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


def _row(tmp_path, monkeypatch, responses):
    context = _context(tmp_path)
    scanner = _Scanner(config=_Config(), context=context, launches=len(responses))
    scanner.use_uv_tool = False
    queue = [dict(response) for response in responses]
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: queue.pop(0),
    )
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "watched", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return row


def _timeout_lead(row) -> str:
    raw = row.raw_results if isinstance(row.raw_results, dict) else {}
    errors = [str(error) for error in [*(raw.get("errors") or []), *(row.errors or [])]]
    leads = [error for error in errors if "timed out" in error and "on source" in error]
    assert leads, errors
    return leads[0]


def test_a_later_runs_failed_stop_is_not_pinned_on_the_timed_out_tool(
    tmp_path, monkeypatch
):
    lead = _timeout_lead(
        _row(tmp_path, monkeypatch, [_TIMED_OUT_AND_KILLED, _CANCELLED_AND_UNSTOPPED])
    )

    assert UNSTOPPED_LATER_RUN_ENDING in lead, lead
    assert COULD_NOT_STOP_ENDING not in lead, lead
    assert WAS_KILLED_ENDING not in lead, lead


def test_a_timeout_whose_own_stop_failed_keeps_its_ending(tmp_path, monkeypatch):
    """Control: one launch, the stop failed, the timeout's own ending."""
    lead = _timeout_lead(_row(tmp_path, monkeypatch, [_TIMED_OUT_AND_UNSTOPPED]))

    assert COULD_NOT_STOP_ENDING in lead, lead
    assert WAS_KILLED_ENDING not in lead, lead


def test_a_timeout_whose_stop_worked_was_killed(tmp_path, monkeypatch):
    """Control: one launch, stopped at the limit."""
    lead = _timeout_lead(_row(tmp_path, monkeypatch, [_TIMED_OUT_AND_KILLED]))

    assert WAS_KILLED_ENDING in lead, lead
    assert "could not stop" not in lead, lead


class TestTheEndingFromTheRecords:
    def _plugin(self, could_not_stop, kept):
        return SimpleNamespace(scan_could_not_stop=could_not_stop, scan_kept_flag=kept)

    def test_no_failed_stop_was_killed(self):
        assert _timeout_ending(self._plugin(None, ("timed_out", "r"))) == (
            WAS_KILLED_ENDING
        )

    def test_a_failed_stop_on_the_timeout_is_the_timeouts(self):
        assert _timeout_ending(self._plugin("pid 1", ("timed_out", "r"))) == (
            COULD_NOT_STOP_ENDING
        )

    def test_a_failed_stop_with_no_flag_is_the_timeouts(self):
        assert _timeout_ending(self._plugin("pid 1", None)) == COULD_NOT_STOP_ENDING

    def test_a_failed_stop_on_a_later_cancelled_run_is_that_runs(self):
        """A cancel is the one other ending that goes through a stop."""
        assert _timeout_ending(self._plugin("pid 1", ("cancelled", "r"))) == (
            UNSTOPPED_LATER_RUN_ENDING
        )

    @pytest.mark.parametrize("flag", ["result_rejected", "signaled"])
    def test_a_later_run_with_no_stop_leaves_the_record_to_the_timeout(self, flag):
        """A tool that died on a signal ASH did not send, or whose result was
        rejected, was never stopped by ASH, so the could-not-stop record can only
        be the timeout's; blaming the later run was the reverse of the fixed bug."""
        assert _timeout_ending(self._plugin("pid 1", (flag, "r"))) == (
            COULD_NOT_STOP_ENDING
        )


class TestTheEndingFromThePerRunRecord:
    """The plugin's per-run record (``scan_could_not_stop_runs``, one entry per run
    whose stop failed, keyed by the flag the run ended with) is exact, so the
    ending reads it first and falls back to the kept flag only when a plugin
    carries none. Red at the base: the record was not read, so a run whose cancel
    stop failed beside a timeout that was killed read as the timeout's own failed
    stop whenever the kept flag was the timeout's."""

    def _plugin(self, runs, could_not_stop="pid 1", kept=("timed_out", "r")):
        return SimpleNamespace(
            scan_could_not_stop_runs=runs,
            scan_could_not_stop=could_not_stop,
            scan_kept_flag=kept,
        )

    def test_the_timeouts_own_failed_stop_is_the_timeouts(self):
        assert _timeout_ending(self._plugin({"timed_out": "r"})) == (
            COULD_NOT_STOP_ENDING
        )
        both = self._plugin(
            {"timed_out": "r", "cancelled": "r"}, kept=("cancelled", "r")
        )
        assert _timeout_ending(both) == COULD_NOT_STOP_ENDING

    def test_another_runs_failed_stop_is_that_runs_whatever_the_kept_flag(self):
        assert _timeout_ending(self._plugin({"cancelled": "r"})) == (
            UNSTOPPED_LATER_RUN_ENDING
        )
        assert _timeout_ending(self._plugin({"unflagged": "r"})) == (
            UNSTOPPED_LATER_RUN_ENDING
        )

    def test_an_empty_record_means_every_stop_worked(self):
        """The record outranks the single could-not-stop string: a plugin whose
        every stop worked carries an empty record whatever else it holds."""
        assert _timeout_ending(self._plugin({})) == WAS_KILLED_ENDING

    def test_a_plugin_with_no_record_keeps_the_kept_flag_reading(self):
        """The control: a plugin class without the record (or a double that
        answers it with something that is not a dict) is read as before."""
        assert _timeout_ending(self._plugin(None, kept=("cancelled", "r"))) == (
            UNSTOPPED_LATER_RUN_ENDING
        )
        assert _timeout_ending(self._plugin("not a record")) == COULD_NOT_STOP_ENDING
        assert _timeout_ending(self._plugin(None, could_not_stop=None)) == (
            WAS_KILLED_ENDING
        )
