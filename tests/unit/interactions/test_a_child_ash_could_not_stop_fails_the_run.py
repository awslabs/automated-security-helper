# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run that ends with a child ASH could not stop exits 1, whatever the gate says.

Why this exists
---------------
``fail_on_incomplete_scanners: false`` is the operator saying "report partial
coverage, do not fail me for it". A child ASH could not stop is a different thing:
the tool may still be running, and it can write into the output directory after
the gate has read it, so the report is not final. That one case fails the run
(exit 1) whether or not the gate is on, with the reason naming the process id, and
the setting's own documentation says so. A plain timeout whose stop worked stays
under the gate: with the gate declined it reports and exits 0.

The results are built through the real scan phase from the runner's own response
shape for a stop that failed (the timeout kept, no exit code, the reason naming
the pid), so these cells read whatever record the run actually makes rather than
pinning a field by hand.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_MARKER

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: The pid the stand-in responses name; nothing on the host has run under it here.
_PID = 4242

#: The runner's response for a timeout whose stop did not end the child (3e's
#: could-not-stop shape): the flag kept, no exit code, the reason naming the pid.
#: Built from the constant and state key the runner emits, never hand-written:
#: a drifted separator or wording here would make these cells quote text the
#: runner no longer writes, and the recorded state is what the grading keys on.
_STOP_FAILED = {
    "returncode": None,
    "timed_out": True,
    "could_not_stop": True,
    "error": (
        "Command timed out after 5s: tool; "
        f"{COULD_NOT_STOP_MARKER} {_PID}), which may still be running"
    ),
}

#: The control: the same timeout, stopped at the limit, with the tool's gone.
_STOPPED_AT_THE_LIMIT = {
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _IgnoresTheResponse(ScannerPluginBase):
    """Runs its tool and reports no findings, whatever the run answered."""

    def model_post_init(self, context):
        # The phase constructs the plugin from its class, with no config to give.
        if self.config is None:
            self.config = _Config()
        self.command = "watched-tool"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=["tool", "scan"], results_dir=self.results_dir, timeout=5
        )
        return {"severity_counts": {}}


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="test"),
    )


def _results_of_a_run(tmp_path, response: Dict[str, Any]) -> AshAggregatedResults:
    """One scan whose only scanner's run answered ``response``, as the model the
    exit code is computed from."""
    context = _context(tmp_path)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_IgnoresTheResponse],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        side_effect=lambda *args, **kwargs: dict(response),
    ):
        results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.messages: List[str] = []

    def emit(self, record) -> None:
        self.messages.append(record.getMessage())


def _exit_code_and_log(results, tmp_path, **opt_kwargs: Any) -> tuple:
    from automated_security_helper.utils.log import ASH_LOGGER

    opts = ScanOptions(
        source_dir=tmp_path / "source", output_dir=tmp_path / "output", **opt_kwargs
    )
    handler = _Lines()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.INFO)
    try:
        code = _compute_exit_code(results, opts)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
    return code, handler.messages


def test_a_child_ash_could_not_stop_fails_the_run_with_the_gate_declined(tmp_path):
    """The run ended with the tool possibly still running, so the output can be
    written after the gate reads it: the run exits 1 even under
    ``fail_on_incomplete_scanners: false``, and the reason names the pid."""
    results = _results_of_a_run(tmp_path, _STOP_FAILED)
    row = results.scanner_results["watched"]
    assert row.status == ScannerStatus.ERROR, (
        f"the could-not-stop run was not recorded as an error: {row!r}"
    )

    code, logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=False
    )

    assert code == 1, (
        "a child ASH could not stop may still write into the output directory, "
        f"so the run must fail whatever the gate says; got exit {code}"
    )
    naming = [line for line in logged if f"pid {_PID}" in line]
    assert naming, (
        f"no exit reason named the pid; the operator cannot find the process: {logged}"
    )


def test_control_a_timeout_whose_stop_worked_stays_under_the_gate(tmp_path):
    """The override is for the could-not-stop ending alone. A timeout whose stop
    ended the tool is ordinary incompleteness: the row is an ERROR either way,
    and with the gate declined the run reports it and exits 0 — while the same
    results under the gate exit 1, so the 0 is the gate's doing, not a run
    recorded as if it had passed."""
    results = _results_of_a_run(tmp_path, _STOPPED_AT_THE_LIMIT)
    row = results.scanner_results.get("watched")
    assert row is not None, "the scanner never ran, so the control shows nothing"
    assert row.status == ScannerStatus.ERROR, (
        f"the stopped timeout was not recorded as an error: {row!r}"
    )

    code, _logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=False
    )
    gated, _logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=True
    )

    assert code == 0, code
    assert gated == 1, gated


def test_a_child_ash_could_not_stop_fails_the_run_with_the_gate_on(tmp_path):
    """With the gate on the same run fails too: the override adds a floor, it does
    not replace the gate."""
    results = _results_of_a_run(tmp_path, _STOP_FAILED)
    assert "watched" in results.scanner_results, (
        "the scanner never ran, so the cell shows nothing"
    )

    code, _logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=True
    )

    assert code == 1, code


def test_the_gate_on_run_still_logs_the_could_not_stop_reason(tmp_path):
    """With the gate on, the same row also trips the incomplete-scanner arm. The
    cause that no setting can silence is the one logged: an operator shown only
    "Scan incomplete" would decline the gate and still fail, with the process
    the exit is about never named."""
    results = _results_of_a_run(tmp_path, _STOP_FAILED)
    assert "watched" in results.scanner_results, (
        "the scanner never ran, so the cell shows nothing"
    )

    code, logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=True
    )

    assert code == 1, code
    naming = [line for line in logged if f"pid {_PID}" in line]
    assert naming, (
        f"no exit reason named the pid with the gate on; the incomplete-scanner "
        f"arm hid the could-not-stop cause: {logged}"
    )


def test_every_exit_cause_is_logged_not_only_the_first_arm(tmp_path):
    """The log is complete, not ordered: a run with a tool ASH could not stop
    AND an incomplete scanner logs both causes before exiting 1. Logging only
    the first arm sent an operator working from ash.log through one fix and one
    re-run per cause."""
    results = _results_of_a_run(tmp_path, _STOP_FAILED)
    row = results.scanner_results.get("watched")
    assert row is not None and row.status == ScannerStatus.ERROR, (
        "the cell shows nothing: no incomplete-scanner cause is present"
    )

    code, logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=True
    )

    assert code == 1, code
    stop_lines = [line for line in logged if "could not" in line and "stopped" in line]
    incomplete_lines = [line for line in logged if line.startswith("Scan incomplete:")]
    assert stop_lines, f"the could-not-stop cause was not logged: {logged}"
    assert incomplete_lines, (
        f"the incomplete-scanner cause was hidden by the earlier arm: {logged}"
    )


def test_the_coverage_gap_check_knows_the_could_not_stop_key():
    """The MCP layer's coverage_complete answer reads the same payload the exit
    code is explained from: a run whose only gap is a tool ASH could not stop
    must not read as complete coverage."""
    from automated_security_helper.core.resource_management.scan_tracking import (
        coverage_has_gap,
    )

    row = {"scanner": "watched", "reason": f"{COULD_NOT_STOP_MARKER} {_PID})"}
    assert coverage_has_gap({"could_not_stop": [row]})
    assert not coverage_has_gap({"could_not_stop": []})


def test_the_settings_docs_say_the_could_not_stop_case_overrides_it():
    """The one case where the operator's setting is overridden is written on the
    setting itself, so an operator reading the field learns it there."""
    description = str(
        AshConfig.model_fields["fail_on_incomplete_scanners"].description or ""
    )
    assert "could not stop" in description, description


#: A tool that prints the could-not-stop wording itself, then exits 1. ASH
#: stopped nothing: the text is the tool's own stderr, data, never a state.
_TOOL_QUOTES_THE_MARKER = {
    "returncode": 1,
    "stdout": "",
    "stderr": (
        "note: ASH could not stop the tool (pid 7), which may still be running\n"
    ),
}


class _RaisesAfterItsRun(_IgnoresTheResponse):
    """Runs its tool, then raises, as a scanner does when no results file came.
    The raise puts the run's stderr among the scan's recorded error lines."""

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        from automated_security_helper.core.exceptions import ScannerError

        self._run_subprocess(
            command=["tool", "scan"], results_dir=self.results_dir, timeout=5
        )
        raise ScannerError("the tool wrote no results file")


def _results_of_a_failed_scan(tmp_path, response: Dict[str, Any]):
    context = _context(tmp_path)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_RaisesAfterItsRun],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        side_effect=lambda *args, **kwargs: dict(response),
    ):
        results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    return populate_metrics_from_unified_source(aggregated_results=results)


def test_tool_text_is_not_read_as_a_tool_ash_could_not_stop(tmp_path):
    """A failed scan's recorded errors hold the tool's own stderr. A tool
    that printed the could-not-stop wording itself is not a tool ASH could not
    stop: that is decided by the state ASH records, never by matching text."""
    from automated_security_helper.interactions.run_ash_scan import (
        scanners_that_could_not_stop,
    )

    results = _results_of_a_failed_scan(tmp_path, dict(_TOOL_QUOTES_THE_MARKER))

    rows = scanners_that_could_not_stop(results)
    assert rows == [], rows


def test_tool_text_does_not_set_the_exit_1_floor(tmp_path):
    """The same scan under fail_on_incomplete_scanners false exits 0, and
    the log carries no reason built from the tool's text — a pid ASH never chose
    must not reach the operator as if ASH reported it."""
    results = _results_of_a_failed_scan(tmp_path, dict(_TOOL_QUOTES_THE_MARKER))

    code, logged = _exit_code_and_log(
        results, tmp_path, fail_on_incomplete_scanners=False
    )

    assert not [line for line in logged if "pid 7" in line], logged
    assert code == 0, (code, logged)


def test_results_without_report_storage_yield_no_rows():
    """The rollup reads its carrier the way every carrier read goes: tolerant of
    an object that does not carry the field at all. A results stand-in without
    additional_reports answers no rows rather than raising."""
    from types import SimpleNamespace

    from automated_security_helper.interactions.run_ash_scan import (
        scanners_that_could_not_stop,
    )

    assert scanners_that_could_not_stop(SimpleNamespace()) == []
