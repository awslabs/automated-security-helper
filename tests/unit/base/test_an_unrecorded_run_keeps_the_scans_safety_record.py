# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_run_unrecorded`` hides a side run from the grade, but not a tool left running.

Why this exists
---------------
A side run (trivy's JSON report, cfn-lint's resources report) is a second launch
of the tool whose result only adds to a report already read. The plugin records
every response (output, errors, exit code, timeout flags), and a side run that
failed must not fail or annotate a scan whose main run was fine, so
``_run_unrecorded`` puts that record back afterwards.

Two things the put-back must not touch:

* A could-not-stop record. It is the signal that a tool ASH could not kill may
  still be writing into the output directory after the report was read, and
  ``run_ash_scan`` fails the run on it. Put back, a side run's failed kill was
  erased and the scan could report PASSED beside a live process.
* Nothing may be left out of step: ``errors`` and the notes ASH wrote beside them
  (``_plugin_log_lines``) are one record, and putting back one without the other
  leaves a note for a run that is over.

The list of attributes put back is hand-kept, so the last test here makes a new
private attribute of the plugin base say which side of the line it is on.
"""

from __future__ import annotations

import logging
import sys

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.scanner_executor import (
    UNSTOPPED_LATER_RUN_ENDING,
    _could_not_stop,
    _timeout_ending,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    TIMEOUT_RETURNCODE,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _Scanner(ScannerPluginBase):
    tool: str = sys.executable

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is not driven here")


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


def _scanner_answering(tmp_path, monkeypatch, *responses) -> _Scanner:
    scanner = _Scanner(config=_Config(), context=_context(tmp_path))
    scanner.use_uv_tool = False
    queue = [dict(response) for response in responses]
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: queue.pop(0),
    )
    return scanner


KILLED_TIMEOUT = {
    "stdout": "",
    "stderr": "",
    "returncode": TIMEOUT_RETURNCODE,
    "timed_out": True,
}

UNSTOPPED_TIMEOUT = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "timed_out": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4242,
}

COMMAND = [sys.executable, "-c", "pass"]


def _run_then_note(scanner: _Scanner):
    """A side run that makes its response, then writes a note of its own that the
    downgrade of a side run's ERROR lines does not keep out of the record."""

    def run(command, **kwargs):
        response = scanner._run_subprocess(command, **kwargs)
        scanner._plugin_log(
            "a side run's note", level=logging.INFO, append_to_stream="stderr"
        )
        return response

    return run


def _side_run(scanner: _Scanner) -> None:
    scanner._run_unrecorded(scanner._run_subprocess, COMMAND, timeout=5)


def test_a_side_run_whose_kill_failed_leaves_the_could_not_stop_record(
    tmp_path, monkeypatch
):
    """The safety signal outlives the put-back: the process is still running."""
    scanner = _scanner_answering(tmp_path, monkeypatch, UNSTOPPED_TIMEOUT)

    _side_run(scanner)

    assert scanner.scan_could_not_stop is not None
    assert "pid 4242" in scanner.scan_could_not_stop
    # Kept, under the side run's own key: it is not the scan's own timeout.
    assert set(scanner.scan_could_not_stop_runs) == {"side_run:timed_out"}
    assert [flag for flag, _ in scanner.scan_could_not_stop_history] == [
        "side_run:timed_out"
    ]


def test_a_side_runs_failed_stop_is_not_read_as_the_scans_own_timeout(
    tmp_path, monkeypatch
):
    """A side run whose tool could not be stopped, then the scan's own run killed
    at its timeout: the headline must not say the timed-out tool survived, and the
    kept record still fails the run."""
    scanner = _scanner_answering(
        tmp_path, monkeypatch, UNSTOPPED_TIMEOUT, KILLED_TIMEOUT
    )

    _side_run(scanner)
    scanner._run_subprocess(command=COMMAND, timeout=5)

    assert _timeout_ending(scanner) != COULD_NOT_STOP_ENDING
    assert _timeout_ending(scanner) == UNSTOPPED_LATER_RUN_ENDING
    # The deliberate property: any could-not-stop entry fails the run, because
    # the process may still be writing into the output directory.
    assert _could_not_stop(scanner) is not None
    assert "pid 4242" in _could_not_stop(scanner)


def test_the_scans_own_failed_stop_is_still_read_as_its_timeout(tmp_path, monkeypatch):
    """Control for the test above: the same record from the scan's own run keeps
    the timeout's own ending."""
    scanner = _scanner_answering(tmp_path, monkeypatch, UNSTOPPED_TIMEOUT)

    scanner._run_subprocess(command=COMMAND, timeout=5)

    assert set(scanner.scan_could_not_stop_runs) == {"timed_out"}
    assert _timeout_ending(scanner) == COULD_NOT_STOP_ENDING


def test_a_side_run_whose_stop_failed_is_named_once_at_error(
    tmp_path, monkeypatch, caplog
):
    """The one line that says which scanner left a process running and how to give
    it longer, written after the put-back so it stays with the scan's lines."""
    scanner = _scanner_answering(tmp_path, monkeypatch, UNSTOPPED_TIMEOUT)

    with caplog.at_level(logging.DEBUG):
        _side_run(scanner)
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]

    assert len(errors) == 1
    text = errors[0].getMessage()
    assert "watched" in text
    assert "scanners.watched.options.scan_timeout" in text
    assert "pid 4242" in text
    assert any("could not be stopped" in line for line in scanner.errors)
    assert scanner._side_run_active is False


def test_a_side_run_that_stopped_cleanly_says_nothing_about_a_stop(
    tmp_path, monkeypatch, caplog
):
    """Control for the test above: a killed timeout adds no could-not-stop line."""
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT)

    with caplog.at_level(logging.DEBUG):
        _side_run(scanner)

    assert not [r for r in caplog.records if "could not be stopped" in r.getMessage()]
    assert scanner.errors == []


def test_a_side_run_that_raises_after_a_failed_kill_keeps_the_record(
    tmp_path, monkeypatch
):
    scanner = _scanner_answering(tmp_path, monkeypatch, UNSTOPPED_TIMEOUT)

    def run_then_raise(command, **kwargs):
        scanner._run_subprocess(command, **kwargs)
        raise RuntimeError("the caller failed after the run")

    with pytest.raises(RuntimeError, match="after the run"):
        scanner._run_unrecorded(run_then_raise, COMMAND, timeout=5)

    assert "pid 4242" in (scanner.scan_could_not_stop or "")


def test_a_side_run_that_stopped_cleanly_adds_no_could_not_stop_record(
    tmp_path, monkeypatch
):
    """Positive control for the tests above: a killed timeout sets none."""
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT)

    _side_run(scanner)

    assert scanner.scan_could_not_stop is None
    assert scanner.scan_could_not_stop_runs == {}
    assert scanner.scan_could_not_stop_history == []


def test_a_main_runs_could_not_stop_record_survives_a_clean_side_run(
    tmp_path, monkeypatch
):
    scanner = _scanner_answering(
        tmp_path, monkeypatch, UNSTOPPED_TIMEOUT, KILLED_TIMEOUT
    )
    scanner._run_subprocess(command=COMMAND, timeout=5)

    _side_run(scanner)

    assert "pid 4242" in (scanner.scan_could_not_stop or "")
    assert len(scanner.scan_could_not_stop_history) == 1


def test_a_side_run_timeout_leaves_the_error_lines_and_the_notes_in_step(
    tmp_path, monkeypatch
):
    """Seeded with a non-zero scan record, so a reset to a clean one fails too.

    The side run writes a note that survives the downgrade of its ERROR lines
    (``append_to_stream="stderr"`` puts it in ``errors`` and in the record of
    ASH's own notes at any level), so the put-back has something to remove from
    both. Without ``_plugin_log_lines`` in the put-back list the note stays.
    """
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT)
    scanner.exit_code = 6
    scanner.errors = ["earlier line"]
    scanner._plugin_log_lines = ["earlier note"]
    errors_before = list(scanner.errors)
    notes_before = list(scanner._plugin_log_lines)

    scanner._run_unrecorded(_run_then_note(scanner), COMMAND, timeout=5)

    assert scanner.exit_code == 6
    assert scanner.errors == errors_before
    assert scanner._plugin_log_lines == notes_before
    assert scanner._scan_timed_out_after is None


def test_a_side_run_that_raises_puts_the_record_back(tmp_path, monkeypatch):
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT)
    scanner.exit_code = 6
    scanner.errors = ["earlier line"]
    scanner._plugin_log_lines = ["earlier note"]
    note_then_run = _run_then_note(scanner)

    def run_then_raise(command, **kwargs):
        note_then_run(command, **kwargs)
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        scanner._run_unrecorded(run_then_raise, COMMAND, timeout=5)

    assert scanner.exit_code == 6
    assert scanner.errors == ["earlier line"]
    assert scanner._plugin_log_lines == ["earlier note"]


def test_the_side_runs_note_is_in_the_record_before_the_put_back(tmp_path, monkeypatch):
    """Control for the two tests above: the note they arrange is really written
    to both lists while the side run is in flight."""
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT)
    seen: dict[str, list[str]] = {}
    note_then_run = _run_then_note(scanner)

    def run_and_look(command, **kwargs):
        response = note_then_run(command, **kwargs)
        seen["errors"] = list(scanner.errors)
        seen["notes"] = list(scanner._plugin_log_lines)
        return response

    scanner._run_unrecorded(run_and_look, COMMAND, timeout=5)

    assert any("a side run's note" in line for line in seen["errors"])
    assert any("a side run's note" in line for line in seen["notes"])


def test_a_side_runs_timeout_note_is_not_shown_at_error(tmp_path, monkeypatch, caplog):
    """The put-back hides the note from the record; it must not print it at ERROR
    for a scan that is then reported as it would have been."""
    scanner = _scanner_answering(tmp_path, monkeypatch, KILLED_TIMEOUT, KILLED_TIMEOUT)

    with caplog.at_level(logging.DEBUG):
        scanner._run_subprocess(command=COMMAND, timeout=5)  # control: a counted run
        counted = [r for r in caplog.records if r.levelno >= logging.ERROR]
        caplog.clear()
        _side_run(scanner)
        side = [r for r in caplog.records if r.levelno >= logging.ERROR]

    assert counted, "the control run logs its timeout at ERROR"
    assert side == []
    assert scanner._side_run_active is False


def test_the_side_run_flag_is_cleared_when_the_run_raises(tmp_path, monkeypatch):
    scanner = _scanner_answering(tmp_path, monkeypatch)

    def boom(command, **kwargs):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        scanner._run_unrecorded(boom, COMMAND)

    assert scanner._side_run_active is False


#: Private attributes of the plugin base that a run writes and a side run puts
#: back, read from ``PluginBase._RUN_RECORD_ATTRIBUTES``; the rest are listed
#: here with the reason they stay as the side run left them.
_LEFT_AS_THE_RUN_LEFT_THEM = {
    "_scan_could_not_stop": "a tool ASH could not kill is still running",
    "_scan_could_not_stop_runs": "the per-run record of the same signal",
    "_scan_could_not_stop_history": "the per-run history of the same signal",
    "_deferred_tool_version_probe": "set before any run, not by one",
    "_uv_run_failure": "reset at the start of each uv run",
    "_verified_pre_installed_executable": "a cache of the tool path, valid for any run",
    "_processed_responses": "marks of responses already recorded; not a scan record",
    "_config_from_context": "how the config was built, not a run's output",
    "_side_run_active": "set and cleared by _run_unrecorded itself",
}


def test_every_private_attribute_of_the_plugin_base_is_on_one_side_of_the_line():
    """A new recorder attribute has to be classified, or the put-back drifts."""
    restored = set(PluginBase._RUN_RECORD_ATTRIBUTES)
    private = set(PluginBase.__private_attributes__)
    unclassified = private - restored - set(_LEFT_AS_THE_RUN_LEFT_THEM)
    assert not unclassified, (
        f"classify {sorted(unclassified)}: add each to _RUN_RECORD_ATTRIBUTES "
        "when a run records it, or to _LEFT_AS_THE_RUN_LEFT_THEM with the reason"
    )
    assert not restored & set(_LEFT_AS_THE_RUN_LEFT_THEM)
    assert "_plugin_log_lines" in restored
