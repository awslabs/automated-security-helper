# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed stop is recorded per run, under the flag that run ended with.

Why this exists
---------------
``scan_could_not_stop`` is one record for the whole plugin, set by any run whose
stop failed and kept across the launches of one ``scan()``. Read alone, a scan
whose first launch timed out and was killed, and whose second launch was
cancelled and could not be stopped, said the timed-out tool "may still be
running": the wrong tool. The plugin now also keeps the reason per run, keyed by
the flag the run ended with, so a reader can ask whether the TIMEOUT's stop
failed instead of whether any stop did. The single record is unchanged, and both
are cleared together.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import TIMEOUT_RETURNCODE

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


def _scanner_whose_runs_answer(tmp_path, monkeypatch, *responses) -> _Scanner:
    """A direct-execution scanner whose runs answer ``responses`` in order."""
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

# No error text, so the recorded reason is the default that names the pid the
# response carries beside the flag; the two runs are told apart by their pids.
UNSTOPPED_TIMEOUT = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "timed_out": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4242,
}

UNSTOPPED_CANCEL = {
    "stdout": "",
    "stderr": "",
    "returncode": None,
    "cancelled": True,
    "could_not_stop": True,
    "could_not_stop_pid": 4343,
}


def _run(scanner: _Scanner) -> None:
    scanner._run_subprocess(command=[sys.executable, "-c", "pass"])


def test_a_killed_timeout_then_an_unstopped_cancel_names_only_the_cancel(
    tmp_path, monkeypatch
):
    """The case that misled the timeout headline: the timeout's own stop worked,
    the later cancel's did not, and the per-run record says so."""
    scanner = _scanner_whose_runs_answer(
        tmp_path, monkeypatch, KILLED_TIMEOUT, UNSTOPPED_CANCEL
    )

    _run(scanner)
    _run(scanner)

    runs = scanner.scan_could_not_stop_runs
    assert set(runs) == {"cancelled"}, runs
    assert "pid 4343" in runs["cancelled"], runs
    assert "timed_out" not in runs
    # The single record is the most recent reason, as before.
    assert scanner.scan_could_not_stop == runs["cancelled"]


def test_two_failed_stops_are_both_recorded(tmp_path, monkeypatch):
    scanner = _scanner_whose_runs_answer(
        tmp_path, monkeypatch, UNSTOPPED_TIMEOUT, UNSTOPPED_CANCEL
    )

    _run(scanner)
    _run(scanner)

    runs = scanner.scan_could_not_stop_runs
    assert set(runs) == {"timed_out", "cancelled"}, runs
    assert "pid 4242" in runs["timed_out"], runs
    assert "pid 4343" in runs["cancelled"], runs
    assert scanner.scan_could_not_stop == runs["cancelled"]


def test_a_run_whose_stop_worked_records_no_run(tmp_path, monkeypatch):
    """The control: no failed stop, nothing in either record."""
    scanner = _scanner_whose_runs_answer(tmp_path, monkeypatch, KILLED_TIMEOUT)

    _run(scanner)

    assert scanner.scan_could_not_stop_runs == {}
    assert scanner.scan_could_not_stop is None


def test_clearing_forgets_the_per_run_records_too(tmp_path, monkeypatch):
    scanner = _scanner_whose_runs_answer(tmp_path, monkeypatch, UNSTOPPED_CANCEL)
    _run(scanner)
    assert scanner.scan_could_not_stop_runs, "the stop failure was not recorded"

    scanner.clear_scan_could_not_stop()

    assert scanner.scan_could_not_stop_runs == {}
    assert scanner.scan_could_not_stop is None


def test_the_mapping_is_a_copy(tmp_path, monkeypatch):
    scanner = _scanner_whose_runs_answer(tmp_path, monkeypatch, UNSTOPPED_CANCEL)
    _run(scanner)

    scanner.scan_could_not_stop_runs.clear()

    assert set(scanner.scan_could_not_stop_runs) == {"cancelled"}
