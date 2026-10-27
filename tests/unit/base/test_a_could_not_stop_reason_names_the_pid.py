# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pid of a tool ASH could not stop rides as data beside the flag.

The reason an operator reads normally comes from the response's own error text,
which names the pid. That text can be missing or unreadable, and the fact must
not degrade with it: the response carries ``could_not_stop_pid`` beside
``could_not_stop``, so the recorded reason still names the process ASH left
running. The number is data from the spawn record; nothing reads it back out of
any text.

The flag itself can also be unreadable. A read that raises leaves the state
UNKNOWN, which is not the same as a stop that worked: the timeout fallback
answers the timeout's own exit code (124) only for a stop known to have worked,
because 124 says ASH stopped the tool, and that is never claimed blind.
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
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_MARKER,
    TIMEOUT_RETURNCODE,
    StartWatch,
    _StartedChild,
)

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
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=[self.tool, "-c", "pass"], results_dir=self.results_dir
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


def _scanner_whose_run_answers(tmp_path, monkeypatch, response) -> _Scanner:
    """A direct-execution scanner whose one run answers ``response``."""
    scanner = _Scanner(config=_Config(), context=_context(tmp_path))
    scanner.use_uv_tool = False
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: dict(response),
    )
    return scanner


def test_the_default_reason_names_the_pid_the_response_carries(tmp_path, monkeypatch):
    """A could-not-stop response whose error text is missing still records a
    reason naming the process, from the pid carried as data beside the flag."""
    scanner = _scanner_whose_run_answers(
        tmp_path,
        monkeypatch,
        {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "timed_out": True,
            "could_not_stop": True,
            "could_not_stop_pid": 4242,
        },
    )

    scanner._run_subprocess(command=[sys.executable, "-c", "pass"])

    reason = scanner.scan_could_not_stop or ""
    assert "pid 4242" in reason, reason
    assert COULD_NOT_STOP_MARKER in reason, reason


def test_the_default_reason_without_a_pid_names_none(tmp_path, monkeypatch):
    """The control: a could-not-stop response that carries no pid records the
    generic reason, and no number is invented for it."""
    scanner = _scanner_whose_run_answers(
        tmp_path,
        monkeypatch,
        {
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "timed_out": True,
            "could_not_stop": True,
        },
    )

    scanner._run_subprocess(command=[sys.executable, "-c", "pass"])

    reason = scanner.scan_could_not_stop or ""
    assert reason, "no could-not-stop reason was recorded"
    assert "pid" not in reason, reason


class _StillRunning:
    """What the spawn record holds of a child a refused stop did not end."""

    pid = 4242
    returncode = None


def test_the_pid_rides_from_the_spawn_record_to_the_response():
    """The writer's side: a failure after a start whose stop was refused carries
    the flag and the recorded child's pid in the response it builds."""
    started = _StartedChild()
    started.process = _StillRunning()
    started.stop_refused = True
    watch = StartWatch()
    watch.started = started

    response = watch.failure_after_the_start(RuntimeError("reading output failed"))

    assert response is not None
    assert response.get("could_not_stop") is True, response
    assert response.get("could_not_stop_pid") == 4242, response


class _FlagReadRaises:
    """A timed-out uv result whose code, error AND could-not-stop reads raise.

    The stop's outcome is then unknown. Unknown must not read as "the stop
    worked": the fallback leaves the exit code as None rather than answering
    the timeout's own 124, which would report a tool that may still be running
    as one ASH stopped.
    """

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = "tool-err\n"
    timed_out = True

    def __getattr__(self, name: str):
        if name in ("returncode", "error", "could_not_stop", "could_not_stop_pid"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


def _uv_scanner_whose_runner_returns(tmp_path, monkeypatch, result) -> _Scanner:
    """A uv scanner whose uv runner returns ``result`` for its one run."""
    scanner = _Scanner(config=_Config(), context=_context(tmp_path))
    scanner.command = "tool"
    scanner.use_uv_tool = True
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.return_value = result
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: runner,
    )
    return scanner


def test_a_timed_out_result_whose_flag_read_raises_gets_no_124(tmp_path, monkeypatch):
    scanner = _uv_scanner_whose_runner_returns(tmp_path, monkeypatch, _FlagReadRaises())

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("timed_out") is True, response
    assert response.get("returncode") is None, response


class _ReturnedCouldNotStopNoText:
    """A returned failed wait ASH could not stop, with its pid and no error text.

    Every field reads cleanly, so this takes the mixin's straight response path.
    """

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = ""
    returncode = None
    post_run_error = True
    could_not_stop = True
    could_not_stop_pid = 4242
    error = None


class _SalvagedCouldNotStopUnreadableText:
    """A could-not-stop timeout with its pid, whose stdout and error reads raise.

    The stdout read sends the mixin into its salvage path, and the error read
    leaves the response with no reason text of its own.
    """

    args = ["uv", "tool", "run"]
    returncode = None
    stderr = ""
    timed_out = True
    could_not_stop = True
    could_not_stop_pid = 4343

    def __getattr__(self, name: str):
        if name in ("stdout", "error"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


class _FlagReadRaisesCodeReadsNone:
    """Only the flag (and stdout) reads raise; the code reads as None.

    The stop's outcome is unknown, so the fallback must not answer 124, and the
    shape (the timeout kept, no code) still records a could-not-stop reason.
    """

    args = ["uv", "tool", "run"]
    returncode = None
    stderr = ""
    timed_out = True

    def __getattr__(self, name: str):
        if name in ("stdout", "could_not_stop"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


class _StoppedTimeoutStdoutRaises:
    """The control: the flag reads False, only the stdout and code reads raise.

    A stop known to have worked keeps the timeout's own code, and no
    could-not-stop reason is recorded for it.
    """

    args = ["uv", "tool", "run"]
    stderr = ""
    timed_out = True
    could_not_stop = False

    def __getattr__(self, name: str):
        if name in ("stdout", "returncode"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


def test_the_returned_uv_path_carries_the_pid_to_the_reason(tmp_path, monkeypatch):
    scanner = _uv_scanner_whose_runner_returns(
        tmp_path, monkeypatch, _ReturnedCouldNotStopNoText()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("could_not_stop_pid") == 4242, response
    assert "pid 4242" in (scanner.scan_could_not_stop or ""), (
        scanner.scan_could_not_stop
    )


def test_the_salvage_path_seeds_the_reason_with_the_pid(tmp_path, monkeypatch):
    """A salvaged could-not-stop response whose own reason text could not be
    read leads with the could-not-stop sentence and the pid, before the
    handling error: the fact the operator acts on is never lost to text that
    happened to be unreadable."""
    scanner = _uv_scanner_whose_runner_returns(
        tmp_path, monkeypatch, _SalvagedCouldNotStopUnreadableText()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("returncode") is None, response
    assert response.get("could_not_stop_pid") == 4343, response
    reason = scanner.scan_could_not_stop or ""
    assert "pid 4343" in reason, reason
    assert reason.index("pid 4343") < reason.index("stdout"), reason


def test_an_unreadable_flag_with_a_readable_none_code_gets_no_124_and_a_reason(
    tmp_path, monkeypatch
):
    scanner = _uv_scanner_whose_runner_returns(
        tmp_path, monkeypatch, _FlagReadRaisesCodeReadsNone()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("returncode") is None, response
    assert scanner.scan_could_not_stop, scanner.scan_could_not_stop


def test_a_readable_false_flag_with_an_unreadable_code_still_gets_124(
    tmp_path, monkeypatch
):
    scanner = _uv_scanner_whose_runner_returns(
        tmp_path, monkeypatch, _StoppedTimeoutStdoutRaises()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("returncode") == TIMEOUT_RETURNCODE, response
    assert scanner.scan_could_not_stop is None, scanner.scan_could_not_stop
