# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool the OS could not start must fail its scan, whatever exit codes it accepts.

Why this file exists
--------------------
On an arm64 CI runner, exec of ``/usr/local/bin/uv`` raised ``OSError: [Errno 14]
Bad address`` before semgrep ever ran. ``run_command_with_output_handling`` caught
it in its generic branch and returned returncode 1. semgrep accepts 1 (it means
"found issues"), so the scan carried on, and the only error reported was the SARIF
file the tool never wrote, labelled "exit code 1: an accepted exit code for this
scanner".

A spawn failure now returns 127 (what shells use for "command not runnable") with
``spawn_failed`` set and a stderr naming the cause. No scanner accepts 127, the
template ``scan()`` names the cause, and ``ScannerExecutor`` reports ERROR even for
a scanner whose own ``scan()`` returned normally. A failed spawn is not retried:
it is reported on the first attempt, whatever the errno. These tests raise the
OSError at the plain runner (``_run_plain``), before it started any child, or at
``subprocess.Popen``, underneath every layer that has to carry it.
"""

import errno
import logging
import subprocess
import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    SpawnFailedProcess,
    run_command,
    run_command_stream_output,
    run_command_with_output_handling,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_PLAIN_RUNNER = "automated_security_helper.utils.subprocess_utils._run_plain"
_SUBPROCESS_POPEN = "automated_security_helper.utils.subprocess_utils.subprocess.Popen"
_EFAULT = OSError(errno.EFAULT, "Bad address", "/usr/local/bin/uv")


class TestSpawnFailureReturnCode:
    @pytest.mark.unit
    def test_is_127_with_the_cause_in_stderr(self, tmp_path):
        with patch(_PLAIN_RUNNER, side_effect=_EFAULT):
            response = run_command_with_output_handling(
                ["uv", "tool", "run", "semgrep"],
                results_dir=tmp_path,
                class_name="SemgrepScanner",
            )

        assert response["returncode"] == SPAWN_FAILURE_RETURNCODE == 127
        assert response["spawn_failed"] is True
        assert "Could not start" in response["stderr"]
        assert "Bad address" in response["stderr"]
        # Scanners default to stderr_preference="write" and read this file to
        # explain the failure, so the cause has to be in it.
        log = tmp_path / "SemgrepScanner.stderr.log"
        assert "Bad address" in log.read_text()

    @pytest.mark.unit
    def test_a_real_missing_executable(self, tmp_path):
        """No mock: the OS itself refuses to start a path that does not exist."""
        missing = str(tmp_path / "no-such-tool")
        response = run_command_with_output_handling(
            [missing], results_dir=tmp_path, timeout=CHILD_TIMEOUT_SECONDS
        )

        assert response["returncode"] == 127
        assert response["spawn_failed"] is True

    @pytest.mark.unit
    def test_run_command(self):
        with patch(_PLAIN_RUNNER, side_effect=_EFAULT):
            result = run_command(["uv", "--version"])

        assert isinstance(result, SpawnFailedProcess)
        assert result.returncode == 127
        assert "Bad address" in result.stderr

    @pytest.mark.unit
    def test_run_command_with_check_still_raises(self):
        with (
            patch(_PLAIN_RUNNER, side_effect=_EFAULT),
            pytest.raises(OSError) as excinfo,
        ):
            run_command(["uv", "--version"], check=True)
        assert excinfo.value.errno == errno.EFAULT

    @pytest.mark.unit
    def test_run_command_stream_output(self):
        with patch(_SUBPROCESS_POPEN, side_effect=_EFAULT):
            assert run_command_stream_output(["uv", "--version"]) == 127

    @pytest.mark.integration
    def test_a_command_that_ran_and_exited_127_is_not_a_spawn_failure(self):
        result = run_command(
            [sys.executable, "-c", "raise SystemExit(127)"],
            timeout=CHILD_TIMEOUT_SECONDS,
        )

        assert result.returncode == 127
        assert not isinstance(result, SpawnFailedProcess)

    @pytest.mark.integration
    def test_an_oserror_writing_logs_is_not_a_spawn_failure(self, tmp_path):
        """Only the spawn is guarded: the tool ran, so this is no spawn failure.

        The tool's own exit code is kept, here 0, and post_run_error says ASH
        could not record its output, which makes the scan ERROR.
        """
        with patch.object(
            subprocess_utils, "_write_stream_log", side_effect=OSError("disk full")
        ):
            response = run_command_with_output_handling(
                [sys.executable, "-c", "print('ran')"],
                results_dir=tmp_path,
                timeout=CHILD_TIMEOUT_SECONDS,
            )

        assert response["returncode"] == 0
        assert response["post_run_error"] is True
        assert response["spawn_failed"] is False
        assert "disk full" in response["error"]


class TestASpawnFailureIsNotRetried:
    @pytest.mark.parametrize(
        "exc",
        [
            OSError(errno.EFAULT, "Bad address", "uv"),
            OSError(errno.ETXTBSY, "Text file busy", "uv"),
            FileNotFoundError(errno.ENOENT, "No such file", "uv"),
        ],
        ids=["EFAULT", "ETXTBSY", "ENOENT"],
    )
    @pytest.mark.unit
    def test_run_command_with_output_handling(self, exc):
        with patch(_PLAIN_RUNNER, side_effect=exc) as run:
            response = run_command_with_output_handling(["uv"])

        assert run.call_count == 1
        assert response["returncode"] == 127
        assert response["spawn_failed"] is True

    @pytest.mark.unit
    def test_run_command(self):
        with patch(_PLAIN_RUNNER, side_effect=_EFAULT) as run:
            result = run_command(["uv", "--version"])

        assert run.call_count == 1
        assert result.returncode == 127

    @pytest.mark.unit
    def test_run_command_stream_output(self):
        with patch(_SUBPROCESS_POPEN, side_effect=_EFAULT) as popen:
            assert run_command_stream_output(["uv", "--version"]) == 127

        assert popen.call_count == 1


@pytest.mark.unit
def test_uv_tool_runner_carries_the_flag(tmp_path):
    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch(_PLAIN_RUNNER, side_effect=_EFAULT),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert isinstance(result, SpawnFailedProcess)
    assert result.returncode == 127


@pytest.fixture
def semgrep(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    scanner = SemgrepScanner(context=context, config=SemgrepScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner, source


@pytest.mark.unit
def test_semgrep_through_uv_is_not_accepted(semgrep):
    """The reported case: accepted codes include 1, and a uv that cannot exec
    must still fail the scan, naming the cause rather than the missing SARIF."""
    scanner, source = semgrep
    assert 1 in scanner.success_exit_codes
    assert scanner.use_uv_tool, "the test must exercise the uv path"

    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(SemgrepScanner, "validate_plugin_dependencies", return_value=True),
        patch(_PLAIN_RUNNER, side_effect=_EFAULT) as run,
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=source, target_type="source")

    assert run.call_count == 1, "a spawn failure is reported, not retried"
    assert run.call_args.args[0][1:3] == ["tool", "run"]
    assert scanner.exit_code == 127
    assert not scanner._exit_code_accepted()
    assert scanner.scan_spawn_failure and "Bad address" in scanner.scan_spawn_failure
    message = str(excinfo.value)
    assert "could not start its tool" in message, message
    assert "Bad address" in message, message
    assert "exit code 127: not an accepted exit code" in message, message


@pytest.mark.unit
def test_127_is_never_accepted_even_when_listed(semgrep):
    scanner, _source = semgrep
    scanner.exit_code = 127
    with patch.object(SemgrepScanner, "success_exit_codes", {0, 1, 127}):
        assert not scanner._exit_code_accepted()
        message = scanner._describe_scan_failure(FileNotFoundError("x"), None)
    assert "not an accepted exit code" in message, message


class _Config(ScannerPluginConfigBase):
    name: str = "lenient"


class _LenientScanner(ScannerPluginBase):
    """Overrides scan() and treats empty output as "no findings", as several do."""

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
            timeout=CHILD_TIMEOUT_SECONDS,
        )
        return {"severity_counts": {}}


def _context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _run(context, scanner):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    return executor._execute_scanner(
        "lenient", scanner, [{"path": context.source_dir, "type": "source"}]
    )


class TestExecutorReportsError:
    @pytest.mark.unit
    def test_even_when_scan_returned_normally(self, tmp_path):
        context = _context(tmp_path)
        scanner = _LenientScanner(config=_Config(), context=context)
        scanner.tool = str(tmp_path / "no-such-tool")

        (container,) = _run(context, scanner)

        assert container.status == ScannerStatus.ERROR
        assert container.exit_code == 127
        first = container.raw_results["errors"][0]
        assert "lenient could not start its tool on source" in first, first

    @pytest.mark.integration
    def test_a_spawn_failure_is_not_charged_to_the_next_target(self, tmp_path):
        context = _context(tmp_path)
        scanner = _LenientScanner(config=_Config(), context=context)
        scanner.tool = str(tmp_path / "no-such-tool")
        _run(context, scanner)
        assert scanner.scan_spawn_failure

        scanner.tool = sys.executable
        scanner.exit_code = 0
        (container,) = _run(context, scanner)

        assert scanner.scan_spawn_failure is None
        assert container.status != ScannerStatus.ERROR


# -- handling that raises keeps the response's flag -------------------------------
#
# When the handler's own handling of a response raises, the response keeps every
# flag it carried, with that flag's code and reason, and the handling error is
# added to the reason, verbatim. post_run_error is added only to a response that
# carried none of the flags, with its real code. And a handling failure never
# runs the tool again: one launch, counted at the stand-ins, whichever path ran it.

#: What ASH's own handling of the response raises; markup in it stays as it is.
_HANDLER_BROKE = "the handler broke [/x]"

#: The flags, one of which every response with an error carries. ``signaled`` is
#: a tool that ended on a signal ASH did not send.
_ERROR_FLAGS = (
    "spawn_failed",
    "timed_out",
    "cancelled",
    "result_rejected",
    "post_run_error",
    "signaled",
)

#: Each case's code and reason; "none" carries no flag and no reason.
_FLAGGED = {
    "spawn_failed": (SPAWN_FAILURE_RETURNCODE, "Could not start tool: Bad address"),
    "timed_out": (124, "Command timed out after 5s: tool"),
    "cancelled": (130, "the scan was cancelled while tool was running"),
    "result_rejected": (125, "the remote result was rejected: a path escapes"),
    "post_run_error": (3, "ASH could not record the output of tool: disk full"),
    "signaled": (-9, "tool ended on SIGKILL (signal 9), a signal ASH did not send"),
    "none": (3, None),
}
FLAGS = sorted(_FLAGGED)


def _response(flag: str) -> dict:
    """The response run_command_with_output_handling answers for ``flag``."""
    code, reason = _FLAGGED[flag]
    response = {"returncode": code, "stdout": "", "stderr": ""}
    if flag != "none":
        response[flag] = True
        response["error"] = reason
    if flag == "post_run_error":
        response["spawn_failed"] = False
    return response


class _Flagged(subprocess.CompletedProcess):
    """What the uv runner returns for ``flag``: the flag and its error as
    attributes, as TimedOutProcess and the other flagged results carry them."""

    def __init__(self, flag: str) -> None:
        code, reason = _FLAGGED[flag]
        super().__init__(["uv", "tool", "run", "tool"], code, "", "")
        if flag != "none":
            setattr(self, flag, True)
            self.error = reason


class _Launches:
    """The stand-ins for both launch paths, counting each launch."""

    def __init__(self, flag: str) -> None:
        self.flag = flag
        self.uv = 0
        self.direct = 0

    def run_tool(self, *args, **kwargs):
        self.uv += 1
        return _Flagged(self.flag)

    def run_command_with_output_handling(self, *args, **kwargs):
        self.direct += 1
        return _response(self.flag)

    @property
    def total(self) -> int:
        return self.uv + self.direct


class _Handled(_LenientScanner):
    """A scanner whose handling the cells make raise, once."""


def _raises_once(original, when=lambda *args, **kwargs: True):
    fired: list = []

    def raising(self, *args, **kwargs):
        if not fired and when(*args, **kwargs):
            fired.append(True)
            raise RuntimeError(_HANDLER_BROKE)
        return original(self, *args, **kwargs)

    return raising


def _scanner_on(tmp_path, monkeypatch, path: str, launches: _Launches) -> _Handled:
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        launches.run_command_with_output_handling,
    )
    if path == "uv":
        scanner.command = "tool"
        scanner.use_uv_tool = True
        runner = MagicMock()
        runner.uv_availability.return_value = (True, None)
        runner.is_uv_available.return_value = True
        runner.run_tool.side_effect = launches.run_tool
        monkeypatch.setattr(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            lambda: runner,
        )
    return scanner


def _assert_the_flag_is_kept(response: dict, flag: str) -> None:
    code, reason = _FLAGGED[flag]
    kept = "post_run_error" if flag == "none" else flag
    assert response.get(kept) is True, response
    for other in _ERROR_FLAGS:
        if other != kept:
            assert response.get(other) is not True, (other, response)
    assert response["returncode"] == code, response
    if reason is not None:
        assert response["error"].startswith(reason), response
    # Added to the reason as it was raised: the field holds text, not markup.
    assert _HANDLER_BROKE in response["error"], response
    assert "\\[" not in response["error"], response
    # An error always comes with one of the flags.
    assert any(response.get(f) is True for f in _ERROR_FLAGS), response
    # No tool ran a second time, so nothing says uv could not run it.
    assert "could not run through uv" not in (
        f"{response.get('error')} {response.get('stderr')}"
    ), response


@pytest.mark.parametrize("path", ["direct", "uv"])
@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.unit
def test_handling_that_raises_keeps_the_responses_flag(
    tmp_path, monkeypatch, flag, path
):
    launches = _Launches(flag)
    scanner = _scanner_on(tmp_path, monkeypatch, path, launches)
    monkeypatch.setattr(
        _Handled,
        "_process_command_response",
        _raises_once(_Handled._process_command_response),
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert launches.total == 1, (launches.uv, launches.direct)
    assert (launches.uv, launches.direct) == ((1, 0) if path == "uv" else (0, 1))
    _assert_the_flag_is_kept(response, flag)


#: The calls after the uv launch that the cells make raise, once: the three in
#: _try_uv_tool_execution's try, and the recorders _run_subprocess calls on the
#: uv result. (There is no _record_result_rejected or _record_cancelled here.)
#: The offline-resolve explainer is not among them: the mixin guards it on its
#: own (uv_tool_mixin.py, around the explainer call), so a raise inside it does
#: not grade the run, and the test after this table pins that.
AFTER_THE_UV_LAUNCH = {
    "process_command_response": ("_process_command_response", None),
    "completion_plugin_log": (
        "_plugin_log",
        lambda message, *args, **kwargs: str(message).startswith(
            "UV tool execution completed"
        ),
    ),
    "record_timeout": ("_record_timeout", None),
    "record_spawn_failure": ("_record_spawn_failure", None),
    "record_post_run_error": ("_record_post_run_error", None),
}


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("call", sorted(AFTER_THE_UV_LAUNCH))
@pytest.mark.unit
def test_handling_that_raises_after_a_uv_launch_runs_nothing_again(
    tmp_path, monkeypatch, call, flag
):
    """A raise after the uv launch returned fell back to direct execution, which
    ran the tool a second time."""
    launches = _Launches(flag)
    scanner = _scanner_on(tmp_path, monkeypatch, "uv", launches)
    name, when = AFTER_THE_UV_LAUNCH[call]
    original = getattr(_Handled, name)
    raising = _raises_once(original, when) if when else _raises_once(original)
    monkeypatch.setattr(_Handled, name, raising)

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert (launches.uv, launches.direct) == (1, 0), (launches.uv, launches.direct)
    _assert_the_flag_is_kept(response, flag)
    # The scan knows ASH failed, and only a start failure says one happened.
    if flag in ("none", "post_run_error"):
        assert scanner.scan_post_run_error, "the scan does not know ASH failed"
    assert scanner.scan_spawn_failure is None or flag == "spawn_failed", (
        scanner.scan_spawn_failure
    )


@pytest.mark.unit
def test_a_raising_offline_explainer_leaves_the_response_alone(tmp_path, monkeypatch):
    """The offline-resolve explainer is best-effort text about a run that was
    already processed. A raise inside it used to fall into the mixin's handler and
    grade the run post_run_error; the mixin now guards it on its own, logs the
    failure at DEBUG, and leaves the run's real result as it was."""
    launches = _Launches("none")
    scanner = _scanner_on(tmp_path, monkeypatch, "uv", launches)
    monkeypatch.setattr(
        _Handled,
        "_explain_offline_resolve_failure",
        _raises_once(_Handled._explain_offline_resolve_failure),
    )
    logged: list = []
    original_log = _Handled._plugin_log

    def recording_log(self, message, *args, **kwargs):
        logged.append((str(message), kwargs.get("level")))
        return original_log(self, message, *args, **kwargs)

    monkeypatch.setattr(_Handled, "_plugin_log", recording_log)

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert (launches.uv, launches.direct) == (1, 0), (launches.uv, launches.direct)
    assert not any(response.get(flag) is True for flag in _ERROR_FLAGS), response
    assert response["returncode"] == _FLAGGED["none"][0], response
    assert not scanner.scan_post_run_error, "the explainer's raise graded the run"
    guard_lines = [
        (message, level)
        for message, level in logged
        if message.startswith("The offline-resolve explainer could not run")
    ]
    assert len(guard_lines) == 1, logged
    message, level = guard_lines[0]
    assert level == logging.DEBUG, guard_lines
    assert "the handler broke" in message, message


def _uv_scanner_whose_run_returns(tmp_path, monkeypatch, result) -> _Handled:
    """A uv scanner whose uv runner returns ``result`` for its run."""
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
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


@pytest.mark.unit
def test_a_uv_response_whose_handling_raised_keeps_its_stderr(tmp_path, monkeypatch):
    """Handling the uv run's response raised. The response kept is the one already
    assembled, the tool's stderr included."""
    result = subprocess.CompletedProcess(["uv", "tool", "run"], 3, "", "tool-err\n")
    scanner = _uv_scanner_whose_run_returns(tmp_path, monkeypatch, result)
    monkeypatch.setattr(
        _Handled,
        "_process_command_response",
        _raises_once(_Handled._process_command_response),
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("post_run_error") is True, response
    assert "tool-err" in (response.get("stderr") or ""), response


class _StdoutRaises:
    """A run's result whose stdout can't be read, so building the response raises.
    Its code and stderr read as a CompletedProcess's do."""

    args = ["uv", "tool", "run"]
    returncode = 3
    stderr = "tool-err\n"

    def __getattr__(self, name: str):
        if name == "stdout":
            raise RuntimeError("reading the run's stdout failed")
        raise AttributeError(name)


@pytest.mark.unit
def test_a_uv_response_that_could_not_be_built_keeps_the_runs_stderr(
    tmp_path, monkeypatch
):
    """Building the uv run's response raised, at its stdout. The failure's response
    still carries the stderr the result holds, not an empty one."""
    scanner = _uv_scanner_whose_run_returns(tmp_path, monkeypatch, _StdoutRaises())

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == 3, response
    assert "tool-err" in (response.get("stderr") or ""), response


class _TimedOutStdoutRaises:
    """A timed-out run's result whose stdout can't be read, so building the
    response raises. Its flag, code, error and stderr read as a TimedOutProcess's
    do."""

    args = ["uv", "tool", "run"]
    returncode = 124
    stderr = "tool-err\n"
    timed_out = True
    error = "Command timed out after 5s: uv tool run tool"

    def __getattr__(self, name: str):
        if name == "stdout":
            raise RuntimeError("reading the run's stdout failed")
        raise AttributeError(name)


@pytest.mark.unit
def test_a_timed_out_response_that_could_not_be_built_keeps_its_timeout(
    tmp_path, monkeypatch
):
    """The uv run timed out, and building its response raised at the stdout. A
    timed-out result is never turned into post_run_error: the flag, its code and
    its reason are kept, with the build failure appended, and the stderr the
    result holds comes along."""
    scanner = _uv_scanner_whose_run_returns(
        tmp_path, monkeypatch, _TimedOutStdoutRaises()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    error = response.get("error") or ""
    assert response.get("timed_out") is True, response
    assert response.get("post_run_error") is not True, response
    assert response.get("returncode") == 124, response
    assert "Command timed out after 5s" in error, response
    assert "reading the run's stdout failed" in error, response
    assert "tool-err" in (response.get("stderr") or ""), response


class _TimedOutReturncodeRaises:
    """A timed-out run's result whose returncode read raises, with something that
    is not an AttributeError. Everything else reads as a TimedOutProcess's does."""

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = "tool-err\n"
    timed_out = True
    error = "Command timed out after 5s: uv tool run tool"

    def __getattr__(self, name: str):
        if name == "returncode":
            raise RuntimeError("reading the run's exit code failed")
        raise AttributeError(name)


@pytest.mark.unit
def test_a_timed_out_response_whose_code_is_unreadable_is_no_spawn_failure(
    tmp_path, monkeypatch
):
    """The same build failure at the returncode. The run happened, so the response
    is never a tool that could not start: the timeout is kept with its own code
    124, and the scan records no start failure. ASH did stop this tool, so no
    code is never the answer: that is only for a run that failed after the start
    or a child ASH could not stop."""
    scanner = _uv_scanner_whose_run_returns(
        tmp_path, monkeypatch, _TimedOutReturncodeRaises()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("spawn_failed") is not True, response
    assert response.get("returncode") != SPAWN_FAILURE_RETURNCODE, response
    assert response.get("timed_out") is True, response
    assert response.get("returncode") == subprocess_utils.TIMEOUT_RETURNCODE, response
    assert "tool-err" in (response.get("stderr") or ""), response
    assert scanner.scan_spawn_failure is None, scanner.scan_spawn_failure


#: The marker for a child ASH could not stop, the constant itself: a fallback
#: literal would keep these cells green while quoting text production no longer
#: writes.
_COULD_NOT_STOP_MARKER = subprocess_utils.COULD_NOT_STOP_MARKER

#: A could-not-stop timeout's error, as run_command_with_output_handling writes it.
_COULD_NOT_STOP_ERROR = (
    "Command timed out after 5s: uv tool run tool; "
    f"{_COULD_NOT_STOP_MARKER} 4242), which may still be running"
)


class _CouldNotStopCodeAndErrorRaise:
    """A timed-out run ASH could not stop, whose code read AND error read both
    raise. The marker lived only in the error, so a guard that reads the text
    cannot see it; the result's recorded could-not-stop state still says the
    stop failed, and that state is what answers."""

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = "tool-err\n"
    timed_out = True
    could_not_stop = True

    def __getattr__(self, name: str):
        if name in ("returncode", "error"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


class _StoppedTimeoutWhoseStderrQuotesTheMarker:
    """A timeout ASH did stop (nothing in its error says otherwise), whose code
    read raises, and whose tool wrote the marker's words to stderr itself."""

    args = ["uv", "tool", "run"]
    stdout = ""
    stderr = f"tool says: {_COULD_NOT_STOP_MARKER} 1)\n"
    timed_out = True
    error = ""

    def __getattr__(self, name: str):
        if name == "returncode":
            raise RuntimeError("reading the run's exit code failed")
        raise AttributeError(name)


@pytest.mark.unit
def test_a_could_not_stop_timeout_whose_error_is_unreadable_gets_no_124(
    tmp_path, monkeypatch
):
    """The 124 fallback decides by the recorded state, never the error's
    text. A could-not-stop timeout keeps no code even when its error cannot be
    read, because the state says the kill failed; a text guard that cannot see
    the marker answers 124 and reports a tool that may still run as stopped."""
    scanner = _uv_scanner_whose_run_returns(
        tmp_path, monkeypatch, _CouldNotStopCodeAndErrorRaise()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("timed_out") is True, response
    # "Keeps no code" in full: not just "not 124" -- a regression answering 127
    # with spawn_failed, or 0, must fail here too.
    assert response.get("returncode") is None, response
    assert response.get("spawn_failed") is not True, response
    assert scanner.scan_spawn_failure is None, scanner.scan_spawn_failure


@pytest.mark.unit
def test_tool_text_quoting_the_marker_does_not_drop_the_124(tmp_path, monkeypatch):
    """The converse. A stopped timeout keeps its own 124 even when the tool
    itself printed the marker's words to stderr: tool text is data, and only
    ASH's recorded state says whether the stop worked."""
    scanner = _uv_scanner_whose_run_returns(
        tmp_path, monkeypatch, _StoppedTimeoutWhoseStderrQuotesTheMarker()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("timed_out") is True, response
    assert response.get("returncode") == subprocess_utils.TIMEOUT_RETURNCODE, response


class _Unprintable:
    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        raise RuntimeError("str() of the error failed")


@pytest.mark.unit
def test_a_post_run_error_whose_reason_cannot_be_read_stays_inside(
    tmp_path, monkeypatch
):
    """A pin of _response_text's tolerance: an error value whose str()
    raises leaves the scan graded post_run_error with the default reason, and
    nothing escapes _run_subprocess."""
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = "tool"
    scanner.use_uv_tool = False
    response = {
        "stdout": "",
        "stderr": "",
        "returncode": 0,
        "post_run_error": True,
        "spawn_failed": False,
        "error": _Unprintable(),
    }
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: dict(response),
    )

    out = scanner._run_subprocess(command=["tool", "scan"])

    assert out.get("post_run_error") is True, out
    assert scanner.scan_post_run_error == "the run's output could not be recorded", (
        scanner.scan_post_run_error
    )


@pytest.mark.parametrize("flag", [f for f in FLAGS if f != "none"])
@pytest.mark.unit
def test_run_tool_keeps_a_flagged_responses_flag_and_stderr(
    tmp_path, monkeypatch, flag
):
    """The uv runner converts run_command_with_output_handling's response into a
    result. Each flag survives that, result_rejected included, with the response's
    error and its stderr."""
    code, reason = _FLAGGED[flag]
    flagged = {
        "returncode": code,
        flag: True,
        "error": reason,
        "stdout": "",
        "stderr": f"tool-err for {flag}",
    }
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda *args, **kwargs: dict(flagged),
    )
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.chdir(tmp_path)

    result = UVToolRunner(uv_executable=sys.executable).run_tool(
        "semgrep", args=["scan"], results_dir=tmp_path / "results"
    )

    assert getattr(result, flag, False) is True, (flag, result)
    assert result.returncode == code, result
    assert result.stderr == f"tool-err for {flag}", result
    assert (getattr(result, "error", "") or "") == reason, result


#: The tool the real-child cells run directly: this Python, which exits 0.
_REAL_TOOL = [sys.executable, "-c", "pass"]


def _uv_scanner_with_a_real_child(tmp_path, monkeypatch):
    """A scanner whose uv runner is this Python: its ``uv tool run`` is then a
    real child that exits 2 on the missing script 'tool', and the direct run is
    _REAL_TOOL. Each launch, through the uv runner or directly, goes through
    run_command_with_output_handling, which the caller wraps to count it."""
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = _REAL_TOOL[0]
    scanner.use_uv_tool = True
    runner = UVToolRunner(uv_executable=sys.executable)
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: runner,
    )
    monkeypatch.chdir(tmp_path)
    return scanner


@pytest.mark.integration
def test_a_uv_runner_that_raises_after_its_child_started_runs_nothing_again(
    tmp_path, monkeypatch
):
    """The uv runner started its child, which ran, and then raised: result is None.
    Whether the launch started is the seam's start record, so the direct fallback
    must not run the tool a second time."""
    real = subprocess_utils.run_command_with_output_handling
    started: list = []

    def started_then_raised(*args, **kwargs):
        response = real(*args, **kwargs)
        started.append(response)
        if len(started) == 1:
            raise RuntimeError("the uv runner broke after its child started")
        return response

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", started_then_raised
    )
    scanner = _uv_scanner_with_a_real_child(tmp_path, monkeypatch)

    response = scanner._run_subprocess(
        command=list(_REAL_TOOL), results_dir=tmp_path / "results"
    )

    assert len(started) == 1, f"the tool started {len(started)} times"
    assert response.get("post_run_error") is True, response
    assert response.get("spawn_failed") is not True, response
    assert response.get("returncode") != SPAWN_FAILURE_RETURNCODE, response
    assert "the uv runner broke after its child started" in response["error"], response


#: Writes a diagnostic to stderr at once, then runs until something stops it.
_DIAGNOSE_PROGRAM = (
    "import sys, time; sys.stderr.write('diag before the failure\\n'); "
    "sys.stderr.flush(); time.sleep(30)"
)
_DIAGNOSES_THEN_SLEEPS = [sys.executable, "-c", _DIAGNOSE_PROGRAM]


def _waiting_fails_once_the_stderr_was_read():
    """Each child's first communicate() reads until its stderr holds the diagnostic,
    then raises: a failure while waiting, after some output was read. Later calls
    on that child are the real ones, so what was read can still be collected."""
    import time

    real = subprocess.Popen.communicate
    failed: list = []

    def communicate(self, *args, **kwargs):
        if any(process is self for process in failed):
            return real(self, *args, **kwargs)
        failed.append(self)
        to_send = args[0] if args else kwargs.get("input")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                real(self, to_send, timeout=0.2)
            except subprocess.TimeoutExpired as partial:
                to_send = None
                if b"diag before the failure" in (partial.stderr or b""):
                    break
            else:
                break
        raise RuntimeError("reading the output failed")

    return patch.object(subprocess.Popen, "communicate", communicate)


@pytest.mark.integration
def test_a_uv_launch_that_raised_during_a_failed_wait_keeps_the_stderr_read(
    tmp_path, monkeypatch
):
    """The uv runner's spawn raised while ASH waited on its child, after the child
    wrote a diagnostic. The response for that failure after the start carries the
    stderr read before it, whatever stderr_preference asked for, as a failure while
    waiting in run_command_with_output_handling does."""

    def run_tool(*args, **kwargs):
        # Under watched_launch, as the real runner's run_tool holds it around
        # the launch's own spawn.
        with subprocess_utils.watched_launch():
            return subprocess_utils.spawn_run(
                list(_DIAGNOSES_THEN_SLEEPS), capture_output=True, text=True
            )

    launches = _Launches("none")
    scanner = _scanner_on(tmp_path, monkeypatch, "uv", launches)
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: MagicMock(
            is_uv_available=MagicMock(return_value=True),
            uv_availability=MagicMock(return_value=(True, None)),
            run_tool=MagicMock(side_effect=run_tool),
        ),
    )

    with _waiting_fails_once_the_stderr_was_read():
        response = scanner._run_subprocess(
            command=["tool", "scan"], results_dir=tmp_path / "results"
        )

    assert launches.direct == 0, "a direct run ran in the uv run's place"
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") is None, response
    assert "diag before the failure" in (response.get("stderr") or ""), response


def _fake_uv_that_writes_both_streams(tmp_path) -> str:
    """A stand-in uv whose ``tool run`` writes a line to each stream and exits 0."""
    uv = tmp_path / "fake-uv-both"
    uv.write_text(
        '#!/bin/sh\ncase " $* " in *" run "*) echo uv-out; echo uv-err >&2;; esac\n'
        "exit 0\n",
        encoding="utf-8",
    )
    uv.chmod(0o755)
    return str(uv)


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in uv is a shell script")
@pytest.mark.integration
def test_a_uv_runner_that_raised_after_its_run_returned_keeps_that_runs_output(
    tmp_path, monkeypatch
):
    """run_command_with_output_handling returned the uv run's response, and the uv
    runner's own conversion of it then raised. The tool ran to its end, so the
    failure after the start carries that run's code, stdout and stderr."""
    real = subprocess_utils.run_command_with_output_handling
    returned: list = []

    def returned_then_raised(*args, **kwargs):
        returned.append(real(*args, **kwargs))
        raise RuntimeError("converting the run's response failed")

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", returned_then_raised
    )
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = _REAL_TOOL[0]
    scanner.use_uv_tool = True
    runner = UVToolRunner(uv_executable=_fake_uv_that_writes_both_streams(tmp_path))
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: runner,
    )
    monkeypatch.chdir(tmp_path)

    response = scanner._run_subprocess(
        command=list(_REAL_TOOL),
        results_dir=tmp_path / "results",
        stdout_preference="return",
        stderr_preference="return",
    )

    assert len(returned) == 1, f"the tool ran {len(returned)} times"
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == 0, response
    assert "uv-out" in (response.get("stdout") or ""), response
    assert "uv-err" in (response.get("stderr") or ""), response


@pytest.mark.parametrize(
    "never_started, reason",
    [
        pytest.param(
            "runner-error",
            "UV tool run failed for tool: uv never started",
            id="uv-runner-error-before-the-start",
        ),
        pytest.param(
            "raise-before-popen", "raised before Popen", id="a-raise-before-popen"
        ),
    ],
)
@pytest.mark.unit
def test_a_uv_launch_that_never_started_runs_nothing_in_its_place(
    tmp_path, monkeypatch, never_started, reason
):
    """The uv launch raised before anything started. A scanner's tool runs
    directly only by the path its dependency check verified, so nothing runs in
    the uv run's place: the result is spawn_failed and 127, with uv's reason, from
    one launch attempt and no direct launch."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

    real = subprocess_utils.run_command_with_output_handling
    attempts: list = []
    started: list = []

    def first_raises_before_any_start(*args, **kwargs):
        attempts.append(kwargs.get("command", args[0] if args else None))
        if len(attempts) == 1:
            if never_started == "runner-error":
                raise UVToolRunnerError(reason)
            raise RuntimeError(reason)
        response = real(*args, **kwargs)
        started.append(response)
        return response

    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        first_raises_before_any_start,
    )
    scanner = _uv_scanner_with_a_real_child(tmp_path, monkeypatch)

    response = scanner._run_subprocess(
        command=list(_REAL_TOOL), results_dir=tmp_path / "results"
    )

    assert attempts, "the uv runner never tried, so the cell shows nothing"
    assert list(attempts[0])[1:3] == ["tool", "run"], attempts
    assert len(attempts) == 1, f"{len(attempts) - 1} launch(es) ran in its place"
    assert not started, f"the tool started {len(started)} times"
    assert response.get("spawn_failed") is True, response
    assert response.get("returncode") == SPAWN_FAILURE_RETURNCODE, response
    assert response.get("post_run_error") is not True, response
    assert reason in (response.get("error") or ""), response


@pytest.mark.integration
def test_a_uv_launch_that_never_started_is_not_read_from_a_probe_before_it(
    tmp_path, monkeypatch
):
    """Inside the uv launch, a probe ran and exited 0, and then the tool's own launch
    raised before it started anything. The launch's start was read from the first
    child any spawn in it started, the probe's, so a launch that never started read
    as one that ran and exited 0. The launch's own start is the one read:
    spawn_failed and 127, with the launch's reason, and nothing runs in its place."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

    real = subprocess_utils.run_command_with_output_handling
    probes: list = []

    def run_tool(*args, **kwargs):
        # A probe before the launch, as `uv --version` is when nothing is cached:
        # a real child that starts and exits 0.
        probes.append(
            real([sys.executable, "-c", "pass"], results_dir=tmp_path / "probe")
        )
        raise UVToolRunnerError("the tool's launch never started")

    launches = _Launches("none")
    scanner = _scanner_on(tmp_path, monkeypatch, "uv", launches)
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: MagicMock(
            is_uv_available=MagicMock(return_value=True),
            uv_availability=MagicMock(return_value=(True, None)),
            run_tool=MagicMock(side_effect=run_tool),
        ),
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert probes, "the probe never ran, so the cell shows nothing"
    assert probes[0].get("returncode") == 0, probes
    assert launches.direct == 0, "a direct run ran in the uv run's place"
    assert response.get("spawn_failed") is True, response
    assert response.get("returncode") == SPAWN_FAILURE_RETURNCODE, response
    assert response.get("post_run_error") is not True, response
    assert "the tool's launch never started" in (response.get("error") or ""), response


@pytest.mark.integration
def test_a_probes_start_before_the_launch_does_not_grade_the_launch(
    tmp_path, monkeypatch
):
    """The runner's own helpers start real children before the launch -- the
    availability probe here, through the real runner. A raise between such a
    helper and the launch (a requirement check that broke) is a launch that
    never started: spawn_failed and 127 with the raise's reason, never a
    failure after the start graded with the helper probe's exit 0. Only the
    launch's own spawn may answer for the launch."""
    from automated_security_helper.utils import uv_tool_runner as runner_module
    from automated_security_helper.utils.uv_tool_runner import (
        _reset_uv_tool_runner_caches,
    )

    _reset_uv_tool_runner_caches()
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = "tool"
    scanner.use_uv_tool = True
    monkeypatch.setattr(
        type(scanner), "_get_tool_version_constraint", lambda self: ">=0"
    )
    uv_runner = UVToolRunner(uv_executable=sys.executable)
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: uv_runner,
    )

    probed: list = []
    real_available = UVToolRunner.uv_availability

    def really_probed(self):
        # Each check probes afresh, as it does after a cache reset: the
        # launch's own re-check then starts a real child right before the
        # launch, the shape that mis-graded it.
        self._uv_available_cache = None
        answer = real_available(self)
        probed.append(answer[0])
        return answer

    monkeypatch.setattr(UVToolRunner, "uv_availability", really_probed)

    def requirement_check_breaks(spec, naming="a tool requirement", **kwargs):
        # The real checked_requirement's signature (spec, naming=..., *,
        # package=...): run_tool passes naming positionally and the package by
        # keyword, and a stub narrower than the real callable raises TypeError
        # instead of this test's own reason.
        raise RuntimeError("a pre-launch step broke")

    monkeypatch.setattr(runner_module, "checked_requirement", requirement_check_breaks)
    monkeypatch.chdir(tmp_path)

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert probed and all(probed), (
        f"the cell shows nothing: no real probe ran: {probed}"
    )
    assert response.get("spawn_failed") is True, response
    assert response.get("returncode") == SPAWN_FAILURE_RETURNCODE, response
    assert response.get("post_run_error") is not True, response
    assert "a pre-launch step broke" in (response.get("error") or ""), response


@pytest.mark.unit
def test_a_raising_values_hook_keeps_the_runners_verdict(tmp_path, monkeypatch):
    """The redaction values are the config's and the plugin's hook together,
    never the hook alone: a hook that raises adds nothing. Read directly in a
    log line of the runner-error arm, the hook's raise escaped that arm and the
    response carried the hook's own crash in place of the runner's verdict."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

    def run_tool(*args, **kwargs):
        raise UVToolRunnerError("the tool's launch never started")

    launches = _Launches("none")
    scanner = _scanner_on(tmp_path, monkeypatch, "uv", launches)

    def hook_breaks(self):
        raise RuntimeError("HOOKCANARY the values hook broke")

    monkeypatch.setattr(type(scanner), "_environment_values", hook_breaks)
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: MagicMock(
            is_uv_available=MagicMock(return_value=True),
            uv_availability=MagicMock(return_value=(True, None)),
            run_tool=MagicMock(side_effect=run_tool),
        ),
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    assert response.get("spawn_failed") is True, response
    assert response.get("returncode") == SPAWN_FAILURE_RETURNCODE, response
    assert "the tool's launch never started" in (response.get("error") or ""), response
    assert "HOOKCANARY" not in str(response), response


class _RefusesAttributes(Exception):
    """An exception whose type refuses attributes set on it, as a frozen one does.
    The interpreter's own (``__traceback__``, ``__context__`` and the rest) are let
    through: contextlib sets ``__traceback__`` as the exception leaves a block."""

    def __setattr__(self, name, value):
        if name.startswith("__") and name.endswith("__"):
            super().__setattr__(name, value)
            return
        raise AttributeError(f"{type(self).__name__} is frozen")


@pytest.mark.unit
def test_a_uv_launch_error_that_refuses_attributes_is_the_reason_given(
    tmp_path, monkeypatch
):
    """The uv launch's runner raised, before anything started, an exception whose
    type refuses attributes. Noting the start on it raised AttributeError in its
    place, and the scan gave that as the reason. The reason is the runner's own
    error, and the launch is one that could not start."""

    def runner(args, **kwargs):
        raise _RefusesAttributes("the runner's own error")

    monkeypatch.setattr(subprocess_utils, "_run_plain", runner)
    monkeypatch.setattr(subprocess_utils, "_run_stoppable", runner)
    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = "tool"
    scanner.use_uv_tool = True
    uv_runner = UVToolRunner(uv_executable=sys.executable)
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: uv_runner,
    )
    monkeypatch.chdir(tmp_path)

    response = scanner._run_subprocess(command=["tool", "scan"], results_dir=None)

    error = response.get("error") or ""
    assert response.get("spawn_failed") is True, response
    assert response.get("returncode") == SPAWN_FAILURE_RETURNCODE, response
    assert "the runner's own error" in error, response
    assert "is frozen" not in error, response


def _fake_uv(tmp_path) -> str:
    """A stand-in uv: its ``tool run`` prints a line, then sleeps well past the 1 s
    timeout here; anything else it is asked exits 0."""
    uv = tmp_path / "fake-uv"
    uv.write_text(
        '#!/bin/sh\ncase " $* " in *" run "*) echo partial; exec sleep 60;; esac\nexit 0\n',
        encoding="utf-8",
    )
    uv.chmod(0o755)
    return str(uv)


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in uv is a shell script")
@pytest.mark.integration
def test_a_uv_run_that_timed_out_writing_its_logs_runs_nothing_again(
    tmp_path, monkeypatch
):
    """The uv run timed out, and writing what it printed to the stream logs failed.
    It is still a timeout: timed_out, with the write's error added. It is never 127,
    never the -9 of ASH's own kill, and nothing runs in its place or a second time."""
    uv = _fake_uv(tmp_path)
    started: list = []

    class _Recorded(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            started.append(self)

    scanner = _Handled(config=_Config(), context=_context(tmp_path))
    scanner.command = _REAL_TOOL[0]
    scanner.use_uv_tool = True
    runner = UVToolRunner(uv_executable=uv)
    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: runner,
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "Popen", _Recorded)
    monkeypatch.setattr(
        subprocess_utils,
        "_write_stream_log",
        MagicMock(side_effect=OSError(errno.ENOSPC, "No space left on device")),
    )
    try:
        response = scanner._run_subprocess(
            command=list(_REAL_TOOL), results_dir=tmp_path / "results", timeout=1
        )
    finally:
        for process in started:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)

    uv_runs = [p for p in started if str(p.args[0]) == uv and "run" in p.args]
    # The uv run's arguments end with the tool's own "-c pass" too, so a direct
    # run is told apart by what it starts.
    direct = [
        p
        for p in started
        if str(p.args[0]) != uv and list(p.args)[-2:] == _REAL_TOOL[-2:]
    ]
    assert uv_runs, "the uv run never started, so the cell shows nothing"
    assert len(uv_runs) == 1, f"the uv run started {len(uv_runs)} times"
    assert not direct, f"{len(direct)} direct run(s) ran in its place"
    assert response.get("timed_out") is True, response
    assert response.get("spawn_failed") is not True, response
    assert response.get("post_run_error") is not True, response
    # A timeout's own code, or none for a child ASH could not stop: never 127, and
    # never the -9 of ASH's own kill, or the 9 abs() makes of it.
    assert response.get("returncode") in (124, None), response
    assert "No space left on device" in (response.get("error") or ""), response


# -- the spawn-failure headline is static; the stderr shows once, redacted --------

#: A FAKE environment-derived value the scanner's redaction hook names. Never a
#: real secret: the cell measures only that this spelling cannot reach the
#: raised text.
_PLANTED_ENV_VALUE = "PLANTEDVALUE0001-read-from-the-environment"

#: A marker in the planted stderr that redaction leaves alone, counted in the
#: raised text: once through the Stderr part. A second copy means the headline
#: quoted the response's text again.
_SPAWN_STDERR_MARKER = "spawn-stderr-marker-7f3"


class _SpawnHeadlineConfig(ScannerPluginConfigBase):
    name: str = "plantedspawn"


class _SpawnFailsRedacted(ScannerPluginBase):
    """Template scan() whose _run_subprocess answers a planted spawn failure.

    The stand-in routes its response through _process_command_response, as
    every production spawn-failure site does (_try_uv_tool_execution's return,
    the uv refusal, the direct run, and the OS-refusal handler), so the stderr
    reaches self.errors redacted and the cell measures the live path from the
    response to the raised text.
    """

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _values_to_redact(self):
        return (_PLANTED_ENV_VALUE,)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        return (
            ["planted-tool", "scan"],
            Path(self.results_dir) / "planted.sarif",
            None,
        )

    def _run_subprocess(self, command, **kwargs):
        response = {
            "stdout": "",
            "stderr": (
                f"{_SPAWN_STDERR_MARKER}: planted-tool could not run on "
                f"{_PLANTED_ENV_VALUE}"
            ),
            "returncode": SPAWN_FAILURE_RETURNCODE,
            "spawn_failed": True,
            "error": f"exec failed on {_PLANTED_ENV_VALUE}",
        }
        self._process_command_response(response)
        return response


@pytest.mark.unit
def test_a_spawn_failure_headline_is_static_and_its_stderr_shows_once_redacted(
    tmp_path,
):
    """The spawn-failure headline carries no response text: the response's
    stderr and error are environment-derived (a tool's quoted path or
    requirement, uv's refusal), and quoting either put the value in the raised
    message in clear. The headline is the static sentence, and the stderr
    reaches the message exactly once, through _describe_scan_failure's Stderr
    part, redacted as _process_command_response stored it."""
    context = _context(tmp_path)
    scanner = _SpawnFailsRedacted(config=_SpawnHeadlineConfig(), context=context)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=context.source_dir, target_type="source")

    message = str(excinfo.value)
    assert "could not start its tool, so it produced no results file." in message, (
        message
    )
    assert _PLANTED_ENV_VALUE not in message, message
    assert message.count(_SPAWN_STDERR_MARKER) == 1, message


class _FlaggedResponseScanner(_SpawnFailsRedacted):
    """Template scan() whose _run_subprocess answers a planted flagged response.

    The response goes back as the tool run built it, with its environment-derived
    error text in clear, so the cell measures the raise in scan() itself."""

    planted_response: ClassVar[dict] = {}

    def _run_subprocess(self, command, **kwargs):
        return dict(type(self).planted_response)


@pytest.mark.parametrize(
    "flag,headline",
    [
        ("post_run_error", "ran, but ASH could not record the scanner's output"),
        ("signaled", "did not finish"),
    ],
)
@pytest.mark.unit
def test_a_flagged_responses_raise_redacts_the_response_error(
    tmp_path, monkeypatch, flag, headline
):
    """The post-run-error and signaled raises quote the response's error text,
    which can name an environment-derived value; both go through the same
    redaction the timeout raise applies."""
    monkeypatch.setattr(
        _FlaggedResponseScanner,
        "planted_response",
        {
            "stdout": "",
            "stderr": "",
            "returncode": 3,
            flag: True,
            "error": f"{_SPAWN_STDERR_MARKER} on {_PLANTED_ENV_VALUE}",
        },
    )
    context = _context(tmp_path)
    scanner = _FlaggedResponseScanner(config=_SpawnHeadlineConfig(), context=context)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=context.source_dir, target_type="source")

    message = str(excinfo.value)
    assert headline in message, message
    assert _SPAWN_STDERR_MARKER in message, message
    assert _PLANTED_ENV_VALUE not in message, message
