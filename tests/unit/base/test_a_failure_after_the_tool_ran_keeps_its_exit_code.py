# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool that ran, and whose output ASH then failed to record, keeps its exit code.

Why this file exists
--------------------
Two kinds of failure reach the catch-alls around a scanner's tool:

- the tool never started (the spawn, or a step before it, raised): exit code 127,
  ``spawn_failed``, and the scan is ERROR, "<scanner> could not start its tool";
- the tool started and exited, and ASH then failed: writing its stream logs, or
  handling its response. Answering that case with exit code 1 would read as
  "ran and found issues" to most scanners, so a scanner that ignores the code
  would be PASSED; 127 would say the command was not found, and it was.

So the second case keeps the tool's real exit code, sets ``post_run_error``
(``spawn_failed`` False) with the error text, and the scan is ERROR, "ASH could
not record the scanner's output". It never reads as "could not start".

Every response that carries an ``error`` also sets one of ``spawn_failed``,
``post_run_error``, ``timed_out``, ``cancelled``, ``result_rejected`` or
``signaled``, so no failure can pass for a clean run (the property cell at the
end). ``signaled`` is a tool that ended on a signal ASH did not send.
``result_rejected`` is a remote executor's: a result that failed validation.
Nothing here sets it, and the property accepts it so that it holds there too.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from typing_extensions import Self

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    run_command_with_output_handling,
)

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: The flags one of which every response carrying an ``error`` sets.
FLAGS = (
    "spawn_failed",
    "post_run_error",
    "timed_out",
    "cancelled",
    "result_rejected",
    "signaled",
)

#: The tool's own exit codes the post-run cells keep.
EXIT_CODES = [pytest.param(0, id="exits-0"), pytest.param(1, id="exits-1")]

_DISK_FULL = OSError(28, "No space left on device")


def _tool(exit_code: int) -> List[str]:
    return [sys.executable, "-c", f"import sys; print('ran'); sys.exit({exit_code})"]


def _log_write_fails():
    return patch.object(subprocess_utils, "_write_stream_log", side_effect=_DISK_FULL)


def _has_a_flag(response: Dict[str, Any]) -> bool:
    return any(response.get(flag) is True for flag in FLAGS)


@pytest.mark.parametrize("exit_code", EXIT_CODES)
@pytest.mark.integration
def test_the_runner_keeps_the_exit_code_when_the_log_write_raises(tmp_path, exit_code):
    with _log_write_fails():
        response = run_command_with_output_handling(
            _tool(exit_code), results_dir=tmp_path, class_name="Tool"
        )

    assert response["returncode"] == exit_code, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response
    assert "No space left on device" in response["error"], response


#: What the stderr tool writes: two lines, one holding an ESC.
TOOL_STDERR = "warning: one\nwarning: two \x1b[31mred\n"


def _tool_with_stderr(exit_code: int) -> List[str]:
    # It prints to stdout too, so the stdout log is the first write that fails.
    writes = f"sys.stderr.write({TOOL_STDERR!r}); print('ran')"
    return [sys.executable, "-c", f"import sys; {writes}; sys.exit({exit_code})"]


@pytest.mark.parametrize("preference", ["write", "return", "both", "none"])
@pytest.mark.parametrize("exit_code", EXIT_CODES)
@pytest.mark.integration
def test_a_post_run_response_carries_the_tools_stderr(tmp_path, exit_code, preference):
    """ASH's own failure is when the tool's diagnostics matter, and the stderr log
    may be what could not be written: the response carries the stderr as the tool
    wrote it, whatever stderr_preference asked for."""
    with _log_write_fails():
        response = run_command_with_output_handling(
            _tool_with_stderr(exit_code),
            results_dir=tmp_path,
            class_name="Tool",
            stderr_preference=preference,
        )

    assert response["post_run_error"] is True, response
    assert response.get("stderr") == TOOL_STDERR, response


@pytest.mark.integration
def test_control_a_post_run_response_without_stderr_carries_none(tmp_path):
    with _log_write_fails():
        response = run_command_with_output_handling(
            _tool(0), results_dir=tmp_path, class_name="Tool"
        )

    assert response["post_run_error"] is True, response
    assert not response.get("stderr"), response


@pytest.mark.integration
def test_run_subprocess_after_a_run_returned_keeps_its_stderr(tmp_path):
    context = _context(tmp_path)
    scanner = _ResponseHandlingFails(config=_Config(), context=context)

    response = scanner._run_subprocess(
        command=_tool_with_stderr(1),
        results_dir=tmp_path / "results",
        stderr_preference="return",
    )

    assert response["post_run_error"] is True, response
    assert response.get("stderr") == TOOL_STDERR, response


@pytest.mark.integration
def test_the_post_run_log_line_is_one_line(tmp_path, caplog):
    raised = OSError("first\nsecond\x1b[31m")
    with (
        patch.object(subprocess_utils, "_write_stream_log", side_effect=raised),
        caplog.at_level("ERROR", logger="ash"),
    ):
        response = run_command_with_output_handling(_tool(0), results_dir=tmp_path)

    logged = [
        r.getMessage() for r in caplog.records if "could not record" in r.getMessage()
    ]
    assert len(logged) == 1, logged
    assert "\n" not in logged[0] and "\x1b" not in logged[0], logged
    assert str(raised) in response["error"], response


class _Config(ScannerPluginConfigBase):
    name: str = "recorder"


class _IgnoresTheResponse(ScannerPluginBase):
    """Runs its tool and reports no findings, whatever the run answered."""

    exit_code_of_tool: int = 0

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=_tool(self.exit_code_of_tool), results_dir=self.results_dir
        )
        return {"severity_counts": {}}


class _FindingsFileEmptyPasses(_IgnoresTheResponse):
    """Passes exactly when its findings file is missing or empty."""

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=_tool(self.exit_code_of_tool), results_dir=self.results_dir
        )
        findings = Path(self.results_dir) / "findings.json"
        if not findings.exists() or not findings.read_text(encoding="utf-8").strip():
            return {"severity_counts": {}}
        return {"severity_counts": {"high": 1}}


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
    (container,) = executor._execute_scanner(
        "recorder", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return container


@pytest.mark.parametrize(
    "scanner_class",
    [_IgnoresTheResponse, _FindingsFileEmptyPasses],
    ids=["ignores-the-response", "findings-file-empty-passes"],
)
@pytest.mark.parametrize("exit_code", EXIT_CODES)
@pytest.mark.integration
def test_a_scanner_whose_output_was_not_recorded_is_an_error(
    tmp_path, scanner_class, exit_code
):
    context = _context(tmp_path)
    scanner = scanner_class(config=_Config(), context=context)
    scanner.exit_code_of_tool = exit_code

    with _log_write_fails():
        container = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    first = container.raw_results["errors"][0]
    assert "could not record the scanner's output" in first, first
    assert "could not start" not in first and "never started" not in first, first
    assert scanner.scan_spawn_failure is None


class _ResponseHandlingFails(_IgnoresTheResponse):
    def _process_command_response(self, response):
        raise RuntimeError("reading the run's response failed")


@pytest.mark.integration
def test_run_subprocess_after_a_run_returned_keeps_its_exit_code(tmp_path):
    context = _context(tmp_path)
    scanner = _ResponseHandlingFails(config=_Config(), context=context)
    scanner.exit_code_of_tool = 1

    response = scanner._run_subprocess(
        command=_tool(1), results_dir=tmp_path / "results"
    )

    assert response["returncode"] == 1, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response
    assert scanner.scan_post_run_error, scanner.scan_post_run_error


@pytest.mark.integration
def test_a_scanner_whose_response_handling_raised_is_an_error(tmp_path):
    context = _context(tmp_path)
    scanner = _ResponseHandlingFails(config=_Config(), context=context)

    container = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    first = container.raw_results["errors"][0]
    assert "could not record the scanner's output" in first, first


def _handling_fails_after(tmp_path, command, scanner_class=None):
    """_run_subprocess's response, when handling a run of ``command`` raised."""
    context = _context(tmp_path)
    scanner = (scanner_class or _ResponseHandlingFails)(
        config=_Config(), context=context
    )
    return scanner._run_subprocess(command=command, results_dir=tmp_path / "results")


@pytest.mark.integration
def test_under_write_the_stderr_log_is_read_back(tmp_path):
    """Under "write", the default, the run's response holds no stderr."""
    response = _handling_fails_after(tmp_path, _tool_with_stderr(1))

    assert response["post_run_error"] is True, response
    assert response.get("stderr") == TOOL_STDERR, response


@pytest.mark.integration
def test_control_under_write_a_tool_without_stderr_carries_none(tmp_path):
    response = _handling_fails_after(tmp_path, _tool(1))

    assert response["post_run_error"] is True, response
    assert not response.get("stderr"), response
    assert "stderr log" not in response["error"], response


@pytest.mark.integration
def test_a_stderr_log_an_earlier_run_left_is_not_read_back(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    log = results / f"{_ResponseHandlingFails.__name__}.stderr.log"
    log.write_text("an earlier command's stderr\n", encoding="utf-8")

    response = _handling_fails_after(tmp_path, _tool(1))

    assert not response.get("stderr"), response


@pytest.mark.integration
def test_a_stderr_log_read_back_is_bounded(tmp_path, monkeypatch):
    from automated_security_helper.base import plugin_base

    monkeypatch.setattr(plugin_base, "_STDERR_LOG_READ_LIMIT", 16)

    response = _handling_fails_after(tmp_path, _tool_with_stderr(1))

    assert response.get("stderr") == TOOL_STDERR[:16] + " ...[truncated]", response


class _LogReplacedByALink(_IgnoresTheResponse):
    """A process the scanner left running puts a link where its stderr log was,
    and then ASH's handling of the run's response raises."""

    link_to: ClassVar[Optional[Path]] = None

    def _process_command_response(self, response):
        log = Path(self.results_dir_of_run) / f"{type(self).__name__}.stderr.log"
        log.unlink()
        log.symlink_to(type(self).link_to)
        raise RuntimeError("reading the run's response failed")

    results_dir_of_run: str = ""


@pytest.mark.integration
def test_a_stderr_log_replaced_by_a_link_is_not_read_back(tmp_path, monkeypatch):
    secret = tmp_path / "host-file"
    secret.write_text("NOT-THE-TOOLS-STDERR\n", encoding="utf-8")
    monkeypatch.setattr(_LogReplacedByALink, "link_to", secret)
    context = _context(tmp_path)
    scanner = _LogReplacedByALink(config=_Config(), context=context)
    scanner.results_dir_of_run = str(tmp_path / "results")

    response = scanner._run_subprocess(
        command=_tool_with_stderr(1), results_dir=tmp_path / "results"
    )

    assert response["post_run_error"] is True, response
    assert "NOT-THE-TOOLS-STDERR" not in str(response), response
    assert "its stderr log could not be read" in response["error"], response


@pytest.mark.integration
def test_a_stderr_log_read_that_raises_is_named_and_raises_nothing(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils.sandbox import fs_guard

    monkeypatch.setattr(
        fs_guard,
        "read_bytes_at_most",
        MagicMock(side_effect=RuntimeError("the read raised")),
        raising=False,
    )

    response = _handling_fails_after(tmp_path, _tool_with_stderr(1))

    assert response["post_run_error"] is True, response
    assert "reading the run's response failed" in response["error"], response
    assert "its stderr log could not be read: the read raised" in response["error"]
    assert not response.get("stderr"), response


@pytest.mark.unit
def test_the_uv_runner_carries_the_flag(tmp_path):
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    answered = {
        "returncode": 1,
        "post_run_error": True,
        "spawn_failed": False,
        "error": "No space left on device",
        "stderr": TOOL_STDERR,
    }
    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(
            subprocess_utils, "run_command_with_output_handling", return_value=answered
        ),
        # Nothing else may start a process here: the uv runner starts its children
        # through the plain runner.
        patch.object(subprocess_utils, "_run_plain", side_effect=AssertionError("ran")),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert result.returncode == 1
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "error", "") == "No space left on device", result
    assert result.stderr == TOOL_STDERR, result


@pytest.mark.unit
def test_the_uv_mixin_carries_the_flag(tmp_path):
    from automated_security_helper.utils.subprocess_utils import PostRunErrorProcess

    context = _context(tmp_path)
    scanner = _IgnoresTheResponse(config=_Config(), context=context)
    scanner.command = "semgrep"
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.return_value = PostRunErrorProcess(
        args=["semgrep"], returncode=0, stdout="", stderr=TOOL_STDERR, error="disk full"
    )
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=runner,
    ):
        response = scanner._try_uv_tool_execution(["semgrep", "scan"], tmp_path)

    assert response["returncode"] == 0, response
    assert response["post_run_error"] is True, response
    assert response["error"] == "disk full", response
    assert response["stderr"] == TOOL_STDERR, response


# -- a check after the tool exited is inside the post-run handling ---------------


@pytest.mark.integration
def test_run_command_after_a_clean_exit_keeps_the_code_when_its_log_raises(
    monkeypatch,
):
    """run_command logs the result after the tool exited; that log raising was
    read as a command that never ran (127)."""
    from automated_security_helper.utils.subprocess_utils import (
        PostRunErrorProcess,
        run_command,
    )

    real_debug = subprocess_utils.ASH_LOGGER.debug

    def debug(message, *args, **kwargs):
        if str(message).startswith("Command succeeded"):
            raise OSError(28, "No space left on device")
        return real_debug(message, *args, **kwargs)

    monkeypatch.setattr(subprocess_utils.ASH_LOGGER, "debug", debug)

    result = run_command(_tool(0))

    assert isinstance(result, PostRunErrorProcess), result
    assert result.returncode == 0, result
    assert not getattr(result, "spawn_failed", False), result
    assert "No space left on device" in result.error, result


@pytest.mark.unit
def test_the_uv_runner_after_a_clean_exit_keeps_the_code_when_its_conversion_raises(
    tmp_path, monkeypatch
):
    """run_tool converts the run's response after the tool exited; a raise there
    was a UVToolRunnerError, and the mixin then ran the tool again directly."""
    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    answered = {"returncode": 0, "stdout": "ran\n"}

    def conversion_fails(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", lambda **k: answered
    )
    monkeypatch.setattr(uv_tool_runner.subprocess, "CompletedProcess", conversion_fails)

    result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == 0, result
    assert "No space left on device" in result.error, result


class _UvResponseHandlingFails(_IgnoresTheResponse):
    # The seam the mixin does not guard on its own: a raise in the offline-resolve
    # explainer is logged and swallowed there (uv_tool_mixin.py), so it grades nothing.
    def _process_command_response(self, response):
        raise RuntimeError("reading the uv run's response failed")


@pytest.mark.unit
def test_the_uv_mixin_after_a_clean_exit_keeps_the_code_and_runs_nothing_again(
    tmp_path,
):
    """The mixin reads the uv run's response after the tool exited; a raise there
    fell back to direct execution, which ran the tool a second time."""
    context = _context(tmp_path)
    scanner = _UvResponseHandlingFails(config=_Config(), context=context)
    scanner.command = "semgrep"
    scanner.use_uv_tool = True
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.return_value = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout="", stderr=""
    )
    with (
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=runner,
        ),
        patch.object(
            subprocess_utils,
            "run_command_with_output_handling",
            side_effect=AssertionError("the tool was run a second time"),
        ),
    ):
        response = scanner._run_subprocess(
            command=["semgrep", "scan"], results_dir=tmp_path / "results"
        )

    assert response["returncode"] == 0, response
    assert response["post_run_error"] is True, response
    assert response["spawn_failed"] is False, response
    assert "reading the uv run's response failed" in response["error"], response
    assert scanner.scan_post_run_error, scanner.scan_post_run_error


# -- the uv path's spawn_failed and timed_out responses say what happened ------


@pytest.mark.parametrize(
    "answered, flag, cause",
    [
        pytest.param(
            {
                "returncode": SPAWN_FAILURE_RETURNCODE,
                "spawn_failed": True,
                "error": "[Errno 2] No such file or directory: 'uv'",
                "stderr": "Could not start uv tool run semgrep: ...",
            },
            "spawn_failed",
            "No such file or directory",
            id="spawn-failed",
        ),
        pytest.param(
            {
                "returncode": 124,
                "timed_out": True,
                "error": "Command timed out after 5s: uv tool run semgrep",
                "stderr": "Command timed out after 5s: uv tool run semgrep",
            },
            "timed_out",
            "timed out after 5s",
            id="timed-out",
        ),
    ],
)
@pytest.mark.unit
def test_the_uv_path_carries_the_error_of_a_failed_start_or_a_timeout(
    tmp_path, answered, flag, cause
):
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(
            subprocess_utils, "run_command_with_output_handling", return_value=answered
        ),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert getattr(result, flag, False) is True, result
    assert cause in getattr(result, "error", ""), result

    context = _context(tmp_path)
    scanner = _IgnoresTheResponse(config=_Config(), context=context)
    scanner.command = "semgrep"
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.return_value = result
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=runner,
    ):
        response = scanner._try_uv_tool_execution(["semgrep", "scan"], tmp_path)

    assert response[flag] is True, response
    assert cause in response.get("error", ""), response


@pytest.mark.integration
def test_the_uv_fallback_after_the_start_keeps_the_code_and_runs_nothing_again(
    monkeypatch, tmp_path
):
    """run_tool without a results_dir runs through spawn_run. A failure there after
    the child started escaped as an exception, and the mixin ran the tool again
    directly. The stand-in uv is this Python, which exits 2 on the missing script
    'tool'; communicate() reads that, and then raises."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    real = subprocess.Popen.communicate

    def communicate(self, *args, **kwargs):
        real(self, *args, **kwargs)
        raise RuntimeError("handling the output failed")

    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(subprocess.Popen, "communicate", communicate)
    monkeypatch.chdir(tmp_path)

    result = UVToolRunner(uv_executable=sys.executable).run_tool(
        "semgrep", args=["scan"]
    )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == 2, result
    assert "handling the output failed" in result.error, result


@pytest.mark.unit
def test_the_uv_fallback_timeout_carries_its_error(monkeypatch):
    """run_tool without a results_dir runs through spawn_run; its timeout's
    result had no error either."""
    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    def times_out(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(uv_tool_runner, "spawn_run", times_out)

    result = UVToolRunner().run_tool("semgrep", args=["scan"], timeout=5)

    assert getattr(result, "timed_out", False) is True, result
    # The limit is its own quoted token, redactable whole (never inside "5s").
    assert "timed out after '5' s" in getattr(result, "error", ""), result


# -- a tool ASH stopped has no exit code of its own -------------------------------

#: A tool still running when ASH's wait on it fails.
_SLEEPS = [sys.executable, "-c", "import time; time.sleep(60)"]

#: What ASH's stop of a child leaves (SIGTERM, then SIGKILL), as a code and as what
#: abs() or a shell makes of it. None of them is ever the tool's code.
_ASH_STOP_CODES = (-15, -9, 15, 9, 143, 137)

_STOPPED_TEXT = "ASH stopped the tool after: reading the output failed"

#: The response for a tool ASH stopped after its wait failed.
_STOPPED = {
    "returncode": None,
    "post_run_error": True,
    "spawn_failed": False,
    "error": _STOPPED_TEXT,
}


def _waiting_fails_while_it_runs():
    return patch.object(
        subprocess.Popen,
        "_communicate",
        side_effect=RuntimeError("reading the output failed"),
    )


@pytest.mark.integration
def test_ashs_stop_of_the_tool_is_never_its_exit_code(tmp_path):
    """The kill that ended a tool ASH gave up waiting on is ASH's, so no code is
    reported for the tool, and none reaches the scanner's exit code through
    abs(): -9 became 9 there."""
    context = _context(tmp_path)
    scanner = _IgnoresTheResponse(config=_Config(), context=context)

    with _waiting_fails_while_it_runs():
        response = scanner._run_subprocess(
            command=_SLEEPS, results_dir=tmp_path / "results"
        )

    assert response["returncode"] is None, response
    assert response["post_run_error"] is True, response
    assert "ASH stopped the tool after" in response["error"], response
    assert scanner.exit_code not in _ASH_STOP_CODES, scanner.exit_code


@pytest.mark.unit
def test_handling_a_stopped_tools_response_keeps_no_code_and_its_reason(tmp_path):
    """ASH's handling of the response raised after the run. The code stays None,
    never 0, a clean exit. The run's own reason is kept, and the handling
    error is added to it."""
    context = _context(tmp_path)
    scanner = _ResponseHandlingFails(config=_Config(), context=context)

    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        return_value=dict(_STOPPED),
    ):
        response = scanner._run_subprocess(
            command=["tool"], results_dir=tmp_path / "results"
        )

    assert response["returncode"] is None, response
    assert response["post_run_error"] is True, response
    assert _STOPPED_TEXT in response["error"], response
    assert "reading the run's response failed" in response["error"], response


@pytest.mark.parametrize(
    "flag, code, reason",
    [
        pytest.param(
            "timed_out", 124, "Command timed out after 5s: tool", id="timeout"
        ),
        pytest.param(
            "cancelled",
            130,
            "the scan was cancelled while tool was running",
            id="cancel",
        ),
    ],
)
@pytest.mark.unit
def test_handling_a_timed_out_or_cancelled_response_keeps_its_flag(
    tmp_path, flag, code, reason
):
    """A timed_out or cancelled result never turns into post_run_error: a later
    failure keeps the flag and adds its error to the run's own."""
    flagged = {"returncode": code, flag: True, "error": reason, "stderr": reason}
    context = _context(tmp_path)
    scanner = _ResponseHandlingFails(config=_Config(), context=context)

    with patch.object(
        subprocess_utils, "run_command_with_output_handling", return_value=flagged
    ):
        response = scanner._run_subprocess(
            command=["tool"], results_dir=tmp_path / "results"
        )

    assert response.get(flag) is True, response
    assert response.get("post_run_error") is not True, response
    assert response["returncode"] == code, response
    assert reason in response["error"], response
    assert "reading the run's response failed" in response["error"], response


@pytest.mark.parametrize(
    "code", [pytest.param(None, id="no-code"), pytest.param(1, id="exits-1")]
)
@pytest.mark.unit
def test_the_uv_runner_with_check_returns_a_post_run_result(tmp_path, code):
    """check= reads the flags before the code: a post-run result is returned, not
    raised as a failed run (None != 0 raised)."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    answered = {
        "returncode": code,
        "post_run_error": True,
        "spawn_failed": False,
        "error": "No space left on device",
    }
    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(
            subprocess_utils, "run_command_with_output_handling", return_value=answered
        ),
    ):
        result = UVToolRunner().run_tool(
            "semgrep", args=["scan"], results_dir=tmp_path, check=True
        )

    assert getattr(result, "post_run_error", False) is True, result
    assert result.returncode == code, result
    assert "No space left on device" in result.error, result


class _TextThatFailsOnce:
    """An error value whose first conversion to text raises: a failure inside the
    uv runner's conversion of a response that was already assembled."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.reads = 0

    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        self.reads += 1
        if self.reads == 1:
            raise RuntimeError("converting the response failed")
        return self.text


@pytest.mark.parametrize(
    "answered, flag, cause",
    [
        pytest.param(
            {"returncode": 124, "timed_out": True, "stderr": ""},
            "timed_out",
            "Command timed out after 5s: uv tool run semgrep",
            id="timed-out",
        ),
        pytest.param(
            {"returncode": 130, "cancelled": True, "stderr": ""},
            "cancelled",
            "the scan was cancelled while uv was running",
            id="cancelled",
        ),
    ],
)
@pytest.mark.unit
def test_the_uv_runners_conversion_failure_keeps_a_timeout_or_a_cancel(
    tmp_path, answered, flag, cause
):
    """The handler builds from the response already assembled: the flag stays,
    post_run_error is not set, and the conversion's error is added to the
    response's own."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    response = {**answered, "error": _TextThatFailsOnce(cause)}
    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(
            subprocess_utils, "run_command_with_output_handling", return_value=response
        ),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert getattr(result, flag, False) is True, result
    assert getattr(result, "post_run_error", False) is not True, result
    assert result.returncode == answered["returncode"], result
    assert cause in result.error, result
    assert "converting the response failed" in result.error, result


@pytest.mark.unit
def test_the_uv_runner_keeps_a_cancel_through_its_conversion(tmp_path):
    """A cancelled response keeps ``cancelled`` through every conversion, the uv
    runner's included."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    answered = {
        "returncode": 130,
        "cancelled": True,
        "error": "the scan was cancelled while uv was running",
    }
    with (
        patch.object(UVToolRunner, "uv_availability", return_value=(True, None)),
        patch.object(
            subprocess_utils, "run_command_with_output_handling", return_value=answered
        ),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert getattr(result, "cancelled", False) is True, result
    assert "the scan was cancelled" in getattr(result, "error", ""), result


class _CancelledProcess(subprocess.CompletedProcess):
    """What a cancelled uv run converts to: the flag and its error."""

    cancelled = True

    def __init__(self, args, returncode, stdout=None, stderr=None, error=""):
        super().__init__(args, returncode, stdout, stderr)
        self.error = error


def _uv_mixin_response(tmp_path, result, scanner_class=_IgnoresTheResponse):
    context = _context(tmp_path)
    scanner = scanner_class(config=_Config(), context=context)
    scanner.command = "semgrep"
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.return_value = result
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=runner,
    ):
        return scanner._try_uv_tool_execution(["semgrep", "scan"], tmp_path)


@pytest.mark.unit
def test_the_uv_mixin_carries_a_cancel(tmp_path):
    """The mixin's response carries ``cancelled`` and its error, as it carries
    ``timed_out``."""
    response = _uv_mixin_response(
        tmp_path,
        _CancelledProcess(
            ["semgrep"], 130, stdout="", stderr="", error="the scan was cancelled"
        ),
    )

    assert response.get("cancelled") is True, response
    assert "the scan was cancelled" in response.get("error", ""), response


@pytest.mark.parametrize(
    "result, flag, cause",
    [
        pytest.param(
            subprocess_utils.TimedOutProcess(
                ["semgrep"],
                124,
                stdout="",
                stderr=TOOL_STDERR,
                error="Command timed out after 5s: uv tool run semgrep",
            ),
            "timed_out",
            "Command timed out after 5s",
            id="timed-out",
        ),
        pytest.param(
            _CancelledProcess(
                ["semgrep"],
                130,
                stdout="",
                stderr=TOOL_STDERR,
                error="the scan was cancelled while uv was running",
            ),
            "cancelled",
            "the scan was cancelled",
            id="cancelled",
        ),
    ],
)
@pytest.mark.unit
def test_the_uv_mixins_handling_failure_keeps_a_timeout_or_a_cancel(
    tmp_path, result, flag, cause
):
    """Reading the uv run's response raised after the run. The response already
    assembled is kept, flag and all, with the handling error added: it turned
    into post_run_error, and the timeout or cancel was lost."""
    response = _uv_mixin_response(tmp_path, result, _UvResponseHandlingFails)

    assert response.get(flag) is True, response
    assert response.get("post_run_error") is not True, response
    assert response["returncode"] == result.returncode, response
    assert response.get("stderr") == TOOL_STDERR, response
    assert cause in response["error"], response
    assert "reading the uv run's response failed" in response["error"], response


# -- tool-supplied text in the uv mixin's debug lines -----------------------------

#: Rich markup an exception's text can hold: a closing tag that raises when parsed,
#: and a link and a style that would render instead of showing.
_MARKUP_IN_THE_ERROR = (
    "bad [/x] then [link=file:///tmp/x]here[/link] and [bold]B[/bold]"
)


@pytest.fixture
def markup_console():
    """ASH_LOGGER through a console handler that renders markup.

    The default console handler is built with markup off, so a line logged without
    NO_MARKUP shows the same there as one logged with it. This sink renders markup
    unless the record says otherwise, which is what tells the two apart.
    """
    import io
    import logging

    from automated_security_helper.utils.console import ash_console
    from automated_security_helper.utils.log import ASH_LOGGER, ConsoleHandler

    buffer = io.StringIO()
    handler = ConsoleHandler(
        console=ash_console(file=buffer, width=400, color_system=None),
        markup=True,
        show_time=False,
        show_path=False,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
    ASH_LOGGER.handlers = [handler]
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield buffer
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)


class _UvResponseHandlingFailsWithMarkup(_IgnoresTheResponse):
    def _process_command_response(self, response):
        raise RuntimeError(_MARKUP_IN_THE_ERROR)


@pytest.mark.unit
def test_the_uv_mixins_response_error_line_shows_markup_as_text(
    tmp_path, markup_console
):
    response = _uv_mixin_response(
        tmp_path,
        subprocess.CompletedProcess(["semgrep"], 0, stdout="", stderr=""),
        _UvResponseHandlingFailsWithMarkup,
    )

    assert response["post_run_error"] is True, response
    # The details message carries the redacted formatted traceback, so the
    # raise's text sits on a later line of the one record.
    output = markup_console.getvalue()
    assert "UV tool response error details (redacted):" in output, output
    assert _MARKUP_IN_THE_ERROR in output, output


@pytest.mark.unit
def test_the_uv_mixins_execution_error_line_shows_markup_as_text(
    tmp_path, markup_console
):
    """run_tool raised before it returned, so the mixin falls back to direct
    execution, and logs why."""
    context = _context(tmp_path)
    scanner = _IgnoresTheResponse(config=_Config(), context=context)
    scanner.command = "semgrep"
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.side_effect = RuntimeError(_MARKUP_IN_THE_ERROR)
    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=runner,
    ):
        response = scanner._try_uv_tool_execution(["semgrep", "scan"], tmp_path)

    assert response is None, response
    # The details message carries the redacted formatted traceback, so the
    # raise's text sits on a later line of the one record.
    output = markup_console.getvalue()
    assert "UV tool execution error details (redacted):" in output, output
    assert _MARKUP_IN_THE_ERROR in output, output


# -- a scanner whose tool ASH stopped is an error ---------------------------------


class _IgnoresAToolThatRuns(_IgnoresTheResponse):
    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(command=_SLEEPS, results_dir=self.results_dir)
        return {"severity_counts": {}}


class _FindingsFileEmptyPassesAToolThatRuns(_FindingsFileEmptyPasses):
    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(command=_SLEEPS, results_dir=self.results_dir)
        findings = Path(self.results_dir) / "findings.json"
        if not findings.exists() or not findings.read_text(encoding="utf-8").strip():
            return {"severity_counts": {}}
        return {"severity_counts": {"high": 1}}


@pytest.mark.parametrize(
    "scanner_class",
    [_IgnoresAToolThatRuns, _FindingsFileEmptyPassesAToolThatRuns],
    ids=["ignores-the-response", "findings-file-empty-passes"],
)
@pytest.mark.integration
def test_a_scanner_whose_tool_ash_stopped_is_an_error(tmp_path, scanner_class):
    """Waiting on the started tool fails while it runs, and ASH stops it. Its exit
    code is unknown, so nothing can pass for a clean run: ERROR, "could not
    record", never PASSED and never "could not start"."""
    context = _context(tmp_path)
    scanner = scanner_class(config=_Config(), context=context)

    with _waiting_fails_while_it_runs():
        container = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    first = container.raw_results["errors"][0]
    assert "could not record the scanner's output" in first, first
    assert "could not start" not in first and "never started" not in first, first
    assert scanner.scan_spawn_failure is None


# -- a child ASH could not stop ---------------------------------------------------

#: A pid no process can have, above the largest pid_max Linux allows (2**22): a
#: signal that gets past the stand-ins below reaches no process.
_UNSTOPPABLE_PID = 2**30 + 7

#: The command the stand-in child is started for. Nothing runs it. The markup in
#: its name shows as text wherever the reason is shown. The name is an absolute
#: path: a name with a directory part that is not anchored is a path relative to
#: the working directory, which the spawn refuses before it starts anything, so the
#: stand-in would never be built.
_UNSTOPPABLE = [
    os.path.join(os.path.abspath(os.sep), "ash-test-no-such-dir", "unstoppable[/x]"),
    "scan",
]

#: What reading the stand-in's output raises in the post_run_error case.
_READ_FAILED = "reading the output failed [/x]"


class _WaitedWithoutABound(BaseException):
    """A wait with no timeout on a child that ignores the kill. In a real run it
    never returns, so the stand-in raises this instead of hanging the suite."""


class _ChildThatIgnoresTheKill:
    """Stands in for subprocess.Popen: a child that never ends, and no program.

    Every stop ASH sends it, to the child or to its group, is delivered and
    ignored, as with a child in uninterruptible sleep. A read or a wait with a
    timeout runs out at once; one without a timeout raises _WaitedWithoutABound.
    Its with-block exit does what Popen's does: it waits for the child, without
    a bound unless the block ended in KeyboardInterrupt.
    """

    def __init__(self, seen: Any, args: Any, *popenargs: Any, **kwargs: Any) -> None:
        self.seen = seen
        self.args = args
        self.pid = _UNSTOPPABLE_PID
        self.returncode = None
        self.stdin = self.stdout = self.stderr = None
        self.text_mode = bool(kwargs.get("text") or kwargs.get("encoding"))
        self.universal_newlines = self.text_mode
        self.reads = 0
        seen.children.append(self)

    def _never_returns(self, call: str) -> None:
        self.seen.unbounded_waits.append(call)
        raise _WaitedWithoutABound(f"{call} on a child that ignores the kill")

    def communicate(self, *args: Any, **kwargs: Any) -> Any:
        timeout = kwargs.get("timeout", args[1] if len(args) > 1 else None)
        self.reads += 1
        if self.reads == 1:
            self.seen.first_read()
            if self.seen.first_read_fails is not None:
                raise self.seen.first_read_fails
        if timeout is None:
            self._never_returns("communicate() without a timeout")
        raise subprocess.TimeoutExpired(self.args, timeout)

    def wait(self, timeout: Optional[float] = None) -> int:
        if timeout is None:
            self._never_returns("wait() without a timeout")
        raise subprocess.TimeoutExpired(self.args, timeout)

    def poll(self) -> None:
        return None

    def kill(self) -> None:
        self.seen.signals.append("kill")

    def terminate(self) -> None:
        self.seen.signals.append("terminate")

    def send_signal(self, signum: int) -> None:
        self.seen.signals.append(signum)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, value: object, traceback: object) -> None:
        if exc_type is KeyboardInterrupt:
            try:
                self.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
        else:
            self.wait()


def _children_that_ignore_the_kill(
    monkeypatch,
    first_read: Any = None,
    first_read_fails: Optional[BaseException] = None,
) -> Any:
    """Make every Popen a _ChildThatIgnoresTheKill, and the signals ASH sends to its
    pid or its group recorded and ignored. Any other pid gets the real call."""
    import os
    from types import SimpleNamespace

    seen = SimpleNamespace(
        children=[],
        signals=[],
        unbounded_waits=[],
        first_read=first_read or (lambda: None),
        first_read_fails=first_read_fails,
    )
    real_popen = subprocess.Popen

    def popen(*args: Any, **kwargs: Any) -> Any:
        # On Windows the tree stop runs taskkill.exe through subprocess.run, which
        # builds a Popen of its own. Handed the stand-in, that run times out, and
        # the standard library's Windows timeout path then waits on it with no
        # bound, which the stand-in reports as a wait of ASH's. taskkill is not
        # the child under test, so it gets the real Popen: against the stand-in's
        # pid it ends at once with "process not found".
        import ntpath

        command = args[0] if args else kwargs.get("args")
        first = (
            command[0] if isinstance(command, (list, tuple)) and command else command
        )
        if os.name == "nt" and ntpath.basename(str(first)).lower() == "taskkill.exe":
            return real_popen(*args, **kwargs)
        return _ChildThatIgnoresTheKill(seen, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen)

    def ignored(real: Any) -> Any:
        def call(pid: int, *rest: Any) -> Any:
            if abs(pid) == _UNSTOPPABLE_PID:
                seen.signals.append((real.__name__, *rest))
                return pid if real.__name__ == "getpgid" else None
            return real(pid, *rest)

        return call

    for name in ("kill", "killpg", "getpgid"):
        real = getattr(os, name, None)
        if real is not None:
            monkeypatch.setattr(os, name, ignored(real))
    return seen


class _RunsAToolASHCannotStop(_IgnoresTheResponse):
    """Runs the stand-in child, and keeps the response it got."""

    tool_timeout: Optional[float] = None
    last_response: Optional[Dict[str, Any]] = None
    scope_seen: bool = False

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        from automated_security_helper.core.cancellation import current_cancel_event

        self.scope_seen = current_cancel_event() is not None
        self.last_response = self._run_subprocess(
            command=list(_UNSTOPPABLE),
            results_dir=self.results_dir,
            timeout=self.tool_timeout,
        )
        return {"severity_counts": {}}


def _says_it_could_not_stop_the_tool(text: str) -> None:
    """The reason of a stop that failed: ASH could not stop the tool, which may
    still be running, and its pid."""
    assert "could not stop" in text.lower(), text
    assert "still" in text.lower() and "running" in text.lower(), text
    assert str(_UNSTOPPABLE_PID) in text, text


def _the_reason_shows_as_text(rendered: str) -> None:
    """The reason reached the console as one line, its markup shown as text, not
    dropped by a markup error and not escaped twice."""
    lines = [
        line
        for line in rendered.splitlines()
        if str(_UNSTOPPABLE_PID) in line and "could not stop" in line.lower()
    ]
    assert lines, f"no rendered line gives the reason:\n{rendered}"
    assert not any("\\[" in line for line in lines), lines


@pytest.mark.parametrize(
    "flag, timeout, first_read_fails, own_text",
    [
        pytest.param("timed_out", 1.0, None, "timed out", id="timed_out"),
        pytest.param(
            "post_run_error",
            None,
            RuntimeError(_READ_FAILED),
            _READ_FAILED,
            id="post_run_error",
        ),
    ],
)
@pytest.mark.unit
def test_a_child_left_running_has_no_code(
    tmp_path, monkeypatch, markup_console, flag, timeout, first_read_fails, own_text
):
    """ASH tried to stop its child and could not, so it may still be running. The
    response keeps the flag that made ASH stop it, with its own text, and has no
    code: the tool never finished on its own, and ASH saw no code of its. The
    reason says ASH could not stop the tool and names the pid, and the scan is
    ERROR."""
    seen = _children_that_ignore_the_kill(
        monkeypatch, first_read_fails=first_read_fails
    )
    context = _context(tmp_path)
    scanner = _RunsAToolASHCannotStop(config=_Config(), context=context)
    scanner.tool_timeout = timeout

    try:
        container = _run(context, scanner)
    except _WaitedWithoutABound as hung:
        pytest.fail(f"ASH waited without a bound on a child it could not stop: {hung}")

    assert not seen.unbounded_waits, seen.unbounded_waits
    assert len(seen.children) == 1, "the stand-in child is not the tool's spawn"
    assert seen.signals, "ASH never tried to stop the child, so the cell shows nothing"
    response = scanner.last_response
    assert response is not None, "the scan never got a response"
    assert response.get(flag) is True, response
    for other in ("spawn_failed", "timed_out", "cancelled", "post_run_error"):
        if other != flag:
            assert response.get(other) is not True, (other, response)
    assert response["returncode"] is None, response
    error = response.get("error") or ""
    _says_it_could_not_stop_the_tool(error)
    assert own_text in error, error
    assert "\\[" not in error, error
    _the_reason_shows_as_text(markup_console.getvalue())
    assert container.status == ScannerStatus.ERROR, container.status


@pytest.mark.unit
def test_a_child_left_running_has_no_code_when_the_scan_was_cancelled(
    tmp_path, monkeypatch, markup_console
):
    """A cancel answers no response: the runner raises ScanCancelled and the scan
    ends CANCELLED. When the cancel could not stop the child, the ScanCancelled
    says so: ASH could not stop the tool, which may still be running, and its
    pid. The cancel stays a cancel."""
    from automated_security_helper.core import cancellation
    from automated_security_helper.core.cancellation import (
        CancelEvent,
        ScanCancelled,
        cancel_scope,
    )

    event = CancelEvent()
    event.stop_promptly = True
    seen = _children_that_ignore_the_kill(monkeypatch, first_read=event.set)
    # The child stays recorded for the server's last stop; that record is this
    # cell's, not the worker's. The registry's die-now mirror holds it too (a
    # child ASH could not stop stays a die-now target), so both copies are
    # isolated to the cell.
    monkeypatch.setattr(subprocess_utils, "_RUNNING_GROUPS", {}, raising=False)
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", (), raising=False)
    context = _context(tmp_path)
    scanner = _RunsAToolASHCannotStop(config=_Config(), context=context)

    try:
        with cancel_scope(event), pytest.raises(ScanCancelled) as info:
            _run(context, scanner)
    except _WaitedWithoutABound as hung:
        pytest.fail(f"ASH waited without a bound on a child it could not stop: {hung}")

    assert scanner.scope_seen, "the scan ran outside the cancel scope"
    assert not seen.unbounded_waits, seen.unbounded_waits
    assert len(seen.children) == 1, "the stand-in child is not the tool's spawn"
    assert seen.signals, "ASH never tried to stop the child, so the cell shows nothing"
    # The isolation comment above promises it, so the cell asserts it: a child
    # ASH could not stop stays a die-now target in the cell-local mirror. On
    # POSIX only, as the registry cells below hold: the server records groups
    # where a group kill is possible, so on Windows nothing is recorded and
    # the cell's other claims stand on their own.
    if os.name == "posix":
        assert _UNSTOPPABLE_PID in cancellation._TOOL_GROUPS, cancellation._TOOL_GROUPS
    _says_it_could_not_stop_the_tool(str(info.value))
    _the_reason_shows_as_text(markup_console.getvalue())


# -- a timeout whose stream-log write fails keeps its timeout ------------------------

#: Writes a line to each stream at once, then runs well past the 1 s timeout here.
_PARTIAL_PROGRAM = (
    "import sys, time; print('partial', flush=True); "
    "sys.stderr.write('diag\\n'); sys.stderr.flush(); time.sleep(60)"
)
_PARTIAL_THEN_SLEEPS = [sys.executable, "-c", _PARTIAL_PROGRAM]


@pytest.mark.integration
def test_a_timeout_whose_log_write_fails_keeps_its_timeout(tmp_path):
    """What the timed-out tool printed is written to its stream logs, and that write
    failed. The run still timed out: timed_out, with its own reason and the write's
    error added. It is never 127 or spawn_failed, and nothing is raised."""
    with _log_write_fails():
        response = run_command_with_output_handling(
            list(_PARTIAL_THEN_SLEEPS),
            results_dir=tmp_path,
            class_name="Tool",
            timeout=1,
        )

    assert response.get("timed_out") is True, response
    assert response.get("spawn_failed") is not True, response
    assert response.get("post_run_error") is not True, response
    assert response["returncode"] == 124, response
    assert "timed out after '1' s" in response["error"], response
    assert "No space left on device" in response["error"], response


class _TimesOutWritingItsLogs(_IgnoresTheResponse):
    """Runs the tool with a 1 s timeout and, as the scan() template does, raises
    when the run timed out."""

    last_response: Optional[Dict[str, Any]] = None

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        from automated_security_helper.core.exceptions import ScannerError

        self.last_response = self._run_subprocess(
            command=list(_PARTIAL_THEN_SLEEPS), results_dir=self.results_dir, timeout=1
        )
        if self.last_response.get("timed_out"):
            raise ScannerError("the tool timed out, so it wrote no results")
        return {"severity_counts": {}}


@pytest.mark.integration
def test_a_scanner_whose_timeout_log_write_failed_reports_the_timeout(tmp_path):
    """_run_subprocess read the runner's exception as a tool that never ran: 127,
    spawn_failed and "could not start", for a tool that ran its whole timeout."""
    context = _context(tmp_path)
    scanner = _TimesOutWritingItsLogs(config=_Config(), context=context)

    with _log_write_fails():
        container = _run(context, scanner)

    response = scanner.last_response
    assert response is not None, "the scan never got a response"
    assert response.get("timed_out") is True, response
    assert response.get("spawn_failed") is not True, response
    assert response.get("returncode") != SPAWN_FAILURE_RETURNCODE, response
    assert scanner.scan_spawn_failure is None, scanner.scan_spawn_failure
    assert scanner.scan_timed_out_after == 1, scanner.scan_timed_out_after
    assert container.status == ScannerStatus.ERROR, container.status
    first = container.raw_results["errors"][0]
    assert "timed out" in first, first
    assert "could not start" not in first, first


# -- a tool that ended on a signal ASH did not send ----------------------------------


#: A SARIF log with one run and no results: what a tool writes for a clean scan.
#: An EMPTY results file is nothing to grade (ScannerPluginBase._handle_empty_results
#: raises), so a template run's clean reading needs a run.
_CLEAN_SARIF = (
    '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "template"}}}]}'
)


class _TemplateScanner(ScannerPluginBase):
    """A scanner on the default scan() template. It runs ``tool_command`` and leaves
    a one-run results file with no findings, which the template reads as a clean
    scan when the exit code is accepted."""

    tool_command: List[str] = []

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        results_file = Path(self.results_dir) / "results.sarif"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        results_file.write_text(_CLEAN_SARIF, encoding="utf-8")
        return list(self.tool_command), results_file, None


def _ends_by_its_own(signum: int) -> List[str]:
    """A child that ends itself with ``signum``. A signal that can be caught gets
    its default action back first, so an ignored disposition it inherited can't
    keep it alive; SIGKILL can't be caught, ignored or reset."""
    restore = (
        ""
        if signum == signal.SIGKILL
        else f"signal.signal({int(signum)}, signal.SIG_DFL); "
    )
    program = f"import os, signal; {restore}os.kill(os.getpid(), {int(signum)})"
    return [sys.executable, "-c", program]


def _template_run(tmp_path, monkeypatch, command: List[str]):
    """The container for one template scan of ``command``, and each response its
    _run_subprocess returned."""
    responses: List[Dict[str, Any]] = []
    real = _TemplateScanner._run_subprocess

    def recording(self, *args, **kwargs):
        response = real(self, *args, **kwargs)
        responses.append(response)
        return response

    monkeypatch.setattr(_TemplateScanner, "_run_subprocess", recording)
    context = _context(tmp_path)
    scanner = _TemplateScanner(config=_Config(), context=context)
    scanner.tool_command = command
    return _run(context, scanner), scanner, responses


def _numbers_besides_the_code(response: Dict[str, Any]) -> List[int]:
    return [
        value
        for key, value in response.items()
        if key != "returncode"
        and isinstance(value, int)
        and not isinstance(value, bool)
    ]


@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.parametrize("signal_name", ["SIGKILL", "SIGHUP"])
@pytest.mark.integration
def test_a_tool_that_ended_on_a_signal_ash_did_not_send_is_an_error(
    tmp_path, monkeypatch, signal_name
):
    """An OOM kill or a hang-up ended the tool, not ASH. The negative code is kept,
    the response says signaled with the signal's number and names it, and the scan
    is ERROR. The negative code is never made positive, so an accepted exit code
    and a clean results file cannot read as a clean scan. Parametrized by name:
    these signals do not exist on Windows, and parametrize evaluates at
    collection."""
    signum = getattr(signal, signal_name)
    container, scanner, responses = _template_run(
        tmp_path, monkeypatch, _ends_by_its_own(signum)
    )

    assert responses, "the scanner never ran its tool, so the cell shows nothing"
    response = responses[-1]
    assert response["returncode"] == -signum.value, response
    assert response.get("signaled") is True, response
    assert signum.value in _numbers_besides_the_code(response), response
    assert signum.name in (response.get("error") or ""), response
    assert scanner.exit_code not in scanner.success_exit_codes, scanner.exit_code
    assert container.status == ScannerStatus.ERROR, container.status


@pytest.mark.integration
def test_control_a_tool_that_exits_with_an_accepted_code_passes(tmp_path, monkeypatch):
    """The cell above isn't vacuous: exit 1 is in the template's accepted set, and
    the same one-run results file reads as a clean scan."""
    container, scanner, responses = _template_run(
        tmp_path, monkeypatch, [sys.executable, "-c", "import sys; sys.exit(1)"]
    )

    assert responses, "the scanner never ran its tool, so the cell shows nothing"
    assert responses[-1]["returncode"] == 1, responses
    assert responses[-1].get("signaled") is not True, responses
    assert scanner.exit_code in scanner.success_exit_codes, scanner.exit_code
    assert container.status == ScannerStatus.PASSED, container.status


class _OneCommandPerTarget(_TemplateScanner):
    """The template scanner with one command per target type, so a two-target scan
    can end one run on a signal while the other renders."""

    commands_by_type: Dict[str, List[str]] = {}

    def _execute_scan(self, target, target_type, global_ignore_paths):
        self.tool_command = list(self.commands_by_type[str(target_type)])
        return super()._execute_scan(target, target_type, global_ignore_paths)


@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.integration
def test_a_signaled_run_is_reported_even_when_the_other_target_rendered(
    tmp_path, monkeypatch
):
    """A scan with two targets: the first target's tool was killed, and the second
    target's run rendered clean. The first run's tool-level cause is never dropped
    by the accounting that saw the second render: its row is ERROR and names the
    signal, while the clean target's row is PASSED."""
    responses: List[Dict[str, Any]] = []
    real = _TemplateScanner._run_subprocess

    def recording(self, *args, **kwargs):
        response = real(self, *args, **kwargs)
        responses.append(response)
        return response

    monkeypatch.setattr(_TemplateScanner, "_run_subprocess", recording)
    context = _context(tmp_path)
    converted = tmp_path / "converted"
    converted.mkdir()
    (converted / "app.py").write_text("print('x')\n")
    scanner = _OneCommandPerTarget(config=_Config(), context=context)
    scanner.commands_by_type = {
        "source": _ends_by_its_own(signal.SIGKILL),
        "converted": [sys.executable, "-c", "raise SystemExit(0)"],
    }

    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    first, second = executor._execute_scanner(
        "recorder",
        scanner,
        [
            {"path": context.source_dir, "type": "source"},
            {"path": converted, "type": "converted"},
        ],
    )

    assert len(responses) == 2, "both tools ran, or the cell shows nothing"
    assert responses[0]["returncode"] == -signal.SIGKILL.value, responses[0]
    assert responses[1]["returncode"] == 0, responses[1]
    assert second.status == ScannerStatus.PASSED, second.status
    assert first.status == ScannerStatus.ERROR, first.status
    raw = first.raw_results if isinstance(first.raw_results, dict) else {}
    errors = " ".join(str(e) for e in [*first.errors, *(raw.get("errors") or [])])
    assert signal.SIGKILL.name in errors, (first.errors, first.raw_results)


def _killed_on(killed: str):
    """A template scanner class whose ``killed`` target's tool kills itself and
    whose other target's exits 0 clean. A class, because the phase constructs the
    plugin from its class; pydantic bakes field defaults at class creation, so
    each parameter gets its own class."""
    other = "converted" if killed == "source" else "source"

    class _OneTargetKilled(_OneCommandPerTarget):
        commands_by_type: Dict[str, List[str]] = {
            killed: _ends_by_its_own(signal.SIGKILL),
            other: [sys.executable, "-c", "raise SystemExit(0)"],
        }

        def model_post_init(self, context):
            if self.config is None:
                self.config = _Config()
            super().model_post_init(context)

    return _OneTargetKilled


@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.parametrize("killed", ["source", "converted"])
@pytest.mark.integration
def test_a_signaled_run_survives_the_phase_rollup(tmp_path, monkeypatch, killed):
    """The cell above, through the phase itself. ScanPhase runs the scanner on
    the source and converted targets in one task; one target's tool was killed
    and the other's rendered clean. Both targets take a turn as the killed one,
    so a rollup that reads only the source is caught too. The killed target's
    own report grades ERROR, and the rollup keeps that tool-level cause: the
    scanner's row is ERROR, never a PASSED the clean target earned, and the
    signal is still named."""
    from automated_security_helper.core.phases.scan_phase import ScanPhase
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )

    responses: List[Dict[str, Any]] = []
    real = _TemplateScanner._run_subprocess

    def recording(self, *args, **kwargs):
        response = real(self, *args, **kwargs)
        responses.append(response)
        return response

    monkeypatch.setattr(_TemplateScanner, "_run_subprocess", recording)
    context = _context(tmp_path)
    # A file with a suffix in work_dir makes the phase add the converted target.
    work_dir = Path(context.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "converted.py").write_text("x = 1\n", encoding="utf-8")

    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_killed_on(killed)],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(aggregated_results=aggregated, parallel=False)
    model = populate_metrics_from_unified_source(aggregated_results=results)

    codes = sorted(
        response.get("returncode") for response in responses if response is not None
    )
    assert codes == [-signal.SIGKILL.value, 0], (
        f"one kill and one clean run, or the cell shows nothing: {responses}"
    )
    reports = model.additional_reports.get("recorder") or {}
    killed_report = reports.get(killed) or {}
    assert str(killed_report.get("status")) == "ERROR", (
        f"the killed {killed} target's own report lost the signaled grading: "
        f"{killed_report}"
    )
    assert signal.SIGKILL.name in str(killed_report), killed_report
    row = model.scanner_results.get("recorder")
    assert row is not None, model.scanner_results
    assert row.status == ScannerStatus.ERROR, (
        f"the clean target's render dropped the signaled run: {row!r}"
    )


# -- the server's stop of a waiting tool is ASH's own stop: a cancel ----------------

#: The stand-in tool's last argument, so the cells can tell its child from any other.
_STOP_TOKEN = "ash-own-stop-4417"

#: Waits a minute: within a cell, only a kill ends it.
_WAITS_FOR_A_STOP = [sys.executable, "-c", "import time; time.sleep(60)", _STOP_TOKEN]

#: How long a cell waits for the tool to be recorded, and then for the scan to end.
#: Far longer than either takes on an idle host, far shorter than the tool's minute.
_STOP_WAIT_SECONDS = 20.0


def _recorded_spawns(monkeypatch) -> List[subprocess.Popen]:
    """Each child a cancellable spawn has recorded, added once its record is done.

    After the real record returns, not before it: a stop that ran while the record
    was still being made is a different case, a child the spawn kills itself."""
    recorded: List[subprocess.Popen] = []
    real = subprocess_utils._record_spawn

    def recording(process: subprocess.Popen) -> bool:
        kept = real(process)
        if kept:
            recorded.append(process)
        return kept

    monkeypatch.setattr(subprocess_utils, "_record_spawn", recording)
    return recorded


def _the_recorded_tool(recorded: List[subprocess.Popen]) -> subprocess.Popen:
    """The stand-in tool's child, once its spawn has recorded it and it runs."""
    deadline = time.monotonic() + _STOP_WAIT_SECONDS
    while time.monotonic() < deadline:
        for process in list(recorded):
            if _STOP_TOKEN in map(str, process.args) and process.poll() is None:
                return process
        time.sleep(0.02)
    pytest.fail(f"the tool was not recorded and running within {_STOP_WAIT_SECONDS} s")


def _template_scan_on_its_own_thread(tmp_path, monkeypatch, command: List[str]):
    """A template scan of ``command`` in a scan's cancel scope, on a thread of its
    own, so that its spawn is a cancellable one. Returns the thread, what the scan
    ended with ("container", or what it "raised"), and each response its
    _run_subprocess returned."""
    responses: List[Dict[str, Any]] = []
    real = _TemplateScanner._run_subprocess

    def recording(self, *args, **kwargs):
        response = real(self, *args, **kwargs)
        responses.append(response)
        return response

    monkeypatch.setattr(_TemplateScanner, "_run_subprocess", recording)
    context = _context(tmp_path)
    scanner = _TemplateScanner(config=_Config(), context=context)
    scanner.tool_command = command
    ended: Dict[str, Any] = {}

    def scan() -> None:
        try:
            with cancel_scope(threading.Event()):
                ended["container"] = _run(context, scanner)
        except BaseException as error:  # a stop ends the scan by raising
            ended["raised"] = error

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    return thread, ended, responses


@pytest.mark.skipif(
    os.name != "posix", reason="the server records groups on POSIX only"
)
@pytest.mark.integration
def test_the_servers_stop_of_a_waiting_tool_is_a_cancel_never_a_signal(
    tmp_path, monkeypatch
):
    """The MCP server's last step, kill_running_groups, SIGKILLs a scanner's tool
    while its cancellable spawn waits on it. That kill is ASH's own stop, so the scan
    ends as a cancel, as a cancel ends on this path: ScanCancelled, saying the server
    is stopping. The child's code is -9, the same as a signal ASH did not send, and
    still nothing is ``signaled``, and the scan is never PASSED. The spawn waited on
    the killed child and returned normally with -9, which read as the tool's own
    exit code."""
    recorded = _recorded_spawns(monkeypatch)
    thread, ended, responses = _template_scan_on_its_own_thread(
        tmp_path, monkeypatch, _WAITS_FOR_A_STOP
    )
    tool = _the_recorded_tool(recorded)
    try:
        killed = subprocess_utils.kill_running_groups()
        thread.join(timeout=_STOP_WAIT_SECONDS)
    finally:
        if tool.poll() is None:
            tool.kill()
            tool.wait(timeout=10)

    assert not thread.is_alive(), "the scan still waited after its tool was killed"
    # The stop reached the tool while it ran: nothing else gives it -9 this soon.
    assert killed >= 1, killed
    assert tool.returncode == -signal.SIGKILL, tool.returncode
    container = ended.get("container")
    assert container is None or container.status != ScannerStatus.PASSED, ended
    signaled = [response for response in responses if response.get("signaled")]
    assert not signaled, signaled
    raised = ended.get("raised")
    assert isinstance(raised, ScanCancelled), (ended, responses)
    assert "the server is stopping" in str(raised), raised


@pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")
@pytest.mark.integration
def test_control_a_tool_that_killed_itself_in_a_cancellable_spawn_is_signaled(
    tmp_path, monkeypatch
):
    """The cell above isn't met by reading every -9 in a cancellable spawn as a
    cancel. The same spawn and the same code, but the tool killed itself and no
    stop of ASH's ran: that is a signal ASH did not send, ``signaled``, and the scan
    is ERROR, not a cancel."""
    recorded = _recorded_spawns(monkeypatch)
    thread, ended, responses = _template_scan_on_its_own_thread(
        tmp_path, monkeypatch, _ends_by_its_own(signal.SIGKILL)
    )
    thread.join(timeout=_STOP_WAIT_SECONDS)

    assert not thread.is_alive(), "the scan did not end after its tool did"
    assert recorded, (
        "the tool did not run in a cancellable spawn, so this shows nothing"
    )
    assert "raised" not in ended, ended
    assert responses, "the scanner never ran its tool, so the cell shows nothing"
    response = responses[-1]
    assert response["returncode"] == -signal.SIGKILL, response
    assert response.get("signaled") is True, response
    assert response.get("cancelled") is not True, response
    assert ended["container"].status == ScannerStatus.ERROR, ended


# -- a kept flag grades the scan, whatever scan() returned ---------------------------

#: A token in each kept flag's reason, so its lines can be counted.
_KEPT_TOKEN = "kept-flag-reason-7319"


@pytest.mark.parametrize(
    "flag, code",
    [
        pytest.param("timed_out", 124, id="timed_out"),
        pytest.param("cancelled", 130, id="cancelled"),
        pytest.param("result_rejected", 125, id="result_rejected"),
    ],
)
@pytest.mark.unit
def test_a_kept_flag_makes_the_scan_an_error_and_is_reported_once(tmp_path, flag, code):
    """The scanner's scan() ignores the response it got, so only the kept flag says
    its run failed. The executor grades the scan ERROR whatever scan() returned, and
    the reason appears once in what the scan reports."""
    reason = f"the run ended with {flag} ({_KEPT_TOKEN})"
    flagged = {"returncode": code, flag: True, "error": reason}
    context = _context(tmp_path)
    scanner = _IgnoresTheResponse(config=_Config(), context=context)

    with patch.object(
        subprocess_utils, "run_command_with_output_handling", return_value=flagged
    ):
        container = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    # Counted in each list, so a line given twice in one of them is seen; one list
    # holding the other's lines counts once.
    counts = [
        sum(_KEPT_TOKEN in str(line) for line in lines)
        for lines in (container.errors, raw.get("errors", []))
    ]
    assert max(counts) == 1, (counts, container.errors, raw.get("errors"))


class _IgnoresARunWithATimeout(_IgnoresTheResponse):
    """Runs its tool with a 5 s timeout, and reports no findings whatever the run
    answered."""

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=_tool(self.exit_code_of_tool),
            results_dir=self.results_dir,
            timeout=5,
        )
        return {"severity_counts": {}}


#: What the runner answers for a run it stopped at the 5 s timeout.
_TIMED_OUT_AT_5 = {
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
    "stderr": "Command timed out after 5s: tool",
}

#: What the recorders raise in the cells below.
_RECORDER_BROKE = "the recorder broke"


def _raising(original, always: bool):
    """``original``, raising _RECORDER_BROKE on its first call, or on every call;
    and the list each raise is counted in."""
    fired: List[bool] = []

    def recorder(self, *args, **kwargs):
        if always or not fired:
            fired.append(True)
            raise RuntimeError(_RECORDER_BROKE)
        return original(self, *args, **kwargs)

    return recorder, fired


def _repeated(lines) -> List[str]:
    lines = [str(line) for line in lines]
    return sorted({line for line in lines if lines.count(line) > 1})


@pytest.mark.parametrize(
    "recorder",
    [
        pytest.param(None, id="control-none-raises"),
        pytest.param("_record_spawn_failure", id="spawn-failure-recorder"),
        pytest.param("_record_post_run_error", id="post-run-recorder"),
    ],
)
@pytest.mark.unit
def test_a_timeout_whose_other_recorder_raised_is_reported_once(
    tmp_path, monkeypatch, recorder
):
    """A timed-out run, and the recorder of another flag raised once while it was
    handled. The handler recorded the timeout a second time, so its report was given
    twice. Each line of what the scan reports is given once. The control raises
    nothing."""
    context = _context(tmp_path)
    scanner = _IgnoresARunWithATimeout(config=_Config(), context=context)
    fired: List[bool] = []
    if recorder is not None:
        raising, fired = _raising(getattr(_IgnoresARunWithATimeout, recorder), False)
        monkeypatch.setattr(_IgnoresARunWithATimeout, recorder, raising)

    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        return_value=dict(_TIMED_OUT_AT_5),
    ):
        container = _run(context, scanner)

    assert recorder is None or fired, "the recorder never raised, so this shows nothing"
    assert container.status == ScannerStatus.ERROR, container.status
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    for lines in (scanner.errors, container.errors, raw.get("errors", [])):
        assert not _repeated(lines), _repeated(lines)
    assert any("timed out" in str(line) for line in raw.get("errors", [])), raw


#: Per case: the response's flag, the recorder the handler runs again for a
#: response that keeps that flag, and the response. The kept-flag recorder is its
#: own case: it is the one the handler's fallback calls for every kept flag.
_RECORDED_AGAIN = {
    "timed_out": ("timed_out", "_record_timeout", _TIMED_OUT_AT_5),
    "spawn_failed": (
        "spawn_failed",
        "_record_spawn_failure",
        {
            "returncode": SPAWN_FAILURE_RETURNCODE,
            "spawn_failed": True,
            "error": "Could not start tool: Bad address",
            "stderr": "Could not start tool: Bad address",
        },
    ),
    "post_run_error": (
        "post_run_error",
        "_record_post_run_error",
        {
            "returncode": 3,
            "post_run_error": True,
            "spawn_failed": False,
            "error": "ASH could not record the output of tool: disk full",
        },
    ),
    "kept-flag-recorder": ("timed_out", "_record_kept_flag", _TIMED_OUT_AT_5),
}


@pytest.mark.parametrize("case", sorted(_RECORDED_AGAIN))
@pytest.mark.unit
def test_a_recorder_that_always_raises_stays_inside_run_subprocess(
    tmp_path, monkeypatch, case
):
    """The recorder of the response's own flag raises every time, and the handler's
    second call to it raised out of _run_subprocess. Each recorder runs at most once
    for a response: _run_subprocess returns the response with its flag and code and
    the recorder's error added, and the scan is still ERROR. The kept-flag recorder
    is covered by name: the state it records is what grades the scan, so a raise in
    it must neither escape nor leave that state unset."""
    flag, recorder, flagged = _RECORDED_AGAIN[case]
    context = _context(tmp_path)
    scanner = _IgnoresARunWithATimeout(config=_Config(), context=context)
    raising, fired = _raising(getattr(_IgnoresARunWithATimeout, recorder), True)
    monkeypatch.setattr(_IgnoresARunWithATimeout, recorder, raising)

    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        side_effect=lambda *args, **kwargs: dict(flagged),
    ):
        try:
            response = scanner._run_subprocess(
                command=_tool(0), results_dir=tmp_path / "results", timeout=5
            )
        except RuntimeError as error:
            pytest.fail(f"the recorder's error raised out of _run_subprocess: {error}")
        container = _run(context, scanner)

    assert fired, "the recorder never raised, so the cell shows nothing"
    assert response.get(flag) is True, response
    assert response["returncode"] == flagged["returncode"], response
    error = response.get("error") or ""
    assert error.startswith(flagged["error"]), response
    assert _RECORDER_BROKE in error, response
    assert container.status == ScannerStatus.ERROR, container.status
    if recorder == "_record_kept_flag":
        # The kept flag's state is what grades the scan, so it still lands even
        # though the recorder that writes it raised.
        assert scanner.scan_kept_flag is not None, "the kept flag was not recorded"


def _catch_all_responses(tmp_path) -> Dict[str, Dict[str, Any]]:
    """One response from each catch-all and conversion this suite owns."""
    responses: Dict[str, Dict[str, Any]] = {}
    run = "automated_security_helper.utils.subprocess_utils._run_plain"

    with patch(run, side_effect=RuntimeError("spawn raised")):
        responses["spawn raises"] = run_command_with_output_handling(
            ["tool"], results_dir=tmp_path / "a"
        )
    with patch.object(
        subprocess_utils, "_prepare_spawn", side_effect=ValueError("plan raised")
    ):
        responses["pre-spawn raises"] = run_command_with_output_handling(
            ["tool"], results_dir=tmp_path / "b"
        )
    # argv[0] is a relative path into a directory that is not there: the OS
    # refuses the exec, and nothing resolves it against PATH in its place. An
    # exit-0 `tool` IS on PATH and the run starts from tmp_path, so a fallback
    # that looked the bare name up on PATH would exit 0 and fail the 127 pin.
    on_path = tmp_path / "on-path"
    on_path.mkdir()
    lookalike = on_path / "tool"
    lookalike.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    lookalike.chmod(0o755)
    held = os.getcwd()
    os.chdir(tmp_path)
    try:
        with patch.dict(
            os.environ, {"PATH": f"{on_path}{os.pathsep}{os.environ.get('PATH', '')}"}
        ):
            responses["a relative argv0"] = run_command_with_output_handling(
                ["no-such-directory/tool", "--version"], results_dir=tmp_path / "i"
            )
    finally:
        os.chdir(held)
    for exit_code in (0, 1):
        with _log_write_fails():
            responses[f"exits {exit_code}, log write raises"] = (
                run_command_with_output_handling(
                    _tool(exit_code), results_dir=tmp_path / f"c{exit_code}"
                )
            )
    with patch(run, side_effect=subprocess.TimeoutExpired(cmd=["tool"], timeout=1)):
        responses["timeout"] = run_command_with_output_handling(
            ["tool"], results_dir=tmp_path / "d", timeout=1
        )
    with _waiting_fails_while_it_runs():
        responses["waiting fails while it runs"] = run_command_with_output_handling(
            _SLEEPS, results_dir=tmp_path / "g"
        )
    if os.name == "posix":
        responses["the tool ended on a signal ASH did not send"] = (
            run_command_with_output_handling(
                _ends_by_its_own(signal.SIGHUP), results_dir=tmp_path / "h"
            )
        )

    context = _context(tmp_path)
    before = _IgnoresTheResponse(config=_Config(), context=context)
    with patch.object(
        subprocess_utils,
        "run_command_with_output_handling",
        side_effect=RuntimeError("raised before the run"),
    ):
        responses["_run_subprocess, before a run"] = before._run_subprocess(
            command=_tool(0), results_dir=tmp_path / "e"
        )
    after = _ResponseHandlingFails(config=_Config(), context=context)
    responses["_run_subprocess, after a run"] = after._run_subprocess(
        command=_tool(0), results_dir=tmp_path / "f"
    )
    return responses


@pytest.mark.integration
def test_every_response_with_an_error_names_what_happened(tmp_path):
    responses = _catch_all_responses(tmp_path)

    unflagged = {
        name: response
        for name, response in responses.items()
        if "error" in response and not _has_a_flag(response)
    }
    assert not unflagged, unflagged
    # The control: the property is not vacuous, every case here did carry an error.
    assert all("error" in response for response in responses.values()), responses


@pytest.mark.integration
def test_no_code_appears_only_with_post_run_error(tmp_path):
    """returncode None means ASH failed while the tool still ran and stopped it, so
    a response carries it only with post_run_error."""
    responses = _catch_all_responses(tmp_path)

    unflagged = {
        name: response
        for name, response in responses.items()
        if response.get("returncode", 0) is None
        and response.get("post_run_error") is not True
    }
    assert not unflagged, unflagged
    # The control: a tool ASH stopped is one of the cases, and it has no code.
    stopped = responses["waiting fails while it runs"]
    assert stopped["returncode"] is None, stopped


@pytest.mark.unit
def test_a_rejected_result_names_what_happened():
    """A remote executor's rejected result counts, though nothing here sets it."""
    rejected = {"error": "the result was rejected", "result_rejected": True}

    assert _has_a_flag(rejected)
    assert not _has_a_flag({"error": "unflagged"}), "the property is vacuous"


@pytest.mark.integration
def test_control_never_started_is_127(tmp_path):
    responses = _catch_all_responses(tmp_path)

    for name in (
        "spawn raises",
        "pre-spawn raises",
        "a relative argv0",
        "_run_subprocess, before a run",
    ):
        assert responses[name]["returncode"] == SPAWN_FAILURE_RETURNCODE, name
        assert responses[name]["spawn_failed"] is True, name
        assert responses[name].get("post_run_error") in (None, False), name
