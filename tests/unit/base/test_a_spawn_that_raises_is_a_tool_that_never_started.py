# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A spawn that raises anything is a tool that never started, never a clean run.

Why this file exists
--------------------
test_scanner_spawn_failure.py covers an OSError from the spawn: exit code 127,
``spawn_failed``, and ERROR from ``ScannerExecutor`` however the scanner's own
``scan()`` read the missing output. Any other exception from the same spawn (a
RuntimeError from a sandbox wrapper, a ValueError from Popen's arguments, a bare
Exception) is reported the way the OSError path reports it: every catch-all
around the spawn gives exit code 127 and ``spawn_failed``, and a scanner whose
``scan()`` ignores the response is ERROR, never PASSED or reported with
findings it never had.

Each catch-all around a spawn now reports it as the OSError path does. The
exceptions are raised at the plain runner (``_run_plain``), before it started any
child, or at ``_prepare_spawn``, underneath every layer that has to carry them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    SPAWN_FAILURE_RETURNCODE,
    SpawnFailedProcess,
    run_command,
    run_command_stream_output,
    run_command_with_output_handling,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_PLAIN_RUNNER = "automated_security_helper.utils.subprocess_utils._run_plain"

#: Raised from the spawn; none is an OSError.
RAISED = {
    "RuntimeError": RuntimeError("the sandbox wrapper could not be prepared"),
    "ValueError": ValueError("stdout and stderr arguments may not be used"),
    "Exception": Exception("something else went wrong"),
}


def _raises(name: str) -> Exception:
    return RAISED[name]


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_command_with_output_handling_from_subprocess_run(tmp_path, name):
    with patch(_PLAIN_RUNNER, side_effect=_raises(name)):
        response = run_command_with_output_handling(
            ["tool", "--scan"], results_dir=tmp_path, class_name="Tool"
        )

    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response
    assert "Could not start tool --scan" in response["stderr"], response
    assert str(RAISED[name]) in response["stderr"], response


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_command_with_output_handling_from_prepare_spawn(
    tmp_path, monkeypatch, name
):
    monkeypatch.setattr(
        subprocess_utils, "_prepare_spawn", MagicMock(side_effect=_raises(name))
    )

    response = run_command_with_output_handling(["tool"], results_dir=tmp_path)

    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE, response
    assert response["spawn_failed"] is True, response


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_command(name):
    with patch(_PLAIN_RUNNER, side_effect=_raises(name)):
        result = run_command(["tool", "--version"])

    assert isinstance(result, SpawnFailedProcess), result
    assert result.returncode == SPAWN_FAILURE_RETURNCODE
    assert str(RAISED[name]) in result.stderr


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_command_stream_output(monkeypatch, name):
    monkeypatch.setattr(
        subprocess_utils, "_prepare_spawn", MagicMock(side_effect=_raises(name))
    )

    assert run_command_stream_output(["tool"]) == SPAWN_FAILURE_RETURNCODE


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_command_stream_output_from_popen(name):
    with patch(
        "automated_security_helper.utils.subprocess_utils.subprocess.Popen",
        side_effect=_raises(name),
    ):
        assert run_command_stream_output(["tool"]) == SPAWN_FAILURE_RETURNCODE


#: Arguments that are not str. The command line was joined with " ".join before
#: the spawn's try, so these raised TypeError out of every helper instead of being
#: reported: a Path names a tool that is not there, and an int is refused by Popen.
NOT_STR_ARGUMENTS = {
    "a Path": ["no-such-tool-for-this-cell", Path("scan-target")],
    "an int": ["no-such-tool-for-this-cell", 7],
}


@pytest.mark.parametrize("arguments", sorted(NOT_STR_ARGUMENTS))
@pytest.mark.parametrize(
    "spawn",
    [
        pytest.param(
            lambda args, tmp_path: run_command_with_output_handling(
                args, results_dir=tmp_path
            )["returncode"],
            id="run_command_with_output_handling",
        ),
        pytest.param(
            lambda args, tmp_path: run_command(args).returncode, id="run_command"
        ),
        pytest.param(
            lambda args, tmp_path: run_command_stream_output(args),
            id="run_command_stream_output",
        ),
    ],
)
def test_an_argument_that_is_not_a_str_is_reported(tmp_path, spawn, arguments):
    args = list(NOT_STR_ARGUMENTS[arguments])

    assert spawn(args, tmp_path) == SPAWN_FAILURE_RETURNCODE


def test_create_process_with_pipes_passes_a_path_argument_to_the_child():
    """create_process_with_pipes joins the command line for its log line too, and
    the join raised TypeError for a Path before Popen was reached."""
    process = subprocess_utils.create_process_with_pipes(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", Path("scan-target")]
    )
    stdout, _ = process.communicate(timeout=60)

    assert process.returncode == 0, stdout
    assert stdout.strip() == "scan-target", stdout


def test_create_process_with_pipes_reports_what_popen_refused(caplog):
    """An int Popen refuses reaches Popen, which logs and raises its own error;
    the join raised before anything was logged."""
    with caplog.at_level("ERROR", logger="ash"), pytest.raises(TypeError):
        subprocess_utils.create_process_with_pipes(list(NOT_STR_ARGUMENTS["an int"]))

    logged = [r.getMessage() for r in caplog.records]
    assert any("Error creating process with pipes" in m for m in logged), logged


def test_run_command_with_check_still_raises():
    with (
        patch(_PLAIN_RUNNER, side_effect=RAISED["RuntimeError"]),
        pytest.raises(RuntimeError),
    ):
        run_command(["tool", "--version"], check=True)


def test_the_uv_tool_runner_carries_the_flag(tmp_path):
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch(_PLAIN_RUNNER, side_effect=RAISED["RuntimeError"]),
    ):
        result = UVToolRunner().run_tool("semgrep", args=["scan"], results_dir=tmp_path)

    assert isinstance(result, SpawnFailedProcess), result
    assert result.returncode == SPAWN_FAILURE_RETURNCODE


@pytest.mark.parametrize(
    "spawn",
    [
        pytest.param(
            lambda tmp_path: run_command_with_output_handling(
                ["tool"], results_dir=tmp_path
            ),
            id="run_command_with_output_handling",
        ),
        pytest.param(lambda tmp_path: run_command(["tool"]), id="run_command"),
        pytest.param(
            lambda tmp_path: run_command_stream_output(["tool"]),
            id="run_command_stream_output",
        ),
    ],
)
def test_the_reason_is_logged_on_one_line(tmp_path, caplog, spawn):
    """The log line goes through shown_on_one_line: one line, the controls as
    escapes. The returned stderr keeps the text as it is, as a tool's own stderr
    in that field does; whatever displays it shows it there."""
    raised = RuntimeError("first line\nsecond line\x1b[31m")
    with (
        patch(_PLAIN_RUNNER, side_effect=raised),
        patch(
            "automated_security_helper.utils.subprocess_utils.subprocess.Popen",
            side_effect=raised,
        ),
    ):
        with caplog.at_level("ERROR", logger="ash"):
            result = spawn(tmp_path)

    logged = [
        r.getMessage() for r in caplog.records if "Could not start" in r.getMessage()
    ]
    assert len(logged) == 1, logged
    assert "\n" not in logged[0] and "\x1b" not in logged[0], logged
    assert "first line" in logged[0] and "second line" in logged[0], logged
    stderr = (
        result["stderr"]
        if isinstance(result, dict)
        else getattr(result, "stderr", None)
    )
    if stderr is not None:
        assert str(raised) in stderr, stderr


class _Config(ScannerPluginConfigBase):
    name: str = "lenient"


class _LenientScanner(ScannerPluginBase):
    """Overrides scan() and ignores the response, as several scanners do."""

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


@pytest.mark.parametrize("name", sorted(RAISED))
def test_a_scanner_that_ignores_the_response_is_an_error(tmp_path, name):
    context = _context(tmp_path)
    scanner = _LenientScanner(config=_Config(), context=context)

    with patch(_PLAIN_RUNNER, side_effect=_raises(name)):
        (container,) = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    assert container.exit_code == SPAWN_FAILURE_RETURNCODE, container.exit_code
    first = container.raw_results["errors"][0]
    assert "lenient could not start its tool on source" in first, first


@pytest.mark.parametrize("name", sorted(RAISED))
def test_run_subprocess_records_an_exception_before_the_run(
    tmp_path, monkeypatch, name
):
    """``_run_subprocess``'s own catch-all, for what raises before anything ran."""
    context = _context(tmp_path)
    scanner = _LenientScanner(config=_Config(), context=context)
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        MagicMock(side_effect=_raises(name)),
    )

    (container,) = _run(context, scanner)

    assert container.status == ScannerStatus.ERROR, container.status
    assert container.exit_code == SPAWN_FAILURE_RETURNCODE, container.exit_code
    reason = scanner.scan_spawn_failure
    assert reason is not None and str(RAISED[name]) in reason, reason
    assert "Could not start" in reason, reason


def test_control_a_tool_that_ran_is_not_a_spawn_failure(tmp_path):
    context = _context(tmp_path)
    scanner = _LenientScanner(config=_Config(), context=context)

    (container,) = _run(context, scanner)

    assert container.status != ScannerStatus.ERROR, container.status
    assert scanner.scan_spawn_failure is None


# A tool that started is never reported as one that never started. The spawn's
# own try in run_command_stream_output, and _run_subprocess's test for a response,
# keep what happens after the start out of the spawn-failure report.


def test_a_streamed_child_whose_cleanup_raises_is_not_a_spawn_failure(caplog):
    """The child started and streamed its output; stopping it then raised."""
    process = MagicMock()
    process.stdout = iter(["a line\n"])
    process.returncode = 0
    process.poll.return_value = None
    process.kill.side_effect = ProcessLookupError("no such process")

    with (
        patch(
            "automated_security_helper.utils.subprocess_utils.subprocess.Popen",
            return_value=process,
        ),
        caplog.at_level("ERROR", logger="ash"),
    ):
        code = run_command_stream_output(["tool"])

    assert code != SPAWN_FAILURE_RETURNCODE, code
    never_ran = [r for r in caplog.records if "Could not start" in r.getMessage()]
    assert not never_ran, [r.getMessage() for r in never_ran]


class _ResponseHandlingFails(_LenientScanner):
    def _process_command_response(self, response):
        raise RuntimeError("reading the run's response failed")


class _TimeoutBookkeepingFails(_LenientScanner):
    def _record_timeout(self, response, timeout):
        raise RuntimeError("recording the run's timeout failed")


@pytest.mark.parametrize(
    "scanner_class",
    [_ResponseHandlingFails, _TimeoutBookkeepingFails],
    ids=["_process_command_response", "_record_timeout"],
)
def test_an_exception_after_a_run_returned_is_not_a_spawn_failure(
    tmp_path, scanner_class
):
    """The tool ran and returned; ASH's own handling of the response raised."""
    context = _context(tmp_path)
    scanner = scanner_class(config=_Config(), context=context)

    response = scanner._run_subprocess(
        command=[sys.executable, "-c", "pass"], results_dir=tmp_path / "results"
    )

    assert response.get("spawn_failed") is not True, response
    assert scanner.scan_spawn_failure is None, scanner.scan_spawn_failure
    assert scanner.exit_code != SPAWN_FAILURE_RETURNCODE, scanner.exit_code
