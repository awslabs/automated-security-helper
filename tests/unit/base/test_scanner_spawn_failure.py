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
a scanner whose own ``scan()`` returned normally. EFAULT and ETXTBSY are retried
once. These tests raise the OSError at ``subprocess.run``, underneath every layer
that has to carry it.
"""

import errno
import sys
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

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_SUBPROCESS_RUN = "automated_security_helper.utils.subprocess_utils.subprocess.run"
_SUBPROCESS_POPEN = "automated_security_helper.utils.subprocess_utils.subprocess.Popen"
_EFAULT = OSError(errno.EFAULT, "Bad address", "/usr/local/bin/uv")


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch):
    monkeypatch.setattr(subprocess_utils, "_SPAWN_RETRY_DELAY_SECONDS", 0)


class TestSpawnFailureReturnCode:
    def test_is_127_with_the_cause_in_stderr(self, tmp_path):
        with patch(_SUBPROCESS_RUN, side_effect=_EFAULT):
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

    def test_a_real_missing_executable(self, tmp_path):
        """No mock: the OS itself refuses to start a path that does not exist."""
        missing = str(tmp_path / "no-such-tool")
        response = run_command_with_output_handling([missing], results_dir=tmp_path)

        assert response["returncode"] == 127
        assert response["spawn_failed"] is True

    def test_run_command(self):
        with patch(_SUBPROCESS_RUN, side_effect=_EFAULT):
            result = run_command(["uv", "--version"])

        assert isinstance(result, SpawnFailedProcess)
        assert result.returncode == 127
        assert "Bad address" in result.stderr

    def test_run_command_with_check_still_raises(self):
        with (
            patch(_SUBPROCESS_RUN, side_effect=_EFAULT),
            pytest.raises(OSError) as excinfo,
        ):
            run_command(["uv", "--version"], check=True)
        assert excinfo.value.errno == errno.EFAULT

    def test_run_command_stream_output(self):
        with patch(_SUBPROCESS_POPEN, side_effect=_EFAULT):
            assert run_command_stream_output(["uv", "--version"]) == 127

    def test_a_command_that_ran_and_exited_127_is_not_a_spawn_failure(self):
        result = run_command([sys.executable, "-c", "raise SystemExit(127)"])

        assert result.returncode == 127
        assert not isinstance(result, SpawnFailedProcess)

    def test_an_oserror_writing_logs_is_not_a_spawn_failure(self, tmp_path):
        """Only the spawn is guarded: the tool ran, so this is the generic path."""
        with patch.object(
            subprocess_utils, "_write_stream_log", side_effect=OSError("disk full")
        ):
            response = run_command_with_output_handling(
                [sys.executable, "-c", "print('ran')"], results_dir=tmp_path
            )

        assert response["returncode"] == 1
        assert "spawn_failed" not in response


class TestTransientSpawnFailureIsRetriedOnce:
    @pytest.mark.parametrize("code", [errno.EFAULT, errno.ETXTBSY])
    def test_a_second_attempt_that_starts_is_used(self, code):
        ran = MagicMock(returncode=0, stdout="ok", stderr="")
        with patch(
            _SUBPROCESS_RUN, side_effect=[OSError(code, "transient"), ran]
        ) as run:
            response = run_command_with_output_handling(
                ["uv"], stdout_preference="return"
            )

        assert run.call_count == 2
        assert response["returncode"] == 0
        assert response["stdout"] == "ok"

    def test_a_second_failure_is_reported(self):
        with patch(_SUBPROCESS_RUN, side_effect=[_EFAULT, _EFAULT]) as run:
            response = run_command_with_output_handling(["uv"])

        assert run.call_count == 2
        assert response["returncode"] == 127

    def test_other_errnos_are_not_retried(self):
        missing = FileNotFoundError(errno.ENOENT, "No such file", "uv")
        with patch(_SUBPROCESS_RUN, side_effect=missing) as run:
            response = run_command_with_output_handling(["uv"])

        assert run.call_count == 1
        assert response["returncode"] == 127


def test_uv_tool_runner_carries_the_flag(tmp_path):
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch(_SUBPROCESS_RUN, side_effect=_EFAULT),
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


def test_semgrep_through_uv_is_not_accepted(semgrep):
    """The reported case: accepted codes include 1, and a uv that cannot exec
    must still fail the scan, naming the cause rather than the missing SARIF."""
    scanner, source = semgrep
    assert 1 in scanner.success_exit_codes
    assert scanner.use_uv_tool, "the test must exercise the uv path"

    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch.object(SemgrepScanner, "validate_plugin_dependencies", return_value=True),
        patch(_SUBPROCESS_RUN, side_effect=_EFAULT) as run,
        pytest.raises(ScannerError) as excinfo,
    ):
        scanner.scan(target=source, target_type="source")

    assert run.call_count == 2, "EFAULT is retried once, then reported"
    assert run.call_args.args[0][1:3] == ["tool", "run"]
    assert scanner.exit_code == 127
    assert not scanner._exit_code_accepted()
    assert scanner.scan_spawn_failure and "Bad address" in scanner.scan_spawn_failure
    message = str(excinfo.value)
    assert "could not start its tool" in message, message
    assert "Bad address" in message, message
    assert "exit code 127: not an accepted exit code" in message, message


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


class TestExecutorReportsError:
    def test_even_when_scan_returned_normally(self, tmp_path):
        context = _context(tmp_path)
        scanner = _LenientScanner(config=_Config(), context=context)
        scanner.tool = str(tmp_path / "no-such-tool")

        (container,) = _run(context, scanner)

        assert container.status == ScannerStatus.ERROR
        assert container.exit_code == 127
        first = container.raw_results["errors"][0]
        assert "lenient could not start its tool on source" in first, first

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
