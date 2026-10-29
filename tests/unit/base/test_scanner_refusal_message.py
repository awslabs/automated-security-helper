# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that refuses a target before its tool starts says so, and no more.

The template ``scan()`` wraps every failure in ``_describe_scan_failure``, which
adds the tool's exit code with a verdict on it and what stderr said. For a failure
before the tool started, such as bandit refusing a target whose link it cannot
leave out, the exit code was the field's default and the message read "(exit code
0: an accepted exit code for this scanner). No stderr captured; checked
<results>/BanditScanner.stderr.log, which the tool did not write": a verdict on a
run that never happened, appended to the refusal.

Now a failure before the tool started gives the refusal and says the tool was not
started; one after it keeps the exit code, its verdict and stderr.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _fake_scanner(tmp_path: Path, *, refuse: bool, exit_code: int = 0):
    """A scanner over the real template whose argument resolution can refuse."""
    source_dir = tmp_path / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    results_file = output_dir / "scanners" / "fake" / "results.json"

    class _FakeScanner(ScannerPluginBase):
        fake_refuse: ClassVar[bool] = refuse
        fake_exit_code: ClassVar[int] = exit_code
        fake_results_file: ClassVar[Path] = results_file

        def model_post_init(self, context) -> None:
            return None

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            if self.fake_refuse:
                raise ScannerError(f"Not running fake-tool on {target}: refused")
            return (["fake-tool", "--scan"], self.fake_results_file, None)

        def _run_subprocess(self, command, results_dir=None, **kwargs):
            self.exit_code = self.fake_exit_code
            return {"returncode": self.fake_exit_code}

    context = MagicMock()
    context.source_dir = source_dir
    context.output_dir = output_dir
    context.work_dir = tmp_path / "work"
    scanner = _FakeScanner.model_construct()
    scanner.context = context
    scanner.config = MagicMock()
    scanner.config.name = "fake-tool"
    scanner.errors = []
    scanner.output = []
    scanner.exit_code = 0
    scanner.results_dir = output_dir / "scanners" / "fake"
    return scanner


def _failure(scanner, target: Path) -> str:
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=target, target_type="source")
    return str(raised.value)


def test_a_refusal_before_the_tool_starts_carries_no_exit_code(tmp_path):
    scanner = _fake_scanner(tmp_path, refuse=True)

    message = _failure(scanner, tmp_path / "src")

    assert "refused" in message
    assert "was not started" in message
    assert "exit code" not in message
    assert "stderr" not in message.lower()


def test_a_tool_that_ran_and_failed_keeps_its_exit_code(tmp_path):
    """The control: the results file is missing after a rejected exit code."""
    scanner = _fake_scanner(tmp_path, refuse=False, exit_code=7)

    message = _failure(scanner, tmp_path / "src")

    assert "exit code 7: not an accepted exit code" in message
    assert "was not started" not in message


#: A marker the planted stderr log carries. The message quotes it only when the
#: log was read.
_LOG_MARKER = "planted-stderr-log-marker-5c2"


def _scan_with_a_planted_log(tmp_path: Path, exit_code: int) -> str:
    """Run the template with a stub tool that writes a stderr log, then fail."""
    scanner = _fake_scanner(tmp_path, refuse=False, exit_code=exit_code)
    log = scanner.fake_results_file.parent / "_FakeScanner.stderr.log"

    def _tool_that_writes_a_log(command, results_dir=None, **kwargs):
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"{_LOG_MARKER}: the tool's own text\n", encoding="utf-8")
        scanner.exit_code = exit_code
        return {"returncode": exit_code}

    with patch.object(scanner, "_run_subprocess", side_effect=_tool_that_writes_a_log):
        return _failure(scanner, tmp_path / "src")


def test_a_rejected_result_never_has_its_stderr_log_read(tmp_path):
    """Exit code 7 is outside the accepted set: the result is rejected, so the
    log the tool wrote is not read for the failure message."""
    message = _scan_with_a_planted_log(tmp_path, exit_code=7)

    assert "exit code 7: not an accepted exit code" in message
    assert _LOG_MARKER not in message


def test_a_rejected_results_message_names_the_log_as_not_read(tmp_path):
    """The message says the log was not read and where it is, in place of the
    "No stderr captured; checked ..." wording, which reads as an empty log."""
    message = _scan_with_a_planted_log(tmp_path, exit_code=7)

    assert "Stderr not read: ASH refused this result" in message
    assert "_FakeScanner.stderr.log" in message
    assert "were not read" in message
    assert "No stderr captured" not in message


def test_a_failure_after_an_accepted_exit_code_still_reads_the_log(tmp_path):
    """The control: the code is accepted and the results file is missing, so
    the same planted log is read and quoted."""
    message = _scan_with_a_planted_log(tmp_path, exit_code=0)

    assert "an accepted exit code for this scanner" in message
    assert _LOG_MARKER in message


def test_a_run_with_no_exit_code_is_described_when_a_results_file_is_given(tmp_path):
    """The verdict is set on every branch: a tool that never ran has no code
    to accept, and the description still comes back whole."""
    scanner = _fake_scanner(tmp_path, refuse=False)
    scanner.exit_code = None

    message = scanner._describe_scan_failure(
        RuntimeError("boom"), scanner.fake_results_file
    )

    assert "the scan reported no exit code" in message
    assert "accepted exit code" not in message


def test_a_run_that_could_not_be_stopped_is_described_with_a_results_file(tmp_path):
    scanner = _fake_scanner(tmp_path, refuse=False, exit_code=124)
    scanner._scan_could_not_stop = "the tool did not end after the kill"

    message = scanner._describe_scan_failure(
        RuntimeError("boom"), scanner.fake_results_file
    )

    assert "no exit code: ASH could not stop the tool" in message
    assert "exit code 124" not in message


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_bandits_link_refusal_carries_no_exit_code(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "outside.py").write_text("y = 2\n", encoding="utf-8")
    # A glob character: bandit's --exclude cannot leave out this path alone.
    (source / "l[1].py").symlink_to(tmp_path / "outside.py")
    output = tmp_path / "ash-output"
    output.mkdir()
    scanner = BanditScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=AshConfig(),
        ),
        config=BanditScannerConfig(),
    )
    scanner.dependencies_satisfied = True

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess") as run,
    ):
        message = _failure(scanner, source)

    run.assert_not_called()
    assert "'l[1].py'" in message
    assert "link leaves the scanned tree" in message
    assert "bandit was not started" in message
    assert "accepted exit code" not in message
    assert "exit code" not in message
