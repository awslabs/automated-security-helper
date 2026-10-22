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
