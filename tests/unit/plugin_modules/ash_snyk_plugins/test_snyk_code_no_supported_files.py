# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code on a tree with no file Snyk supports is SKIPPED, not ERROR.

``snyk code test`` exits 3 when the target holds no file it supports ("no supported
projects detected"); 0 and 1 are a completed scan and 2 is a failure. scan() raised
ScannerError on every exit code but 0, so a repository with no file Snyk Code reads
-- a Terraform-only or YAML-only tree, say -- recorded snyk-code ERROR, and the
default completeness gate failed the scan for a scanner that had nothing to do.

The maintainer's ruling: exit 3 is SKIPPED. scan() now records that it evaluated
nothing (``targets_attempted = 0``), which the executor grades SKIPPED. Exit 2 still
raises.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)


@pytest.fixture
def context(tmp_path: Path, monkeypatch) -> PluginContext:
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.tf").write_text('resource "null_resource" "x" {}\n')
    output = tmp_path / "output"
    (output / "converted").mkdir(parents=True)
    fake = tmp_path / "bin" / "snyk"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(fake))
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


def _exits(code: int):
    """A snyk run that exits ``code`` and writes no SARIF, as snyk does on 2 and 3."""

    def _side_effect(self, command, **kwargs):
        self.exit_code = max(self.exit_code, code)
        return {"stdout": "", "stderr": "", "returncode": code}

    return _side_effect


def _scanner(context: PluginContext) -> SnykCodeScanner:
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def test_exit_three_evaluated_nothing_and_does_not_raise(context):
    scanner = _scanner(context)
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(3)
    ):
        result = scanner.scan(target=context.source_dir, target_type="source")

    assert result is not False and result is not None
    assert scanner.targets_attempted == 0


def test_exit_three_is_graded_skipped(context):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(3)
    ):
        (container,) = executor._execute_scanner(
            "snyk-code",
            _scanner(context),
            [{"path": context.source_dir, "type": "source"}],
        )

    assert container.status == ScannerStatus.SKIPPED, container.raw_results


def test_control_exit_two_still_raises(context):
    scanner = _scanner(context)
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(2)
    ):
        with pytest.raises(ScannerError, match="exit code 2"):
            scanner.scan(target=context.source_dir, target_type="source")


def test_a_later_target_does_not_inherit_the_zero(context):
    """The count is reset per target, so the next run makes its own claim."""
    scanner = _scanner(context)
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(3)
    ):
        scanner.scan(target=context.source_dir, target_type="source")
    scanner.exit_code = 0
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(2)
    ):
        with pytest.raises(ScannerError):
            scanner.scan(target=context.source_dir, target_type="source")

    assert scanner.targets_attempted is None
