# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code on a tree with no file Snyk supports is SKIPPED, not ERROR.

``snyk code test`` exits 3 when the target holds no file it supports ("no supported
projects detected"); 0 and 1 are a completed scan and 2 is a failure. scan() raised
ScannerError on every exit code but 0, so a repository with no file Snyk Code reads
-- a Terraform-only or YAML-only tree, say -- recorded snyk-code ERROR, and the
default completeness gate failed the scan for a scanner that had nothing to do.

The rule: exit 3 is SKIPPED. scan() now records that it evaluated
nothing (``targets_attempted = 0``), which the executor grades SKIPPED. Exit 2 still
raises.
"""

from __future__ import annotations

import json
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


pytestmark = pytest.mark.unit


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
        # scan() holds no exit code until snyk returns one, as the template does.
        self.exit_code = max(self.exit_code or 0, code)
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


def test_a_later_target_does_not_inherit_the_exit_code_or_the_zero(context):
    """The exit code and the count are reset per target, so a run that exits 2 after
    one that exited 3 is a failure, not a second "no supported files"."""
    scanner = _scanner(context)
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(3)
    ):
        scanner.scan(target=context.source_dir, target_type="source")
    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=_exits(2)
    ):
        with pytest.raises(ScannerError):
            scanner.scan(target=context.source_dir, target_type="source")

    assert scanner.targets_attempted is None


#: One result, so the converted target's findings are what its own run reported.
SNYK_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "SnykCode", "rules": [{"id": "python/X"}]}},
            "results": [
                {
                    "ruleId": "python/X",
                    "level": "error",
                    "message": {"text": "x"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "nb.py"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_the_converted_target_after_an_exit_three_source_reports_its_findings(
    context, monkeypatch
):
    """One instance over both targets, as the executor runs it, with the real
    _run_subprocess: the source exits 3, the converted tree exits 0 with a finding.
    The converted target was graded SKIPPED with no findings, because exit_code kept
    the worst code of every run of the instance (base/plugin_base.py)."""
    from automated_security_helper.utils import subprocess_utils

    (context.work_dir / "nb.py").write_text("print(1)\n")

    def run(command, *args, **kwargs):
        command = [str(part) for part in command]
        sarif = next(
            (part for part in command if part.startswith("--sarif-file-output=")), None
        )
        # The source target is tested as a copy of the scan set, so its own
        # directory is not in the argv. Each target's results go to a directory
        # named for it, which is how the run for the source is told from the
        # converted one.
        if sarif is not None and Path(sarif.split("=", 1)[1]).parent.name == "source":
            return {"returncode": 3, "stdout": "", "stderr": "no supported files"}
        if sarif is not None:
            Path(sarif.split("=", 1)[1]).write_text(json.dumps(SNYK_SARIF))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", run)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    containers = executor._execute_scanner(
        "snyk-code",
        _scanner(context),
        [
            {"path": context.source_dir, "type": "source"},
            {"path": context.work_dir, "type": "converted"},
        ],
    )

    by_target = {container.target_type: container for container in containers}
    assert by_target["source"].status == ScannerStatus.SKIPPED
    converted = by_target["converted"]
    assert converted.finding_count == 1, (converted.status, converted.exit_code)
    assert converted.status != ScannerStatus.SKIPPED
