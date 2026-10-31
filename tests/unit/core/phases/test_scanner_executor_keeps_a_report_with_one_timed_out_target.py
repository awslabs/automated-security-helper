# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One timed-out target among several does not cost the others their findings.

A scanner that runs its tool once per target (cfn-guard runs once per template)
records a run that timed out in its own accounting: the target counts as failed,
the failure is named in its errors, and the scan goes on to the next target and
returns the merged report. The executor read the plugin's kept timeout flag alone
and raised, which replaced that whole report with one failure record, so one
template's timeout lost every other template's findings.

Now the report is kept when the plugin counted a failed target among more
attempted and returned a result; the row is still ERROR, with the timeout on it.
The controls are the shapes that are discarded as before: a scanner whose every
attempted target timed out, and one that counts no targets at all.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock

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

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: The run of one template, killed at its timeout.
_TIMED_OUT: Dict[str, Any] = {
    "stdout": "",
    "stderr": "",
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}

#: The run of a template that rendered.
_FINISHED: Dict[str, Any] = {"stdout": "", "stderr": "", "returncode": 0}

#: What the scan returns: the merged report of the templates that rendered.
_MERGED_REPORT: Dict[str, Any] = {"severity_counts": {"high": 1}}


class _Config(ScannerPluginConfigBase):
    name: str = "per-template"


class _PerTemplateScanner(ScannerPluginBase):
    """Runs its tool once per template and, when it counts targets, records a
    killed run as one failed target and goes on, as cfn-guard does."""

    tool: str = sys.executable
    templates: int = 2
    counts_targets: bool = True
    targets_attempted: int | None = None
    targets_failed: int = 0

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        if self.counts_targets:
            self.targets_attempted = 0
            self.targets_failed = 0
        for index in range(self.templates):
            response = self._run_subprocess(
                command=[self.tool, "-c", "pass"],
                results_dir=self.results_dir,
                timeout=5,
            )
            if not self.counts_targets:
                continue
            self.targets_attempted += 1
            if response.get("timed_out"):
                self.targets_failed += 1
                self.errors.append(f"template-{index}.yaml: the tool was killed")
        return dict(_MERGED_REPORT)


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "template-0.yaml").write_text("Resources: {}\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _row(tmp_path, monkeypatch, responses: List[Dict[str, Any]], **scanner_fields):
    """One executor row for a scanner whose runs answer ``responses`` in order."""
    context = _context(tmp_path)
    scanner = _PerTemplateScanner(
        config=_Config(), context=context, templates=len(responses), **scanner_fields
    )
    scanner.use_uv_tool = False
    pending = [dict(response) for response in responses]

    def run(**kwargs):
        return pending.pop(0)

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", run)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "per-template", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return row


def test_the_other_templates_report_is_kept_and_the_row_is_error(tmp_path, monkeypatch):
    """One of two templates timed out: the merged report the scan returned is the
    row's result, and the row says ERROR with the timeout on it."""
    row = _row(tmp_path, monkeypatch, [_TIMED_OUT, _FINISHED])

    assert isinstance(row.raw_results, dict), row.raw_results
    assert row.raw_results.get("severity_counts") == {"high": 1}, row.raw_results
    assert row.raw_results.get("status") != "failed", row.raw_results
    assert row.status == ScannerStatus.ERROR
    assert any("timed out" in str(error) for error in row.errors), row.errors


def test_a_scanner_whose_every_template_timed_out_is_discarded_as_before(
    tmp_path, monkeypatch
):
    """The control: with no template rendered there is nothing to keep, and the
    row holds the failure record."""
    row = _row(tmp_path, monkeypatch, [_TIMED_OUT])

    assert isinstance(row.raw_results, dict), row.raw_results
    assert row.raw_results.get("status") == "failed", row.raw_results
    assert "severity_counts" not in row.raw_results
    assert row.status == ScannerStatus.ERROR


def test_a_scanner_that_counts_no_targets_is_discarded_as_before(tmp_path, monkeypatch):
    """The control: a scanner that makes no claim about targets cannot have
    recorded the failure itself, so its result is not trusted."""
    row = _row(tmp_path, monkeypatch, [_TIMED_OUT, _FINISHED], counts_targets=False)

    assert isinstance(row.raw_results, dict), row.raw_results
    assert row.raw_results.get("status") == "failed", row.raw_results
    assert "severity_counts" not in row.raw_results
    assert row.status == ScannerStatus.ERROR
