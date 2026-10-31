# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unused-suppressions report names the scanners that did not run.

Why this file exists
--------------------
A suppression is matched against the findings a scanner reports. A scanner
that did not run (tool missing, error, skipped, excluded) reported nothing, so
a suppression for one of its findings could not be matched and read as unused,
with the report's "remove it" advice and no caveat. The report now lists those
scanners and qualifies its counts; a suppression carries no scanner name, so
it cannot say which entries are affected.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)

pytestmark = pytest.mark.unit


def _context(tmp_path) -> PluginContext:
    config = AshConfig()
    config.global_settings.suppressions = [
        AshSuppression(path="src/app.py", rule_id="B201", reason="one"),
    ]
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _model(**scanners) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.used_suppressions = set()
    model.scanner_results = {
        name: ScannerTargetStatusInfo(**fields) for name, fields in scanners.items()
    }
    return model


def test_scanners_that_did_not_run_are_named_with_a_caveat(tmp_path):
    """Red at the base: the report had no such keys."""
    context = _context(tmp_path)
    model = _model(
        bandit={"status": ScannerStatus.PASSED},
        semgrep={"status": ScannerStatus.MISSING},
        checkov={"status": ScannerStatus.ERROR},
        grype={"status": ScannerStatus.SKIPPED},
    )

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert report["scanners_not_run"] == ["checkov", "grype", "semgrep"]
    assert "did not run" in report["scope_caveat"]
    assert "semgrep" in report["scope_caveat"]
    assert report["summary"]["unused_suppressions"] == 1


def test_the_markdown_copy_carries_the_caveat(tmp_path):
    context = _context(tmp_path)
    UnusedSuppressionsReporter(context=context).report(
        _model(semgrep={"status": ScannerStatus.MISSING})
    )

    markdown = (
        context.output_dir / "reports" / "ash.unused-suppressions.md"
    ).read_text(encoding="utf-8")
    assert "Scanners that did not run" in markdown
    assert "semgrep" in markdown


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param(
            {"status": ScannerStatus.PASSED, "dependencies_satisfied": False},
            id="dependencies-not-satisfied",
        ),
        pytest.param(
            {"status": ScannerStatus.PASSED, "excluded": True},
            id="excluded",
        ),
    ],
)
def test_each_reason_a_scanner_did_not_run_counts_on_its_own(tmp_path, fields):
    """Each condition the reporter reads is set alone, with a PASSED status,
    so the row counts as not run for that condition and no other. The
    fixture's values are the type a scan writes to ``scanner_results``
    (``Dict[str, ScannerTargetStatusInfo]``, a flat record per scanner)."""
    context = _context(tmp_path)
    model = _model(bandit={"status": ScannerStatus.PASSED}, semgrep=fields)

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert report["scanners_not_run"] == ["semgrep"]


def test_a_scan_where_every_scanner_ran_carries_no_caveat(tmp_path):
    """The control: the existing shape is unchanged when nothing was skipped."""
    context = _context(tmp_path)
    model = _model(
        bandit={"status": ScannerStatus.PASSED},
        semgrep={"status": ScannerStatus.FAILED},
    )

    report = json.loads(UnusedSuppressionsReporter(context=context).report(model))

    assert "scanners_not_run" not in report
    assert "scope_caveat" not in report
