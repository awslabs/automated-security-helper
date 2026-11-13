# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unused report is read as a list of entries and found as a regular file.

Why this file exists
--------------------
Lint iterated the report's ``unused_suppressions`` as it found it, so a report
that held ``null`` or a number there ended ``ash config lint --fix-unused`` in a
``TypeError``, where the fixer, which guarded the shape, returned with nothing to
do. The one reader of the report (``_read_unused_report``) now refuses a value
that is not a list, so lint warns as it does for any report it cannot read and
the fixer returns as before.

The lookup of the report also accepted any name that could be statted: a
directory, a FIFO or a device was handed to the reader, and the open of a FIFO
waits for a writer. Only a regular file is a report.
"""

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)

pytestmark = pytest.mark.unit

CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)


def _layout(tmp_path: Path):
    config = tmp_path / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_bytes(CONFIG.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    return config, reports / "ash.unused-suppressions.json"


@pytest.mark.parametrize(
    "listed",
    [pytest.param(None, id="null"), pytest.param(5, id="number")],
)
def test_lint_warns_about_a_report_whose_list_is_not_a_list(tmp_path, listed):
    """Red at the base: iterating the value raised ``TypeError`` out of lint."""
    config, report = _layout(tmp_path)
    report.write_text(json.dumps({"unused_suppressions": listed}), encoding="utf-8")

    result = ConfigLinter.lint(config, check_unused=True)

    warnings = [
        i
        for i in result.issues
        if i.category == LintCategory.SUPPRESSION_UNUSED
        and i.severity == LintSeverity.WARNING
    ]
    assert len(warnings) == 1, result.issues
    assert "Failed to read unused suppressions report" in warnings[0].message


@pytest.mark.parametrize(
    "listed",
    [pytest.param(None, id="null"), pytest.param(5, id="number")],
)
def test_the_fixer_still_returns_the_file_unchanged_for_it(tmp_path, listed):
    config, report = _layout(tmp_path)
    report.write_text(json.dumps({"unused_suppressions": listed}), encoding="utf-8")
    before = config.read_bytes().decode("utf-8")

    fixed, issues, _stamp = ConfigLinter.fix_unused_suppressions(config)

    assert issues == []
    assert fixed == before


def test_a_report_with_a_list_is_still_read(tmp_path):
    """The positive control: an empty list and a list of entries both read."""
    config, report = _layout(tmp_path)
    report.write_text(json.dumps({"unused_suppressions": []}), encoding="utf-8")
    assert ConfigLinter._read_unused_report(report) == {"unused_suppressions": []}

    entry = {"path": "src/a.py", "rule_id": "B101", "reason": "one"}
    report.write_text(json.dumps({"unused_suppressions": [entry]}), encoding="utf-8")
    result = ConfigLinter.lint(config, check_unused=True)
    unused = [
        i
        for i in result.issues
        if i.category == LintCategory.SUPPRESSION_UNUSED
        and i.message.startswith("Unused suppression:")
    ]
    assert len(unused) == 1


def test_a_directory_at_the_report_name_is_no_report(tmp_path):
    """Red at the base: the directory was returned as the report."""
    config, report = _layout(tmp_path)
    report.mkdir()

    assert ConfigLinter.find_unused_report(config) == (None, None)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform has no FIFOs")
def test_a_fifo_at_the_report_name_is_no_report(tmp_path):
    """Red at the base: the FIFO was returned as the report. Only the lookup
    runs here, which stats the name and never opens it."""
    config, report = _layout(tmp_path)
    os.mkfifo(report)

    assert ConfigLinter.find_unused_report(config) == (None, None)


def test_a_regular_report_is_found(tmp_path):
    """The positive control for the two tests above."""
    config, report = _layout(tmp_path)
    report.write_text("{}", encoding="utf-8")

    found, stamp = ConfigLinter.find_unused_report(config)

    assert found == report
    assert stamp is not None
