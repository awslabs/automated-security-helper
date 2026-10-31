# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only a scanner a later scan would run holds ``--fix-unused`` back.

Why this file exists
--------------------
The unused-suppressions report lists the scanners that did not run
(``scanners_not_run``), and ``ash config lint --fix-unused`` comments nothing
out for a report that lists any. The reporter listed every scanner whose row
was SKIPPED, including a scanner that found nothing to scan (npm-audit without a
lockfile, cdk-nag without a template) and one the configuration turns off
(``enabled: false``). On an ordinary scan of a Python-only tree several scanners
read SKIPPED that way, so the key was never empty and the fixer never fixed
anything, with advice that told the operator to enable a scanner that had
nothing to scan.

The reporter now lists a scanner only when a later scan of the same tree and
configuration would run it: its tool missing, an error, a dependency not
satisfied, or an exclusion that belongs to one run (``--scanners``,
``--exclude-scanners``, a shard split, ``--python-only``). A row that is excluded
with no recorded reason stays listed, since the cause is then unknown.

Red at the base, by reading: ``_scanners_not_run`` put every SKIPPED row, every
excluded row and every row with ``dependencies_satisfied`` False in the list, so
each ``scanners_not_run`` absence and each "comments the entry out" assertion
below failed there (the key was present, the fixer returned the text unchanged).
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
)
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

CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: one\n"
)

#: A scanner that looked and found nothing to scan: SKIPPED, not excluded.
NOTHING_TO_SCAN = {
    "status": ScannerStatus.SKIPPED,
    "excluded": False,
    "dependencies_satisfied": True,
    "skipped_reason": "no lockfile in the scanned tree",
}

#: A scanner the configuration turns off, as the scan phase records it.
DISABLED_IN_CONFIG = {
    "status": ScannerStatus.SKIPPED,
    "excluded": True,
    "dependencies_satisfied": True,
    "skipped_reason": "disabled in the configuration (enabled: false)",
}


def _context(tmp_path: Path) -> PluginContext:
    config = AshConfig()
    config.global_settings.suppressions = [
        AshSuppression(path="src/a.py", rule_id="B101", reason="one"),
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


def _report(tmp_path: Path, **scanners) -> dict:
    context = _context(tmp_path)
    return json.loads(
        UnusedSuppressionsReporter(context=context).report(_model(**scanners))
    )


def _config_with_report(tmp_path: Path, report: dict) -> Path:
    """The linter's layout: the config in ``.ash`` and the report under
    ``ash_output/reports`` beside it, the report as the reporter wrote it."""
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_bytes(CONFIG.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    return config_path


def test_a_scanner_with_nothing_to_scan_is_not_listed(tmp_path):
    """Red at the base: a SKIPPED row was listed whatever the cause."""
    report = _report(
        tmp_path,
        bandit={"status": ScannerStatus.PASSED},
        **{"npm-audit": NOTHING_TO_SCAN},
    )

    assert "scanners_not_run" not in report
    assert "scope_caveat" not in report
    assert report["summary"]["unused_suppressions"] == 1


@pytest.mark.parametrize(
    "reason",
    [
        pytest.param(
            "disabled in the configuration (enabled: false)", id="config-only"
        ),
        pytest.param(
            "disabled in the configuration (enabled: false), not named by --scanners",
            id="config-and-selection",
        ),
        pytest.param("cdk-nag is disabled in the configuration", id="executor-wording"),
    ],
)
def test_a_scanner_the_configuration_disables_is_not_listed(tmp_path, reason):
    """Red at the base: the ``excluded`` flag alone listed the scanner. A full
    scan of the same configuration leaves it out too, so a suppression for its
    findings is unused in the ordinary sense."""
    report = _report(
        tmp_path,
        bandit={"status": ScannerStatus.PASSED},
        **{"cdk-nag": {**DISABLED_IN_CONFIG, "skipped_reason": reason}},
    )

    assert "scanners_not_run" not in report


@pytest.mark.parametrize(
    "reason",
    [
        pytest.param("excluded from this run (--exclude-scanners)", id="exclusion"),
        pytest.param("not named by --scanners", id="allowlist"),
        pytest.param(
            "assigned to another shard (this run is shard 2 of 3)", id="shard"
        ),
        pytest.param(None, id="no-recorded-reason"),
    ],
)
def test_an_exclusion_that_belongs_to_one_run_is_still_listed(tmp_path, reason):
    """The positive control for the two tests above: a scanner the operator left
    out for this run alone runs in the next full scan, so its suppressions stay
    in doubt. A row with no recorded reason is listed as well: the cause is
    unknown, and the listed side comments nothing out."""
    report = _report(
        tmp_path,
        bandit={"status": ScannerStatus.PASSED},
        semgrep={
            "status": ScannerStatus.SKIPPED,
            "excluded": True,
            "skipped_reason": reason,
        },
    )

    assert report["scanners_not_run"] == ["semgrep"]


def test_only_the_scanners_a_later_scan_would_run_are_named(tmp_path):
    """Four unrunnable rows beside the two that are not listed: the list holds
    the tool-missing, the error and the unsatisfied-dependency scanners and
    neither the nothing-to-scan nor the config-disabled one."""
    report = _report(
        tmp_path,
        bandit={"status": ScannerStatus.PASSED},
        semgrep={"status": ScannerStatus.MISSING, "dependencies_satisfied": False},
        checkov={"status": ScannerStatus.ERROR},
        grype={"status": ScannerStatus.PASSED, "dependencies_satisfied": False},
        **{"npm-audit": NOTHING_TO_SCAN, "cdk-nag": DISABLED_IN_CONFIG},
    )

    assert report["scanners_not_run"] == ["checkov", "grype", "semgrep"]
    assert "npm-audit" not in report["scope_caveat"]
    assert "cdk-nag" not in report["scope_caveat"]


def test_fix_unused_comments_the_entry_out_when_only_such_scanners_read_skipped(
    tmp_path,
):
    """The end to end of the finding. Red at the base: the report carried
    ``scanners_not_run: ['cdk-nag', 'npm-audit']``, the fixer returned the
    config unchanged and listed no fix, for every scan with a scanner that had
    nothing to scan."""
    report = _report(
        tmp_path / "scan",
        bandit={"status": ScannerStatus.PASSED},
        **{"npm-audit": NOTHING_TO_SCAN, "cdk-nag": DISABLED_IN_CONFIG},
    )
    config_path = _config_with_report(tmp_path / "project", report)
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 1
    assert fixed_content != before
    assert "# - path: src/a.py" in fixed_content


def test_fix_unused_still_leaves_the_entry_when_a_scanner_could_not_run(tmp_path):
    """The positive control for the test above: with a MISSING scanner beside
    the same two, the report lists it and the fixer comments nothing out."""
    report = _report(
        tmp_path / "scan",
        bandit={"status": ScannerStatus.PASSED},
        semgrep={"status": ScannerStatus.MISSING, "dependencies_satisfied": False},
        **{"npm-audit": NOTHING_TO_SCAN, "cdk-nag": DISABLED_IN_CONFIG},
    )
    config_path = _config_with_report(tmp_path / "project", report)
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert report["scanners_not_run"] == ["semgrep"]
    assert fixed_issues == []
    assert fixed_content == before


def test_lint_offers_the_entry_and_names_no_scanner_that_had_nothing_to_scan(
    tmp_path,
):
    """Lint over the same report: the entry is fixable and no issue says a
    scanner did not run, so the advice cannot tell the operator to enable a
    scanner that has nothing to scan."""
    report = _report(
        tmp_path / "scan",
        bandit={"status": ScannerStatus.PASSED},
        **{"npm-audit": NOTHING_TO_SCAN, "cdk-nag": DISABLED_IN_CONFIG},
    )
    config_path = _config_with_report(tmp_path / "project", report)

    result = ConfigLinter.lint(config_path, check_unused=True)

    unused = [i for i in result.issues if i.category == LintCategory.SUPPRESSION_UNUSED]
    entries = [i for i in unused if i.message.startswith("Unused suppression:")]
    assert len(entries) == 1, unused
    assert entries[0].fixable
    assert not any("did not run" in i.message for i in unused)
