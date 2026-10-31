# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""core.unified_metrics: what the metrics row keeps, and what the rebuilt row sets.

- ScannerMetrics keeps its text as given: the threshold shown is the threshold
  graded, and the scanner name is the key the row is written under.
- The readers of the per-target reports skip a report that names another scanner
  and keep one that names none (the key it is filed under is the scanner).
- A non-list ``inputs_not_scanned`` value does not raise.
- The rebuilt scanner_results row marks ``dependencies_satisfied`` and ``excluded``
  set only when the metrics or the existing row say so, writes the exit code as
  the metrics have it (None for a tool that never ran; a row whose tool ran keeps
  its recorded code when the reports carry none), and carries no skipped reason
  the metrics do not have.
- An unrecognized status is counted as an error and rebuilt as ERROR, not PASSED.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core import unified_metrics
from automated_security_helper.core.unified_metrics import (
    ScannerMetrics,
    _populate_scanner_results_from_unified_metrics,
    _populate_summary_stats_from_unified_metrics,
    coverage_shortfalls,
    inputs_not_scanned,
    target_counts,
    tool_exit_code,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _metrics(**fields) -> ScannerMetrics:
    values = {"scanner_name": "tool", "status": "PASSED"}
    values.update(fields)
    return ScannerMetrics(**values)


class TestTheMetricsRow:
    def test_text_fields_are_kept_as_given(self):
        metrics = _metrics(scanner_name="bandit ", threshold="HIGH ")

        assert metrics.threshold == "HIGH "
        assert metrics.scanner_name == "bandit "


class TestTheReportReaders:
    def test_a_report_naming_another_scanner_is_skipped(self):
        model = AshAggregatedResults()
        model.additional_reports = {
            "bandit": {
                "source": {
                    "scanner_name": "semgrep",
                    "status": "PASSED",
                    "targets_attempted": 4,
                    "targets_failed": 1,
                    "exit_code": 7,
                    "inputs_not_scanned": [{"path": "a", "reason": "r"}],
                }
            }
        }

        assert target_counts(model, "bandit") == (None, 0)
        assert tool_exit_code(model, "bandit") is None
        assert inputs_not_scanned(model) == []

    def test_a_coverage_claim_filed_under_another_scanner_is_marked_unknown(self):
        """The skipped report above still carries a lost target and an unscanned
        input. Credited to nobody, the scanner it names would read as having covered
        everything; its coverage is listed as unknown instead, with a warning."""
        model = AshAggregatedResults()
        model.additional_reports = {
            "bandit": {
                "source": {
                    "scanner_name": "semgrep",
                    "status": "ERROR",
                    "targets_attempted": 4,
                    "targets_failed": 1,
                }
            }
        }

        with patch.object(unified_metrics.ASH_LOGGER, "warning") as warning:
            shortfalls = coverage_shortfalls(model)

        assert shortfalls == [("semgrep", None, None)]
        message = warning.call_args.args[0]
        assert "'bandit'" in message and "'semgrep'" in message, message

    def test_a_misfiled_report_that_claims_no_coverage_is_not_a_shortfall(self):
        """Control: the same misfiled report with only a status says nothing about
        coverage, so no scanner is listed and nothing is warned."""
        model = AshAggregatedResults()
        model.additional_reports = {
            "bandit": {"source": {"scanner_name": "semgrep", "status": "PASSED"}}
        }

        with patch.object(unified_metrics.ASH_LOGGER, "warning") as warning:
            shortfalls = coverage_shortfalls(model)

        assert shortfalls == []
        warning.assert_not_called()

    def test_a_report_filed_under_its_own_scanner_is_not_marked_unknown(self):
        """Control: the same claim under the scanner's own key is read as its own."""
        model = AshAggregatedResults()
        model.additional_reports = {
            "semgrep": {
                "source": {
                    "scanner_name": "semgrep",
                    "status": "ERROR",
                    "targets_attempted": 4,
                    "targets_failed": 1,
                }
            }
        }

        assert coverage_shortfalls(model) == [("semgrep", 4, 1)]

    def test_a_report_naming_no_scanner_is_still_read(self):
        """A report filed under the scanner's key with no ``scanner_name`` (a results
        file written before the field existed, a hand-built one) is the scanner's:
        its counters feed the partial-audit claim and its unscanned inputs the
        console summary. Only the calculator's STATUS reader refuses it. Both
        counters are written: an attempt count with no failure accounting is the
        untrustworthy pair whatever the report's name (``target_counts``)."""
        model = AshAggregatedResults()
        model.additional_reports = {
            "bandit": {
                "source": {
                    "status": "PASSED",
                    "targets_attempted": 4,
                    "targets_failed": 0,
                    "inputs_not_scanned": [{"path": "a.lock", "reason": "offline"}],
                }
            }
        }

        assert target_counts(model, "bandit") == (4, 0)
        assert inputs_not_scanned(model) == [("bandit", "a.lock", "offline")]

    def test_a_non_list_inputs_not_scanned_value_does_not_raise(self):
        model = AshAggregatedResults()
        model.additional_reports = {
            "bandit": {
                "source": {"scanner_name": "bandit", "inputs_not_scanned": 5},
                "converted": {
                    "scanner_name": "bandit",
                    "inputs_not_scanned": [{"path": "a.lock", "reason": "offline"}],
                },
            }
        }

        assert inputs_not_scanned(model) == [("bandit", "a.lock", "offline")]


class TestTheRebuiltRow:
    def test_a_fresh_row_marks_only_the_fields_the_metrics_have(self):
        model = AshAggregatedResults()

        _populate_scanner_results_from_unified_metrics(
            model, [_metrics(exit_code=None, skipped_reason=None)]
        )

        row = model.scanner_results["tool"]
        assert "dependencies_satisfied" not in row.model_fields_set, (
            row.model_fields_set
        )
        assert "excluded" not in row.model_fields_set, row.model_fields_set
        assert "skipped_reason" not in row.model_fields_set, row.model_fields_set
        # The exit code is written as the metrics have it, None included: the
        # model's default 0 would read as a tool that ran and exited clean.
        assert row.exit_code is None

    def test_a_missing_row_sets_the_flag_and_an_existing_flag_follows_the_metrics(
        self,
    ):
        model = AshAggregatedResults()
        model.scanner_results["tool"] = ScannerTargetStatusInfo(
            status=ScannerStatus.MISSING, dependencies_satisfied=False, exit_code=3
        )

        _populate_scanner_results_from_unified_metrics(
            model,
            [_metrics(status="PASSED", dependencies_missing=False, exit_code=None)],
        )

        row = model.scanner_results["tool"]
        assert row.dependencies_satisfied is True
        # The row said MISSING, so its code 3 is not the record of a run: the
        # rebuilt status says the tool ran, the reports carry no code, and the
        # row carries none. Red at the base: the stale 3 survived the rebuild.
        assert row.exit_code is None

        _populate_scanner_results_from_unified_metrics(
            model, [_metrics(status="MISSING", dependencies_missing=True, exit_code=2)]
        )
        row = model.scanner_results["tool"]
        assert row.dependencies_satisfied is False
        assert row.exit_code == 2

    def test_a_row_whose_tool_ran_keeps_its_recorded_code_when_the_reports_have_none(
        self,
    ):
        """The metrics read the exit code from the per-target reports. A results
        file whose rows carry a code and whose reports carry none (an older
        writer, a merged file) has the row as the code's only record; the
        rebuild used to erase it with the metrics' None. Red at the base: the
        row read None after the rebuild. A rebuild to ERROR keeps no code (the
        next test: kept, it survived one rebuild and not the second)."""
        for ran in ("PASSED", "FAILED"):
            model = AshAggregatedResults()
            model.scanner_results["tool"] = ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, exit_code=3
            )

            _populate_scanner_results_from_unified_metrics(
                model, [_metrics(status=ran, exit_code=None)]
            )

            assert model.scanner_results["tool"].exit_code == 3, ran

    def test_rebuilding_a_rebuilt_row_gives_the_same_exit_code(self):
        """A rebuild is run again on a file that was rebuilt (``ash report``,
        ``ash merge``), so the rule has to give one answer however often it is
        applied. Red at the base: a PASSED row with code 3 rebuilt to ERROR kept
        the 3, and the second rebuild, which finds an ERROR row, dropped it, so a
        saved results file and the same file after a report disagreed."""
        for recorded in ("PASSED", "FAILED"):
            for rebuilt in ("ERROR", recorded):
                model = AshAggregatedResults()
                model.scanner_results["tool"] = ScannerTargetStatusInfo(
                    status=ScannerStatus(recorded), exit_code=3
                )
                rows = [_metrics(status=rebuilt, exit_code=None)]

                _populate_scanner_results_from_unified_metrics(model, rows)
                first = model.scanner_results["tool"].exit_code
                _populate_scanner_results_from_unified_metrics(model, rows)
                second = model.scanner_results["tool"].exit_code

                assert first == second, (recorded, rebuilt, first, second)

    def test_a_code_on_a_row_that_did_not_say_the_tool_ran_is_not_kept(self):
        """The row's own status decides whether its code is the record of a run:
        an ERROR row of an older file carries the model's default 0 and a MISSING
        or SKIPPED row a stale code, and the rebuild kept them when it reached a
        status under which the tool ran. Red at the base: the code survived."""
        for recorded in ("MISSING", "SKIPPED", "ERROR"):
            for rebuilt in ("ERROR", "PASSED"):
                model = AshAggregatedResults()
                model.scanner_results["tool"] = ScannerTargetStatusInfo(
                    status=ScannerStatus(recorded), exit_code=0
                )

                _populate_scanner_results_from_unified_metrics(
                    model, [_metrics(status=rebuilt, exit_code=None)]
                )

                assert model.scanner_results["tool"].exit_code is None, (
                    recorded,
                    rebuilt,
                )

    def test_a_row_whose_tool_never_ran_carries_none_whatever_it_recorded(self):
        """The control: a MISSING or SKIPPED tool ran nothing, so a code the row
        recorded (a stale one from an earlier run) is not kept, and a code the
        metrics do have replaces the row's."""
        for never_ran in ("MISSING", "SKIPPED"):
            model = AshAggregatedResults()
            model.scanner_results["tool"] = ScannerTargetStatusInfo(
                status=ScannerStatus.PASSED, exit_code=3
            )

            _populate_scanner_results_from_unified_metrics(
                model, [_metrics(status=never_ran, exit_code=None)]
            )

            assert model.scanner_results["tool"].exit_code is None, never_ran

        model = AshAggregatedResults()
        model.scanner_results["tool"] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED, exit_code=3
        )
        _populate_scanner_results_from_unified_metrics(
            model, [_metrics(status="PASSED", exit_code=5)]
        )
        assert model.scanner_results["tool"].exit_code == 5

    def test_an_unrecognized_status_is_counted_and_rebuilt_as_error(self, monkeypatch):
        warnings = []
        monkeypatch.setattr(
            unified_metrics.ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: warnings.append(str(message)),
        )
        model = AshAggregatedResults()
        rows = [_metrics(status="WEIRD"), _metrics(scanner_name="other")]

        _populate_summary_stats_from_unified_metrics(model, rows)
        _populate_scanner_results_from_unified_metrics(model, rows)

        stats = model.metadata.summary_stats
        assert (stats.passed, stats.error) == (1, 1)
        assert model.scanner_results["tool"].status == ScannerStatus.ERROR
        assert any("unrecognized status" in line for line in warnings), warnings
