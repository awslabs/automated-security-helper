# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The statistics calculator reads a failure's marks and a scanner's counts one way.

- A report that carries an ``exception`` is a failure's wherever it is read: not a
  partial loss, so the same reports give the same status whether or not the
  scanner has a recorded row.
- ``verify_sarif_finding_counts`` compares the SARIF with the findings the SARIF
  can hold: the counts a scanner recorded on a dict result are not a mismatch.
- An ``additional_reports`` entry names a scanner only when one of its values is
  shaped as a serialized container (a ``status`` or a ``scanner_name``): a
  plugin's mapping of mappings is not a phantom ERROR scanner.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _model(additional_reports: dict | None = None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if additional_reports is not None:
        model.additional_reports = additional_reports
    return model


def _report(scanner_name: str, target: str = "source", **fields) -> dict:
    report = {"scanner_name": scanner_name, "target_type": target, "status": "PASSED"}
    report.update(fields)
    return report


def _partial_loss(scanner_name: str, **fields) -> dict:
    """One tree's ERROR report with the counters of a partial loss and no findings:
    the ERROR ``determine_status`` gives a partial loss whose findings pass the gate."""
    return _report(
        scanner_name,
        status="ERROR",
        targets_attempted=3,
        targets_failed=1,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        **fields,
    )


class TestAnExceptionIsAFailuresMarkEverywhere:
    """``target_report_is_partial_loss`` refused ``raw_results.status == "failed"`` and
    ``could_not_stop`` but not an ``exception``, while ``_status_info_from_report`` and
    ``recorded_error_is_partial_loss`` read an ``exception`` as a crash. A report with
    partial counters and an ``exception`` (a merged or hand-written file; the executor's
    own rows also carry ``raw_results.status``) was therefore a crash for a scanner with
    a recorded ERROR row and a partial loss for one without, and with a finding on the
    other tree the row-less scanner read FAILED where the recorded one read ERROR."""

    def test_an_exception_mark_is_not_a_partial_loss(self):
        report = _partial_loss("cdk-nag", exception="RuntimeError: the run raised")

        assert (
            ScannerStatisticsCalculator.target_report_is_partial_loss(report, "MEDIUM")
            is False
        )

    def test_the_counters_alone_still_are_one(self):
        """Control: the same report without the mark is the partial loss it reads as."""
        assert (
            ScannerStatisticsCalculator.target_report_is_partial_loss(
                _partial_loss("cdk-nag"), "MEDIUM"
            )
            is True
        )

    @staticmethod
    def _crashed_partial_tree_beside_a_finding(with_row: bool) -> AshAggregatedResults:
        model = _model(
            {
                "cdk-nag": {
                    "source": _partial_loss(
                        "cdk-nag", exception="RuntimeError: the run raised"
                    ),
                    "converted": _report(
                        "cdk-nag",
                        "converted",
                        status="FAILED",
                        raw_results={"findings": [{"rule": "AwsSolutions-S1"}]},
                        severity_counts={"high": 1},
                    ),
                }
            }
        )
        if with_row:
            model.scanner_results["cdk-nag"] = ScannerTargetStatusInfo(
                status=ScannerStatus.ERROR
            )
        return model

    def test_the_same_reports_read_error_with_and_without_a_recorded_row(self):
        without_row = self._crashed_partial_tree_beside_a_finding(with_row=False)
        with_row = self._crashed_partial_tree_beside_a_finding(with_row=True)

        _, _, error_without_row = ScannerStatisticsCalculator.get_scanner_status_info(
            without_row, "cdk-nag"
        )
        _, _, error_with_row = ScannerStatisticsCalculator.get_scanner_status_info(
            with_row, "cdk-nag"
        )

        # The recorded-row read was already ERROR (recorded_error_is_partial_loss
        # refuses the exception); the row-less read let the converted tree's
        # HIGH finding outrank what it took for a partial loss and read FAILED.
        assert error_with_row is True
        assert error_without_row is True

    def test_a_partial_loss_without_the_mark_still_yields_to_a_finding(self):
        """Control: the rule the cure keeps. No crash mark, so the source tree's
        partial loss yields to the converted tree's gate-failing finding (FAILED)."""
        model = _model(
            {
                "cdk-nag": {
                    "source": _partial_loss("cdk-nag"),
                    "converted": _report(
                        "cdk-nag",
                        "converted",
                        status="FAILED",
                        raw_results={"findings": [{"rule": "AwsSolutions-S1"}]},
                        severity_counts={"high": 1},
                    ),
                }
            }
        )

        _, _, error = ScannerStatisticsCalculator.get_scanner_status_info(
            model, "cdk-nag"
        )

        assert error is False


def _sarif(scanner_name: str, levels: list[str]) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=scanner_name)),
                results=[
                    Result(
                        ruleId=f"R{i}",
                        level=level,
                        message=Message(text="x"),
                        properties=PropertyBag(scanner_name=scanner_name),
                    )
                    for i, level in enumerate(levels)
                ],
            )
        ]
    )


def _dict_result_report(scanner_name: str, **counts) -> dict:
    """A target report of a scanner that returned a dict instead of SARIF: the
    processor keeps the dict as ``raw_results`` and the executor's counts beside it."""
    return _report(
        scanner_name,
        raw_results={
            "findings": [{"rule": f"R{i}"} for i in range(sum(counts.values()))]
        },
        severity_counts=counts,
    )


class TestTheSarifCompareTakesTheDictCountsBackOut:
    """``extract_sarif_counts_for_scanner`` adds the counts recorded on a dict-result
    report to the scanner's row, because the merged SARIF never holds those findings.
    ``verify_sarif_finding_counts`` compared the SARIF's length with the rows' totals as
    they stood, so every run in which a scanner returned a dict with findings was
    reported as a mismatch while its statistics were right."""

    def test_a_dict_result_beside_a_complete_sarif_is_not_a_mismatch(self):
        model = _model({"bandit": {"source": _dict_result_report("bandit", high=3)}})
        model.sarif = _sarif("bandit", ["error", "warning"])

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)

        # The row counts the dict's findings (that is the point of adding them).
        assert stats["bandit"]["total"] == 5
        assert ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is True

    def test_a_dict_result_alone_matches_an_empty_sarif(self):
        model = _model({"bandit": {"source": _dict_result_report("bandit", high=3)}})

        assert ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is True

    def test_a_sarif_report_whose_raw_results_were_dropped_adds_nothing(self):
        """Control: a report with counts and no dict ``raw_results`` is a SARIF
        report's (the processor drops the raw SARIF), so its findings are in the
        SARIF and nothing is taken out."""
        model = _model(
            {
                "bandit": {
                    "source": _report(
                        "bandit",
                        severity_counts={"critical": 1, "medium": 1},
                    )
                }
            }
        )
        model.sarif = _sarif("bandit", ["error", "warning"])

        assert ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is True

    def test_a_sarif_result_no_row_accounts_for_is_still_a_mismatch(self):
        """Control: the compare still fails on a real disagreement. A result that
        names no scanner is counted in no row, so the SARIF holds one finding the
        rows do not."""
        model = _model({"bandit": {"source": _dict_result_report("bandit", high=3)}})
        model.sarif = SarifReport(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="unnamed")),
                    results=[
                        Result(ruleId="R0", level="error", message=Message(text="x"))
                    ],
                )
            ]
        )

        assert ScannerStatisticsCalculator.verify_sarif_finding_counts(model) is False


class TestAMappingOfMappingsIsNotAScanner:
    """The filter that keeps a plugin's own ``additional_reports`` entries out of the
    scanner list accepted any mapping holding a mapping. ``{"summary": {"files": 10}}``
    passed it, has no ``scanner_name`` for the status readers to match, and so became
    an ERROR row with nothing recorded, the phantom the filter was added to remove."""

    def test_a_plugins_nested_entry_is_not_a_scanner(self):
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model(
                {
                    "bandit": {"source": _report("bandit")},
                    "sbom-meta": {"summary": {"files": 10}},
                }
            )
        )

        assert set(stats) == {"bandit"}, sorted(stats)

    def test_a_report_naming_no_scanner_still_names_one(self):
        """Control: a results file written before ``scanner_name`` existed carries
        the status alone, and its entry is a scanner as before."""
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model({"legacy": {"source": {"status": "PASSED", "duration": 1.0}}})
        )

        assert set(stats) == {"legacy"}, sorted(stats)

    def test_a_report_with_a_name_and_no_status_still_names_one(self):
        """Control: either key is enough."""
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model({"bandit": {"source": {"scanner_name": "bandit", "duration": 1.0}}})
        )

        assert set(stats) == {"bandit"}, sorted(stats)
