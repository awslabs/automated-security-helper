"""The statistics calculator reads the shapes a results file can hold without lying.

Each test pins one reading of ``ScannerStatisticsCalculator`` over a shape a merged,
hand-written or plugin-written results file can carry:

- an ``additional_reports`` entry that is not a scanner's reports is not a phantom
  ERROR scanner;
- one scanner under two spellings of its name is one scanner, counted once;
- a non-mapping entry under a scanner's name does not raise, and the duration
  sums every target the scanner reported under;
- a SARIF result whose ``scanner_name`` is null or not text, or whose ``tags`` is
  null, names no scanner and does not raise;
- a scanner section with ``options: null`` or a non-string threshold does not
  abort the summary;
- an environment reference recorded under another spelling of the scanner's
  section is still shown as the reference;
- ``get_summary_statistics`` counts a scanner the way ``get_scanner_status`` grades
  it: an error is an error, findings outrank the did-not-run statuses, and a
  scanner that evaluated nothing is skipped, not passed.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import AshAggregatedResults
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


def _report(scanner_name: str, target: str = "source", **fields) -> dict:
    report = {
        "scanner_name": scanner_name,
        "target_type": target,
        "status": "PASSED",
        "duration": 1.5,
    }
    report.update(fields)
    return report


def _model(additional_reports: dict | None = None) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    if additional_reports is not None:
        model.additional_reports = additional_reports
    return model


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


class TestOnlyReportShapedEntriesAreScanners:
    def test_a_plugins_own_entry_is_not_a_scanner(self):
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model(
                {
                    "bandit": {"source": _report("bandit")},
                    "findings": [{"rule": "x"}],
                    "notes": "free text",
                    "empty": {},
                }
            )
        )

        assert set(stats) == {"bandit"}, sorted(stats)


class TestOneScannerUnderTwoSpellingsIsOne:
    def test_findings_are_counted_once(self):
        model = _model({"bandit": {"source": _report("bandit")}})
        model.sarif = _sarif("Bandit", ["error", "warning"])

        stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
        summary = ScannerStatisticsCalculator.get_summary_statistics(model)

        assert list(stats) == ["bandit"], sorted(stats)
        assert stats["bandit"]["total"] == 2
        assert summary["total_scanners"] == 1
        assert summary["total_findings"] == 2


class TestNonMappingEntriesAndDurations:
    @pytest.mark.parametrize("value", [None, 7, "text", ["a"]])
    def test_a_non_mapping_entry_does_not_raise(self, value):
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model({"bandit": {"source": _report("bandit")}, "odd": value})
        )

        assert "odd" not in stats
        assert stats["bandit"]["duration"] == 1.5

    def test_the_duration_sums_every_target(self):
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model(
                {
                    "cdk-nag": {
                        "source": _report("cdk-nag", duration=2.0),
                        "converted": _report("cdk-nag", "converted", duration=3.0),
                    }
                }
            )
        )

        assert stats["cdk-nag"]["duration"] == 5.0

    def test_a_null_duration_reads_none(self):
        """No report recorded a duration: None, formatted "N/A" by every reader,
        never a 0.0 that reads "<1ms"."""
        stats = ScannerStatisticsCalculator.extract_scanner_statistics(
            _model({"bandit": {"source": _report("bandit", duration=None)}})
        )

        assert stats["bandit"]["duration"] is None


class TestScannerNameFromAResult:
    def _name(self, **properties):
        return ScannerStatisticsCalculator._get_scanner_name_from_result(
            SimpleNamespace(properties=SimpleNamespace(**properties))
        )

    def test_a_null_scanner_name_falls_through_to_the_tags(self):
        assert self._name(scanner_name=None, tags=["bandit"]) == "bandit"

    def test_a_non_text_scanner_name_names_nothing(self):
        assert self._name(scanner_name=5, tags=None) is None

    def test_null_tags_do_not_raise(self):
        assert self._name(tags=None) is None

    def test_a_non_text_tag_is_skipped(self):
        assert self._name(tags=[5, "semgrep"]) == "semgrep"

    def test_a_text_scanner_name_is_returned(self):
        """Control."""
        assert self._name(scanner_name="checkov") == "checkov"


class TestThresholdsFromAnExternalSection:
    def test_options_null_does_not_raise(self):
        model = _model({"ext": {"source": _report("ext")}})
        with patch.object(
            type(model.ash_config), "get_plugin_config", return_value={"options": None}
        ):
            threshold, source = ScannerStatisticsCalculator.get_scanner_threshold_info(
                model, "ext"
            )

        assert source == "global"
        assert threshold == model.ash_config.global_settings.severity_threshold

    def test_a_non_string_threshold_does_not_abort_the_summary(self):
        model = _model({"ext": {"source": _report("ext")}})
        with patch.object(
            type(model.ash_config),
            "get_plugin_config",
            return_value={"options": {"severity_threshold": 5}},
        ):
            (metrics,) = get_unified_scanner_metrics(model)

        assert metrics.threshold == "5"
        assert metrics.threshold_source == "config"


class TestARecordedReferenceUnderAnotherSpelling:
    @pytest.mark.parametrize("written_key", ["bandit", "Bandit", "BANDIT"])
    def test_the_reference_is_shown(self, written_key):
        conf = SimpleNamespace(
            _environment_references=[
                SimpleNamespace(
                    key=False,
                    path=("scanners", written_key, "options", "severity_threshold"),
                    written="${ASH_BANDIT_THRESHOLD}",
                )
            ]
        )

        shown = ScannerStatisticsCalculator._recorded_reference_shown(
            conf, ("scanners", "bandit", "options", "severity_threshold")
        )

        assert shown == "${ASH_BANDIT_THRESHOLD}"

    def test_another_scanners_reference_is_not(self):
        conf = SimpleNamespace(
            _environment_references=[
                SimpleNamespace(
                    key=False,
                    path=("scanners", "semgrep", "options", "severity_threshold"),
                    written="${ASH_SEMGREP_THRESHOLD}",
                )
            ]
        )

        assert (
            ScannerStatisticsCalculator._recorded_reference_shown(
                conf, ("scanners", "bandit", "options", "severity_threshold")
            )
            is None
        )


_SUMMARY_KEY_OF_STATUS = {
    "PASSED": "passed_scanners",
    "FAILED": "failed_scanners",
    "SKIPPED": "skipped_scanners",
    "MISSING": "missing_scanners",
    "ERROR": "error_scanners",
}


def _a_model_that_grades(status: str) -> AshAggregatedResults:
    """One scanner, ``tool``, built from real reports so that ``status`` is what
    ``get_scanner_status`` answers for it."""
    if status == "PASSED":
        return _model(
            {"tool": {"source": _report("tool", targets_attempted=2, targets_failed=0)}}
        )
    if status == "FAILED":
        model = _model({"tool": {"source": _report("tool")}})
        model.sarif = _sarif("tool", ["error"])
        return model
    if status == "MISSING":
        return _model({"tool": {"source": _report("tool", status="MISSING")}})
    if status == "ERROR":
        return _model(
            {
                "tool": {
                    "source": _report(
                        "tool", status="ERROR", targets_attempted=2, targets_failed=2
                    )
                }
            }
        )
    if status == "SKIPPED":
        return _model(
            {
                "tool": {
                    "source": _report(
                        "tool", status="SKIPPED", targets_attempted=0, targets_failed=0
                    )
                }
            }
        )
    raise AssertionError(status)


class TestTheSummaryCountsAScannerAsItsStatusReadsIt:
    """The summary and ``get_scanner_status`` branch on the same flags in the same
    order. The cases below are not hand-picked flag sets: each is a model built from
    reports, graded by ``get_scanner_status``, and the summary must count the
    scanner under that status and no other."""

    @pytest.mark.parametrize(
        "status", ["PASSED", "FAILED", "MISSING", "ERROR", "SKIPPED"]
    )
    def test_the_scanner_is_counted_under_the_status_it_reads(self, status):
        model = _a_model_that_grades(status)

        assert ScannerStatisticsCalculator.get_scanner_status(model, "tool") == status

        summary = ScannerStatisticsCalculator.get_summary_statistics(model)

        assert summary["total_scanners"] == 1
        for read_status, key in _SUMMARY_KEY_OF_STATUS.items():
            assert summary[key] == (1 if read_status == status else 0), (
                status,
                key,
                summary,
            )

    def test_an_error_beside_findings_is_an_error_in_both(self):
        """error outranks findings in both readers: an ERROR report with a SARIF
        result is ERROR, not FAILED."""
        model = _a_model_that_grades("ERROR")
        model.sarif = _sarif("tool", ["error"])

        assert ScannerStatisticsCalculator.get_scanner_status(model, "tool") == "ERROR"
        summary = ScannerStatisticsCalculator.get_summary_statistics(model)
        assert summary["error_scanners"] == 1
        assert summary["failed_scanners"] == 0


class TestSummaryStatisticsFollowTheStatus:
    def _summary(self, **flags):
        row = {
            "suppressed": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
            "actionable": 0,
            "excluded": False,
            "dependencies_missing": False,
            "error": False,
            "evaluated_nothing": False,
        }
        row.update(flags)
        with patch.object(
            ScannerStatisticsCalculator,
            "extract_scanner_statistics",
            return_value={"scanner": row},
        ):
            return ScannerStatisticsCalculator.get_summary_statistics(_model())

    def test_an_error_is_counted_as_an_error(self):
        summary = self._summary(error=True)

        assert summary["error_scanners"] == 1
        assert summary["passed_scanners"] == 0

    def test_evaluated_nothing_is_skipped(self):
        summary = self._summary(evaluated_nothing=True)

        assert summary["skipped_scanners"] == 1
        assert summary["passed_scanners"] == 0

    def test_findings_outrank_excluded(self):
        summary = self._summary(excluded=True, high=1, total=1, actionable=1)

        assert summary["failed_scanners"] == 1
        assert summary["skipped_scanners"] == 0

    def test_unusable_target_counters_are_counted_as_an_error_like_the_status(self):
        """get_scanner_status grades a scanner whose stored counters cannot be read
        (more failures than attempts) ERROR; the summary counted it passed. Red at
        the base: error_scanners 0, passed_scanners 1."""
        model = _model()
        model.additional_reports = {
            "tool": {
                "source": _report(
                    "tool", targets_attempted=3, targets_failed=5, status="PASSED"
                )
            }
        }

        status = ScannerStatisticsCalculator.get_scanner_status(model, "tool")
        summary = ScannerStatisticsCalculator.get_summary_statistics(model)

        assert status == "ERROR"
        assert summary["error_scanners"] == 1
        assert summary["passed_scanners"] == 0

    def test_a_clean_scanner_passed(self):
        """Control."""
        summary = self._summary()

        assert summary["passed_scanners"] == 1
        assert summary["error_scanners"] == 0
