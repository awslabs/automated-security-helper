# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Facts the shared report emitter states: when, how long, and how many.

* ``time_delta`` is the age of the scan. It dropped the scan time's UTC offset
  and read the local wall time as UTC, so it was wrong by the offset, and it was
  never computed for the layout that names UTC outright.
* A scanner that did not run, and a scanner of a merged workspace file (which
  records no per-scanner duration), took no measured time; their rows read
  ``<1ms`` as though they had run and been fast.
* The masthead's "unavailable" figure counted a scanner that also counted as
  completed, so completed, disabled and unavailable could add up to more than
  the scanners there are.
* Findings an additional report lists reach the cards and the hotspots, and the
  headline summary left them out.
* A coverage gap beside findings at the gate read as a warning.
* A snippet SARIF puts under a location's region was never recovered.
* A negative limit sliced the findings from the end.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
    coverage_shortfall_text,
    parse_scan_time,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
)

pytestmark = pytest.mark.unit


def _model(reports: dict) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.additional_reports = reports
    return model


def _rows(model: AshAggregatedResults, *, human: bool = True) -> dict:
    return {
        row["scanner_name"]: row
        for row in ReportContentEmitter(
            model, human_presentation=human
        ).get_scanner_results()
    }


class TestAShortfallNeverReadsBelowZero:
    def test_a_failed_count_above_the_attempted_count_is_not_negative(self):
        text = coverage_shortfall_text(2, 5)
        assert text.startswith("evaluated 0 of 2 target(s)"), text
        assert "-" not in text, text

    def test_an_ordinary_shortfall_is_unchanged(self):
        assert (
            coverage_shortfall_text(4, 1)
            == "evaluated 3 of 4 target(s); 1 could not be evaluated"
        )


class TestTheAgeOfTheScanKeepsItsOffset:
    def test_a_scan_time_with_an_offset_is_the_instant_it_names(self):
        scanned_at = datetime.now(timezone.utc) - timedelta(hours=1)
        model = AshAggregatedResults()
        model.metadata.generated_at = scanned_at.astimezone(
            timezone(timedelta(hours=-5))
        ).isoformat(timespec="seconds")

        delta = ReportContentEmitter(model).get_metadata()["time_delta"]

        # The offset used to be dropped and the local wall time read as UTC,
        # which made this six hours.
        assert timedelta(hours=1) <= delta < timedelta(hours=1, minutes=2), delta

    def test_a_utc_scan_time_is_unchanged(self):
        scanned_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        model = AshAggregatedResults()
        model.metadata.generated_at = scanned_at.isoformat(timespec="seconds")

        delta = ReportContentEmitter(model).get_metadata()["time_delta"]

        assert timedelta(minutes=30) <= delta < timedelta(minutes=32), delta

    @pytest.mark.parametrize(
        ("text", "instant"),
        [
            (
                "2026-01-15T12:00:00+05:30",
                datetime(2026, 1, 15, 6, 30, tzinfo=timezone.utc),
            ),
            (
                "2026-01-15T12:00:00-05:00",
                datetime(2026, 1, 15, 17, 0, tzinfo=timezone.utc),
            ),
            ("2026-01-15T12:00:00Z", datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)),
            (
                "2026-01-15T12:00:00.987654Z",
                datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc),
            ),
            ("2026-01-15 12:00:00", datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)),
            (
                "2026-01-15 - 12:00 (UTC)",
                datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc),
            ),
        ],
    )
    def test_each_layout_is_read_as_an_aware_instant(self, text, instant):
        parsed = parse_scan_time(text)
        assert parsed is not None, text
        assert parsed.utcoffset() is not None, "the instant carries its zone"
        assert parsed == instant

    def test_text_that_is_no_time_is_none(self):
        assert parse_scan_time("yesterday afternoon") is None
        assert parse_scan_time("2026-01-15T12:00:00+99:00") is None


class TestADurationIsOnlyWhatWasMeasured:
    @staticmethod
    def _reports() -> dict:
        return {
            "bandit": {
                "source": {
                    "scanner_name": "bandit",
                    "status": "PASSED",
                    "duration": 90.0,
                }
            },
            "cdk-nag": {
                "source": {
                    "scanner_name": "cdk-nag",
                    "status": "SKIPPED",
                    "excluded": True,
                    "dependencies_satisfied": True,
                    "duration": 0.0,
                }
            },
            "grype": {
                "source": {
                    "scanner_name": "grype",
                    "status": "MISSING",
                    "dependencies_satisfied": False,
                    "duration": 0.0,
                }
            },
        }

    def test_a_scanner_that_did_not_run_has_no_duration(self):
        rows = _rows(_model(self._reports()))
        assert rows["bandit"]["duration"] == 90.0
        assert rows["cdk-nag"]["duration"] is None, rows["cdk-nag"]
        assert rows["grype"]["duration"] is None, rows["grype"]

    def test_a_machine_readable_export_keeps_the_recorded_number(self):
        rows = _rows(_model(self._reports()), human=False)
        assert rows["bandit"]["duration"] == 90.0
        assert rows["cdk-nag"]["duration"] == 0.0, rows["cdk-nag"]
        assert rows["grype"]["duration"] == 0.0, rows["grype"]

    def test_the_text_report_shows_not_available_for_them(self, test_plugin_context):
        report = TextReporter(context=test_plugin_context).report(
            _model(self._reports())
        )
        rows = {
            line.split()[0]: line for line in report.splitlines() if line[:1].isalpha()
        }
        assert "1m 30s" in rows["bandit"], rows["bandit"]
        assert "N/A" in rows["cdk-nag"] and "<1ms" not in rows["cdk-nag"], rows[
            "cdk-nag"
        ]
        assert "N/A" in rows["grype"] and "<1ms" not in rows["grype"], rows["grype"]

    def test_a_workspace_scan_records_no_scanner_duration(self):
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 0.0,
                    }
                }
            }
        )
        # The control: a single-directory scan keeps the measured zero it was given.
        assert _rows(model)["bandit"]["duration"] == 0.0

        model.workspace = WorkspaceResults(
            workspace_file="/w/.ash-workspace.yaml",
            workspace_root="/w",
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project="api",
                    relative_path="api",
                    display_label="api",
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold="MEDIUM",
                    output_path="projects/api",
                )
            ],
        )
        assert _rows(model)["bandit"]["duration"] is None
        assert _rows(model, human=False)["bandit"]["duration"] == 0.0


class TestTheMastheadCountsEachScannerOnce:
    def test_a_scanner_that_ran_and_is_named_for_attention_is_not_also_unavailable(
        self, monkeypatch
    ):
        # A scanner that completed, and that the completeness record also names
        # (one tree lacked its dependency), is listed for attention.
        incompleteness = SimpleNamespace(
            scanners=[("bandit", "MISSING")],
            converters=[],
            unevaluated_rules=[],
            no_scanner_ran=False,
            could_not_stop=[],
        )
        monkeypatch.setattr(
            "automated_security_helper.interactions.run_ash_scan.scan_incompleteness",
            lambda *args, **kwargs: incompleteness,
        )
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                },
                "grype": {
                    "source": {
                        "scanner_name": "grype",
                        "status": "ERROR",
                        "duration": 1.0,
                    }
                },
            }
        )

        summary = ReportContentEmitter(model).get_scan_summary()

        assert summary["completed"] == 1, summary
        assert "bandit" in summary["unavailable"], "it is still named for attention"
        # Only grype did not complete.
        assert summary["unavailable_count"] == 1, summary
        assert (
            summary["completed"] + summary["skipped"] + summary["unavailable_count"]
            <= summary["scanners"]
        ), summary


class TestFindingsAnAdditionalReportListsAreCounted:
    def test_the_headline_counts_what_the_cards_show(self):
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                },
                "custom-plugin": [
                    {
                        "title": "Hard-coded endpoint",
                        "description": "A plugin's own finding.",
                        "severity": "HIGH",
                        "file_path": "app.py",
                        "line_start": 3,
                    }
                ],
            }
        )
        emitter = ReportContentEmitter(model)
        cards = [
            vuln for vuln in emitter.flat_vulns if emitter.is_finding_actionable(vuln)
        ]
        assert len(cards) == 1, "the finding reaches the cards as actionable"

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 1, summary
        assert summary["counts"]["high"] == 1, summary
        assert summary["title"] == "Review required", summary

    def test_a_listed_finding_rated_outside_the_ladder_is_counted_as_medium(self):
        """A listed finding whose severity text is none of the five levels.

        The flattening reads a plugin's own rating as the gate reads a SARIF
        result with an unknown level, so the finding reaches the summary as
        MEDIUM: it is actionable under the default threshold and counted in the
        medium bucket, and the counts have the five names and no sixth. An
        earlier shape of this test expected an ``unknown`` bucket, which the
        model never produces.
        """
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                },
                "custom-plugin": [
                    {
                        "title": "Hard-coded endpoint",
                        "description": "A plugin's own finding.",
                        "severity": "HIGH",
                        "file_path": "app.py",
                        "line_start": 3,
                    },
                    {
                        "title": "An odd rating",
                        "description": "A plugin's own finding, rated outside ASH's levels.",
                        "severity": "UNRATED",
                        "file_path": "app.py",
                        "line_start": 9,
                    },
                ],
            }
        )
        emitter = ReportContentEmitter(model)
        assert [vuln.severity for vuln in emitter.flat_vulns] == ["HIGH", "MEDIUM"]
        assert all(
            emitter.is_finding_actionable(vuln) for vuln in emitter.flat_vulns
        ), "both listed findings are at or above the default threshold"

        summary = emitter.get_scan_summary()

        assert summary["actionable"] == 2, summary
        assert summary["counts"]["high"] == 1, summary
        assert summary["counts"]["medium"] == 1, summary
        assert "unknown" not in summary["counts"], summary
        assert summary["active"] == 2, summary
        assert summary["below_threshold"] == 0, summary

    def test_a_row_marked_with_its_source_report_is_read_by_the_mark_not_its_place(
        self,
    ):
        """Rows that carry ``source_report`` are selected by that key.

        The additional-report findings were read as the last N flat rows,
        checked only by scanner name, so a SARIF row of the same scanner that
        sat in the tail was counted twice and a listed finding that sat
        elsewhere was dropped. With the marker, the two listed findings are
        found between the SARIF rows, and the SARIF rows of the same scanner
        are not.
        """
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                },
                "custom-plugin": [
                    {"title": "a", "severity": "HIGH", "file_path": "app.py"},
                    {"title": "b", "severity": "LOW", "file_path": "app.py"},
                ],
            }
        )
        emitter = ReportContentEmitter(model)

        def row(severity: str, source_report: "str | None") -> SimpleNamespace:
            return SimpleNamespace(
                scanner="custom-plugin",
                severity=severity,
                is_suppressed=False,
                workspace_project=None,
                source_report=source_report,
            )

        emitter.flat_vulns = [
            row("CRITICAL", None),
            row("HIGH", "custom-plugin"),
            row("CRITICAL", None),
            row("LOW", "custom-plugin"),
        ]

        extras = emitter._additional_report_findings()

        assert [vuln.severity for vuln in extras] == ["HIGH", "LOW"], extras
        summary = emitter.get_scan_summary()
        assert summary["counts"]["high"] == 1, summary
        assert summary["counts"]["low"] == 1, summary
        assert summary["counts"]["critical"] == 0, summary

    def test_the_buckets_are_the_five_levels_when_every_severity_is_known(self):
        model = _model(
            {
                "bandit": {
                    "source": {
                        "scanner_name": "bandit",
                        "status": "PASSED",
                        "duration": 1.0,
                    }
                },
                "custom-plugin": [
                    {
                        "title": "Hard-coded endpoint",
                        "description": "A plugin's own finding.",
                        "severity": "HIGH",
                        "file_path": "app.py",
                        "line_start": 3,
                    }
                ],
            }
        )
        summary = ReportContentEmitter(model).get_scan_summary()
        assert set(summary["counts"]) == {"critical", "high", "medium", "low", "info"}


class TestACoverageGapBesideFindingsIsADanger:
    @staticmethod
    def _model(with_finding: bool) -> AshAggregatedResults:
        model = AshAggregatedResults(ash_config=get_default_config())
        # The same gate in both variants, so the two differ in the finding alone.
        model.ash_config.global_settings.severity_threshold = "CRITICAL"
        if with_finding:
            model.sarif.runs[0].results = [
                Result(
                    ruleId="R1",
                    level="error",
                    message=Message(text="Review the fixture"),
                    properties=PropertyBag(scanner_name="bandit"),
                )
            ]
        model.additional_reports["bandit"] = {
            "source": {
                "scanner_name": "bandit",
                "status": "PASSED",
                "duration": 1.0,
                "targets_attempted": 4,
                "targets_failed": 2,
            }
        }
        return model

    def test_actionable_findings_and_a_gap_read_as_danger(self):
        summary = ReportContentEmitter(self._model(True)).get_scan_summary()
        assert summary["title"] == "Scan incomplete", summary
        assert summary["actionable"] == 1, summary
        assert summary["tone"] == "danger", summary

    def test_a_gap_alone_stays_a_warning(self):
        summary = ReportContentEmitter(self._model(False)).get_scan_summary()
        assert summary["title"] == "Scan incomplete", summary
        assert summary["actionable"] == 0, summary
        assert summary["tone"] == "warning", summary


class TestASnippetIsFoundWhereSarifPutsIt:
    @staticmethod
    def _snippet(raw: dict) -> str | None:
        vuln = FlatVulnerability(
            id="f-1",
            title="t",
            description="d",
            severity="HIGH",
            scanner="bandit",
            scanner_type="SAST",
            raw_data=json.dumps(raw),
        )
        return ReportContentEmitter(AshAggregatedResults())._extract_code_snippet(vuln)

    @staticmethod
    def _location(snippet_key: str) -> dict:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": "app.py"},
                snippet_key: {"startLine": 3, "snippet": {"text": "eval(user_input)"}},
            }
        }

    def test_a_snippet_in_a_results_region(self):
        assert (
            self._snippet({"locations": [self._location("region")]})
            == "eval(user_input)"
        )

    def test_a_snippet_in_a_results_context_region(self):
        raw = {"locations": [self._location("contextRegion")]}
        assert self._snippet(raw) == "eval(user_input)"

    def test_a_snippet_in_a_code_flow_location(self):
        raw = {
            "codeFlows": [
                {
                    "threadFlows": [
                        {"locations": [{"location": self._location("region")}]}
                    ]
                }
            ]
        }
        assert self._snippet(raw) == "eval(user_input)"

    def test_a_result_with_no_snippet_is_none(self):
        assert self._snippet({"locations": [{"physicalLocation": {}}]}) is None

    def test_a_fenced_message_yields_the_code_without_its_info_string(self):
        """The fence's language name is not code. The flattener's reader leaves it
        out; the emitter's own read of the same message kept it, and the trailing
        newline with it, so a report built from a record flattened without a
        snippet showed ``python`` as the first line of the code."""
        raw = {"message": {"text": "Found:\n```python\neval(user_input)\n```\n"}}
        assert self._snippet(raw) == "eval(user_input)"

    def test_a_bare_fence_yields_its_stripped_block(self):
        raw = {"message": {"text": "```\neval(user_input)\n```"}}
        assert self._snippet(raw) == "eval(user_input)"

    def test_a_message_with_one_fence_marker_is_none(self):
        assert self._snippet({"message": {"text": "unterminated ``` here"}}) is None


class TestANegativeLimitListsNone:
    def test_a_negative_limit_does_not_slice_from_the_end(self):
        model = AshAggregatedResults(ash_config=get_default_config())
        model.sarif.runs[0].results = [
            Result(
                ruleId=f"R{index}",
                level="error",
                message=Message(text=f"Finding {index}"),
                properties=PropertyBag(scanner_name="bandit"),
            )
            for index in range(3)
        ]
        emitter = ReportContentEmitter(model)

        assert len(emitter.get_detailed_findings(2)) == 2
        assert emitter.get_detailed_findings(-1) == []
