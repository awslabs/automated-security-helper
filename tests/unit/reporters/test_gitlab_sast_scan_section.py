# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST ``scan`` section and vulnerability ids tell the truth about the run.

Three things the report used to get wrong:

* ``scan.status`` read ``success`` with no ``messages`` when a selected scanner
  was MISSING or at ERROR, so a run that scanned nothing was byte-identical to
  a clean scan of the same tree.
* ``scan.start_time`` and ``end_time`` were ``generated_at`` cut at the first
  ``+``: a negative offset survived (schema-invalid) and a positive one left
  local wall time labelled as the UTC the schema documents.
* ``id`` and the ASH finding-id identifier hashed the rule, file and line only,
  so two distinct findings of one rule at one line shared an id, and the id
  differed from the one every other ASH report gives the same finding.
"""

import json
import re

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def reporter(test_plugin_context):
    return GitLabSASTReporter(context=test_plugin_context)


def _result(rule_id: str, text: str) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=text),
        properties=PropertyBag(scanner_name="bandit"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri="app/main.py"),
                    region=Region(startLine=7),
                )
            )
        ],
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif.runs[0].results = list(results)
    return model


class TestScanStatusReportsScannersThatDidNotComplete:
    def _with_scanner(
        self, status: ScannerStatus, *results: Result, excluded: bool = False
    ) -> AshAggregatedResults:
        model = _model(*results)
        model.ash_config = AshConfig(project_name="scan-status-test")
        model.scanner_results["bandit"] = ScannerStatusInfo(
            status=status,
            excluded=excluded,
            dependencies_satisfied=status is not ScannerStatus.MISSING,
        )
        model.additional_reports["bandit"] = {
            "source": {"scanner_name": "bandit", "status": status.value}
        }
        return model

    @pytest.mark.parametrize("status", [ScannerStatus.MISSING, ScannerStatus.ERROR])
    def test_status_is_failure_with_a_message_naming_the_scanner(
        self, reporter, status
    ):
        report = json.loads(reporter.report(self._with_scanner(status)))

        assert report["scan"]["status"] == "failure"
        values = [m["value"] for m in report["scan"]["messages"]]
        assert any("bandit" in v and status.value in v for v in values), values
        assert all(m["level"] == "warn" for m in report["scan"]["messages"])

    def test_a_completed_scanner_keeps_a_clean_success(self, reporter):
        report = json.loads(reporter.report(self._with_scanner(ScannerStatus.PASSED)))

        assert report["scan"]["status"] == "success"
        assert "messages" not in report["scan"]

    def test_a_failed_scanner_is_one_that_ran_and_found_something(self, reporter):
        """FAILED is an outcome (the scanner ran and its findings failed the
        gate), not a coverage gap: no message says it did not complete."""
        model = self._with_scanner(ScannerStatus.FAILED, _result("B105", "x = 's'"))

        report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 1
        assert not any(
            "did not complete" in m["value"] for m in report["scan"].get("messages", [])
        )

    def test_an_excluded_scanner_is_not_a_coverage_gap(self, reporter):
        """Beside a scanner that ran: a run whose every scanner is SKIPPED has
        scanned nothing at all, which is a message of its own."""
        model = self._with_scanner(ScannerStatus.PASSED)
        model.scanner_results["semgrep"] = ScannerStatusInfo(
            status=ScannerStatus.SKIPPED, excluded=True, dependencies_satisfied=True
        )
        model.additional_reports["semgrep"] = {
            "source": {"scanner_name": "semgrep", "status": ScannerStatus.SKIPPED.value}
        }

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "success"
        assert "messages" not in report["scan"]

    def test_an_error_scanner_with_findings_is_still_reported_as_a_failure(
        self, reporter
    ):
        """The masking case: a scanner at ERROR whose partial output still holds a
        finding reports the finding AND the gap, never one hiding the other."""
        model = self._with_scanner(ScannerStatus.ERROR, _result("B105", "x = 's'"))

        report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 1
        assert report["scan"]["status"] == "failure"
        assert any(
            "bandit" in m["value"] and "ERROR" in m["value"]
            for m in report["scan"]["messages"]
        )


class TestScanTimestampsAreUtc:
    @pytest.mark.parametrize(
        ("generated_at", "expected"),
        [
            ("2026-10-29T10:00:00-07:00", "2026-10-29T17:00:00"),
            ("2026-10-29T10:00:00+02:00", "2026-10-29T08:00:00"),
            ("2026-10-29T10:00:00+00:00", "2026-10-29T10:00:00"),
            ("2026-10-29T10:00:00Z", "2026-10-29T10:00:00"),
            ("2026-10-29T10:00:00", "2026-10-29T10:00:00"),
            # datetime.isoformat()'s default form; the schema pattern has no
            # fraction, so it is cut
            ("2026-10-29T10:00:00.123456+00:00", "2026-10-29T10:00:00"),
            # the UTC instant falls on the next calendar day
            ("2026-10-29T20:00:00-07:00", "2026-10-30T03:00:00"),
        ],
    )
    def test_the_scan_times_are_the_utc_instant(self, reporter, generated_at, expected):
        model = _model()
        model.metadata.generated_at = generated_at

        scan = json.loads(reporter.report(model))["scan"]

        assert scan["start_time"] == expected
        assert scan["end_time"] == expected

    @pytest.mark.parametrize("generated_at", ["", "not-a-date", "2026-13-45T99:00:00"])
    def test_a_malformed_generated_at_still_yields_a_schema_shaped_document(
        self, reporter, generated_at
    ):
        """A timestamp that will not parse falls back to the current UTC instant
        in the schema's form, on the report path and on the failure path, so a
        bad ``generated_at`` never costs the artefact."""
        model = _model()
        model.metadata.generated_at = generated_at
        pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"

        report = json.loads(reporter.report(model))
        failure = json.loads(reporter._failure_report(model, "detail"))

        assert report["scan"]["status"] == "success"
        assert re.fullmatch(pattern, report["scan"]["start_time"])
        assert re.fullmatch(pattern, report["scan"]["end_time"])
        assert failure["scan"]["status"] == "failure"
        assert re.fullmatch(pattern, failure["scan"]["start_time"])

    def test_the_failure_report_uses_the_same_conversion(self, reporter):
        model = _model()
        model.metadata.generated_at = "2026-10-29T10:00:00-07:00"

        scan = json.loads(reporter._failure_report(model, "detail"))["scan"]

        assert scan["start_time"] == "2026-10-29T17:00:00"


class TestVulnerabilityIdsAreTheSharedFindingIds:
    def test_two_findings_of_one_rule_at_one_line_get_distinct_ids(self, reporter):
        model = _model(
            _result("B105", "password = 'first'"),
            _result("B105", "password = 'second'"),
        )

        first, second = json.loads(reporter.report(model))["vulnerabilities"]

        assert first["id"] != second["id"]
        first_ash = [
            i["value"] for i in first["identifiers"] if i["type"] == "ash-finding-id"
        ]
        second_ash = [
            i["value"] for i in second["identifiers"] if i["type"] == "ash-finding-id"
        ]
        assert first_ash != second_ash

    def test_the_id_is_the_flattened_findings_id(self, reporter):
        model = _model(_result("B105", "hardcoded password string"))

        (vuln,) = json.loads(reporter.report(model))["vulnerabilities"]

        (flat,) = model.to_flat_vulnerabilities()
        assert vuln["id"] == flat.id
        assert {
            i["value"] for i in vuln["identifiers"] if i["type"] == "ash-finding-id"
        } == {flat.id}

    def test_a_flattening_with_more_rows_than_results_vouches_for_none(
        self, reporter, monkeypatch
    ):
        """The length check used to run after the list was cut to size, so a
        flattening with an extra row passed it and every id after the extra row
        named another finding. A length that differs means no position is known
        to line up, and every finding keeps its legacy id."""
        model = _model(_result("B105", "one"), _result("B106", "two"))
        flat = list(model.to_flat_vulnerabilities())
        extra = flat[0].model_copy(update={"id": "an-extra-row"})
        monkeypatch.setattr(
            AshAggregatedResults, "to_flat_vulnerabilities", lambda self: flat + [extra]
        )

        ids = [v["id"] for v in json.loads(reporter.report(model))["vulnerabilities"]]

        assert len(ids) == 2
        assert set(ids).isdisjoint({item.id for item in flat} | {"an-extra-row"})

    @pytest.mark.parametrize(
        "drift",
        [{"rule_id": "B999"}, {"file_path": "elsewhere/other.py"}],
        ids=["another-rule", "another-file"],
    )
    def test_a_row_describing_another_finding_falls_back_alone(
        self, reporter, monkeypatch, drift
    ):
        """One drifted pair costs that finding its shared id and no other: the
        fallback used to be all-or-nothing, which changed every id of the report
        between two pipelines of the same tree."""
        model = _model(
            _result("B105", "one"), _result("B106", "two"), _result("B107", "three")
        )
        flat = list(model.to_flat_vulnerabilities())
        drifted = flat[1].model_copy(update={"id": "drifted-row", **drift})
        monkeypatch.setattr(
            AshAggregatedResults,
            "to_flat_vulnerabilities",
            lambda self: [flat[0], drifted, flat[2]],
        )

        first, second, third = json.loads(reporter.report(model))["vulnerabilities"]

        assert first["id"] == flat[0].id
        assert third["id"] == flat[2].id
        assert second["id"] not in {"drifted-row", flat[1].id}
