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
    def _with_scanner(self, status: ScannerStatus) -> AshAggregatedResults:
        model = _model()
        model.ash_config = AshConfig(project_name="scan-status-test")
        model.scanner_results["bandit"] = ScannerStatusInfo(
            status=status,
            excluded=False,
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


class TestScanTimestampsAreUtc:
    @pytest.mark.parametrize(
        ("generated_at", "expected"),
        [
            ("2026-10-29T10:00:00-07:00", "2026-10-29T17:00:00"),
            ("2026-10-29T10:00:00+02:00", "2026-10-29T08:00:00"),
            ("2026-10-29T10:00:00+00:00", "2026-10-29T10:00:00"),
            ("2026-10-29T10:00:00Z", "2026-10-29T10:00:00"),
            ("2026-10-29T10:00:00", "2026-10-29T10:00:00"),
        ],
    )
    def test_the_scan_times_are_the_utc_instant(self, reporter, generated_at, expected):
        model = _model()
        model.metadata.generated_at = generated_at

        scan = json.loads(reporter.report(model))["scan"]

        assert scan["start_time"] == expected
        assert scan["end_time"] == expected

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
