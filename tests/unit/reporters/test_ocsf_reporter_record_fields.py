# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""OCSF records carry the fields the schema defines, with the values it defines.

* A result that names its rule through ``rule.id`` rather than ``ruleId`` was
  emitted as "Unknown Rule"; SARIF allows either.
* ``vulnerabilities[].cve.uid`` is the CVE identifier; a scanner rule id was
  published there, telling a SIEM that every finding was a known CVE.
* ``activity_id`` 1 is Create in the vulnerability_finding class, and its name
  was "Scan", an activity the class does not define.
* The all-failed error response was given the total as its processed count, so
  it doubled the total and stated a 50% success rate.
"""

import json
from datetime import datetime, timezone

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    ACTIVITY_NAME,
    OcsfReporter,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    ActivityId,
    Metadata,
    Product,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    Result,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def reporter(test_plugin_context):
    return OcsfReporter(context=test_plugin_context)


@pytest.fixture
def metadata():
    return Metadata(
        product=Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version="1.0.0",
        ),
        version="1.1.0",
        logged_time=int(datetime.now(timezone.utc).timestamp() * 1000),
    )


class TestRuleIdIsReadFromRuleIdOrRule:
    def test_a_rule_named_through_rule_id_is_read(self, reporter):
        result = Result.model_validate(
            {"rule": {"id": "R-FROM-RULE"}, "level": "error", "message": {"text": "m"}}
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "R-FROM-RULE"

    def test_rule_id_wins_when_both_are_set(self, reporter):
        result = Result.model_validate(
            {
                "ruleId": "R-ID",
                "rule": {"id": "R-FROM-RULE"},
                "level": "error",
                "message": {"text": "m"},
            }
        )

        assert reporter._create_vulnerability_from_result(result).title == "R-ID"


class TestCveIsOnlyACve:
    def test_a_scanner_rule_id_is_not_a_cve(self, reporter):
        result = Result(ruleId="B602", level=Level.error, message=Message(text="m"))

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == "B602"
        assert vulnerability.cve is None

    def test_a_cve_rule_id_is_a_cve(self, reporter):
        result = Result(
            ruleId="CVE-2024-12345", level=Level.error, message=Message(text="m")
        )

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.cve.uid == "CVE-2024-12345"
        assert vulnerability.cve.desc == "m"


class TestActivityIsCreate:
    def test_a_finding_record_is_a_create_activity(self, reporter, metadata):
        result = Result(ruleId="R", level=Level.error, message=Message(text="m"))

        finding = reporter._create_vulnerability_finding(result, metadata, 1)

        assert ACTIVITY_NAME == "Create"
        assert finding.activity_id == ActivityId.integer_1
        assert finding.activity_name == "Create"


class TestTheErrorResponseCountsOnce:
    def test_processed_and_failed_are_not_both_the_total(self, reporter):
        payload = json.loads(reporter._create_error_response("boom", 1, 0, 3))

        assert payload[0]["processing_statistics"] == {
            "processed_results_count": 0,
            "failed_results_count": 3,
            "total_results_count": 3,
            "success_rate_percent": 0,
        }

    def test_the_all_failed_report_states_the_real_total(self, reporter, monkeypatch):
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R2", level=Level.error, message=Message(text="b")),
        ]

        def explode(*args, **kwargs):
            raise RuntimeError("cannot build")

        monkeypatch.setattr(reporter, "_create_vulnerability_finding", explode)

        payload = json.loads(reporter.report(model))

        stats = payload[0]["processing_statistics"]
        assert stats["total_results_count"] == 2
        assert stats["processed_results_count"] == 0
        assert stats["failed_results_count"] == 2
        assert stats["success_rate_percent"] == 0
