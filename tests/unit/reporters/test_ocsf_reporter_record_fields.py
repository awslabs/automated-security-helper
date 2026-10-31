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
import logging
import uuid
from datetime import datetime, timezone

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    ocsf_reporter as ocsf_module,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    _FINDING_UID_NAMESPACE,
    ACTIVITY_NAME,
    CONVERSION_SHORTFALL_LABEL,
    DEGRADED_FINDING_LABEL,
    OcsfReporter,
    _fallback_identities,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    ActivityId,
    Metadata,
    Product,
    SeverityId,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    Message1,
    PropertyBag,
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

    @pytest.mark.parametrize(
        ("rule_id", "uid"),
        [
            ("CVE-2022-40897-setuptools", "CVE-2022-40897"),
            ("CVE-2021-44228-log4j-core", "CVE-2021-44228"),
            ("cve-2024-12345", "CVE-2024-12345"),
        ],
    )
    def test_a_cve_at_the_head_of_a_rule_id_is_that_cve(self, reporter, rule_id, uid):
        """Grype names its rules ``<CVE id>-<package>``, so the finding is a
        known CVE and ``cve.uid`` is the identifier alone, upper-cased; the
        title keeps the rule id as the scanner wrote it."""
        result = Result(ruleId=rule_id, level=Level.error, message=Message(text="m"))

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.title == rule_id
        assert vulnerability.cve.uid == uid

    @pytest.mark.parametrize(
        "rule_id",
        [
            "GHSA-abcd-1234-efgh",
            "setuptools-CVE-2022-40897",
            "CVE-2024-1",
            "CVE-24-12345",
        ],
    )
    def test_a_rule_id_without_a_cve_at_its_head_has_no_cve(self, reporter, rule_id):
        result = Result(ruleId=rule_id, level=Level.error, message=Message(text="m"))

        vulnerability = reporter._create_vulnerability_from_result(result)

        assert vulnerability.cve is None


class TestActivityIsCreate:
    def test_a_finding_record_is_a_create_activity(self, reporter, metadata):
        result = Result(ruleId="R", level=Level.error, message=Message(text="m"))

        finding = reporter._create_vulnerability_finding(result, metadata, 1)

        assert ACTIVITY_NAME == "Create"
        assert finding.activity_id == ActivityId.integer_1
        assert finding.activity_name == "Create"


class TestTheErrorResponseCountsOnce:
    def test_processed_and_failed_are_not_both_the_total(self, reporter):
        payload = json.loads(
            reporter._create_error_response(
                error_message="boom",
                current_time_ms=1,
                processed_count=0,
                failed_count=3,
            )
        )

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


class TestFindingUidIsStableAcrossRuns:
    """``finding_info.uid`` was a fresh uuid4 per run, so a SIEM accumulated one
    record per scan for one finding and could never update or close it."""

    def test_the_same_result_gets_the_same_uid_in_two_reporters(
        self, test_plugin_context, metadata
    ):
        result = Result(ruleId="R", level=Level.error, message=Message(text="same"))

        first = OcsfReporter(context=test_plugin_context)._create_vulnerability_finding(
            result, metadata, 1
        )
        second = OcsfReporter(
            context=test_plugin_context
        )._create_vulnerability_finding(result, metadata, 2)

        assert first.finding_info.uid == second.finding_info.uid
        uuid.UUID(first.finding_info.uid)

    def test_different_findings_get_different_uids(self, reporter, metadata):
        first = reporter._create_vulnerability_finding(
            Result(ruleId="R", level=Level.error, message=Message(text="one")),
            metadata,
            1,
        )
        second = reporter._create_vulnerability_finding(
            Result(ruleId="R", level=Level.error, message=Message(text="two")),
            metadata,
            1,
        )

        assert first.finding_info.uid != second.finding_info.uid

    def test_the_report_derives_the_uid_from_the_shared_finding_id(self, reporter):
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
        ]

        records = json.loads(reporter.report(model))

        flat_ids = [item.id for item in model.to_flat_vulnerabilities()]
        assert [r["finding_info"]["uid"] for r in records] == [
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, flat_id)) for flat_id in flat_ids
        ]
        # Two identical results in one run are two findings (the flattened id's
        # occurrence counter), so their uids differ.
        assert records[0]["finding_info"]["uid"] != records[1]["finding_info"]["uid"]

    def test_an_extra_flattened_row_takes_no_other_findings_uid(
        self, reporter, monkeypatch
    ):
        """An extra flattened row used to pass the length check (taken after the
        list was cut to size) and shift every later uid onto another finding.
        The pairing now walks the rows and gives each result the next row that
        describes it, so the extra row is passed over: both findings keep the
        uid of their own flattened id and nothing is derived from the extra.

        The extra row here is a copy of the first finding's row placed after
        it, so the first finding has already taken its own row; an extra row
        that describes no result is passed over wherever it sits (the next
        test)."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R2", level=Level.error, message=Message(text="b")),
        ]
        flat = list(model.to_flat_vulnerabilities())
        extra = flat[0].model_copy(update={"id": "an-extra-row"})
        monkeypatch.setattr(
            AshAggregatedResults,
            "to_flat_vulnerabilities",
            lambda self: [flat[0], extra, flat[1]],
        )

        uids = [r["finding_info"]["uid"] for r in json.loads(reporter.report(model))]

        assert uids == [
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, item.id)) for item in flat
        ]
        assert str(uuid.uuid5(_FINDING_UID_NAMESPACE, "an-extra-row")) not in uids

    @pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
    def test_an_extra_row_describing_no_result_is_passed_over_wherever_it_sits(
        self, reporter, monkeypatch, position
    ):
        """Placed before the rows that describe the results, an extra row is
        the first one the walk meets; it describes neither result, so each
        finding still takes its own row."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R2", level=Level.error, message=Message(text="b")),
        ]
        flat = list(model.to_flat_vulnerabilities())
        extra = flat[0].model_copy(update={"id": "an-extra-row", "rule_id": "R9"})
        rows = list(flat)
        rows.insert(position, extra)
        monkeypatch.setattr(
            AshAggregatedResults, "to_flat_vulnerabilities", lambda self: rows
        )

        uids = [r["finding_info"]["uid"] for r in json.loads(reporter.report(model))]

        assert uids == [
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, item.id)) for item in flat
        ]
        assert str(uuid.uuid5(_FINDING_UID_NAMESPACE, "an-extra-row")) not in uids

    @pytest.mark.parametrize(
        "drift",
        [{"rule_id": "R9"}, {"file_path": "elsewhere/other.py"}],
        ids=["another-rule", "another-file"],
    )
    def test_a_row_describing_another_finding_falls_back_alone(
        self, reporter, monkeypatch, drift
    ):
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R2", level=Level.error, message=Message(text="b")),
            Result(ruleId="R3", level=Level.error, message=Message(text="c")),
        ]
        flat = list(model.to_flat_vulnerabilities())
        drifted = flat[1].model_copy(update={"id": "drifted-row", **drift})
        monkeypatch.setattr(
            AshAggregatedResults,
            "to_flat_vulnerabilities",
            lambda self: [flat[0], drifted, flat[2]],
        )

        first, second, third = [
            r["finding_info"]["uid"] for r in json.loads(reporter.report(model))
        ]

        assert first == str(uuid.uuid5(_FINDING_UID_NAMESPACE, flat[0].id))
        assert third == str(uuid.uuid5(_FINDING_UID_NAMESPACE, flat[2].id))
        assert second not in {
            str(uuid.uuid5(_FINDING_UID_NAMESPACE, key))
            for key in ("drifted-row", flat[1].id)
        }


class TestTheIdentityOfAResultWithNoSharedId:
    @staticmethod
    def _markdown_result(markdown: str) -> Result:
        # The schema requires ``text`` on a message that carries markdown, so a
        # message "given in markdown" is an empty ``text`` beside the markdown.
        return Result(
            ruleId="R1",
            level=Level.error,
            message=Message(root=Message1(text="", markdown=markdown)),
        )

    def test_messages_given_in_markdown_are_told_apart_at_one_site(self):
        """Read as ``text`` alone, every markdown-only message was the same
        empty part of the key, so two findings at one site shared an identity
        and the second was numbered as a repeat of the first."""
        first = self._markdown_result("first finding")
        second = self._markdown_result("second finding")

        both = _fallback_identities([first, second], [None, None])

        assert "occurrence" not in both[0] and "occurrence" not in both[1]
        assert both[0] != both[1]

    def test_a_findings_identity_does_not_depend_on_a_sibling(self):
        """With the sibling fixed (absent from the run) the other finding keeps
        the identity it had beside it."""
        first = self._markdown_result("first finding")
        second = self._markdown_result("second finding")

        beside = _fallback_identities([first, second], [None, None])
        alone = _fallback_identities([second], [None])

        assert alone[0] == beside[1]

    def test_a_result_that_states_no_finding_takes_no_number(self):
        """The array leaves such a result out, so it must not be counted among
        the identical findings around it: the finding after it was numbered 2
        instead of 1, and its uid changed when the rule stopped evaluating."""
        finding = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        not_applicable = Result(
            ruleId="R1",
            kind=Kind.notApplicable,
            level=Level.none,
            message=Message(text="m"),
        )
        twin = Result(ruleId="R1", level=Level.error, message=Message(text="m"))

        with_it = _fallback_identities([finding, not_applicable, twin], [None] * 3)
        without_it = _fallback_identities([finding, twin], [None, None])

        assert with_it[1] is None
        assert [with_it[0], with_it[2]] == without_it


class TestTheFallbackRecordKeepsWhatItCanRead:
    def test_severity_and_project_survive_a_failed_primary_build(
        self, reporter, metadata, monkeypatch
    ):
        result = Result(
            ruleId="R",
            level=Level.error,
            message=Message(text="m"),
            properties=PropertyBag(workspace_project="api"),
        )

        def explode(*args, **kwargs):
            raise RuntimeError("status failed")

        monkeypatch.setattr(reporter, "_determine_status_from_suppressions", explode)

        finding = reporter._create_vulnerability_finding(result, metadata, 1)

        assert finding.finding_info.title == "Error processing finding R"
        assert finding.severity_id == SeverityId.integer_5
        assert finding.vulnerabilities[0].severity == "CRITICAL"
        assert "workspace_project:api" in (finding.metadata.labels or [])

    def test_a_degraded_record_keeps_the_uid_of_its_whole_record(
        self, reporter, monkeypatch
    ):
        """The uid carried a ``|fallback`` suffix, so a finding that degraded in
        one run and built whole in the next was two records in a SIEM for good.
        The degraded label tells the two records apart; the uid is the finding's
        own."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a"))
        ]

        def finding_records(document: str) -> list:
            return [
                record
                for record in json.loads(document)
                if CONVERSION_SHORTFALL_LABEL
                not in (record["metadata"].get("labels") or [])
            ]

        (whole,) = finding_records(reporter.report(model))

        def explode(*args, **kwargs):
            raise RuntimeError("status failed")

        monkeypatch.setattr(reporter, "_determine_status_from_suppressions", explode)
        (degraded,) = finding_records(reporter.report(model))

        assert DEGRADED_FINDING_LABEL in degraded["metadata"]["labels"]
        assert DEGRADED_FINDING_LABEL not in (whole["metadata"].get("labels") or [])
        assert degraded["finding_info"]["uid"] == whole["finding_info"]["uid"]

    def test_a_direct_call_keeps_the_uid_when_the_message_has_nothing_to_read(
        self, reporter, metadata, monkeypatch
    ):
        """Called without an identity, the builder keys the finding on its own
        fields. The whole record read an empty message as "No description" and
        the degraded one read it as empty, so the same finding had two uids."""
        result = Result(
            ruleId="R1", level=Level.error, message=Message(root=Message1(text=""))
        )
        whole = reporter._create_vulnerability_finding(result, metadata, 1)

        def explode(*args, **kwargs):
            raise RuntimeError("status failed")

        monkeypatch.setattr(reporter, "_determine_status_from_suppressions", explode)
        degraded = reporter._create_vulnerability_finding(result, metadata, 1)

        assert DEGRADED_FINDING_LABEL in (degraded.metadata.labels or [])
        assert DEGRADED_FINDING_LABEL not in (whole.metadata.labels or [])
        assert degraded.finding_info.uid == whole.finding_info.uid

    def test_a_record_cut_down_to_minimal_info_keeps_its_uid_and_is_labeled(
        self, reporter, metadata, monkeypatch
    ):
        """When the finding info cannot be built, a minimal one is written in its
        place. It carried a ``|fallback-info`` suffix on the uid, so the finding
        was two records in a SIEM across runs, and nothing on the record said it
        had lost its title and description."""
        result = Result(ruleId="R1", level=Level.error, message=Message(text="a"))
        whole = reporter._create_vulnerability_finding(result, metadata, 1)

        real = ocsf_module.FindingInfo

        def rejects_all_but_the_minimal_info(*args, **kwargs):
            if kwargs.get("title") != "Error creating finding title":
                raise ValueError("the finding info was rejected")
            return real(*args, **kwargs)

        monkeypatch.setattr(
            ocsf_module, "FindingInfo", rejects_all_but_the_minimal_info
        )
        minimal = reporter._create_vulnerability_finding(result, metadata, 1)

        assert minimal.finding_info.title == "Error creating finding title"
        assert minimal.finding_info.uid == whole.finding_info.uid
        assert DEGRADED_FINDING_LABEL in (minimal.metadata.labels or [])
        assert DEGRADED_FINDING_LABEL not in (whole.metadata.labels or [])


class TestTheShortfallRecordCannotCostTheFindings:
    def test_a_shortfall_record_that_cannot_be_built_leaves_the_findings(
        self, reporter, monkeypatch, caplog
    ):
        """The shortfall record was built inside the findings array's guard,
        whose answer to an exception is the error envelope, so one rejected
        record discarded every finding it stood beside. The findings are now
        written as they are and the loss of the note is an error that names the
        counts it would have carried."""
        model = AshAggregatedResults()
        model.sarif.runs[0].results = [
            Result(ruleId="R1", level=Level.error, message=Message(text="a")),
            Result(ruleId="R2", level=Level.error, message=Message(text="b")),
        ]

        def explode(*args, **kwargs):
            raise RuntimeError("status failed")

        # Every finding takes the fallback path, so the array is degraded and
        # the shortfall record is called for.
        monkeypatch.setattr(reporter, "_determine_status_from_suppressions", explode)

        def rejected(*args, **kwargs):
            raise ValueError("the shortfall record was rejected")

        monkeypatch.setattr(reporter, "_create_shortfall_finding", rejected)

        with caplog.at_level(logging.ERROR):
            records = json.loads(reporter.report(model))

        assert [r["vulnerabilities"][0]["title"] for r in records] == ["R1", "R2"]
        assert all("error" not in r for r in records)
        assert all(
            CONVERSION_SHORTFALL_LABEL not in (r["metadata"].get("labels") or [])
            for r in records
        )
        assert any(
            "shortfall record could not be built" in m and "2 degraded" in m
            for m in caplog.messages
        )
