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
import sys
from datetime import datetime, timedelta, timezone

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions import run_ash_scan
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
from automated_security_helper.utils.content_db_staleness import ContentDbAgeRecord

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

    @pytest.mark.parametrize("status", [ScannerStatus.MISSING, ScannerStatus.ERROR])
    def test_the_operators_gate_off_keeps_success_and_still_warns(
        self, reporter, status
    ):
        """``fail_on_incomplete_scanners: false`` is the operator accepting an
        incomplete scan: the exit code is 0, and this report said ``failure``
        beside it. The gap is still a ``warn`` message; the status follows the
        operator's gate, as the exit code does."""
        model = self._with_scanner(status)
        model.ash_config = AshConfig(
            project_name="scan-status-test", fail_on_incomplete_scanners=False
        )

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "success"
        values = [m["value"] for m in report["scan"]["messages"]]
        assert any("bandit" in v and status.value in v for v in values), values
        assert all(m["level"] == "warn" for m in report["scan"]["messages"])

    def test_the_gate_defaults_on_when_the_model_carries_no_config(self, reporter):
        """A results object with no config answers as the exit code's resolver
        does with no config at all: the gate is on."""
        model = self._with_scanner(ScannerStatus.MISSING)
        model.ash_config = None

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "failure"

    def test_a_scan_module_that_cannot_be_imported_keeps_the_vulnerabilities(
        self, reporter, monkeypatch
    ):
        """The import of the scan entry point sat outside the guard, so an import
        failure reached ``report()`` and became the failure artefact with no
        vulnerabilities, the very loss the guard exists to prevent."""
        model = self._with_scanner(ScannerStatus.MISSING, _result("B105", "x = 's'"))
        monkeypatch.setitem(
            sys.modules, "automated_security_helper.interactions.run_ash_scan", None
        )

        report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 1
        assert not any(
            m["level"] == "fatal" for m in report["scan"].get("messages", [])
        )


def _stale_record(scanner: str, database: str) -> ContentDbAgeRecord:
    measured_at = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    return ContentDbAgeRecord(
        name=database,
        scanner=scanner,
        built=measured_at - timedelta(days=9),
        measured_by="the scanner's own report",
        max_age=timedelta(days=7),
        measured_at=measured_at,
        policy="fail",
        bound_source="config",
        bound_is_tool_default=False,
        refresh="run the scanner's database update",
    )


#: One ``ScanIncompleteness`` per arm of the exit code that is not a scanner row,
#: with the words a reader of the report should find about it.
_OTHER_ARMS = {
    "converter-did-not-run": (
        run_ash_scan.ScanIncompleteness(
            converters=(
                run_ash_scan.IncompleteConverter("archive", "the tool crashed"),
            )
        ),
        (
            "Converter archive did not complete (the tool crashed); the inputs it "
            "would have converted were not scanned."
        ),
    ),
    "rule-not-evaluated": (
        run_ash_scan.ScanIncompleteness(unevaluated_rules=("AwsSolutions-S1",)),
        (
            "Rule AwsSolutions-S1 could not be evaluated; what it would have found "
            "is absent from this report."
        ),
    ),
    "stale-database": (
        run_ash_scan.ScanIncompleteness(
            stale_content_databases=(_stale_record("grype", "vulnerability-db"),)
        ),
        (
            "Scanner grype ran against a content database (vulnerability-db) past "
            "its declared age bound; its findings may be out of date."
        ),
    ),
    "tool-could-not-be-stopped": (
        run_ash_scan.ScanIncompleteness(could_not_stop=(("semgrep", "pid 4242"),)),
        (
            "Scanner semgrep's tool could not be stopped (pid 4242); it may still "
            "have been writing when this report was taken."
        ),
    ),
}


def _answering(facts: run_ash_scan.ScanIncompleteness):
    """A stand-in for ``scan_incompleteness`` that answers *facts* with the gate
    on and, with it off, only the arms the exit code asks with the gate off."""

    def fake(results, *, gate, **kwargs):
        if gate:
            return facts
        return run_ash_scan.ScanIncompleteness(
            unevaluated_rules=facts.unevaluated_rules,
            stale_content_databases=facts.stale_content_databases,
            could_not_stop=facts.could_not_stop,
        )

    return fake


class TestScanStatusReportsEveryArmOfTheExitCode:
    """``scan.status`` read two of the exit code's arms (incomplete scanners and
    no scanner having run), so a scan that exited 1 because a rule was not
    evaluated, a converter did not run, a content database was stale or a tool
    could not be stopped read ``success`` with no message: byte-identical to a
    clean scan, with every scanner PASSED."""

    @pytest.mark.parametrize("arm", list(_OTHER_ARMS), ids=list(_OTHER_ARMS))
    def test_each_arm_is_a_failure_with_its_own_message(
        self, reporter, monkeypatch, arm
    ):
        facts, expected = _OTHER_ARMS[arm]
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", _answering(facts))
        model = _model(_result("B105", "x = 's'"))
        model.ash_config = AshConfig(project_name="scan-status-test")

        report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 1
        assert report["scan"]["status"] == "failure"
        assert report["scan"]["messages"] == [{"level": "warn", "value": expected}]

    @pytest.mark.parametrize(
        "arm", ["rule-not-evaluated", "stale-database", "tool-could-not-be-stopped"]
    )
    def test_an_arm_the_gate_does_not_cover_fails_the_scan_with_the_gate_off(
        self, reporter, monkeypatch, arm
    ):
        """These arms exit 1 whatever ``fail_on_incomplete_scanners`` says, so
        the status follows them with the gate off too."""
        facts, expected = _OTHER_ARMS[arm]
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", _answering(facts))
        model = _model()
        model.ash_config = AshConfig(
            project_name="scan-status-test", fail_on_incomplete_scanners=False
        )

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "failure"
        assert report["scan"]["messages"] == [{"level": "warn", "value": expected}]

    def test_a_converter_behind_the_gate_keeps_success_with_the_gate_off(
        self, reporter, monkeypatch
    ):
        facts, expected = _OTHER_ARMS["converter-did-not-run"]
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", _answering(facts))
        model = _model()
        model.ash_config = AshConfig(
            project_name="scan-status-test", fail_on_incomplete_scanners=False
        )

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "success"
        assert report["scan"]["messages"] == [{"level": "warn", "value": expected}]

    def test_every_arm_at_once_lists_every_message(self, reporter, monkeypatch):
        facts = run_ash_scan.ScanIncompleteness(
            scanners=(("bandit", "MISSING"),),
            converters=(run_ash_scan.IncompleteConverter("archive", "crashed"),),
            unevaluated_rules=("AwsSolutions-S1", "AwsSolutions-S2"),
            could_not_stop=(("semgrep", "pid 4242"),),
        )
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", _answering(facts))
        model = _model()
        model.ash_config = AshConfig(project_name="scan-status-test")

        report = json.loads(reporter.report(model))

        values = [m["value"] for m in report["scan"]["messages"]]
        assert report["scan"]["status"] == "failure"
        assert len(values) == 5
        assert values[0] == (
            "Scanner bandit did not complete (MISSING); its findings are absent "
            "from this report."
        )
        assert values[1].startswith("Converter archive did not complete (crashed)")
        assert values[2].startswith("Rule AwsSolutions-S1 could not be evaluated")
        assert values[3].startswith("Rule AwsSolutions-S2 could not be evaluated")
        assert values[4].startswith("Scanner semgrep's tool could not be stopped")

    def test_the_status_is_read_from_the_exit_codes_object_not_the_messages(
        self, reporter, monkeypatch
    ):
        """A ``ScanIncompleteness`` that is truthy for a reason this reporter has
        no message for still fails the scan: the status is the object's truth
        value, so the next arm the exit code grows is not read as success."""

        class _Newer(run_ash_scan.ScanIncompleteness):
            def __bool__(self):
                return True

        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", _answering(_Newer()))
        model = _model()
        model.ash_config = AshConfig(project_name="scan-status-test")

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "failure"


class TestACoverageThatCannotBeReadIsNotVouchedFor:
    """When ``scan_incompleteness`` itself raised, the report said ``success``
    with no message, the loss logged at DEBUG: a MISSING scanner read as a
    clean scan. The vulnerabilities are kept, as before; the report now says it
    cannot vouch for coverage, and under a gate that is on the scan reads as
    incomplete."""

    @staticmethod
    def _raising(results, *, gate, **kwargs):
        raise RuntimeError("the scan module could not read this model")

    def test_a_raising_read_is_a_warning_and_a_failure_under_the_gate(
        self, reporter, monkeypatch, caplog
    ):
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", self._raising)
        model = _model(_result("B105", "x = 's'"))
        model.ash_config = AshConfig(project_name="scan-status-test")

        with caplog.at_level("WARNING"):
            report = json.loads(reporter.report(model))

        assert len(report["vulnerabilities"]) == 1
        assert report["scan"]["status"] == "failure"
        assert report["scan"]["messages"] == [
            {
                "level": "warn",
                "value": (
                    "Scanner coverage could not be determined; this report "
                    "cannot say whether the scan was complete."
                ),
            }
        ]
        assert any(
            "coverage could not be determined" in record.getMessage()
            and record.levelname == "WARNING"
            for record in caplog.records
        )

    def test_with_the_gate_off_the_warning_stays_and_the_status_is_success(
        self, reporter, monkeypatch
    ):
        monkeypatch.setattr(run_ash_scan, "scan_incompleteness", self._raising)
        model = _model()
        model.ash_config = AshConfig(
            project_name="scan-status-test", fail_on_incomplete_scanners=False
        )

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "success"
        assert [m["level"] for m in report["scan"]["messages"]] == ["warn"]

    def test_an_unimportable_scan_module_reads_the_same_way(
        self, reporter, monkeypatch
    ):
        model = _model()
        model.ash_config = AshConfig(project_name="scan-status-test")
        monkeypatch.setitem(
            sys.modules, "automated_security_helper.interactions.run_ash_scan", None
        )

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "failure"
        assert [m["level"] for m in report["scan"]["messages"]] == ["warn"]


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
