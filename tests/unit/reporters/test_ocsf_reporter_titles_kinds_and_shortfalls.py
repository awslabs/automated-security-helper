# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""OCSF records say what the scan found, in the shape the schema and a SIEM read.

* ``finding_info.title`` had its 120-character cap applied to the message part
  alone, so a long rule id and file name pushed the title past it and the
  ellipsis was added after a full-width slice.
* A location uri with backslash separators gave the whole path as the file name.
* A message given by ``id`` alone was described as "No description".
* A result whose kind says no problem (pass, notApplicable, informational) was
  emitted as a New vulnerability finding.
* One location value the schema refuses discarded every location, the CVE and
  the description of the finding.
* Results dropped for a failed build or serialization left no mark in the array,
  and the all-failed-to-serialize response counted the processed findings as
  processed, doubling the total and stating 50% success.
* A file name holding a lone surrogate reached ``json.dumps`` and was written as
  a lone ``\\udcXX`` escape, which strict JSON parsers reject.
* The shortfall record said "0 finding(s) could not be converted" and "The
  array is incomplete" for an array that held every finding and only carried
  degraded records; it names the counts that are not zero.
"""

import json
from datetime import datetime, timezone

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    CONVERSION_SHORTFALL_LABEL,
    DEGRADED_FINDING_LABEL,
    TITLE_MAX_LENGTH,
    OcsfReporter,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    Metadata,
    Product,
    VulnerabilityFinding,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind,
    Level,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

AshAggregatedResults.model_rebuild()


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


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _located(uri: str, line: int = 1) -> Location:
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri), region=Region(startLine=line)
        )
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="t")), results=list(results))],
    )
    return model


class TestTitles:
    def test_a_truncated_title_is_at_most_the_cap_with_its_ellipsis(
        self, reporter, metadata
    ):
        result = Result(
            ruleId="R1", level=Level.error, message=Message(text="word " * 60)
        )

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        assert len(finding.finding_info.title) == TITLE_MAX_LENGTH
        assert finding.finding_info.title.endswith("...")

    def test_a_prefix_past_the_cap_is_cut_too(self, reporter, metadata):
        result = Result(
            ruleId="R" * 130,
            level=Level.error,
            message=Message(text="m"),
            locations=[_located("src/app.py")],
        )

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        assert len(finding.finding_info.title) == TITLE_MAX_LENGTH
        assert finding.finding_info.title.endswith("...")

    def test_a_short_title_is_written_whole(self, reporter, metadata):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        assert finding.finding_info.title == "R1 - m"


class TestFileNamesAndMessages:
    def test_a_backslash_uri_names_the_file_not_the_path(self, reporter, metadata):
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="m"),
            locations=[_located("C:\\repo\\src\\app.py", 3)],
        )

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        (code,) = finding.vulnerabilities[0].affected_code
        assert code.file.name == "app.py"
        assert code.file.path == "C:\\repo\\src\\app.py"
        assert " in app.py - " in finding.finding_info.title

    def test_a_message_given_by_id_is_described_by_it(self, reporter, metadata):
        # message is required on Result, so the id-only message is given at
        # construction rather than assigned after.
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message.model_validate({"id": "default"}),
        )

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        assert finding.finding_info.desc == "default"
        assert finding.vulnerabilities[0].desc == "default"
        assert finding.finding_info.title == "R1 - default"

    def test_a_message_of_spaces_alone_is_no_description(self, reporter, metadata):
        # Whitespace is no description: written as-is, it titled the finding
        # "R1 -    " and described it as three spaces.
        result = Result(ruleId="R1", level=Level.error, message=Message(text="   "))

        finding = reporter._create_vulnerability_finding(result, metadata, _now_ms())

        assert finding.finding_info.desc == "No description"
        assert finding.finding_info.title == "R1 - No description"


class TestNonFindingKinds:
    @pytest.mark.parametrize(
        "kind", [Kind.pass_, Kind.notApplicable, Kind.informational]
    )
    def test_a_result_that_states_no_problem_is_not_emitted(self, reporter, kind):
        payload = json.loads(
            reporter.report(
                _model(
                    Result(
                        ruleId="CDK-1",
                        kind=kind,
                        level=Level.none,
                        message=Message(text="x"),
                    ),
                    Result(ruleId="B102", level=Level.error, message=Message(text="y")),
                )
            )
        )

        assert [r["vulnerabilities"][0]["title"] for r in payload] == ["B102"]


class TestOneBadLocation:
    def test_the_other_locations_and_the_description_are_kept(self, reporter):
        result = Result(
            ruleId="R1",
            level=Level.error,
            message=Message(text="the description"),
            locations=[_located("src/bad.py", 1), _located("src/good.py", 2)],
        )
        result.locations[0].physicalLocation.root.region.startLine = "not-a-line"

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.desc == "the description"
        assert [c.file.name for c in vuln.affected_code] == ["good.py"]


class TestShortfalls:
    def test_a_dropped_result_leaves_a_shortfall_record(self, reporter, monkeypatch):
        original = OcsfReporter._create_vulnerability_finding

        # The stub forwards whatever the report passes (shared_id, identity,
        # anything added later), so only the BROKEN result fails; a stub with a
        # fixed parameter list failed on every result once the report passed a
        # keyword it did not name, and the test then read the all-failed
        # response instead of the shortfall record it is about.
        def flaky(self, result, *args, **kwargs):
            if result.ruleId == "BROKEN":
                raise RuntimeError("cannot build")
            return original(self, result, *args, **kwargs)

        monkeypatch.setattr(OcsfReporter, "_create_vulnerability_finding", flaky)
        payload = json.loads(
            reporter.report(
                _model(
                    Result(
                        ruleId="BROKEN", level=Level.error, message=Message(text="x")
                    ),
                    Result(ruleId="FINE", level=Level.error, message=Message(text="y")),
                )
            )
        )

        assert len(payload) == 2
        shortfall = payload[1]
        assert CONVERSION_SHORTFALL_LABEL in shortfall["metadata"]["labels"]
        assert shortfall["status_id"] == 99
        assert shortfall["vulnerabilities"] == []
        assert (
            "1 finding(s) could not be converted" in shortfall["finding_info"]["title"]
        )

    def test_a_degraded_record_is_marked_and_counted(self, reporter, monkeypatch):
        def broken_vulnerability(self, result):
            raise RuntimeError("no vulnerability")

        monkeypatch.setattr(
            OcsfReporter, "_create_vulnerability_from_result", broken_vulnerability
        )
        payload = json.loads(
            reporter.report(
                _model(
                    Result(ruleId="R1", level=Level.error, message=Message(text="x"))
                )
            )
        )

        assert DEGRADED_FINDING_LABEL in payload[0]["metadata"]["labels"]
        shortfall = payload[1]
        assert CONVERSION_SHORTFALL_LABEL in shortfall["metadata"]["labels"]
        assert "1 record(s) were built by the fallback" in shortfall["status_detail"]
        # Nothing is missing, so the record names the degraded count alone and
        # does not call a complete array incomplete.
        assert shortfall["finding_info"]["title"] == (
            "1 record(s) built by the fallback path"
        )
        assert "could not be converted" not in shortfall["finding_info"]["title"]
        assert "incomplete" not in shortfall["status_detail"].lower()
        assert shortfall["status"] == "Degraded"

    def test_a_shortfall_with_both_counts_names_both(self, reporter, metadata):
        record = reporter._create_shortfall_finding(2, 1, metadata, _now_ms())

        assert record.finding_info.title == (
            "2 finding(s) could not be converted to OCSF; "
            "1 record(s) built by the fallback path"
        )
        assert (
            "2 finding(s) of this scan could not be converted" in record.status_detail
        )
        assert "1 record(s) were built by the fallback path" in record.status_detail
        assert record.status_detail.endswith("The array is incomplete.")
        assert record.status == "Incomplete"

    def test_an_all_failed_to_serialize_response_counts_nothing_as_processed(
        self, reporter, monkeypatch
    ):
        def boom(self, *args, **kwargs):
            raise RuntimeError("cannot dump")

        monkeypatch.setattr(VulnerabilityFinding, "model_dump", boom)
        payload = json.loads(
            reporter.report(
                _model(
                    Result(ruleId="R1", level=Level.error, message=Message(text="x")),
                    Result(ruleId="R2", level=Level.error, message=Message(text="y")),
                )
            )
        )

        (error,) = payload
        stats = error["processing_statistics"]
        assert stats["processed_results_count"] == 0
        assert stats["failed_results_count"] == 2
        assert stats["total_results_count"] == 2
        assert stats["success_rate_percent"] == 0


class TestUndecodableNames:
    def test_a_lone_surrogate_in_a_uri_is_written_as_text(self, reporter):
        payload_text = reporter.report(
            _model(
                Result(
                    ruleId="R1",
                    level=Level.error,
                    message=Message(text="m"),
                    locations=[_located("src/caf\udce9.py")],
                )
            )
        )

        parsed = json.loads(payload_text)
        # A lone surrogate cannot be encoded; the record form is plain text.
        json.dumps(parsed, ensure_ascii=False).encode("utf-8")
        path = parsed[0]["vulnerabilities"][0]["affected_code"][0]["file"]["path"]
        assert "udce9" in path
