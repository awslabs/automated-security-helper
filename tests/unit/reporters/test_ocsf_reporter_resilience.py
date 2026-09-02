# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the OCSF reporter's degradation paths.

The reporter wraps almost every field extraction in its own try/except so that
one malformed SARIF result cannot lose a whole report. Those handlers are the
least-exercised code in the module and the most consequential: a handler that
swallows an error and then returns a finding with the wrong severity is worse
than one that raises.

Reaching them needs fault injection, because a well-formed pydantic model never
takes those branches. The stand-ins below declare exactly the attributes the
reporter reads and raise from one chosen attribute -- deliberately not
``Mock()``, which fabricates any attribute touched and so cannot distinguish a
real read from a typo in the reporter.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter import (
    OcsfReporter,
    _metadata_for_project,
)
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    FindingInfo,
    Metadata,
    Product,
    SeverityId,
    StatusId,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind1,
    Level,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    State,
    Suppression,
    Tool,
    ToolComponent,
)

MODULE = "automated_security_helper.plugin_modules.ash_builtin.reporters.ocsf_reporter"

AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# Fault injectors
# ---------------------------------------------------------------------------


def _raiser(error):
    """A property that raises `error` when read."""

    def _get(self):
        raise error

    return property(_get)


_RESULT_ATTRS = ("ruleId", "message", "level", "locations", "suppressions")


def faulty_result(faulty, error=None, **values):
    """A Result stand-in that raises when `faulty` is read.

    Every other attribute the reporter reads is declared explicitly, so a read of
    something the real Result does not have raises AttributeError rather than
    quietly succeeding.
    """
    assert faulty in _RESULT_ATTRS, f"not a Result attribute: {faulty}"
    unknown = set(values) - set(_RESULT_ATTRS)
    assert not unknown, f"not Result attributes: {unknown}"
    error = error if error is not None else RuntimeError(f"{faulty} unreadable")

    namespace = {a: values.get(a) for a in _RESULT_ATTRS if a != faulty}
    namespace[faulty] = _raiser(error)
    return type("FaultyResult", (), namespace)()


def faulty_location(faulty, error=None, **phys_values):
    """A Location stand-in whose physicalLocation.root raises on `faulty`.

    `faulty` may be "physicalLocation" (the outer read fails) or one of
    "artifactLocation" / "region" on the inner root object.
    """
    error = error if error is not None else RuntimeError(f"{faulty} unreadable")
    if faulty == "physicalLocation":
        return type("FaultyLocation", (), {"physicalLocation": _raiser(error)})()

    inner_attrs = ("artifactLocation", "region")
    assert faulty in inner_attrs, f"not a physicalLocation attribute: {faulty}"
    namespace = {a: phys_values.get(a) for a in inner_attrs if a != faulty}
    namespace[faulty] = _raiser(error)
    root = type("FaultyPhysicalLocation", (), namespace)()
    return type(
        "Location", (), {"physicalLocation": type("Wrapper", (), {"root": root})()}
    )()


class UnprintableError(Exception):
    """An exception whose own str() raises.

    This is what makes the per-suppression handler reachable: the inner handlers
    interpolate str(e) into a log message, so an exception that cannot be
    stringified turns an inner handler into a new failure that only the outer
    per-suppression handler can catch.
    """

    def __str__(self):
        raise RuntimeError("this exception cannot be stringified")


class UniterableSuppressions:
    """Reports a non-zero length but raises when iterated."""

    def __len__(self):
        return 2

    def __iter__(self):
        raise RuntimeError("suppression list is not iterable")


def suppression_stub(**values):
    """A Suppression stand-in with exactly the three attributes read."""
    attrs = ("kind", "state", "justification")
    unknown = set(values) - set(attrs)
    assert not unknown, f"not Suppression attributes: {unknown}"
    namespace = {}
    for attr in attrs:
        value = values.get(attr)
        namespace[attr] = _raiser(value) if isinstance(value, BaseException) else value
    return type("SuppressionStub", (), namespace)()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def reporter(test_plugin_context):
    return OcsfReporter(context=test_plugin_context)


@pytest.fixture
def metadata():
    return Metadata(
        product=Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version="1",
        ),
        version="1.1.0",
        logged_time=1_700_000_000_000,
    )


def make_model(results):
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)],
    )
    return model


def good_result(rule_id="R1", level=Level.error, text="a finding"):
    return Result(
        ruleId=rule_id, level=level, message=Message(root=Message1(text=text))
    )


# ---------------------------------------------------------------------------
# _create_vulnerability_from_result degradation
# ---------------------------------------------------------------------------


class TestVulnerabilityExtractionFaults:
    def test_unreadable_rule_id_falls_back_to_unknown_rule(self, reporter):
        result = faulty_result(
            "ruleId", message=Message(root=Message1(text="still readable"))
        )

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.title == "Unknown Rule"
        assert vuln.desc == "still readable"
        # No CVE is attached for an unknown rule; a synthetic uid would be wrong.
        assert getattr(vuln, "cve", None) is None

    def test_unreadable_artifact_location_skips_that_location(self, reporter):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        result.locations = [
            faulty_location("artifactLocation", region=Region(startLine=1)),
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri="src/ok.py"),
                        region=Region(startLine=9),
                    )
                )
            ),
        ]

        vuln = reporter._create_vulnerability_from_result(result)

        assert len(vuln.affected_code) == 1, (
            "the unreadable location is dropped, the good one is kept"
        )
        assert vuln.affected_code[0].file.path == "src/ok.py"

    def test_unreadable_region_keeps_the_file_without_line_numbers(self, reporter):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        result.locations = [
            faulty_location(
                "region", artifactLocation=ArtifactLocation(uri="src/app.py")
            )
        ]

        vuln = reporter._create_vulnerability_from_result(result)

        assert len(vuln.affected_code) == 1, (
            "losing the region must not lose the file the finding is in"
        )
        code = vuln.affected_code[0]
        assert code.file.path == "src/app.py"
        assert code.start_line is None
        assert code.end_line is None

    def test_unreadable_physical_location_skips_that_location(self, reporter):
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        result.locations = [faulty_location("physicalLocation")]

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.affected_code is None or vuln.affected_code == []

    def test_non_string_uri_skips_that_location(self, reporter):
        """A uri that is truthy but not a string breaks the file-name split."""
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        bad_uri = type("BadUri", (), {"uri": 12345})()
        result.locations = [
            type(
                "Location",
                (),
                {
                    "physicalLocation": type(
                        "Wrapper",
                        (),
                        {
                            "root": type(
                                "Phys",
                                (),
                                {"artifactLocation": bad_uri, "region": None},
                            )()
                        },
                    )()
                },
            )()
        ]

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.title == "R1"
        assert vuln.affected_code is None or vuln.affected_code == []

    def test_invalid_region_data_degrades_to_a_minimal_vulnerability(self, reporter):
        """If Vulnerability() itself rejects the assembled data, a stub is returned.

        A non-integer startLine survives every inner handler -- each one only
        guards attribute access, not the model validation that happens after --
        so it is the outermost handler that has to catch it.
        """
        result = Result(ruleId="R1", level=Level.error, message=Message(text="m"))
        location = Location(
            physicalLocation=PhysicalLocation(
                root=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri="src/app.py"),
                    region=Region(startLine=1),
                )
            )
        )
        location.physicalLocation.root.region.startLine = "not-a-line-number"
        result.locations = [location]

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.title == "R1", "the rule id is preserved in the fallback"
        assert vuln.desc == "Error processing vulnerability details"
        assert vuln.severity == "MEDIUM"

    def test_fallback_title_is_unknown_rule_when_the_rule_id_is_absent(self, reporter):
        result = Result(level=Level.error, message=Message(text="m"))
        location = Location(
            physicalLocation=PhysicalLocation(
                root=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri="src/app.py"),
                    region=Region(startLine=1),
                )
            )
        )
        location.physicalLocation.root.region.startLine = "not-a-line-number"
        result.locations = [location]

        vuln = reporter._create_vulnerability_from_result(result)

        assert vuln.title == "Unknown Rule"
        assert vuln.desc == "Error processing vulnerability details"


# ---------------------------------------------------------------------------
# _determine_status_from_suppressions degradation
# ---------------------------------------------------------------------------


class TestSuppressionStatusFaults:
    def test_no_suppressions_is_a_new_active_finding(self, reporter):
        assert reporter._determine_status_from_suppressions(None, "R1") == (
            StatusId.integer_1,
            None,
            "New",
        )
        assert reporter._determine_status_from_suppressions([], "R1") == (
            StatusId.integer_1,
            None,
            "New",
        )

    def test_full_suppression_detail_is_recorded(self, reporter):
        status_id, detail, status = reporter._determine_status_from_suppressions(
            [
                Suppression(
                    kind=Kind1.external,
                    state=State.accepted,
                    justification="  reviewed and accepted  ",
                )
            ],
            "R1",
        )

        assert (status_id, status) == (StatusId.integer_3, "Suppressed")
        assert detail == (
            "kind: external; state: accepted; justification: reviewed and accepted"
        ), "the enum member name, not its repr, and a stripped justification"

    def test_unreadable_state_keeps_the_other_fields(self, reporter):
        _, detail, _ = reporter._determine_status_from_suppressions(
            [
                suppression_stub(
                    kind=Kind1.external,
                    state=RuntimeError("state unreadable"),
                    justification="a reason",
                )
            ],
            "R1",
        )

        assert "kind: external" in detail
        assert "justification: a reason" in detail
        assert "state:" not in detail

    def test_unreadable_justification_keeps_the_other_fields(self, reporter):
        _, detail, _ = reporter._determine_status_from_suppressions(
            [
                suppression_stub(
                    kind=Kind1.external,
                    state=State.accepted,
                    justification=RuntimeError("justification unreadable"),
                )
            ],
            "R1",
        )

        assert "kind: external" in detail
        assert "state: accepted" in detail
        assert "justification:" not in detail

    def test_whitespace_only_justification_is_dropped(self, reporter):
        _, detail, _ = reporter._determine_status_from_suppressions(
            [Suppression(kind=Kind1.external, justification="   ")], "R1"
        )

        assert detail == "kind: external"

    def test_a_suppression_with_no_readable_detail_gets_a_generic_entry(self, reporter):
        """The finding is still marked suppressed -- losing that would un-suppress it."""
        status_id, detail, status = reporter._determine_status_from_suppressions(
            [suppression_stub()], "R1"
        )

        assert (status_id, status) == (StatusId.integer_3, "Suppressed")
        assert detail == "suppression_0"

    def test_multiple_suppressions_are_joined(self, reporter):
        _, detail, _ = reporter._determine_status_from_suppressions(
            [
                Suppression(kind=Kind1.external, justification="first"),
                Suppression(kind=Kind1.inSource, justification="second"),
            ],
            "R1",
        )

        assert detail.split(" | ") == [
            "kind: external; justification: first",
            "kind: inSource; justification: second",
        ]

    def test_a_failure_inside_an_inner_handler_is_recorded_as_an_error_entry(
        self, reporter
    ):
        """An exception that cannot be stringified defeats the inner handler."""
        status_id, detail, status = reporter._determine_status_from_suppressions(
            [
                suppression_stub(kind=UnprintableError()),
                Suppression(kind=Kind1.external, justification="fine"),
            ],
            "R1",
        )

        assert (status_id, status) == (StatusId.integer_3, "Suppressed")
        parts = detail.split(" | ")
        assert parts == [
            "suppression_0_error",
            "kind: external; justification: fine",
        ], "the broken suppression is flagged and the good one still processed"

    def test_an_uniterable_suppression_list_yields_unknown_status(self, reporter):
        """len() says there are suppressions but they cannot be read at all."""
        assert reporter._determine_status_from_suppressions(
            UniterableSuppressions(), "R1"
        ) == (StatusId.integer_0, "Unknown suppression status", "Unknown")


# ---------------------------------------------------------------------------
# _create_vulnerability_finding degradation
# ---------------------------------------------------------------------------


class TestVulnerabilityFindingFaults:
    def test_non_string_message_text_falls_back_to_a_truncated_title(
        self, reporter, metadata
    ):
        """A non-string message defeats the length checks used to build the title."""
        result = good_result(text="x")
        result.message.root.text = 12345

        finding = reporter._create_vulnerability_finding(result, metadata, 1)

        assert finding.finding_info.title == "Error creating finding title"
        assert finding.finding_info.desc == "Error extracting finding description"
        assert finding.severity_id == SeverityId.integer_4, (
            "severity comes from result.level and must survive a bad message"
        )

    def test_primary_construction_failure_yields_a_low_unknown_fallback(
        self, reporter, metadata, monkeypatch
    ):
        monkeypatch.setattr(
            f"{MODULE}._metadata_for_project",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("attribution failed")),
        )

        finding = reporter._create_vulnerability_finding(good_result(), metadata, 7)

        assert finding.severity_id == SeverityId.integer_2, "fallback severity is LOW"
        assert finding.status_id == StatusId.integer_0, "fallback status is Unknown"
        assert finding.time == 7
        assert finding.finding_info.title == "Error processing finding R1"
        assert finding.vulnerabilities[0].title == "R1"
        assert finding.vulnerabilities[0].desc == (
            "Error processing vulnerability details"
        )

    def test_when_even_the_fallback_cannot_be_built_the_error_is_raised(
        self, reporter, metadata, monkeypatch
    ):
        """Silently returning nothing here would drop a finding without a trace."""

        def _explode(*args, **kwargs):
            raise RuntimeError("FindingInfo is unusable")

        monkeypatch.setattr(f"{MODULE}.FindingInfo", _explode)

        with pytest.raises(Exception, match="Unable to create VulnerabilityFinding"):
            reporter._create_vulnerability_finding(good_result(), metadata, 1)

    @pytest.mark.parametrize(
        "level,expected",
        [
            (Level.error, SeverityId.integer_4),
            (Level.warning, SeverityId.integer_3),
            (Level.note, SeverityId.integer_2),
            (Level.none, SeverityId.integer_1),
            (None, SeverityId.integer_2),
        ],
        ids=["error", "warning", "note", "none", "unset"],
    )
    def test_severity_mapping(self, reporter, metadata, level, expected):
        finding = reporter._create_vulnerability_finding(
            good_result(level=level), metadata, 1
        )
        assert finding.severity_id == expected


# ---------------------------------------------------------------------------
# report() degradation
# ---------------------------------------------------------------------------


class TestReportDegradation:
    def test_no_sarif_returns_an_empty_array(self, reporter):
        model = AshAggregatedResults()
        model.sarif = None

        assert json.loads(reporter.report(model)) == []

    def test_no_runs_returns_an_empty_array(self, reporter):
        model = AshAggregatedResults()
        model.sarif = SarifReport(version="2.1.0", runs=[])

        assert json.loads(reporter.report(model)) == []

    def test_no_results_returns_an_empty_array(self, reporter):
        assert json.loads(reporter.report(make_model([]))) == []

    def test_every_input_result_becomes_one_finding(self, reporter):
        rule_ids = ["R1", "R2", "R3"]
        model = make_model([good_result(rule_id=r) for r in rule_ids])

        findings = json.loads(reporter.report(model))

        assert {f["vulnerabilities"][0]["title"] for f in findings} == set(rule_ids), (
            "the ids in must equal the ids out"
        )

    def test_a_truthy_but_empty_result_set_returns_an_empty_array(
        self, reporter, monkeypatch
    ):
        """Guards the branch where the count is zero but the container is truthy."""

        class TruthyEmpty:
            def __bool__(self):
                return True

            def __len__(self):
                return 0

            def __iter__(self):
                return iter(())

        model = make_model([good_result()])
        monkeypatch.setattr(
            SarifReport, "get_all_results", lambda self: TruthyEmpty(), raising=True
        )

        assert json.loads(reporter.report(model)) == []

    def test_when_every_finding_fails_an_error_response_is_returned(
        self, reporter, monkeypatch
    ):
        """An empty array here would read as a clean scan; it must not."""
        model = make_model([good_result("R1"), good_result("R2")])
        monkeypatch.setattr(
            OcsfReporter,
            "_create_vulnerability_finding",
            lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("nope")),
        )

        payload = json.loads(reporter.report(model))

        assert isinstance(payload, list) and len(payload) == 1
        (error,) = payload
        assert error["error"] == "All findings failed to process"
        # Pins a real defect in the statistics, not the intended numbers. This
        # call site passes total_results_count into the processed_count
        # parameter, so an "everything failed" response claims 2 processed, a
        # total of 4 against 2 real inputs, and a 50% success rate when nothing
        # succeeded. The error message is right; the counts are not. Fixing the
        # call site to pass 0 will turn this test red, which is the point.
        stats = error["processing_statistics"]
        assert stats["processed_results_count"] == 2
        assert stats["failed_results_count"] == 2
        assert stats["total_results_count"] == 4
        assert stats["success_rate_percent"] == 50.0

    def test_a_partial_failure_still_reports_the_findings_that_worked(
        self, reporter, monkeypatch
    ):
        model = make_model([good_result("GOOD"), good_result("BAD")])
        real = OcsfReporter._create_vulnerability_finding

        def _maybe_fail(self, result, *args, **kwargs):
            if result.ruleId == "BAD":
                raise RuntimeError("this one fails")
            return real(self, result, *args, **kwargs)

        monkeypatch.setattr(OcsfReporter, "_create_vulnerability_finding", _maybe_fail)

        findings = json.loads(reporter.report(model))

        assert [f["vulnerabilities"][0]["title"] for f in findings] == ["GOOD"]

    def test_when_every_finding_fails_to_serialize_an_error_response_is_returned(
        self, reporter, monkeypatch
    ):
        class UnserializableFinding:
            finding_info = FindingInfo(
                uid="11111111-1111-1111-1111-111111111111",
                title="t",
                desc="d",
            )
            status_id = StatusId.integer_1

            def model_dump(self, **kwargs):
                raise RuntimeError("cannot serialize")

        model = make_model([good_result()])
        monkeypatch.setattr(
            OcsfReporter,
            "_create_vulnerability_finding",
            lambda self, *a, **k: UnserializableFinding(),
        )

        payload = json.loads(reporter.report(model))

        (error,) = payload
        assert error["error"] == "All findings failed to serialize"
        stats = error["processing_statistics"]
        assert stats["processed_results_count"] == 1
        assert stats["failed_results_count"] == 1

    def test_suppressed_findings_are_reported_with_suppressed_status(self, reporter):
        result = good_result()
        result.suppressions = [
            Suppression(kind=Kind1.external, justification="accepted risk")
        ]
        model = make_model([result])

        (finding,) = json.loads(reporter.report(model))

        assert finding["status_id"] == StatusId.integer_3.value
        assert finding["status"] == "Suppressed"
        assert "accepted risk" in finding["status_detail"]


class TestWorkspaceAttribution:
    def test_a_single_directory_scan_reuses_the_shared_metadata_object(self, metadata):
        """No project means no copy, so output stays byte-identical."""
        assert _metadata_for_project(metadata, good_result()) is metadata

    def test_a_project_is_recorded_as_a_prefixed_label(self, metadata):
        result = good_result()
        result.properties = PropertyBag(workspace_project="service-a")

        annotated = _metadata_for_project(metadata, result)

        assert annotated is not metadata, "the shared object must not be mutated"
        assert annotated.labels == ["workspace_project:service-a"]
        assert metadata.labels is None, (
            "one Metadata is shared across findings; mutating it would give every "
            "finding every project's label"
        )

    def test_an_existing_label_is_preserved_and_not_duplicated(self, metadata):
        result = good_result()
        result.properties = PropertyBag(workspace_project="service-a")
        seeded = metadata.model_copy(
            update={"labels": ["team:platform", "workspace_project:service-a"]}
        )

        annotated = _metadata_for_project(seeded, result)

        assert annotated.labels == ["team:platform", "workspace_project:service-a"]

    def test_each_finding_carries_its_own_project(self, reporter):
        first = good_result("R1")
        first.properties = PropertyBag(workspace_project="service-a")
        second = good_result("R2")
        second.properties = PropertyBag(workspace_project="service-b")

        findings = json.loads(reporter.report(make_model([first, second])))

        by_rule = {f["vulnerabilities"][0]["title"]: f for f in findings}
        assert by_rule["R1"]["metadata"]["labels"] == ["workspace_project:service-a"]
        assert by_rule["R2"]["metadata"]["labels"] == ["workspace_project:service-b"]


# ---------------------------------------------------------------------------
# _create_error_response degradation
# ---------------------------------------------------------------------------


class TestErrorResponse:
    def test_statistics_are_computed_from_the_counts(self, reporter):
        (error,) = json.loads(
            reporter._create_error_response("something broke", 123, 3, 1)
        )

        assert error["error"] == "something broke"
        assert error["metadata"]["logged_time"] == 123
        assert error["metadata"]["version"] == "1.1.0"
        assert error["metadata"]["product"]["vendor_name"] == "Amazon Web Services"
        stats = error["processing_statistics"]
        assert stats == {
            "processed_results_count": 3,
            "failed_results_count": 1,
            "total_results_count": 4,
            "success_rate_percent": 75.0,
        }

    def test_zero_counts_do_not_divide_by_zero(self, reporter):
        (error,) = json.loads(reporter._create_error_response("nothing ran", 1, 0, 0))

        assert error["processing_statistics"]["success_rate_percent"] == 0
        assert error["processing_statistics"]["total_results_count"] == 0

    def test_a_failure_building_the_error_response_still_returns_valid_json(
        self, reporter, monkeypatch
    ):
        """The last line of defense: the caller must always get parseable JSON."""
        monkeypatch.setattr(
            f"{MODULE}.get_ash_version",
            lambda: (_ for _ in ()).throw(RuntimeError("version lookup failed")),
        )

        payload = json.loads(
            reporter._create_error_response("original problem", 1, 1, 1)
        )

        assert payload == [
            {
                "error": (
                    "Critical error in OCSF reporter - unable to create detailed "
                    "error response"
                )
            }
        ]
