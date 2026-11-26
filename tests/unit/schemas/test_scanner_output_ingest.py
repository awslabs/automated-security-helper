"""A scanner's report is read through the ingest step, which repairs what the model refuses.

One value the SARIF or CycloneDX model refuses, a region that starts on line 0, a
link that is not a URL, a key the spec does not define, used to cost the scanner
its whole report. The ingest step drops or rewrites the smallest out-of-spec part
whose loss changes no finding, notes it, and validates again. What it cannot
repair (a missing message, a level the spec does not define, a suppression of a
kind it does not define) is refused with the model's own error, as before.

The cases are the refusals measured against the pinned models, one out-of-spec
element each, started from a real capture of gitleaks or zizmor (SARIF) and of
syft (CycloneDX). Each case checks the report validates, every other result is
equal to a plain validation of the unmutated capture, the repaired result keeps
what identifies it, and the record names the kind and the place, never a value.
"""

from __future__ import annotations

import copy
import json
import pickle
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest import mock

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import Invocation, SarifReport
from automated_security_helper.schemas.scanner_output_ingest import (
    IngestRecord,
    ingest_cyclonedx,
    ingest_sarif,
    read_json_text_tolerant,
    read_json_tolerant,
)

pytestmark = pytest.mark.unit

_DATA = Path(__file__).resolve().parents[2] / "test_data"

#: One seed for every property test of the suite, so a run is the same run.
SUITE_SEED = 20261126


def _load(relative: str) -> Any:
    return json.loads((_DATA / relative).read_text(encoding="utf-8"))


_BASES = {
    "gitleaks": _load("scanners/gitleaks/gitleaks-8.30.1.sarif"),
    "zizmor": _load("scanners/zizmor/zizmor-1.30.1.sarif"),
}
_SYFT = _load("snapshot_fixture/scanner_outputs/syft.cdx.json")

_R0 = "runs/0/results/0"
_REGION = f"{_R0}/locations/0/physicalLocation/region"
_RULE0 = "runs/0/tool/driver/rules/0"
_DRIVER = "runs/0/tool/driver"


# --------------------------------------------------------------------------- #
# Reaching into a capture
# --------------------------------------------------------------------------- #


def _result(doc: dict, index: int = 0) -> dict:
    return doc["runs"][0]["results"][index]


def _physical(doc: dict, index: int = 0) -> dict:
    return _result(doc, index)["locations"][0]["physicalLocation"]


def _region(doc: dict, index: int = 0) -> dict:
    return _physical(doc, index)["region"]


def _rule(doc: dict) -> dict:
    return doc["runs"][0]["tool"]["driver"]["rules"][0]


def _driver(doc: dict) -> dict:
    return doc["runs"][0]["tool"]["driver"]


def _run(doc: dict) -> dict:
    return doc["runs"][0]


def _put(where: Callable[[dict], dict], key: str, value: Any) -> Callable[[dict], None]:
    def mutate(doc: dict) -> None:
        where(doc)[key] = value

    return mutate


def _flow_region(doc: dict) -> dict:
    flow = _result(doc)["codeFlows"][0]["threadFlows"][0]["locations"][0]
    return flow["location"]["physicalLocation"]["region"]


def _identity(result: Any) -> tuple:
    """What identifies a finding to everything downstream of the report."""
    return (
        result.level,
        result.kind,
        result.ruleId,
        result.ruleIndex,
        len(result.locations or []),
        result.message.model_dump(mode="json") if result.message else None,
        [s.model_dump(mode="json") for s in (result.suppressions or [])],
    )


# --------------------------------------------------------------------------- #
# The repair cases
# --------------------------------------------------------------------------- #


class Case(NamedTuple):
    base: str
    mutate: Callable[[dict], None]
    #: (action, code, pointer) for each change the record must name, in any order.
    notes: tuple
    #: Results the mutation touched; every other result must equal the capture's.
    touched: tuple = (0,)
    #: Whether the repair rewrites a field that is part of the finding's identity
    #: (a number written as text), so only that result's identity may differ.
    rewrites_identity: bool = False
    check: Callable[[SarifReport], None] | None = None


def _case(id_: str, base: str, mutate: Callable, *notes: tuple, **extra: Any) -> Any:
    return pytest.param(Case(base, mutate, notes, **extra), id=id_)


def _dropped(code: str, pointer: str) -> tuple:
    return ("dropped", code, pointer)


def _rewritten(code: str, pointer: str) -> tuple:
    return ("rewritten", code, pointer)


def _result_is(
    index: int, check: Callable[[Any], None]
) -> Callable[[SarifReport], None]:
    return lambda report: check(report.runs[0].results[index])


def _has_one_related_location(result: Any) -> None:
    assert len(result.relatedLocations) == 1


def _has_no_fix(result: Any) -> None:
    assert not result.fixes


def _tags_are_text(result: Any) -> None:
    assert result.properties.tags == ["1", "a"]


def _fingerprint_is_text(result: Any) -> None:
    assert result.partialFingerprints["/home/u/x"] == "1"


def _only_the_good_work_item_stays(result: Any) -> None:
    assert [str(u) for u in result.workItemUris] == ["https://ok.example/1"]


_REPAIRS = [
    # R: a region or a line out of range. The finding stays, without its lines.
    *[
        _case(
            f"startLine {value!r}",
            "gitleaks",
            _put(_region, "startLine", value),
            _dropped("region_line_unreadable", _REGION),
        )
        for value in (0, -1, "x", 1.5)
    ],
    *[
        _case(
            f"region {field} {value!r}",
            "gitleaks",
            _put(_region, field, value),
            _dropped("region_field_unreadable", f"{_REGION}/{field}"),
        )
        for field, value in (
            ("startColumn", 0),
            ("endLine", 0),
            ("endColumn", 0),
            ("charOffset", -2),
            ("byteLength", -1),
            ("snippet", "x"),
        )
    ],
    _case(
        "region with a key the spec does not define",
        "gitleaks",
        _put(_region, "foo", 1),
        _dropped("unknown_key", f"{_REGION}/*"),
    ),
    _case(
        "region that is a list",
        "gitleaks",
        _put(_physical, "region", []),
        _dropped("region_field_unreadable", _REGION),
    ),
    _case(
        "related location with a region at line 0 keeps the related location",
        "zizmor",
        lambda doc: _result(doc).__setitem__(
            "relatedLocations",
            [
                {
                    "id": 1,
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a"},
                        "region": {"startLine": 0},
                    },
                }
            ],
        ),
        _dropped(
            "region_line_unreadable",
            f"{_R0}/relatedLocations/0/physicalLocation/region",
        ),
        check=_result_is(0, _has_one_related_location),
    ),
    _case(
        "thread flow location with a region at line 0",
        "zizmor",
        lambda doc: _flow_region(doc).__setitem__("startLine", 0),
        _dropped(
            "region_line_unreadable",
            f"{_R0}/codeFlows/0/threadFlows/0/locations/0/location/physicalLocation/region",
        ),
    ),
    _case(
        "fix whose deleted region is at line 0",
        "zizmor",
        lambda doc: _result(doc).__setitem__(
            "fixes",
            [
                {
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": "a"},
                            "replacements": [{"deletedRegion": {"startLine": 0}}],
                        }
                    ]
                }
            ],
        ),
        _dropped("fix_unreadable", f"{_R0}/fixes/0"),
        check=_result_is(0, _has_no_fix),
    ),
    # Result fields that are not part of the finding's identity.
    *[
        _case(
            f"result {field} {value!r}",
            "gitleaks",
            _put(_result, field, value),
            _dropped(f"{field}_unreadable", f"{_R0}/{field}"),
        )
        for field, value in (
            ("rank", 101),
            ("rank", -2),
            ("guid", "not-a-guid"),
            ("correlationGuid", "not-a-guid"),
            ("occurrenceCount", 0),
            ("baselineState", "fixed"),
            ("hostedViewerUri", "relative/x"),
        )
    ],
    _case(
        "one work item uri that is not a URL",
        "gitleaks",
        _put(_result, "workItemUris", ["TICKET-1", "https://ok.example/1"]),
        _dropped("workItemUris_entry_unreadable", f"{_R0}/workItemUris/0"),
        check=_result_is(0, _only_the_good_work_item_stays),
    ),
    _case(
        "code flow with no thread flows",
        "zizmor",
        _put(_result, "codeFlows", [{"threadFlows": []}]),
        _dropped("codeFlows_entry_unreadable", f"{_R0}/codeFlows/0"),
    ),
    _case(
        "related locations that is not a list",
        "gitleaks",
        _put(_result, "relatedLocations", {}),
        _dropped("relatedLocations_unreadable", f"{_R0}/relatedLocations"),
    ),
    # Maps and bags: one entry costs only itself.
    _case(
        "tags that is not a list",
        "gitleaks",
        _put(_result, "properties", {"tags": "a"}),
        _dropped("property_unreadable", f"{_R0}/properties/tags"),
    ),
    _case(
        "tags with a number and a null",
        "gitleaks",
        _put(_result, "properties", {"tags": [1, None, "a"]}),
        _rewritten("number_as_text", f"{_R0}/properties/tags/0"),
        _dropped("tag_not_text", f"{_R0}/properties/tags/1"),
        check=_result_is(0, _tags_are_text),
    ),
    _case(
        "property key that is not valid Unicode",
        "gitleaks",
        _put(_result, "properties", {chr(0xDCE9): 1, "kept": 2}),
        _dropped("property_unreadable", f"{_R0}/properties/*"),
    ),
    _case(
        "properties that is not an object",
        "gitleaks",
        _put(_result, "properties", "x"),
        _dropped("property_unreadable", f"{_R0}/properties"),
    ),
    _case(
        "fingerprint that is a number",
        "gitleaks",
        _put(_result, "partialFingerprints", {"/home/u/x": 1}),
        _rewritten("number_as_text", f"{_R0}/partialFingerprints/*"),
        check=_result_is(0, _fingerprint_is_text),
    ),
    _case(
        "fingerprint that is a list",
        "gitleaks",
        _put(_result, "fingerprints", {"k": ["x"]}),
        _dropped("fingerprint_unreadable", f"{_R0}/fingerprints/*"),
    ),
    # Rule descriptors: the field goes, never the id or the default configuration.
    *[
        _case(
            f"rule {field} {value!r}",
            "gitleaks",
            _put(_rule, field, value),
            _dropped("rule_field_unreadable", f"{_RULE0}/{field}"),
        )
        for field, value in (
            ("helpUri", "N/A"),
            ("helpUri", ""),
            ("helpUri", "docs/rule.md"),
            ("shortDescription", "x"),
            ("fullDescription", "x"),
            ("help", {"text": None}),
            ("guid", "x"),
        )
    ],
    _case(
        "rule tags with a number and a null",
        "gitleaks",
        _put(_rule, "properties", {"tags": [1, None]}),
        _rewritten("number_as_text", f"{_RULE0}/properties/tags/0"),
        _dropped("tag_not_text", f"{_RULE0}/properties/tags/1"),
        touched=(),
    ),
    _case(
        "rule with a key the spec does not define",
        "gitleaks",
        _put(_rule, "foo", 1),
        _dropped("unknown_key", f"{_RULE0}/*"),
        touched=(),
    ),
    # Tool components.
    *[
        _case(
            f"driver {field} {value!r}",
            "gitleaks",
            _put(_driver, field, value),
            _dropped("tool_field_unreadable", f"{_DRIVER}/{field}"),
            touched=(),
        )
        for field, value in (
            ("informationUri", "github.com/x"),
            ("downloadUri", "./bin"),
            ("language", "C"),
            ("guid", "x"),
            ("contents", ["other"]),
        )
    ],
    # The tool's own invocation: what ASH does not read may go.
    _case(
        "invocation start time that is not a date",
        "gitleaks",
        _put(
            _run,
            "invocations",
            [{"executionSuccessful": True, "startTimeUtc": "yesterday"}],
        ),
        _dropped("invocation_field_unreadable", "runs/0/invocations/0/startTimeUtc"),
        touched=(),
    ),
    # Run fields.
    *[
        _case(
            f"run {field} {value!r}",
            "gitleaks",
            _put(_run, field, value),
            _dropped("run_field_unreadable", f"runs/0/{field}"),
            touched=(),
        )
        for field, value in (
            ("columnKind", "bytes"),
            ("language", "x_"),
            ("automationDetails", {"guid": "x"}),
        )
    ],
    _case(
        "version control provenance with no repository",
        "gitleaks",
        _put(_run, "versionControlProvenance", [{"branch": "main"}]),
        _dropped("run_field_unreadable", "runs/0/versionControlProvenance/0"),
        touched=(),
    ),
    # Lists other parts refer to by index: never the element, only a field.
    *[
        _case(
            f"artifact {field} {value!r}",
            "gitleaks",
            _put(_run, "artifacts", [{"location": {"uri": "a"}, field: value}]),
            _dropped("indexed_field_unreadable", f"runs/0/artifacts/0/{field}"),
            touched=(),
        )
        for field, value in (
            ("roles", ["unknown"]),
            ("mimeType", "text"),
            ("length", -2),
        )
    ],
    _case(
        "artifact hash that is a number",
        "gitleaks",
        _put(_run, "artifacts", [{"location": {"uri": "a"}, "hashes": {"sha-256": 5}}]),
        _rewritten("number_as_text", "runs/0/artifacts/0/hashes/*"),
        touched=(),
    ),
    # Unknown keys, wherever the model fixes the keys.
    _case(
        "log with a key the spec does not define",
        "gitleaks",
        lambda doc: doc.__setitem__("foo", 1),
        _dropped("unknown_key", "*"),
        touched=(),
    ),
    _case(
        "run with a key the spec does not define",
        "gitleaks",
        _put(_run, "foo", 1),
        _dropped("unknown_key", "runs/0/*"),
        touched=(),
    ),
    _case(
        "result with a key the spec does not define",
        "gitleaks",
        _put(_result, "foo", 1),
        _dropped("unknown_key", f"{_R0}/*"),
    ),
    _case(
        "artifact location with a key the spec does not define",
        "gitleaks",
        lambda doc: _physical(doc)["artifactLocation"].__setitem__("foo", 1),
        _dropped(
            "unknown_key", f"{_R0}/locations/0/physicalLocation/artifactLocation/*"
        ),
    ),
    _case(
        "base id with a key the spec does not define",
        "gitleaks",
        _put(_run, "originalUriBaseIds", {"SRC": {"uri": "a", "foo": 1}}),
        _dropped("unknown_key", "runs/0/originalUriBaseIds/*/*"),
        touched=(),
    ),
    # A number where the spec wants text is written as its decimal text.
    _case(
        "rule id that is a number",
        "gitleaks",
        _put(_result, "ruleId", 5),
        _rewritten("number_as_text", f"{_R0}/ruleId"),
        rewrites_identity=True,
        check=_result_is(0, lambda r: r.ruleId == "5" or pytest.fail(r.ruleId)),
    ),
    _case(
        "message text that is a number",
        "gitleaks",
        lambda doc: _result(doc)["message"].__setitem__("text", 5),
        _rewritten("number_as_text", f"{_R0}/message/text"),
        rewrites_identity=True,
        check=_result_is(
            0, lambda r: r.message.root.text == "5" or pytest.fail("text")
        ),
    ),
    _case(
        "artifact uri that is a number",
        "gitleaks",
        lambda doc: _physical(doc)["artifactLocation"].__setitem__("uri", 123),
        _rewritten(
            "number_as_text", f"{_R0}/locations/0/physicalLocation/artifactLocation/uri"
        ),
        rewrites_identity=True,
    ),
    _case(
        "driver version that is a number",
        "gitleaks",
        _put(_driver, "version", 8),
        _rewritten("number_as_text", f"{_DRIVER}/version"),
        touched=(),
    ),
    _case(
        "rule name that is a number",
        "gitleaks",
        _put(_rule, "name", 1.5),
        _rewritten("number_as_text", f"{_RULE0}/name"),
        touched=(),
    ),
    _case(
        "rule reference whose id is a number",
        "zizmor",
        _put(_result, "rule", {"id": 5}),
        _rewritten("number_as_text", f"{_R0}/rule/id"),
    ),
    # Several defects in one document: each repaired, each in its own result.
    _case(
        "three defects in three results",
        "gitleaks",
        lambda doc: (
            _region(doc, 0).__setitem__("startLine", 0),
            _region(doc, 1).__setitem__("startColumn", 0),
            _result(doc, 2).__setitem__("rank", -2),
        ),
        _dropped("region_line_unreadable", _REGION),
        _dropped(
            "region_field_unreadable",
            "runs/0/results/1/locations/0/physicalLocation/region/startColumn",
        ),
        _dropped("rank_unreadable", "runs/0/results/2/rank"),
        touched=(0, 1, 2),
    ),
]


def check_repair_case(case: Case, ingest: Callable = ingest_sarif) -> IngestRecord:
    """Run one repair case through *ingest* and check what a repair owes."""
    capture = _BASES[case.base]
    doc = copy.deepcopy(capture)
    case.mutate(doc)
    before = json.dumps(doc, sort_keys=True, default=str)
    record = IngestRecord()

    report = ingest(doc, record)

    assert json.dumps(doc, sort_keys=True, default=str) == before, "the input changed"
    summary = record.summary()
    assert summary is not None
    got = [(e["action"], e["code"], e["pointer"]) for e in summary["elements"]]
    assert sorted(got) == sorted(case.notes)
    assert record.repaired == len(case.notes)
    assert record.left_out == 0
    plain = SarifReport.model_validate(capture)
    got_results, want_results = report.runs[0].results, plain.runs[0].results
    assert len(got_results) == len(want_results)
    for index, (kept, original) in enumerate(zip(got_results, want_results)):
        if index not in case.touched:
            assert kept == original, f"result {index} changed"
        elif not case.rewrites_identity:
            assert _identity(kept) == _identity(original), (
                f"result {index} lost its identity"
            )
    if case.check is not None:
        case.check(report)
    assert record.results_read == len(want_results)
    return record


@pytest.mark.parametrize("case", _REPAIRS)
def test_one_out_of_spec_part_is_repaired_and_every_finding_is_kept(case):
    check_repair_case(case)


def test_a_repair_that_gives_up_the_least_is_chosen_where_the_spec_offers_two_shapes():
    """A physical location is one of two shapes, so the model reports both shapes'
    errors. The repair that drops only the region wins over the one that would
    drop the whole related location."""
    case = next(
        p.values[0]
        for p in _REPAIRS
        if p.id == "related location with a region at line 0 keeps the related location"
    )
    record = check_repair_case(case)
    assert [e["code"] for e in record.summary()["elements"]] == [
        "region_line_unreadable"
    ]


# --------------------------------------------------------------------------- #
# What the table does not admit
# --------------------------------------------------------------------------- #

_REFUSED = [
    ("message missing", "gitleaks", lambda doc: _result(doc).pop("message")),
    ("message empty", "gitleaks", _put(_result, "message", {})),
    ("level the spec does not define", "gitleaks", _put(_result, "level", "info")),
    ("kind the spec does not define", "gitleaks", _put(_result, "kind", "issue")),
    (
        "suppression of a kind the spec does not define",
        "gitleaks",
        _put(_result, "suppressions", [{"kind": "inline"}]),
    ),
    (
        "default configuration level",
        "gitleaks",
        _put(_rule, "defaultConfiguration", {"level": "info"}),
    ),
    ("driver name missing", "gitleaks", lambda doc: _driver(doc).pop("name")),
    ("rule id missing", "gitleaks", lambda doc: _rule(doc).pop("id")),
    (
        "notification with no message",
        "gitleaks",
        _put(
            _run,
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [{"level": "error"}],
                }
            ],
        ),
    ),
    (
        "invocation with no outcome",
        "gitleaks",
        _put(_run, "invocations", [{"exitCode": 1}]),
    ),
    ("locations that is not a list", "gitleaks", _put(_result, "locations", {})),
    ("runs that is not a list", "gitleaks", lambda doc: doc.__setitem__("runs", {})),
    (
        "version the spec does not define",
        "gitleaks",
        lambda doc: doc.__setitem__("version", "2.1"),
    ),
    (
        "result that is not an object",
        "gitleaks",
        lambda doc: _run(doc)["results"].__setitem__(0, "x"),
    ),
    ("rule reference with nothing in it", "zizmor", _put(_result, "rule", {})),
]


@pytest.mark.parametrize(
    ("base", "mutate"), [pytest.param(b, m, id=i) for i, b, m in _REFUSED]
)
def test_a_part_the_table_does_not_admit_is_refused_as_before(base, mutate):
    doc = copy.deepcopy(_BASES[base])
    mutate(doc)
    with pytest.raises(ValidationError) as plain:
        SarifReport.model_validate(copy.deepcopy(doc))
    record = IngestRecord()

    with pytest.raises(ValidationError) as ingested:
        ingest_sarif(doc, record)

    assert record.is_empty
    assert ingested.value.error_count() == plain.value.error_count()


def test_the_repairs_made_before_a_refusal_are_kept_and_only_the_remaining_errors_are_raised():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = 0
    _result(doc, 1).pop("message")
    record = IngestRecord()

    with pytest.raises(ValidationError) as refused:
        ingest_sarif(doc, record)

    assert record.repaired == 1
    assert [e["code"] for e in record.summary()["elements"]] == [
        "region_line_unreadable"
    ]
    errors = refused.value.errors(include_input=False)
    assert [tuple(e["loc"]) for e in errors] == [("runs", 0, "results", 1, "message")]


def test_a_document_of_another_shape_is_refused_not_guessed_at():
    for raw in ([], "x", 5, None, {"runs": 5}, {"runs": [5]}):
        with pytest.raises(ValidationError):
            ingest_sarif(raw, IngestRecord())


@pytest.mark.parametrize(
    "raw",
    [
        {"not": "sarif"},
        {"error": "the tool could not read the template", "code": 2},
        {"$schema": "https://example.com/other.json", "note": "x"},
        {"results": [{"ruleId": "r"}]},
    ],
    ids=["one unknown key", "a tool's error object", "another schema", "a result list"],
)
def test_a_json_object_that_is_not_a_sarif_log_is_refused_and_not_repaired_to_an_empty_one(
    raw,
):
    """Every key such a document holds is one the model does not define, so
    dropping them would leave a report with no run, which a reader takes for a
    scan that found nothing."""
    record = IngestRecord()

    with pytest.raises(ValidationError):
        ingest_sarif(copy.deepcopy(raw), record)

    assert record.is_empty


@pytest.mark.parametrize(
    "raw",
    [
        {"version": "2.1.0", "runs": [], "tool_note": "x"},
        {"runs": [], "tool_note": "x"},
        {"version": "2.1.0", "tool_note": "x"},
    ],
    ids=["version and runs", "runs only", "version only"],
)
def test_a_sarif_log_with_a_key_of_the_tools_own_is_still_repaired(raw):
    record = IngestRecord()

    report = ingest_sarif(copy.deepcopy(raw), record)

    assert not report.runs
    assert [(e["action"], e["code"]) for e in record.summary()["elements"]] == [
        ("dropped", "unknown_key")
    ]


# --------------------------------------------------------------------------- #
# What the record holds
# --------------------------------------------------------------------------- #


def test_a_valid_report_is_read_as_the_model_reads_it_and_notes_nothing():
    record = IngestRecord()
    doc = copy.deepcopy(_BASES["zizmor"])

    report = ingest_sarif(doc, record)

    assert report == SarifReport.model_validate(_BASES["zizmor"])
    assert record.is_empty and record.summary() is None and record.sentence() is None
    assert record.notifications() == []
    assert record.results_read == 7


def test_every_sarif_file_of_the_test_data_reads_as_before():
    """The 46 files the model accepts at main give no note and the model's own
    report; the reduced fixture it refuses is refused here too."""
    kept, refused = 0, []
    for path in sorted(_DATA.rglob("*.sarif")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        try:
            plain = SarifReport.model_validate(raw)
        except ValidationError:
            with pytest.raises(ValidationError):
                ingest_sarif(raw, IngestRecord())
            refused.append(path.name)
            continue
        record = IngestRecord()
        assert ingest_sarif(raw, record) == plain, path.name
        assert record.is_empty, path.name
        kept += 1
    assert kept >= 40, f"only {kept} files read"
    assert refused == ["results_sarif.sarif"]


def test_the_sentence_names_kinds_and_counts_and_nothing_else():
    record = IngestRecord()
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = 0
    _region(doc, 1)["startLine"] = 0
    ingest_sarif(doc, record)

    assert record.sentence("gitleaks") == (
        "ASH repaired 2 parts of gitleaks' report that SARIF does not allow "
        "(a region with no readable line)."
    )
    assert record.sentence("semgrep").startswith(
        "ASH repaired 2 parts of semgrep's report"
    )
    assert record.sentence().startswith("ASH repaired 2 parts of this scanner's report")


def test_the_summary_counts_exactly_and_names_at_most_fifty_elements():
    record = IngestRecord()
    for index in range(70):
        record.note("dropped", "region_line_unreadable", ("runs", 0, "results", index))
    record.note(
        "rewritten", "number_as_text", ("runs", 0, "results", 3, "ruleId"), count=4
    )

    summary = record.summary()

    assert summary["repaired"] == 74
    assert summary["changes"] == [
        {"action": "dropped", "code": "region_line_unreadable", "count": 70},
        {"action": "rewritten", "code": "number_as_text", "count": 4},
    ]
    assert len(summary["elements"]) == 50
    assert summary["elements_not_listed"] == 21
    json.dumps(summary)


def test_a_rule_id_is_kept_only_when_it_is_a_plain_identifier():
    record = IngestRecord()
    record.note("dropped", "unknown_key", ("runs",), rule_id="generic-api-key")
    record.note("dropped", "unknown_key", ("runs",), rule_id="/home/user/x")
    record.note("dropped", "unknown_key", ("runs",), rule_id="a b")
    record.note("dropped", "unknown_key", ("runs",), rule_id=5)

    assert [e["rule_id"] for e in record.summary()["elements"]] == [
        "generic-api-key",
        None,
        None,
        None,
    ]


def test_a_repair_names_the_rule_of_the_result_it_is_in():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = 0
    record = IngestRecord()
    ingest_sarif(doc, record)

    assert record.summary()["elements"][0]["rule_id"] == _result(doc, 0)["ruleId"]


def test_a_pointer_never_carries_a_key_the_tool_chose():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _result(doc)["partialFingerprints"] = {"/home/u/secret-name": 1}
    _result(doc)["secret-key"] = 1
    record = IngestRecord()
    ingest_sarif(doc, record)

    pointers = sorted(e["pointer"] for e in record.summary()["elements"])
    assert pointers == [f"{_R0}/*", f"{_R0}/partialFingerprints/*"]


def test_a_pointer_is_prefixed_with_an_ordinal_scope_and_never_a_name():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc)["startLine"] = 0
    record = IngestRecord()
    with record.scoped("template 3"):
        ingest_sarif(copy.deepcopy(doc), record)
    with record.scoped("/home/user/templates/prod.yaml"):
        ingest_sarif(copy.deepcopy(doc), record)
    ingest_sarif(copy.deepcopy(doc), record)

    pointers = [e["pointer"] for e in record.summary()["elements"]]
    assert pointers == [f"template 3: {_REGION}", f"input: {_REGION}", _REGION]


def test_nothing_the_report_held_reaches_the_record_or_the_error():
    secrets = ("SECRET-LINE", "SECRET-KEY", "SECRET-URI", "/home/secret-user")
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = secrets[0]
    _result(doc, 0)["ruleId"] = secrets[3] + "/rule"
    _result(doc, 1)[secrets[1]] = secrets[1]
    _rule(doc)["helpUri"] = secrets[2]
    _result(doc, 2)["level"] = "SECRET-LEVEL"
    record = IngestRecord()

    with pytest.raises(ValidationError) as refused:
        ingest_sarif(doc, record)

    text = json.dumps(
        [record.summary(), record.sentence("gitleaks"), record.notifications()]
    )
    text += str(refused.value) + repr(refused.value.errors(include_input=False))
    for secret in (*secrets, "SECRET-LEVEL"):
        assert secret not in text


def test_the_input_is_not_changed_even_when_it_is_refused():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = 0
    _result(doc, 1).pop("message")
    before = json.dumps(doc, sort_keys=True)

    with pytest.raises(ValidationError):
        ingest_sarif(doc, IngestRecord())

    assert json.dumps(doc, sort_keys=True) == before


def test_a_record_pickles_and_its_notification_is_a_warning_the_model_reads():
    record = IngestRecord()
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc)["startLine"] = 0
    ingest_sarif(doc, record)

    assert pickle.loads(pickle.dumps(record)).summary() == record.summary()
    invocation = Invocation.model_validate(
        {
            "executionSuccessful": True,
            "toolExecutionNotifications": record.notifications(),
        }
    )
    (notification,) = invocation.toolExecutionNotifications
    assert str(getattr(notification.level, "value", notification.level)) == "warning"
    assert notification.message.root.text == record.sentence()


# --------------------------------------------------------------------------- #
# Reading the bytes
# --------------------------------------------------------------------------- #


def test_a_byte_order_mark_is_dropped_and_noted():
    record = IngestRecord()

    assert read_json_tolerant(b"\xef\xbb\xbf" + b'{"a": 1}', record) == {"a": 1}
    assert read_json_text_tolerant(chr(0xFEFF) + '{"a": 1}', record) == {"a": 1}

    assert record.summary()["changes"] == [
        {"action": "rewritten", "code": "bom", "count": 2}
    ]


def test_bytes_that_are_not_utf8_are_held_as_the_lone_surrogates_ash_holds_names_as():
    record = IngestRecord()

    value = read_json_tolerant(b'{"a": "x\xe9y\xe9"}', record)

    assert value == {"a": "x" + chr(0xDCE9) + "y" + chr(0xDCE9)}
    assert record.summary()["changes"] == [
        {"action": "rewritten", "code": "bytes_not_utf8", "count": 2}
    ]


def test_a_control_character_inside_a_string_is_accepted_and_noted():
    record = IngestRecord()

    assert read_json_text_tolerant('{"a": "x\ty"}', record) == {"a": "x\ty"}

    assert record.summary()["changes"] == [
        {"action": "rewritten", "code": "control_character", "count": 1}
    ]


@pytest.mark.parametrize("data", [b"", b"  \n\t ", b"\xef\xbb\xbf", b"null"])
def test_an_empty_file_or_a_json_null_reads_as_none(data):
    assert read_json_tolerant(data, IngestRecord()) is None


@pytest.mark.parametrize("data", [b'{"a": ', b"not json", b'{"a": "x\ty"'])
def test_any_other_json_error_is_raised_as_json_raises_it(data):
    with pytest.raises(json.JSONDecodeError):
        read_json_tolerant(data, IngestRecord())


def test_a_report_with_a_byte_that_is_not_utf8_in_a_message_keeps_every_finding():
    doc = copy.deepcopy(_BASES["gitleaks"])
    _result(doc)["message"]["text"] = "a name with a PLACEHOLDER byte"
    data = json.dumps(doc).encode("utf-8").replace(b"PLACEHOLDER", b"\xe9")
    record = IngestRecord()

    report = ingest_sarif(read_json_tolerant(data, record), record)

    assert len(report.runs[0].results) == 5
    assert [e["code"] for e in record.summary()["elements"]] == ["bytes_not_utf8"]


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def _many(count: int, mutate: Callable[[dict], None]) -> dict:
    doc = copy.deepcopy(_BASES["gitleaks"])
    template = _result(doc)
    doc["runs"][0]["results"] = []
    for _ in range(count):
        result = copy.deepcopy(template)
        mutate(result)
        doc["runs"][0]["results"].append(result)
    return doc


def test_ten_thousand_unrepairable_results_are_refused_in_one_validation():
    doc = _many(10_000, lambda result: result.pop("message"))
    real = SarifReport.model_validate

    with mock.patch.object(SarifReport, "model_validate", wraps=real) as validate:
        with pytest.raises(ValidationError):
            ingest_sarif(doc, IngestRecord())

    assert validate.call_count == 1


def test_a_document_takes_at_most_ten_thousand_changes_then_is_refused():
    doc = _many(
        10_001,
        lambda result: result["locations"][0]["physicalLocation"]["region"].update(
            startLine=0
        ),
    )
    record = IngestRecord()
    real = SarifReport.model_validate

    with mock.patch.object(SarifReport, "model_validate", wraps=real) as validate:
        with pytest.raises(ValidationError):
            ingest_sarif(doc, record)

    assert record.repaired == 10_000
    assert validate.call_count <= 9


# --------------------------------------------------------------------------- #
# The repair never changes what a finding is (property)
# --------------------------------------------------------------------------- #

_PLAIN = {name: SarifReport.model_validate(raw) for name, raw in _BASES.items()}


def _bad_line(draw: Any, doc: dict, index: int) -> None:
    _region(doc, index)["startLine"] = draw(st.integers(max_value=0))


def _bad_column(draw: Any, doc: dict, index: int) -> None:
    field = draw(st.sampled_from(["startColumn", "endLine", "endColumn"]))
    _region(doc, index)[field] = draw(st.integers(max_value=0))


def _extra_key(draw: Any, doc: dict, index: int) -> None:
    where = draw(
        st.sampled_from(
            [_result(doc, index), _region(doc, index), _physical(doc, index)]
        )
    )
    where["x-" + draw(st.text(min_size=1, max_size=8))] = draw(st.integers())


def _bad_rank(draw: Any, doc: dict, index: int) -> None:
    _result(doc, index)["rank"] = draw(st.sampled_from([-5, 101, 1e9]))


def _numeric_tags(draw: Any, doc: dict, index: int) -> None:
    _result(doc, index)["properties"] = {
        "tags": draw(
            st.lists(st.one_of(st.integers(), st.none(), st.text()), max_size=4)
        )
    }


def _numeric_fingerprint(draw: Any, doc: dict, index: int) -> None:
    _result(doc, index)["partialFingerprints"] = {"k": draw(st.integers())}


def _tool_key_property(draw: Any, doc: dict, index: int) -> None:
    key = draw(st.integers(0xDC80, 0xDCFF).map(chr))
    _result(doc, index)["properties"] = {key: 1, "kept": draw(st.integers())}


def _bad_help_uri(draw: Any, doc: dict, index: int) -> None:
    _rule(doc)["helpUri"] = draw(st.sampled_from(["", "N/A", "docs/x.md", "x y"]))


_ADMITTED = [
    _bad_line,
    _bad_column,
    _extra_key,
    _bad_rank,
    _numeric_tags,
    _numeric_fingerprint,
    _tool_key_property,
    _bad_help_uri,
]


@seed(SUITE_SEED)
@settings(derandomize=True, database=None, deadline=None, max_examples=40)
@given(data=st.data())
def test_no_repair_changes_a_finding_it_keeps(data):
    name = data.draw(st.sampled_from(sorted(_BASES)), label="capture")
    doc = copy.deepcopy(_BASES[name])
    count = len(_result_list(doc))
    for step in range(data.draw(st.integers(1, 3), label="mutations")):
        mutation = data.draw(st.sampled_from(_ADMITTED), label=f"mutation {step}")
        index = data.draw(st.integers(0, count - 1), label=f"result {step}")
        mutation(data.draw, doc, index)

    report = ingest_sarif(doc, IngestRecord())

    kept = report.runs[0].results
    assert len(kept) == count
    for got, want in zip(kept, _PLAIN[name].runs[0].results):
        assert _identity(got) == _identity(want)


def _result_list(doc: dict) -> list:
    return doc["runs"][0]["results"]


# --------------------------------------------------------------------------- #
# CycloneDX
# --------------------------------------------------------------------------- #


def _component(doc: dict) -> dict:
    return doc["components"][0]


_CDX_REPAIRS = [
    (
        "component with a key the spec does not define",
        lambda d: _component(d).update(foundBy="x"),
        [("dropped", "unknown_key", "components/0/*")],
    ),
    (
        "document with a key the spec does not define",
        lambda d: d.update(foo=1),
        [("dropped", "unknown_key", "*")],
    ),
    (
        "purl that is a number",
        lambda d: _component(d).update(purl=5),
        [("rewritten", "number_as_text", "components/0/purl")],
    ),
    (
        "purl that is a list",
        lambda d: _component(d).update(purl=["a"]),
        [("dropped", "purl_unreadable", "components/0/purl")],
    ),
    (
        "version that is a number",
        lambda d: _component(d).update(version=2),
        [("rewritten", "number_as_text", "components/0/version")],
    ),
    (
        "hash with an algorithm the spec does not define",
        lambda d: _component(d).update(
            hashes=[{"alg": "SHA-999", "content": "a" * 32}]
        ),
        [("dropped", "hashes_entry_unreadable", "components/0/hashes/0")],
    ),
    (
        "property with no name",
        lambda d: _component(d).update(properties=[{"value": "a"}]),
        [("dropped", "properties_entry_unreadable", "components/0/properties/0")],
    ),
    (
        "external reference of a type the spec does not define",
        lambda d: _component(d).update(
            externalReferences=[
                {"type": "homepage-x", "url": "https://a"},
                {"type": "website", "url": "https://b"},
            ]
        ),
        [
            (
                "dropped",
                "externalReferences_entry_unreadable",
                "components/0/externalReferences/0",
            )
        ],
    ),
    (
        "supplier whose name is a list",
        lambda d: _component(d).update(supplier={"name": ["x"]}),
        [("dropped", "supplier_unreadable", "components/0/supplier")],
    ),
    (
        "serial number that is not a UUID",
        lambda d: d.update(serialNumber="urn:uuid:not-a-uuid"),
        [("dropped", "document_field_unreadable", "serialNumber")],
    ),
    (
        "timestamp that is not a date",
        lambda d: d["metadata"].update(timestamp="yesterday"),
        [("dropped", "metadata_field_unreadable", "metadata/timestamp")],
    ),
    (
        "dependency with no ref",
        lambda d: d.update(dependencies=[{"dependsOn": ["a"]}, {"ref": "ok"}]),
        [("dropped", "dependency_entry_unreadable", "dependencies/0")],
    ),
    (
        "nested component with a key the spec does not define",
        lambda d: _component(d).update(
            components=[{"type": "library", "name": "n", "foundBy": 1}]
        ),
        [("dropped", "unknown_key", "components/0/components/0/*")],
    ),
]

_CDX_REFUSED = [
    (
        "component type the spec does not define",
        lambda d: _component(d).update(type="unknown-type"),
    ),
    ("component type missing", lambda d: _component(d).pop("type")),
    ("component name missing", lambda d: _component(d).pop("name")),
    ("component bom-ref empty", lambda d: _component(d).update({"bom-ref": ""})),
    (
        "component scope the spec does not define",
        lambda d: _component(d).update(scope="maybe"),
    ),
    ("bom format other than CycloneDX", lambda d: d.update(bomFormat="SPDX")),
    ("components that is not a list", lambda d: d.update(components={})),
    ("component version that is a list", lambda d: _component(d).update(version=["x"])),
]


@pytest.mark.parametrize(
    ("mutate", "notes"),
    [pytest.param(m, n, id=i) for i, m, n in _CDX_REPAIRS],
)
def test_a_component_with_one_out_of_spec_part_keeps_the_sbom(mutate, notes):
    doc = copy.deepcopy(_SYFT)
    mutate(doc)
    record = IngestRecord()

    report = ingest_cyclonedx(doc, record)

    got = [(e["action"], e["code"], e["pointer"]) for e in record.summary()["elements"]]
    assert sorted(got) == sorted(notes)
    assert (
        len(report.root.components if hasattr(report, "root") else report.components)
        == 2
    )
    assert record.results_read == 2 and record.format_name == "CycloneDX"
    assert "CycloneDX does not allow" in record.sentence("syft")


@pytest.mark.parametrize("mutate", [pytest.param(m, id=i) for i, m in _CDX_REFUSED])
def test_a_part_of_the_sbom_the_table_does_not_admit_is_refused(mutate):
    doc = copy.deepcopy(_SYFT)
    mutate(doc)
    record = IngestRecord()

    with pytest.raises(ValidationError):
        ingest_cyclonedx(doc, record)

    assert record.is_empty


@pytest.mark.parametrize(
    "raw",
    [{"not": "cyclonedx"}, {"error": "no image", "code": 2}, {"results": []}],
    ids=["one unknown key", "a tool's error object", "a result list"],
)
def test_a_json_object_that_is_not_an_sbom_is_refused_and_not_repaired_to_an_empty_one(
    raw,
):
    record = IngestRecord()

    with pytest.raises(ValidationError):
        ingest_cyclonedx(copy.deepcopy(raw), record)

    assert record.is_empty


def test_a_valid_sbom_is_read_as_the_model_reads_it():
    record = IngestRecord()

    assert ingest_cyclonedx(
        copy.deepcopy(_SYFT), record
    ) == CycloneDXReport.model_validate(_SYFT)
    assert record.is_empty


# --------------------------------------------------------------------------- #
# The suite can fail (controls)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("index", [0, 20, 40])
def test_control_the_repair_cases_fail_when_the_model_reads_the_report_alone(index):
    case = _REPAIRS[index].values[0]

    with pytest.raises(ValidationError):
        check_repair_case(
            case, ingest=lambda raw, record: SarifReport.model_validate(raw)
        )


def test_control_a_pointer_that_keeps_the_tools_keys_fails_the_pointer_case(
    monkeypatch,
):
    def keeps_every_key(self, pointer):
        return "/".join(str(token) for token in pointer) or "(document)"

    monkeypatch.setattr(IngestRecord, "_pointer_text", keeps_every_key)
    case = next(p.values[0] for p in _REPAIRS if p.id == "fingerprint that is a number")

    with pytest.raises(AssertionError):
        check_repair_case(case)


def test_control_a_repair_that_drops_a_second_finding_fails_the_other_results_check():
    def drops_a_result(raw, record):
        report = ingest_sarif(raw, record)
        report.runs[0].results = report.runs[0].results[:-1]
        return report

    case = next(p.values[0] for p in _REPAIRS if p.id == "startLine 0")

    with pytest.raises(AssertionError):
        check_repair_case(case, ingest=drops_a_result)


def test_control_a_repair_that_hides_what_it_did_fails_the_notes_check():
    case = next(p.values[0] for p in _REPAIRS if p.id == "startLine 0")

    def silent(raw, record):
        return ingest_sarif(raw, IngestRecord())

    with pytest.raises(AssertionError):
        check_repair_case(case, ingest=silent)
