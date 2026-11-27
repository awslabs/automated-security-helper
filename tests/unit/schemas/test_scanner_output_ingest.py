"""A scanner's report is read through the ingest step, which repairs what the model refuses.

One value the SARIF or CycloneDX model refuses, a region that starts on line 0, a
link that is not a URL, a key the spec does not define, used to cost the scanner
its whole report. The ingest step drops or rewrites the smallest out-of-spec part
whose loss changes no finding, notes it, and validates again. What it cannot
repair (a missing message, a level the spec does not define, a suppression of a
kind it does not define) is refused with the model's own error, as before.

The cases are the refusals measured against the pinned models, one out-of-spec
element each, started from a real capture of gitleaks or zizmor (SARIF) and of
syft (CycloneDX). Each case says what the repair owes: the nodes it takes out or
rewrites, by their place in the mutated document. The test makes exactly those
changes by hand and checks the repaired report equals the report that document
validates to, so a repair that gives up more than it notes, or writes another
value, fails. Every other result must equal a plain validation of the unmutated
capture, and the record must name the kind and the place, never a value.
"""

from __future__ import annotations

import copy
import json
import pickle
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple
from unittest import mock

import pytest
from hypothesis import given, seed, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from automated_security_helper.schemas import scanner_output_ingest
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

#: One seed for the suite's property test, so a run is the same run. An explicit
#: seed wins over ``derandomize`` and, unlike it, does not move when the test body
#: is edited.
SUITE_SEED = 20261126


def _load(relative: str) -> Any:
    return json.loads((_DATA / relative).read_text(encoding="utf-8"))


_BASES = {
    "gitleaks": _load("scanners/gitleaks/gitleaks-8.30.1.sarif"),
    "zizmor": _load("scanners/zizmor/zizmor-1.30.1.sarif"),
}
_SYFT = _load("snapshot_fixture/scanner_outputs/syft.cdx.json")


# --------------------------------------------------------------------------- #
# Places in a document, and the pointers the record writes for them
# --------------------------------------------------------------------------- #


class Key(str):
    """A key the tool chose (a property name, a fingerprint name, a base id).

    A pointer writes it ``*``, so a record never holds a name the tool made up.
    """

    __slots__ = ()


def _pointer(path: tuple) -> str:
    """The pointer the record writes for *path*: list indices and the schema's own
    names as they are, a key the tool chose as ``*``."""
    return "/".join("*" if isinstance(token, Key) else str(token) for token in path)


_R0 = ("runs", 0, "results", 0)
_REGION = (*_R0, "locations", 0, "physicalLocation", "region")
_RULE0 = ("runs", 0, "tool", "driver", "rules", 0)
_DRIVER = ("runs", 0, "tool", "driver")


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
# What a repair owes, and the repair made by hand
# --------------------------------------------------------------------------- #


class Change(NamedTuple):
    """One repair a case owes: take the node at *path* out, or write *text* there."""

    action: str
    code: str
    #: Where the node is in the mutated document, as the tool wrote it.
    path: tuple
    text: str | None = None


def _dropped(code: str, *path: Any) -> Change:
    return Change("dropped", code, path)


def _rewritten(code: str, text: str, *path: Any) -> Change:
    return Change("rewritten", code, path, text)


def _notes_of(changes: Iterable[Change]) -> list[tuple[str, str, str]]:
    """What the record must name for *changes*, in order."""
    return sorted((c.action, c.code, _pointer(c.path)) for c in changes)


def _order(path: tuple) -> tuple:
    return tuple((0, token) if isinstance(token, int) else (1, token) for token in path)


def repaired_by_hand(doc: Any, changes: Iterable[Change]) -> Any:
    """*doc* with each change made where it says and nothing else: the repair a case
    owes, made without the module under test."""
    out = copy.deepcopy(doc)
    for change in sorted(changes, key=lambda item: _order(item.path), reverse=True):
        parent = out
        for token in change.path[:-1]:
            parent = parent[token]
        if change.action == "dropped":
            del parent[change.path[-1]]
        else:
            parent[change.path[-1]] = change.text
    return out


def _errors_of(error: ValidationError) -> list[tuple[tuple, str]]:
    """Where each error is and what kind it is."""
    return [
        (tuple(item["loc"]), item["type"]) for item in error.errors(include_input=False)
    ]


# --------------------------------------------------------------------------- #
# The repair cases
# --------------------------------------------------------------------------- #


class Case(NamedTuple):
    base: str
    mutate: Callable[[dict], None]
    #: What the repair owes. The results these touch are compared with the repair
    #: made by hand; every other result must equal the capture's.
    changes: tuple
    check: Callable[[SarifReport], None] | None = None


def _case(id_: str, base: str, mutate: Callable, *changes: Change, **extra: Any) -> Any:
    return pytest.param(Case(base, mutate, changes, **extra), id=id_)


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


def _rule_id_is_text(result: Any) -> None:
    assert result.ruleId == "5"


def _message_is_text(result: Any) -> None:
    assert result.message.root.text == "5"


def _uri_is_text(result: Any) -> None:
    assert result.locations[0].physicalLocation.root.artifactLocation.uri == "123"


def _driver_version_is_gone(report: SarifReport) -> None:
    assert report.runs[0].tool.driver.version is None


def _only_the_text_tag_stays(result: Any) -> None:
    assert result.properties.tags == ["a"]


def _base_id_keeps_its_uri(report: SarifReport) -> None:
    assert report.runs[0].originalUriBaseIds["SRC"].uri == "file:///src/"


_REPAIRS = [
    # R: a region or a line out of range. The finding stays, without its lines.
    *[
        _case(
            f"startLine {value!r}",
            "gitleaks",
            _put(_region, "startLine", value),
            _dropped("region_line_unreadable", *_REGION),
        )
        for value in (0, -1, "x", 1.5)
    ],
    *[
        _case(
            f"region {field} {value!r}",
            "gitleaks",
            _put(_region, field, value),
            _dropped("region_field_unreadable", *_REGION, field),
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
        _dropped("unknown_key", *_REGION, Key("foo")),
    ),
    _case(
        "region that is a list",
        "gitleaks",
        _put(_physical, "region", []),
        _dropped("region_field_unreadable", *_REGION),
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
            *_R0,
            "relatedLocations",
            0,
            "physicalLocation",
            "region",
        ),
        check=_result_is(0, _has_one_related_location),
    ),
    _case(
        "thread flow location with a region at line 0",
        "zizmor",
        lambda doc: _flow_region(doc).__setitem__("startLine", 0),
        _dropped(
            "region_line_unreadable",
            *_R0,
            "codeFlows",
            0,
            "threadFlows",
            0,
            "locations",
            0,
            "location",
            "physicalLocation",
            "region",
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
        _dropped("fix_unreadable", *_R0, "fixes", 0),
        check=_result_is(0, _has_no_fix),
    ),
    # Result fields that are not part of the finding's identity.
    *[
        _case(
            f"result {field} {value!r}",
            "gitleaks",
            _put(_result, field, value),
            _dropped(f"{field}_unreadable", *_R0, field),
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
        _dropped("workItemUris_entry_unreadable", *_R0, "workItemUris", 0),
        check=_result_is(0, _only_the_good_work_item_stays),
    ),
    _case(
        "code flow with no thread flows",
        "zizmor",
        _put(_result, "codeFlows", [{"threadFlows": []}]),
        _dropped("codeFlows_entry_unreadable", *_R0, "codeFlows", 0),
    ),
    _case(
        "related locations that is not a list",
        "gitleaks",
        _put(_result, "relatedLocations", {}),
        _dropped("relatedLocations_unreadable", *_R0, "relatedLocations"),
    ),
    # Maps and bags: one entry costs only itself.
    _case(
        "tags that is not a list",
        "gitleaks",
        _put(_result, "properties", {"tags": "a"}),
        _dropped("property_unreadable", *_R0, "properties", "tags"),
    ),
    _case(
        "tags with a number and a null",
        "gitleaks",
        _put(_result, "properties", {"tags": [1, None, "a"]}),
        _rewritten("number_as_text", "1", *_R0, "properties", "tags", 0),
        _dropped("tag_not_text", *_R0, "properties", "tags", 1),
        check=_result_is(0, _tags_are_text),
    ),
    _case(
        "property key that is not valid Unicode",
        "gitleaks",
        _put(_result, "properties", {chr(0xDCE9): 1, "kept": 2}),
        _dropped("property_unreadable", *_R0, "properties", Key(chr(0xDCE9))),
    ),
    _case(
        "properties that is not an object",
        "gitleaks",
        _put(_result, "properties", "x"),
        _dropped("property_unreadable", *_R0, "properties"),
    ),
    _case(
        "fingerprint that is a number",
        "gitleaks",
        _put(_result, "partialFingerprints", {"/home/u/x": 1}),
        _rewritten(
            "number_as_text", "1", *_R0, "partialFingerprints", Key("/home/u/x")
        ),
        check=_result_is(0, _fingerprint_is_text),
    ),
    _case(
        "fingerprint that is a list",
        "gitleaks",
        _put(_result, "fingerprints", {"k": ["x"]}),
        _dropped("fingerprint_unreadable", *_R0, "fingerprints", Key("k")),
    ),
    # Rule descriptors: the field goes, never the id or the default configuration.
    *[
        _case(
            f"rule {field} {value!r}",
            "gitleaks",
            _put(_rule, field, value),
            _dropped("rule_field_unreadable", *_RULE0, field),
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
        _rewritten("number_as_text", "1", *_RULE0, "properties", "tags", 0),
        _dropped("tag_not_text", *_RULE0, "properties", "tags", 1),
    ),
    _case(
        "rule with a key the spec does not define",
        "gitleaks",
        _put(_rule, "foo", 1),
        _dropped("unknown_key", *_RULE0, Key("foo")),
    ),
    # Tool components.
    *[
        _case(
            f"driver {field} {value!r}",
            "gitleaks",
            _put(_driver, field, value),
            _dropped("tool_field_unreadable", *_DRIVER, field),
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
        _dropped(
            "invocation_field_unreadable", "runs", 0, "invocations", 0, "startTimeUtc"
        ),
    ),
    # Run fields.
    *[
        _case(
            f"run {field} {value!r}",
            "gitleaks",
            _put(_run, field, value),
            _dropped("run_field_unreadable", "runs", 0, field),
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
        _dropped("run_field_unreadable", "runs", 0, "versionControlProvenance", 0),
    ),
    # Lists other parts refer to by index: never the element, only a field.
    *[
        _case(
            f"artifact {field} {value!r}",
            "gitleaks",
            _put(_run, "artifacts", [{"location": {"uri": "a"}, field: value}]),
            _dropped("indexed_field_unreadable", "runs", 0, "artifacts", 0, field),
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
        _rewritten(
            "number_as_text",
            "5",
            "runs",
            0,
            "artifacts",
            0,
            "hashes",
            Key("sha-256"),
        ),
    ),
    # Unknown keys, wherever the model fixes the keys.
    _case(
        "log with a key the spec does not define",
        "gitleaks",
        lambda doc: doc.__setitem__("foo", 1),
        _dropped("unknown_key", Key("foo")),
    ),
    _case(
        "run with a key the spec does not define",
        "gitleaks",
        _put(_run, "foo", 1),
        _dropped("unknown_key", "runs", 0, Key("foo")),
    ),
    _case(
        "result with a key the spec does not define",
        "gitleaks",
        _put(_result, "foo", 1),
        _dropped("unknown_key", *_R0, Key("foo")),
    ),
    _case(
        "artifact location with a key the spec does not define",
        "gitleaks",
        lambda doc: _physical(doc)["artifactLocation"].__setitem__("foo", 1),
        _dropped(
            "unknown_key",
            *_R0,
            "locations",
            0,
            "physicalLocation",
            "artifactLocation",
            Key("foo"),
        ),
    ),
    _case(
        "base id with a key the spec does not define",
        "gitleaks",
        _put(_run, "originalUriBaseIds", {"SRC": {"uri": "a", "foo": 1}}),
        _dropped(
            "unknown_key", "runs", 0, "originalUriBaseIds", Key("SRC"), Key("foo")
        ),
    ),
    # A number where the spec wants text is written as its decimal text.
    _case(
        "rule id that is a number",
        "gitleaks",
        _put(_result, "ruleId", 5),
        _rewritten("number_as_text", "5", *_R0, "ruleId"),
        check=_result_is(0, _rule_id_is_text),
    ),
    _case(
        "message text that is a number",
        "gitleaks",
        lambda doc: _result(doc)["message"].__setitem__("text", 5),
        _rewritten("number_as_text", "5", *_R0, "message", "text"),
        check=_result_is(0, _message_is_text),
    ),
    _case(
        "artifact uri that is a number",
        "gitleaks",
        lambda doc: _physical(doc)["artifactLocation"].__setitem__("uri", 123),
        _rewritten(
            "number_as_text",
            "123",
            *_R0,
            "locations",
            0,
            "physicalLocation",
            "artifactLocation",
            "uri",
        ),
        check=_result_is(0, _uri_is_text),
    ),
    _case(
        "driver version that is a number",
        "gitleaks",
        _put(_driver, "version", 8),
        _rewritten("number_as_text", "8", *_DRIVER, "version"),
    ),
    _case(
        "rule name that is a number",
        "gitleaks",
        _put(_rule, "name", 5),
        _rewritten("number_as_text", "5", *_RULE0, "name"),
    ),
    _case(
        "rule reference whose id is a number",
        "zizmor",
        _put(_result, "rule", {"id": 5}),
        _rewritten("number_as_text", "5", *_R0, "rule", "id"),
    ),
    # A number with a fraction is never written as text: reading 3.20 gave 3.2, and
    # a version or a name that changed would not be the tool's. A field that does
    # not identify the finding goes instead, and the repair names it.
    _case(
        "driver version that is a float",
        "gitleaks",
        _put(_driver, "version", 3.20),
        _dropped("tool_field_unreadable", *_DRIVER, "version"),
        check=_driver_version_is_gone,
    ),
    _case(
        "rule name that is a float",
        "gitleaks",
        _put(_rule, "name", 1.10),
        _dropped("rule_field_unreadable", *_RULE0, "name"),
    ),
    _case(
        "tags with a float and a text",
        "gitleaks",
        _put(_result, "properties", {"tags": [2.10, "a"]}),
        _dropped("tag_not_text", *_R0, "properties", "tags", 0),
        check=_result_is(0, _only_the_text_tag_stays),
    ),
    # The table a location's uriBaseId is resolved through keeps every entry and
    # its uri: only a field that describes the entry goes.
    _case(
        "base id with a description that is not a message",
        "gitleaks",
        _put(
            _run,
            "originalUriBaseIds",
            {"SRC": {"uri": "file:///src/", "description": "the root"}},
        ),
        _dropped(
            "run_field_unreadable",
            "runs",
            0,
            "originalUriBaseIds",
            Key("SRC"),
            "description",
        ),
        check=_base_id_keeps_its_uri,
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
        _dropped("region_line_unreadable", *_REGION),
        _dropped(
            "region_field_unreadable",
            "runs",
            0,
            "results",
            1,
            "locations",
            0,
            "physicalLocation",
            "region",
            "startColumn",
        ),
        _dropped("rank_unreadable", "runs", 0, "results", 2, "rank"),
    ),
]


def check_repair_case(
    case: Case, ingest: Callable[[Any, IngestRecord], SarifReport] = ingest_sarif
) -> IngestRecord:
    """Run one repair case through *ingest* and check what a repair owes."""
    capture = _BASES[case.base]
    doc = copy.deepcopy(capture)
    case.mutate(doc)
    owed = SarifReport.model_validate(repaired_by_hand(doc, case.changes))
    before = json.dumps(doc, sort_keys=True, default=str)
    record = IngestRecord()

    report = ingest(doc, record)

    assert json.dumps(doc, sort_keys=True, default=str) == before, "the input changed"
    summary = record.summary()
    assert summary is not None, "the record names nothing"
    got = [(e["action"], e["code"], e["pointer"]) for e in summary["elements"]]
    assert sorted(got) == _notes_of(case.changes), (
        "the record's notes differ from the case's"
    )
    assert record.repaired == len(case.changes), "the record's count differs"
    assert record.left_out == 0, "a result was left out"
    plain = SarifReport.model_validate(capture)
    got_results, want_results = report.runs[0].results, plain.runs[0].results
    assert len(got_results) == len(want_results), "a result was lost"
    touched = {c.path[3] for c in case.changes if c.path[:3] == ("runs", 0, "results")}
    for index, (kept, original) in enumerate(zip(got_results, want_results)):
        if index not in touched:
            assert kept == original, f"result {index} changed"
    assert report == owed, "the report differs from the minimal repair"
    if case.check is not None:
        case.check(report)
    assert record.results_read == len(want_results), "the results read differ"
    return record


@pytest.mark.parametrize("case", _REPAIRS)
def test_one_out_of_spec_part_is_repaired_and_every_finding_is_kept(case):
    check_repair_case(case)


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
        "configuration notification with no message",
        "gitleaks",
        _put(
            _run,
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "toolConfigurationNotifications": [{"level": "warning"}],
                }
            ],
        ),
    ),
    (
        "rule configuration override with no configuration",
        "gitleaks",
        _put(
            _run,
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "ruleConfigurationOverrides": [{"descriptor": {"id": "x"}}],
                }
            ],
        ),
    ),
    (
        "notification configuration override with a level the spec does not define",
        "gitleaks",
        _put(
            _run,
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "notificationConfigurationOverrides": [
                        {"configuration": {"level": "info"}, "descriptor": {"id": "x"}}
                    ],
                }
            ],
        ),
    ),
    (
        "invocation with no outcome",
        "gitleaks",
        _put(_run, "invocations", [{"exitCode": 1}]),
    ),
    # A number with a fraction is never written as text, and where no other
    # repair is admitted the report is refused as before.
    ("rule id that is a float", "gitleaks", _put(_result, "ruleId", 2.10)),
    (
        "message text that is a float",
        "gitleaks",
        lambda doc: _result(doc)["message"].__setitem__("text", 1.10),
    ),
    (
        "artifact uri that is a float",
        "gitleaks",
        lambda doc: _physical(doc)["artifactLocation"].__setitem__("uri", 3.20),
    ),
    # The table a location's uriBaseId is resolved through is never dropped from,
    # and neither is an entry's uri.
    (
        "base id whose uri is a list",
        "gitleaks",
        _put(_run, "originalUriBaseIds", {"SRC": {"uri": ["file:///src/"]}}),
    ),
    (
        "base id that is not an object",
        "gitleaks",
        _put(_run, "originalUriBaseIds", {"SRC": "file:///src/"}),
    ),
    ("base id table that is a list", "gitleaks", _put(_run, "originalUriBaseIds", [])),
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
    assert _errors_of(ingested.value) == _errors_of(plain.value)


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


#: The .sarif files under tests/test_data, and which of them the model refuses. A
#: fixture added or taken away changes these on purpose, and the test says so.
_FIXTURES_THE_MODEL_ACCEPTS = 46
_FIXTURES_THE_MODEL_REFUSES = ["results_sarif.sarif"]


def test_every_sarif_file_of_the_test_data_reads_as_before():
    """The files the model accepts at main give no note and the model's own report;
    the reduced fixture it refuses is refused here too."""
    kept, refused = 0, []
    for path in sorted(_DATA.rglob("*.sarif")):
        raw = read_json_tolerant(path.read_bytes(), IngestRecord())
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
    assert refused == _FIXTURES_THE_MODEL_REFUSES, (
        "a fixture the model refuses was added or taken away: name it in "
        "_FIXTURES_THE_MODEL_REFUSES"
    )
    assert kept == _FIXTURES_THE_MODEL_ACCEPTS, (
        f"{kept} files read, not {_FIXTURES_THE_MODEL_ACCEPTS}: a fixture was added "
        "or taken away"
    )


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
    assert pointers == [
        _pointer((*_R0, Key("secret-key"))),
        _pointer((*_R0, "partialFingerprints", Key("/home/u/secret-name"))),
    ]
    assert pointers == ["runs/0/results/0/*", "runs/0/results/0/partialFingerprints/*"]


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
    region = _pointer(_REGION)
    assert pointers == [f"template 3: {region}", f"input: {region}", region]


@pytest.mark.parametrize(
    ("label", "shown"),
    [
        ("template 3", "template 3"),
        ("chunk 12", "chunk 12"),
        ("batch 2.1", "batch 2.1"),
        ("/home/user/templates/prod.yaml", "input"),
        ("prod.yaml", "input"),
        ("acme-secrets.env", "input"),
        ("jsmith", "input"),
        ("template prod", "input"),
        ("template 1234567", "input"),
        ("Template 3", "input"),
        ("", "input"),
    ],
)
def test_a_scope_label_is_a_word_and_an_ordinal_and_anything_else_is_input(
    label, shown
):
    """A file name fits any pattern loose enough to take ``prod.yaml``, so the label
    must be the form callers write, a lowercase word and an ordinal."""
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc)["startLine"] = 0
    record = IngestRecord()

    with record.scoped(label):
        ingest_sarif(doc, record)

    (element,) = record.summary()["elements"]
    assert element["pointer"] == f"{shown}: {_pointer(_REGION)}"


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


def test_a_report_read_from_bytes_that_are_not_utf8_is_written_as_json_and_read_back():
    """A byte that is not UTF-8 is read as a lone surrogate, which no UTF-8 writer can
    encode. The SARIF models hold such text in its record form, the six characters
    of the escape, so the report the scanner writes is the report it read."""
    doc = copy.deepcopy(_BASES["gitleaks"])
    _result(doc)["message"]["text"] = "a name with a PLACEHOLDER byte"
    data = json.dumps(doc).encode("utf-8").replace(b"PLACEHOLDER", b"\xe9")
    record = IngestRecord()
    report = ingest_sarif(read_json_tolerant(data, record), record)

    written = report.model_dump_json(exclude_none=True, exclude_unset=True)
    again = SarifReport.model_validate_json(written)

    escape = chr(0x5C) + "udce9"
    assert report.runs[0].results[0].message.root.text == f"a name with a {escape} byte"
    assert again.runs[0].results[0].message.root.text == f"a name with a {escape} byte"
    assert len(again.runs[0].results) == len(report.runs[0].results)


# --------------------------------------------------------------------------- #
# Numbers where the spec wants text
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("number", [0, 7, 10, 120, 12345678901234567890])
def test_an_integer_is_written_back_as_its_decimal_text(number):
    log = copy.deepcopy(_BASES["gitleaks"])
    _result(log)["ruleId"] = number
    sbom = copy.deepcopy(_SYFT)
    _component(sbom)["version"] = number

    assert ingest_sarif(log, IngestRecord()).runs[0].results[0].ruleId == str(number)
    assert ingest_cyclonedx(sbom, IngestRecord()).components[0].version.root == str(
        number
    )


@pytest.mark.parametrize("digits", ["1.10", "2.10", "3.20", "1e2", "0.5"])
def test_a_number_with_a_fraction_or_an_exponent_is_never_written_back_as_text(digits):
    """JSON text such as 1.10 is read as the float 1.1. Writing that back as text
    would give a rule id or a version the tool did not write, so where no other
    repair is admitted the report is refused, as the model refuses it."""
    number = json.loads(digits)
    assert isinstance(number, float)
    log = copy.deepcopy(_BASES["gitleaks"])
    _result(log)["ruleId"] = number
    sbom = copy.deepcopy(_SYFT)
    _component(sbom)["version"] = number
    sarif_record, cyclonedx_record = IngestRecord(), IngestRecord()

    with pytest.raises(ValidationError):
        ingest_sarif(log, sarif_record)
    with pytest.raises(ValidationError):
        ingest_cyclonedx(sbom, cyclonedx_record)

    assert sarif_record.is_empty and cyclonedx_record.is_empty


def test_a_round_whose_edit_fails_names_nothing_it_did_not_make(monkeypatch):
    """A change is noted once the round's edits are made. An edit that raises ends
    the read in a refusal, and the record does not name a change that was not made."""
    doc = copy.deepcopy(_BASES["gitleaks"])
    _region(doc, 0)["startLine"] = 0
    record = IngestRecord()

    def cannot_be_reached(doc, path):
        raise KeyError(path)

    monkeypatch.setattr(scanner_output_ingest, "_get", cannot_be_reached)

    with pytest.raises(ValidationError):
        ingest_sarif(doc, record)

    assert record.is_empty


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
    assert 1 <= validate.call_count <= 9


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


class CdxCase(NamedTuple):
    mutate: Callable[[dict], None]
    #: What the repair owes, by place in the mutated document.
    changes: tuple


def _cdx_case(id_: str, mutate: Callable, *changes: Change) -> Any:
    return pytest.param(CdxCase(mutate, changes), id=id_)


_CDX_REPAIRS = [
    _cdx_case(
        "component with a key the spec does not define",
        lambda d: _component(d).update(foundBy="x"),
        _dropped("unknown_key", "components", 0, Key("foundBy")),
    ),
    _cdx_case(
        "document with a key the spec does not define",
        lambda d: d.update(foo=1),
        _dropped("unknown_key", Key("foo")),
    ),
    _cdx_case(
        "purl that is a number",
        lambda d: _component(d).update(purl=5),
        _rewritten("number_as_text", "5", "components", 0, "purl"),
    ),
    _cdx_case(
        "purl that is a list",
        lambda d: _component(d).update(purl=["a"]),
        _dropped("purl_unreadable", "components", 0, "purl"),
    ),
    _cdx_case(
        "version that is a number",
        lambda d: _component(d).update(version=2),
        _rewritten("number_as_text", "2", "components", 0, "version"),
    ),
    _cdx_case(
        "hash with an algorithm the spec does not define",
        lambda d: _component(d).update(
            hashes=[{"alg": "SHA-999", "content": "a" * 32}]
        ),
        _dropped("hashes_entry_unreadable", "components", 0, "hashes", 0),
    ),
    _cdx_case(
        "property with no name",
        lambda d: _component(d).update(properties=[{"value": "a"}]),
        _dropped("properties_entry_unreadable", "components", 0, "properties", 0),
    ),
    _cdx_case(
        "external reference of a type the spec does not define",
        lambda d: _component(d).update(
            externalReferences=[
                {"type": "homepage-x", "url": "https://a"},
                {"type": "website", "url": "https://b"},
            ]
        ),
        _dropped(
            "externalReferences_entry_unreadable",
            "components",
            0,
            "externalReferences",
            0,
        ),
    ),
    _cdx_case(
        "supplier whose name is a list",
        lambda d: _component(d).update(supplier={"name": ["x"]}),
        _dropped("supplier_unreadable", "components", 0, "supplier"),
    ),
    _cdx_case(
        "serial number that is not a UUID",
        lambda d: d.update(serialNumber="urn:uuid:not-a-uuid"),
        _dropped("document_field_unreadable", "serialNumber"),
    ),
    _cdx_case(
        "timestamp that is not a date",
        lambda d: d["metadata"].update(timestamp="yesterday"),
        _dropped("metadata_field_unreadable", "metadata", "timestamp"),
    ),
    _cdx_case(
        "dependency with no ref",
        lambda d: d.update(dependencies=[{"dependsOn": ["a"]}, {"ref": "ok"}]),
        _dropped("dependency_entry_unreadable", "dependencies", 0),
    ),
    _cdx_case(
        "nested component with a key the spec does not define",
        lambda d: _component(d).update(
            components=[{"type": "library", "name": "n", "foundBy": 1}]
        ),
        _dropped("unknown_key", "components", 0, "components", 0, Key("foundBy")),
    ),
    # A number with a fraction is never written as text (1.10 reads as 1.1): the
    # field goes where it may, and the version of a component is refused below.
    _cdx_case(
        "purl that is a float",
        lambda d: _component(d).update(purl=2.10),
        _dropped("purl_unreadable", "components", 0, "purl"),
    ),
    # One bad entry of a list costs that entry, not the list.
    _cdx_case(
        "composition with an aggregate the spec does not define",
        lambda d: d.update(
            compositions=[{"aggregate": "everything"}, {"aggregate": "complete"}]
        ),
        _dropped("document_entry_unreadable", "compositions", 0),
    ),
    _cdx_case(
        "service whose name is a list",
        lambda d: d.update(services=[{"name": ["x"]}, {"name": "kept"}]),
        _dropped("document_entry_unreadable", "services", 0),
    ),
    _cdx_case(
        "document external reference of a type the spec does not define",
        lambda d: d.update(
            externalReferences=[
                {"type": "homepage-x", "url": "https://a"},
                {"type": "website", "url": "https://b"},
            ]
        ),
        _dropped("document_entry_unreadable", "externalReferences", 0),
    ),
    _cdx_case(
        "metadata author that is not an object",
        lambda d: d["metadata"].update(authors=[5, {"name": "kept"}]),
        _dropped("metadata_entry_unreadable", "metadata", "authors", 0),
    ),
    # The component the BOM describes follows the rules of a component.
    _cdx_case(
        "described component with a purl that is a list",
        lambda d: d["metadata"].update(
            component={"type": "library", "name": "n", "purl": ["a"]}
        ),
        _dropped("purl_unreadable", "metadata", "component", "purl"),
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
    ("component version that is a float", lambda d: _component(d).update(version=1.10)),
    # A vulnerability is a finding: one bad entry refuses the SBOM, where dropping
    # the list would read as an SBOM that holds none.
    (
        "vulnerability with a field of the wrong type",
        lambda d: d.update(vulnerabilities=[{"id": ["x"]}, {"id": "CVE-2021-0001"}]),
    ),
    (
        "described component with a type the spec does not define",
        lambda d: d["metadata"].update(component={"type": "unknown-type", "name": "n"}),
    ),
    (
        "described component with no name",
        lambda d: d["metadata"].update(component={"type": "library"}),
    ),
]


def check_cdx_repair_case(
    case: CdxCase,
    ingest: Callable[[Any, IngestRecord], CycloneDXReport] = ingest_cyclonedx,
) -> IngestRecord:
    """Run one CycloneDX repair case through *ingest* and check what a repair owes,
    as ``check_repair_case`` does for SARIF."""
    doc = copy.deepcopy(_SYFT)
    case.mutate(doc)
    owed = CycloneDXReport.model_validate(repaired_by_hand(doc, case.changes))
    before = json.dumps(doc, sort_keys=True, default=str)
    record = IngestRecord()

    report = ingest(doc, record)

    assert json.dumps(doc, sort_keys=True, default=str) == before, "the input changed"
    summary = record.summary()
    assert summary is not None, "the record names nothing"
    got = [(e["action"], e["code"], e["pointer"]) for e in summary["elements"]]
    assert sorted(got) == _notes_of(case.changes), (
        "the record's notes differ from the case's"
    )
    assert record.repaired == len(case.changes), "the record's count differs"
    assert record.left_out == 0, "a component was left out"
    plain = CycloneDXReport.model_validate(_SYFT)
    got_components, want_components = report.components, plain.components
    assert len(got_components) == len(want_components), "a component was lost"
    touched = {
        c.path[1]
        for c in case.changes
        if c.path[:1] == ("components",) and len(c.path) > 1
    }
    for index, (kept, original) in enumerate(zip(got_components, want_components)):
        if index not in touched:
            assert kept == original, f"component {index} changed"
    assert report == owed, "the report differs from the minimal repair"
    assert record.results_read == len(want_components), "the components read differ"
    assert record.format_name == "CycloneDX"
    assert "CycloneDX does not allow" in record.sentence("syft")
    return record


@pytest.mark.parametrize("case", _CDX_REPAIRS)
def test_a_component_with_one_out_of_spec_part_keeps_the_sbom(case):
    check_cdx_repair_case(case)


@pytest.mark.parametrize("mutate", [pytest.param(m, id=i) for i, m in _CDX_REFUSED])
def test_a_part_of_the_sbom_the_table_does_not_admit_is_refused(mutate):
    doc = copy.deepcopy(_SYFT)
    mutate(doc)
    with pytest.raises(ValidationError) as plain:
        CycloneDXReport.model_validate(copy.deepcopy(doc))
    record = IngestRecord()

    with pytest.raises(ValidationError) as ingested:
        ingest_cyclonedx(doc, record)

    assert record.is_empty
    assert _errors_of(ingested.value) == _errors_of(plain.value)


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
#
# Each control makes the comparison fail in one way and names the check it must
# reach (``match=``), so a control that fails at some other assertion is a
# failed control.
# --------------------------------------------------------------------------- #


def _case_named(name: str) -> Case:
    return next(p.values[0] for p in _REPAIRS if p.id == name)


@pytest.mark.parametrize("case", _REPAIRS)
def test_control_the_model_alone_refuses_every_repair_case(case):
    doc = copy.deepcopy(_BASES[case.base])
    case.mutate(doc)

    with pytest.raises(ValidationError):
        SarifReport.model_validate(doc)


@pytest.mark.parametrize("case", _CDX_REPAIRS)
def test_control_the_model_alone_refuses_every_cyclonedx_repair_case(case):
    doc = copy.deepcopy(_SYFT)
    case.mutate(doc)

    with pytest.raises(ValidationError):
        CycloneDXReport.model_validate(doc)


def test_control_a_pointer_that_keeps_the_tools_keys_fails_the_notes_check(
    monkeypatch,
):
    def keeps_every_key(self, pointer):
        return "/".join(str(token) for token in pointer) or "(document)"

    monkeypatch.setattr(IngestRecord, "_pointer_text", keeps_every_key)

    with pytest.raises(AssertionError, match="the record's notes differ"):
        check_repair_case(_case_named("fingerprint that is a number"))


def test_control_a_repair_that_drops_a_second_finding_fails_the_count_check():
    def drops_a_result(raw, record):
        report = ingest_sarif(raw, record)
        report.runs[0].results = report.runs[0].results[:-1]
        return report

    with pytest.raises(AssertionError, match="a result was lost"):
        check_repair_case(_case_named("startLine 0"), ingest=drops_a_result)


def test_control_a_repair_that_changes_another_finding_fails_the_other_results_check():
    def changes_a_result(raw, record):
        report = ingest_sarif(raw, record)
        report.runs[0].results[1].ruleId = "changed-by-the-control"
        return report

    with pytest.raises(AssertionError, match="result 1 changed"):
        check_repair_case(_case_named("startLine 0"), ingest=changes_a_result)


def test_control_a_repair_that_hides_what_it_did_fails_the_notes_check():
    def silent(raw, record):
        return ingest_sarif(raw, IngestRecord())

    with pytest.raises(AssertionError, match="the record names nothing"):
        check_repair_case(_case_named("startLine 0"), ingest=silent)


def test_control_a_repair_that_gives_up_more_than_it_notes_fails_the_comparison():
    """A bad start column costs the column; a repair that also threw the region
    away would lose the line, and the notes alone would not show it."""

    def drops_the_region(raw, record):
        report = ingest_sarif(raw, record)
        location = report.runs[0].results[0].locations[0]
        location.physicalLocation.root.region = None
        return report

    with pytest.raises(
        AssertionError, match="the report differs from the minimal repair"
    ):
        check_repair_case(_case_named("region startColumn 0"), ingest=drops_the_region)


def test_control_a_repair_that_writes_another_value_fails_the_comparison():
    def writes_another_id(raw, record):
        report = ingest_sarif(raw, record)
        report.runs[0].results[0].ruleId = "6"
        return report

    with pytest.raises(
        AssertionError, match="the report differs from the minimal repair"
    ):
        check_repair_case(
            _case_named("rule id that is a number"), ingest=writes_another_id
        )


def test_control_a_cyclonedx_repair_that_changes_another_component_fails_that_check():
    def changes_a_component(raw, record):
        report = ingest_cyclonedx(raw, record)
        report.components[1].name = "changed-by-the-control"
        return report

    case = _CDX_REPAIRS[2].values[0]
    with pytest.raises(AssertionError, match="component 1 changed"):
        check_cdx_repair_case(case, ingest=changes_a_component)


def test_control_a_cyclonedx_repair_that_drops_the_purl_it_should_rewrite_fails_the_comparison():
    def drops_the_purl(raw, record):
        report = ingest_cyclonedx(raw, record)
        report.components[0].purl = None
        return report

    case = _CDX_REPAIRS[2].values[0]
    with pytest.raises(
        AssertionError, match="the report differs from the minimal repair"
    ):
        check_cdx_repair_case(case, ingest=drops_the_purl)
