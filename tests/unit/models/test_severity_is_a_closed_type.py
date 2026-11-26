# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding's severity is a closed type at both boundaries.

``FlatVulnerability.severity`` is typed as :class:`Severity`, so a value that is not
on the ladder is a ``ValidationError`` at ingest, and the flat frame's ``severity``
column is a polars ``Enum`` of the ladder, so a value that is not on the ladder
raises when the frame is built. Both halves ship together so they cannot drift.

The three route families that construct a finding all grade through the ladder and
so always hold a ladder value; the tests here pin that, because the closed type is
only safe while it stays true:

* a SARIF result, through ``_resolve_severity`` and ``result_severity``;
* an ``additional_reports`` entry, through ``_additional_report_severity``, whose
  fallback for text it cannot grade is MEDIUM (a ladder value, pinned here);
* the ``ash inspect`` suppression matcher's stand-in finding.

Wire spellings stay the plain ladder text: the stored attribute is a ``Severity``
member that renders, compares, hashes and dumps as its text, and the frame cell is
the text.
"""

from __future__ import annotations

import json

import polars as pl
import pytest
from pydantic import ValidationError

from automated_security_helper.cli.inspect.inspect_findings_app import _as_scanned
from automated_security_helper.models.flat_frame import FLAT_SPEC, flat_frame
from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    _additional_report_severity,
    _resolve_severity,
)
from automated_security_helper.models.frame_model import (
    FrameSpecError,
    frame_schema,
    to_frame,
)
from automated_security_helper.models.vocab import SEVERITY_VALUES, Severity
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.severity_ladder import result_severity

pytestmark = pytest.mark.unit

LADDER = list(SEVERITY_VALUES)
OFF_LADDER = [
    "WEIRD",
    "moderate",
    "UNKNOWN",
    "",
    " ",
    "high",
    "High",
    "9.0",
    "Severity.HIGH",
    # On the ladder once stripped: the field used to accept it and stored the
    # padded text; it is refused now, on purpose.
    " HIGH ",
    "HIGH\n",
]


def build(severity):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity=severity,
        scanner="Sc",
        scanner_type="SAST",
    )


def sarif_result(**fields):
    payload = {
        "ruleId": "R1",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
        **fields,
    }
    return Result.model_validate(payload)


# --- ingest: the field is closed --------------------------------------------------


@pytest.mark.parametrize("value", OFF_LADDER)
def test_an_off_ladder_text_is_refused_at_ingest(value):
    with pytest.raises(ValidationError) as caught:
        build(value)
    assert [error["loc"] for error in caught.value.errors()] == [("severity",)]


@pytest.mark.parametrize("value", [None, 3, 1.5, ["HIGH"], {"HIGH": 1}])
def test_a_value_that_is_not_text_is_refused_at_ingest(value):
    with pytest.raises(ValidationError):
        build(value)


@pytest.mark.parametrize("value", LADDER)
def test_every_ladder_value_is_stored_as_its_member_and_reads_as_its_text(value):
    finding = build(value)
    assert finding.severity is Severity(value)
    # every reader that interpolates or compares the severity sees the ladder text
    assert str(finding.severity) == value
    assert f"{finding.severity}" == value
    assert f"{finding.severity:>8}" == value.rjust(8)
    assert "%s" % finding.severity == value
    assert finding.severity == value
    assert hash(finding.severity) == hash(value)
    assert finding.model_dump(mode="json")["severity"] == value
    assert type(finding.model_dump(mode="json")["severity"]) is str
    assert json.loads(finding.model_dump_json())["severity"] == value
    assert json.dumps({"severity": finding.severity}) == f'{{"severity": "{value}"}}'


@pytest.mark.parametrize("member", list(Severity))
def test_a_severity_member_is_accepted(member):
    assert build(member).severity is member


def test_the_json_schema_names_the_ladder():
    schema = FlatVulnerability.model_json_schema()
    prop = schema["properties"]["severity"]
    resolved = (
        schema["$defs"][prop["$ref"].rsplit("/", 1)[1]] if "$ref" in prop else prop
    )
    assert resolved["enum"] == LADDER


# --- frame: the column is closed ---------------------------------------------------


def test_the_severity_column_is_a_polars_enum_of_the_ladder():
    assert frame_schema(FLAT_SPEC)["severity"] == pl.Enum(LADDER)
    assert flat_frame([]).schema["severity"] == pl.Enum(LADDER)


def test_a_ladder_finding_round_trips_through_the_enum_column():
    findings = [build(value) for value in LADDER]
    frame = flat_frame(findings)
    assert frame["severity"].cast(pl.String).to_list() == LADDER
    assert frame["severity"].dtype == pl.Enum(LADDER)


@pytest.mark.parametrize("value", ["WEIRD", "high", "", "SÄVERE\udcff", None])
def test_an_off_ladder_value_raises_at_frame_build(value):
    finding = build("LOW")
    finding.__dict__["severity"] = value  # built around the model's validation
    with pytest.raises(FrameSpecError) as caught:
        flat_frame([finding])
    assert "severity" in str(caught.value)


def test_a_refused_frame_row_does_not_poison_a_valid_build():
    bad = build("LOW")
    bad.__dict__["severity"] = "WEIRD"
    with pytest.raises(FrameSpecError):
        to_frame([bad], FLAT_SPEC)
    assert flat_frame([build("HIGH")])["severity"].cast(pl.String).to_list() == ["HIGH"]


# --- every construction path yields a ladder value --------------------------------


LEVELS = ["error", "warning", "note", "none", None, "bogus", "ERROR", ""]
DECLARED = [None, "", "moderate", "critical", " high ", "Info", "SPICY", 7]


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("declared", DECLARED)
def test_a_sarif_result_always_grades_onto_the_ladder(level, declared):
    properties = {} if declared is None else {"issue_severity": declared}
    payload = {"properties": properties}
    if level is not None:
        payload["level"] = level
    try:
        result = sarif_result(**payload)
    except ValidationError:
        pytest.skip("the SARIF model itself refuses this level")
    graded = result_severity(result)
    assert graded in LADDER
    assert _resolve_severity(result) == graded
    finding = FlatVulnerability.from_sarif_result(result, "Sc", "SAST")
    assert finding.severity is Severity(graded)
    assert flat_frame([finding])["severity"].cast(pl.String).to_list() == [graded]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("CRITICAL", "CRITICAL"),
        ("high", "HIGH"),
        ("error", "CRITICAL"),
        ("warning", "MEDIUM"),
        ("note", "LOW"),
        ("none", "INFO"),
        ("moderate", "MEDIUM"),
        ("SPICY", "MEDIUM"),
        ("", "MEDIUM"),
        ("   ", "MEDIUM"),
        (None, "MEDIUM"),
        (7, "MEDIUM"),
        (["HIGH"], "MEDIUM"),
    ],
)
def test_an_additional_report_severity_always_grades_onto_the_ladder(raw, expected):
    # The fallback is MEDIUM, which is a ladder value: the closed field accepts it.
    # It still grades junk silently; removing it is its own decision.
    assert _additional_report_severity(raw) == expected
    entry = {"id": "x", "title": "t", "severity": raw}
    finding = FlatVulnerability.from_additional_report(entry, "Sc")
    assert finding.severity == expected


def test_the_inspect_suppression_matcher_builds_for_any_recorded_severity():
    for recorded in [None, "", "moderate", "high", "HIGH", "weird", 3]:
        scanned = _as_scanned(
            {"file": "a.py", "line": 3, "rule_id": "R1", "severity": recorded}
        )
        assert scanned is not None
        assert scanned.severity in LADDER
