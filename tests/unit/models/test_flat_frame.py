# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flattened findings as a frame: ``models/flat_frame.py`` and
``AshAggregatedResults._flat_frame``.

The columns are in the module docstring of ``flat_frame``; this pins them and the
two things a consumer relies on: ``i`` is the position in the flat list, and text
and line numbers a frame column cannot hold survive the trip.
"""

from __future__ import annotations

import polars as pl
import pytest

from automated_security_helper.models.flat_frame import (
    flat_frame,
    suppressed_by_scanner,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_identity import canonical
from automated_security_helper.utils.frame_text import unwire, wire
from tests.unit.models._suppressed_count_helpers import (
    SCANNER,
    build_model,
    suppressed_result,
)

pytestmark = pytest.mark.unit

SCHEMA = {
    "i": pl.Int64,
    "id": pl.String,
    "scanner": pl.String,
    "scanner_key": pl.String,
    "scanner_type": pl.String,
    "rule_id": pl.String,
    "severity": pl.Enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    "file_path": pl.String,
    "line_start": pl.Int64,
    "line_end": pl.Int64,
    "line_overflow": pl.Boolean,
    "is_suppressed": pl.Boolean,
    "source_report": pl.String,
    "has_identity": pl.Boolean,
    "fingerprinted": pl.Boolean,
    "base": pl.String,
    "correlation_id": pl.String,
}


def row(index, scanner="Sc", **fields):
    entry = {"id": f"id{index}", "title": "t", "severity": "LOW", **fields}
    return FlatVulnerability.from_additional_report(entry, scanner)


def test_the_columns_and_their_types_are_the_documented_ones():
    frame = flat_frame([row(0)])
    assert dict(frame.schema) == SCHEMA
    assert list(frame.columns) == list(SCHEMA)


def test_an_empty_list_is_an_empty_frame_with_the_schema():
    frame = flat_frame([])
    assert frame.height == 0
    assert dict(frame.schema) == SCHEMA
    assert suppressed_by_scanner(frame) == {}


def test_a_row_carries_what_the_finding_holds():
    finding = row(
        0,
        scanner="Sc",
        rule_id="R1",
        file_path="dir/a.py",
        line_start=3,
        line_end=9,
        severity="HIGH",
    )
    (got,) = flat_frame([finding]).iter_rows(named=True)
    assert got["i"] == 0 and got["id"] == finding.id == "Sc-id0"
    assert got["scanner"] == "Sc" and got["scanner_key"] == "sc"
    assert got["rule_id"] == "R1" and got["file_path"] == "dir/a.py"
    assert (got["line_start"], got["line_end"], got["line_overflow"]) == (3, 9, False)
    assert got["severity"] == finding.severity
    assert got["is_suppressed"] is False
    assert got["source_report"] == "Sc"
    # an entry that carries its plugin's id has no identity
    assert got["has_identity"] is False and got["base"] is None


def test_a_finding_with_an_identity_carries_its_base_and_whether_it_is_fingerprinted():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    (finding,) = model.to_flat_vulnerabilities()
    (got,) = flat_frame([finding]).iter_rows(named=True)
    assert got["has_identity"] is True
    assert got["fingerprinted"] is False
    assert got["source_report"] is None
    assert got["base"] == canonical(finding.identity_base)


def test_a_line_that_does_not_fit_64_bits_is_null_and_flagged():
    fits = row(0, line_start=2**63 - 1, line_end=-(2**63))
    over = row(1, line_start=2**63, line_end=4)
    under = row(2, line_start=1, line_end=-(2**63) - 1)
    none = row(3)
    frame = flat_frame([fits, over, under, none])
    assert frame["line_start"].to_list() == [2**63 - 1, None, 1, None]
    assert frame["line_end"].to_list() == [-(2**63), 4, None, None]
    assert frame["line_overflow"].to_list() == [False, True, True, False]
    assert over.line_start == 2**63  # the finding still has the number


def test_text_the_finding_holds_comes_back_as_it_was_held():
    # the model may rewrite a lone surrogate it is given; whatever a finding holds,
    # the frame carries, so that two findings' paths are equal in the frame
    # exactly when they are on the findings
    left = row(0, scanner="s\udcff", file_path="a/\udcff.py")
    right = row(1, scanner="s\udcff", file_path="a/\udcfe.py")
    frame = flat_frame([left, right])
    assert [unwire(text) for text in frame["file_path"]] == [
        left.file_path,
        right.file_path,
    ]
    assert unwire(frame["scanner"][0]) == left.scanner
    assert frame["scanner_key"][0] == wire(left.scanner.lower())
    assert (frame["file_path"][0] == frame["file_path"][1]) == (
        left.file_path == right.file_path
    )


def test_a_lone_surrogate_in_a_frame_cell_is_carried_not_refused():
    # a finding built around the model's validation can hold one; the frame
    # must not refuse the whole run for it
    finding = row(0)
    finding.__dict__["file_path"] = "a/\udcff.py"
    frame = flat_frame([finding])
    assert unwire(frame["file_path"][0]) == "a/\udcff.py"


def test_suppressed_counts_are_by_lowercased_scanner_in_order_of_first_sight():
    findings = [row(i, scanner=s) for i, s in enumerate(["B", "a", "b", "A", "c", "b"])]
    for finding, suppressed in zip(findings, [True, True, True, False, False, True]):
        finding.is_suppressed = suppressed
    counts = suppressed_by_scanner(flat_frame(findings))
    assert counts == {"b": 3, "a": 1}
    assert list(counts) == ["b", "a"]


def test_the_model_accessor_has_a_row_per_flat_finding_in_its_order():
    model = build_model(
        sarif_results=[
            suppressed_result(SCANNER, "R1"),
            suppressed_result(SCANNER, "R2"),
        ]
    )
    model.additional_reports = {"plug": [{"id": "p1", "title": "t", "severity": "LOW"}]}
    flat = model.to_flat_vulnerabilities()
    frame = model._flat_frame()
    assert frame["i"].to_list() == list(range(len(flat))) == [0, 1, 2]
    assert frame["id"].to_list() == [finding.id for finding in flat]
    assert frame["source_report"].to_list() == [None, None, "plug"]
    assert frame["is_suppressed"].to_list() == [True, True, False]


def test_the_accessor_sees_a_suppression_set_on_a_finding_since():
    model = build_model(sarif_results=[suppressed_result(SCANNER, "R1")])
    (finding,) = model.to_flat_vulnerabilities()
    assert model._flat_frame()["is_suppressed"].to_list() == [True]
    finding.is_suppressed = False
    assert model._flat_frame()["is_suppressed"].to_list() == [False]
