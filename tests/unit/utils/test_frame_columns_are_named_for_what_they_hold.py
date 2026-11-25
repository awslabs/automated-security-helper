# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A frame column that is not a model field says so in its name, and has a schema.

The finding-diff side frame, the report grading frame and the package identity
frame are internal to their modules, so nothing outside reads their column names;
what these pin is that each column holds what its name says:

- the suppression flag is ``is_suppressed``, the model's and ``flat_frame``'s name;
- the identity message and the upper-cased severity are not under the bare
  ``message`` and ``severity`` names the model uses for other values;
- the grading frame always has the same four typed columns.

The no-bare-name-for-transformed-values rule binds ``SIDE_SPEC``, whose columns
are join inputs; the reporter-local ASFF derived frame and GitLab projection
keep ``severity`` for their own transformed grades, which nothing joins on.
"""

from __future__ import annotations

import polars as pl
import pytest

from automated_security_helper.models.flat_frame import flat_frame
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.frame_model import frame_schema
from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
    GRADED_SCHEMA,
    active_level_counts,
    flag_total,
    graded_frame,
)
from automated_security_helper.utils import finding_diff
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity

pytestmark = pytest.mark.unit


def _finding(**overrides) -> FlatVulnerability:
    fields = {
        "id": "f-1",
        "title": "t",
        "description": "d",
        "severity": "HIGH",
        "scanner": "bandit",
        "scanner_type": "SAST",
        "rule_id": "B101",
        "file_path": "a.py",
        "line_start": 3,
        "line_end": 4,
        "is_suppressed": False,
    }
    fields.update(overrides)
    severity = fields.pop("severity")
    return flat_with_severity(severity, **fields)


class TestSideFrameColumnNames:
    def test_suppression_is_named_as_the_model_and_the_flat_frame_name_it(self):
        schema = frame_schema(finding_diff.SIDE_SPEC)
        assert "is_suppressed" in schema
        assert "suppressed" not in schema
        assert "is_suppressed" in flat_frame([_finding()]).columns

    def test_transformed_values_do_not_sit_under_bare_model_field_names(self):
        schema = frame_schema(finding_diff.SIDE_SPEC)
        assert "message" not in schema
        assert "severity" not in schema
        assert {"identity_message", "severity_uc"} <= set(schema)

    def test_the_severity_column_holds_the_upper_cased_severity(self):
        # A finding the fallback key covers needs an identity base; read the cell
        # the way the frame reads it, from fallback_key.
        finding = _finding(severity="High")
        side = finding_diff._side([finding])
        key = finding_diff.fallback_key(finding)
        if key is None:
            assert side["severity_uc"].to_list() == [None]
        else:
            assert side["severity_uc"].to_list() == ["HIGH"]
        assert dict(side.schema) == frame_schema(finding_diff.SIDE_SPEC)

    def test_the_suppression_cell_is_the_findings_flag(self):
        side = finding_diff._side(
            [_finding(id="a", is_suppressed=True), _finding(id="b")]
        )
        assert side["is_suppressed"].to_list() == [True, False]
        assert side["i"].to_list() == [0, 1]

    def test_line_columns_are_dense_ranks_not_lines(self):
        """The side frame holds ranks (no line is a null rank), so an enormous line
        needs no overflow flag: its rank is small, and the order is kept."""
        huge = 10**30
        side = finding_diff._side(
            [
                _finding(id="a", line_start=5, line_end=huge),
                _finding(id="b", line_start=None, line_end=None),
            ]
        )
        assert side["line_start"].to_list() == [0, None]
        assert side["line_end"].to_list() == [1, None]


class TestSideFrameKeyMemo:
    def test_the_fallback_key_is_computed_once_per_finding(self, monkeypatch):
        """Three columns read the key's members; the memo keeps the identity-base
        copy and the json.dumps to one pass over the findings."""
        calls = 0
        real = finding_diff.fallback_key

        def counting(finding):
            nonlocal calls
            calls += 1
            return real(finding)

        monkeypatch.setattr(finding_diff, "fallback_key", counting)
        findings = [_finding(id="a"), _finding(id="b"), _finding(id="c")]
        side = finding_diff._side(findings)
        assert calls == len(findings)
        assert dict(side.schema) == frame_schema(finding_diff.SIDE_SPEC)

    def test_the_memo_does_not_outlive_the_call(self):
        finding_diff._side([_finding()])
        assert finding_diff._SIDE_KEYS.get() is None

    def test_the_key_columns_read_the_same_without_the_memo(self):
        """``to_frame`` over SIDE_SPEC outside ``_side`` (no memo installed)
        computes the key per column and fills the same cells."""
        from automated_security_helper.models.frame_model import to_frame

        findings = [_finding(id="a", severity="High"), _finding(id="b")]
        direct = to_frame(findings, finding_diff.SIDE_SPEC)
        through = finding_diff._side(findings)
        assert direct.to_dicts() == through.to_dicts()


class TestGradedFrameSchema:
    def test_it_has_the_same_four_typed_columns_with_and_without_actionable(self):
        without = graded_frame(["high"], [False], [False])
        with_it = graded_frame(["high"], [False], [False], actionable=[True])
        assert without.schema == with_it.schema == GRADED_SCHEMA
        assert list(GRADED_SCHEMA) == [
            "level",
            "is_suppressed",
            "left_out",
            "actionable",
        ]

    def test_actionable_is_null_when_it_was_not_decided(self):
        frame = graded_frame(["high", "low"], [False, True], [False, False])
        assert frame["actionable"].to_list() == [None, None]
        assert flag_total(frame, "actionable") == 0

    def test_an_empty_grading_still_has_the_schema(self):
        assert graded_frame([], [], []).schema == GRADED_SCHEMA

    def test_active_levels_count_the_unsuppressed_rows_in_first_seen_order(self):
        frame = graded_frame(
            ["medium", "high", "medium", "high"],
            [False, False, True, False],
            [False] * 4,
        )
        assert active_level_counts(frame) == [("medium", 1), ("high", 2)]
        assert flag_total(frame, "is_suppressed") == 1

    def test_the_old_column_name_is_gone(self):
        assert "suppressed" not in graded_frame(["high"], [True], [False]).columns
        assert pl.Boolean == GRADED_SCHEMA["is_suppressed"]
