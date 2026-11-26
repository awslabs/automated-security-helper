# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The severity ladder is spelled once, in ``models.vocab``, and derived everywhere.

``Severity`` and ``SeverityThreshold`` are the only places the five ladder words
and the five gate words appear as text. The ladder module's tables, the flat
finding model's severity tuple, the frame layer's severity column vocabulary and
the count-bucket field names all derive from them, and these tests pin that so a
sixth member, a renamed member or a reordering reaches every consumer.

The second half is the proof the closing of the severity vocabulary (a typed
field, a polars ``Enum`` column) needs first: every route that builds a finding's
severity yields one of the ladder's five words, whatever a scanner wrote.
"""

import ast
from pathlib import Path

import pytest

from automated_security_helper.models import asharp_model, flat_vulnerability
from automated_security_helper.models.flat_frame import FLAT_SPEC
from automated_security_helper.models.flat_vulnerability import (
    _additional_report_severity,
    _resolve_severity,
)
from automated_security_helper.models.frame_model import column_vocabularies
from automated_security_helper.models.vocab import (
    SEVERITY_BUCKETS,
    SEVERITY_THRESHOLD_VALUES,
    SEVERITY_VALUES,
    SUPPRESSED_COUNT_KEY,
    Severity,
    SeverityThreshold,
)
from automated_security_helper.utils import severity_ladder

pytestmark = pytest.mark.unit

PACKAGE = Path(severity_ladder.__file__).resolve().parent.parent

#: The files whose ladder words must come from the enums, not from text.
DERIVED_FILES = (
    "utils/severity_ladder.py",
    "models/flat_vulnerability.py",
    "models/asharp_model.py",
)

LADDER_WORDS = frozenset(
    {m.value for m in Severity}
    | {m.value for m in SeverityThreshold}
    | {m.value.lower() for m in Severity}
)


def _spelled_ladder_words(source: str):
    """Every ``(line, text)`` string constant naming a ladder word, outside the
    docstrings."""
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        )
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in LADDER_WORDS
        and id(node) not in docstrings
    ]


def test_the_scan_finds_a_planted_ladder_word():
    assert _spelled_ladder_words('x = ("LOW", "MEDIUM")\n') == [
        (1, "LOW"),
        (1, "MEDIUM"),
    ]
    assert _spelled_ladder_words('"""HIGH"""\nx = 1\n') == []


@pytest.mark.parametrize("relative", DERIVED_FILES)
def test_no_ladder_word_is_spelled_as_text_in_the_derived_files(relative):
    source = (PACKAGE / relative).read_text(encoding="utf-8")
    assert _spelled_ladder_words(source) == [], relative


def test_the_ladders_name_tuples_are_the_enums_own():
    assert severity_ladder.SEVERITIES is SEVERITY_VALUES
    assert severity_ladder.SEVERITY_THRESHOLDS is SEVERITY_THRESHOLD_VALUES
    assert severity_ladder.SEVERITY_COUNT_KEYS is SEVERITY_BUCKETS
    assert flat_vulnerability._SEVERITY_ORDER is SEVERITY_VALUES
    assert flat_vulnerability._VALID_ISSUE_SEVERITIES == set(SEVERITY_VALUES)


def test_the_rank_tables_follow_the_member_order():
    members = list(Severity)
    top = len(members) - 1
    assert severity_ladder._SEVERITY_RANK == {
        m.value: top - i for i, m in enumerate(members)
    }
    assert severity_ladder.SEVERITY_DISPLAY_ORDER == {
        m.value: i for i, m in enumerate(members)
    }
    assert severity_ladder._THRESHOLD_MIN_RANK == {
        t.value: 0 if t is SeverityThreshold.ALL else top - members.index(Severity(t))
        for t in SeverityThreshold
    }
    # keys are plain text, so a dump or a repr never shows a member
    for table in (
        severity_ladder._SEVERITY_RANK,
        severity_ladder._THRESHOLD_MIN_RANK,
        severity_ladder.SEVERITY_DISPLAY_ORDER,
    ):
        assert all(type(key) is str for key in table)


def test_the_sarif_level_map_grades_onto_enum_members():
    assert severity_ladder._SARIF_LEVEL_TO_SEVERITY == {
        "error": Severity.CRITICAL.value,
        "warning": Severity.MEDIUM.value,
        "note": Severity.LOW.value,
        "none": Severity.INFO.value,
    }
    assert all(
        type(v) is str for v in severity_ladder._SARIF_LEVEL_TO_SEVERITY.values()
    )


def test_the_frame_severity_column_vocabulary_is_the_ladder():
    assert column_vocabularies(FLAT_SPEC)["severity"] == tuple(
        m.value for m in Severity
    )


def test_the_lowercase_counter_names_are_derived_and_pinned():
    expected = tuple(m.value.lower() for m in Severity)
    assert expected == ("critical", "high", "medium", "low", "info")
    assert severity_ladder.SEVERITY_COUNT_KEYS == expected
    assert asharp_model._SEVERITY_ORDER == expected
    assert asharp_model._VALID_INCREMENT_FIELDS == expected + (SUPPRESSED_COUNT_KEY,)
    # the record's own field names cannot be derived, so they are pinned to it
    assert tuple(asharp_model.ScannerSeverityCount.model_fields) == (
        SUPPRESSED_COUNT_KEY,
        *expected,
    )


# --- every construction path yields a ladder word ---------------------------------

OFF_LADDER = ["moderate", "", "   ", "Warning!", "none ", "7", "ALL", "unknown", "\x00"]
LADDER_ANY_CASE = [
    text
    for m in Severity
    for text in (m.value, m.value.lower(), m.value.title(), f"  {m.value} ")
]
LEVELS = [None, "error", "warning", "note", "none", "ERROR", "bogus", 3, ""]


def _result(level, declared):
    properties = {} if declared is None else {"issue_severity": declared}
    result = {"ruleId": "r", "message": {"text": "m"}, "properties": properties}
    if level is not None:
        result["level"] = level
    return result


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize(
    "declared", [None, *OFF_LADDER, *LADDER_ANY_CASE, 5, ["HIGH"], {"a": 1}]
)
def test_the_gates_severity_is_always_a_ladder_word(level, declared):
    graded = severity_ladder.result_severity(_result(level, declared))
    assert graded in SEVERITY_VALUES
    assert type(graded) is str


@pytest.mark.parametrize(
    "raw",
    [None, 0, 1.5, [], {}, b"HIGH", *OFF_LADDER, *LADDER_ANY_CASE, *LEVELS[1:5]],
)
def test_an_additional_reports_severity_is_always_a_ladder_word(raw):
    graded = _additional_report_severity(raw)
    assert graded in SEVERITY_VALUES
    assert type(graded) is str


def test_the_unreadable_default_of_an_additional_report_is_the_missing_levels_grade():
    # no level states MEDIUM everywhere: the default is the ladder's own answer
    assert _additional_report_severity(None) == severity_ladder.result_severity(
        {"properties": {}}
    )
    assert _additional_report_severity(None) == Severity.MEDIUM.value


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("declared", [None, "moderate", "high", "INFO"])
def test_a_resolved_sarif_result_severity_is_a_ladder_word(level, declared):
    from automated_security_helper.schemas.sarif_schema_model import Result

    kwargs = {"ruleId": "r", "message": {"text": "m"}}
    if level in ("error", "warning", "note", "none"):
        kwargs["level"] = level
    if declared is not None:
        kwargs["properties"] = {"issue_severity": declared}
    assert _resolve_severity(Result(**kwargs)) in SEVERITY_VALUES
