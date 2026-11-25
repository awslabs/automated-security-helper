# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The drift gate for frame schemas derived from models: ``models/frame_model.py``.

Every registered frame layer's derived schema must equal the schema its builder
constructs (names, dtypes and column order), and every name its model holds must
have a decided frame fate, so a field added to a model fails here until someone
decides what the frame does with it. The planted-field controls prove the failure
is loud, and the mechanism tests pin what a marker does.
"""

from __future__ import annotations

from typing import Annotated, Any, Callable, Dict, Optional, Tuple

import polars as pl
import pytest
from pydantic import BaseModel

from automated_security_helper.models.flat_frame import (
    FLAT_SPEC,
    flat_frame,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.frame_model import (
    Computed,
    EnumColumn,
    FrameSpec,
    FrameSpecError,
    NotInFrame,
    OverflowNullable,
    Position,
    RankEncoded,
    Ranked,
    RawText,
    WireText,
    assert_accounted,
    column_vocabularies,
    frame_columns,
    frame_schema,
    to_frame,
    unaccounted,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
    GRADED_SCHEMA,
    graded_frame,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    _derived_frame,
    _derived_schema,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    _projection,
    _projection_schema,
)
from automated_security_helper.utils.finding_diff import SIDE_SPEC, _side
from automated_security_helper.utils.finding_identity import identity_frame_spec
from automated_security_helper.utils.frame_text import unwire, wire
from automated_security_helper.utils.suppression_frame import (
    _chunk_frame,
    _span_frame,
    line_span_spec,
)
from tests.unit.models.test_flat_frame import SCHEMA as FLAT_HAND_SCHEMA
from tests.unit.models.test_flat_frame import row

pytestmark = pytest.mark.unit

# Every frame layer that derives its schema: the spec and the callable that builds
# the frame the layer ships, called with no rows.
FRAME_SPECS: Dict[str, Tuple[FrameSpec, Callable[[], pl.DataFrame]]] = {
    "flat_frame": (FLAT_SPEC, lambda: flat_frame([])),
    "suppression_line_span": (line_span_spec(), lambda: _span_frame([], [])),
    "finding_diff_side": (SIDE_SPEC, lambda: _side([])),
}

# Models whose frames are derived from a whole run's keys, so no per-row column
# can be projected straight off the model and there is no schema to pin -- but
# every name the model holds still needs a decided frame fate.
ACCOUNTED_SPECS: Dict[str, FrameSpec] = {
    "finding_identity": identity_frame_spec(),
}

ALL_SPECS: Dict[str, FrameSpec] = {
    **{name: spec for name, (spec, _build) in FRAME_SPECS.items()},
    **ACCOUNTED_SPECS,
}

# Population-B frames: the rows are gradings, drafts or prepared values computed
# on the host, so there is no model to derive a spec from (design section 7).
# The registry pins each one's declared schema dict against the frame its
# builder constructs, so the schema has one record beyond the builder itself.
HAND_SCHEMAS: Dict[
    str, Tuple[Callable[[], Dict[str, Any]], Callable[[], pl.DataFrame]]
] = {
    "graded_frame": (
        lambda: dict(GRADED_SCHEMA),
        lambda: graded_frame([], [], []),
    ),
    "graded_frame_actionable": (
        lambda: dict(GRADED_SCHEMA),
        lambda: graded_frame([], [], [], []),
    ),
    "asff_derived_input": (_derived_schema, lambda: _derived_frame([])),
    "gitlab_sast_projection": (_projection_schema, lambda: _projection([])),
}


@pytest.mark.parametrize("name", sorted(HAND_SCHEMAS))
def test_a_hand_schema_frame_builds_exactly_its_declared_schema(name):
    declared, build = HAND_SCHEMAS[name]
    assert list(dict(build().schema).items()) == list(declared().items())


def test_the_graded_readers_read_declared_columns_over_a_real_row():
    """The schema-equality case above cannot fail for a builder that passes the
    whole declared dict as ``schema=``; what can drift is a reader naming a
    column the schema no longer declares. One real row through each reader."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
        active_level_counts,
        flag_total,
    )

    frame = graded_frame(["high"], [False], [True], [True])
    assert active_level_counts(frame) == [("high", 1)]
    assert flag_total(frame, "is_suppressed") == 0
    assert flag_total(frame, "left_out") == 1
    assert flag_total(frame, "actionable") == 1
    suppressed = graded_frame(["high"], [True], [False])
    assert active_level_counts(suppressed) == []
    assert flag_total(suppressed, "is_suppressed") == 1


def test_the_asff_derived_reader_reads_declared_columns_over_real_rows():
    """``_derived`` is the one consumer of the ASFF derived frame; its four
    output cells prove each ``pl.col`` it selects is a declared column holding
    what the schema says."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
        _derived,
    )

    active = row(0, severity="critical")
    archived = row(1)
    archived.__dict__["is_suppressed"] = True
    derived = _derived(
        [
            {"severity": "critical", "flat": active, "is_cve": True},
            {"severity": "not-on-the-table", "flat": archived, "is_cve": False},
        ]
    )
    assert derived == [
        {
            "label": "CRITICAL",
            "type": "Software and Configuration Checks/Vulnerabilities/CVE",
            "record_state": "ACTIVE",
            "suppressed_text": "false",
        },
        {
            "label": "INFORMATIONAL",
            "type": "Software and Configuration Checks/Vulnerabilities",
            "record_state": "ARCHIVED",
            "suppressed_text": "true",
        },
    ]


@pytest.mark.parametrize("name", sorted(FRAME_SPECS))
def test_the_derived_schema_is_the_schema_the_builder_constructs(name):
    spec, build = FRAME_SPECS[name]
    derived = frame_schema(spec)
    built = dict(build().schema)
    assert list(derived.items()) == list(built.items())


@pytest.mark.parametrize("name", sorted(ALL_SPECS))
def test_every_name_the_model_holds_has_a_decided_frame_fate(name):
    spec = ALL_SPECS[name]
    assert unaccounted(spec) == []
    assert_accounted(spec)


def test_the_flat_frame_schema_is_the_documented_one_in_the_documented_order():
    assert list(frame_schema(FLAT_SPEC).items()) == list(FLAT_HAND_SCHEMA.items())


def test_the_suppression_line_columns_carry_the_rank_policy_from_the_model():
    info = {column.name: column for column in frame_columns(line_span_spec())}
    assert set(info) == {"line_start", "line_end"}
    for column in info.values():
        assert column.rank_group == "lines"
        assert column.dtype == "Int64"
        assert column.nullable is True  # both fields are Optional on the model


def test_the_chunk_frame_line_columns_are_the_derived_span_columns():
    frame = _chunk_frame(row(0), [])
    built = dict(frame.schema)
    # the predicate booleans are results of host predicates, not model fields,
    # so they stay hand-declared; static_ok is their conjunction with the lines
    assert list(built) == [
        "live",
        "rule",
        "base",
        "rest",
        "engine",
        "line_start",
        "line_end",
        "static_ok",
    ]
    derived = frame_schema(line_span_spec())
    assert {name: built[name] for name in derived} == derived


def test_the_suppression_markers_leave_validation_and_the_json_schema_alone():
    schema = AshSuppression.model_json_schema()
    assert "RankEncoded" not in str(schema)
    assert schema["properties"]["line_start"]["anyOf"] == [
        {"type": "integer"},
        {"type": "null"},
    ]


class _PlantedField(FlatVulnerability):
    planted_field: str = "x"


class _PlantedProperty(FlatVulnerability):
    @property
    def planted_property(self) -> str:
        return "x"


class _PlantedPrivate(FlatVulnerability):
    _planted_private: int = 0


@pytest.mark.parametrize(
    "model, name",
    [
        (_PlantedField, "planted_field"),
        (_PlantedProperty, "planted_property"),
        (_PlantedPrivate, "_planted_private"),
    ],
)
def test_a_name_added_to_the_model_fails_the_gate_loudly(model, name):
    planted = FrameSpec(model, FLAT_SPEC.columns, FLAT_SPEC.waived)
    assert unaccounted(planted) == [name]
    with pytest.raises(FrameSpecError, match=name):
        assert_accounted(planted)


def test_the_planted_field_passes_once_its_fate_is_decided():
    projected = FrameSpec(
        _PlantedField, FLAT_SPEC.columns + ("planted_field",), FLAT_SPEC.waived
    )
    waived = FrameSpec(
        _PlantedField,
        FLAT_SPEC.columns,
        {**FLAT_SPEC.waived, "planted_field": "not a column"},
    )
    assert unaccounted(projected) == [] == unaccounted(waived)
    assert "planted_field" in frame_schema(projected)


def test_the_flat_spec_declares_what_the_model_cannot_show():
    info = {column.name: column for column in frame_columns(FLAT_SPEC)}
    # required fields derive a non-nullable contract (the frame once hedged nulls
    # for them); the optional ones, and the private-attribute column, stay nullable
    for required in ("id", "scanner", "scanner_type", "severity", "is_suppressed"):
        assert info[required].nullable is False, required
    for optional in ("rule_id", "file_path", "source_report", "base"):
        assert info[optional].nullable is True, optional
    assert info["line_overflow"].source == "flag"
    assert [c.name for c in frame_columns(FLAT_SPEC)].index("line_overflow") == (
        [c.name for c in frame_columns(FLAT_SPEC)].index("line_end") + 1
    )


def test_the_emitters_severity_order_is_the_models_vocabulary():
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        _SEVERITY_ORDER,
    )

    vocabulary = column_vocabularies(FLAT_SPEC)["severity"]
    assert list(_SEVERITY_ORDER) == list(vocabulary)
    assert list(_SEVERITY_ORDER.values()) == list(range(len(vocabulary)))


def test_a_non_nullable_flag_is_never_null_for_a_finding_holding_none():
    # FlatVulnerability does not validate assignment, so an instance built around
    # validation (model_construct, __dict__) can hold None in a required bool; the
    # builder this frame replaced wrote bool(...) there, so the cell is False
    finding = row(0)
    finding.__dict__["is_suppressed"] = None
    cells = flat_frame([finding])["is_suppressed"]
    assert cells.to_list() == [False]
    assert cells.null_count() == 0


def test_the_flatjson_report_gives_that_finding_a_real_is_suppressed_value():
    from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
        FlatJSONReporter,
    )

    finding = row(0)
    finding.__dict__["is_suppressed"] = None
    flag = flat_frame([finding])["is_suppressed"].to_list()[0]
    assert FlatJSONReporter._finding_dict(finding, flag)["is_suppressed"] is False


def test_every_string_column_of_the_flat_frame_is_wired():
    # the flat_frame docstring says so; a RawText marker on a projected field
    # would opt a column out without any sign at the use site
    assert not any(column.raw for column in frame_columns(FLAT_SPEC))
    finding = row(0)
    finding.__dict__["scanner"] = "SÄVERE\udcff"
    assert unwire(flat_frame([finding])["scanner"][0]) == "SÄVERE\udcff"


def test_severity_is_a_polars_enum_of_its_vocabulary():
    ladder = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert column_vocabularies(FLAT_SPEC) == {"severity": ladder}
    assert frame_schema(FLAT_SPEC)["severity"] == pl.Enum(list(ladder))
    off_ladder = row(0)
    off_ladder.__dict__["severity"] = "WEIRD"  # built around the model's validation
    with pytest.raises(FrameSpecError, match="severity"):
        flat_frame([off_ladder])


def test_the_markers_leave_validation_and_the_json_schema_alone():
    schema = FlatVulnerability.model_json_schema()
    text = str(schema)
    for marker in ("NotInFrame", "OverflowNullable", "EnumColumn", "RankEncoded"):
        assert marker not in text
    assert schema["properties"]["line_start"]["anyOf"] == [
        {"type": "integer"},
        {"type": "null"},
    ]
    assert "enum" not in schema["properties"]["severity"]


def test_building_the_frame_never_validates_or_dumps_a_model(monkeypatch):
    findings = [row(0), row(1, line_start=2**70)]

    def refuse(*_args, **_kwargs):
        raise AssertionError("a frame operation touched pydantic per row")

    for attribute in ("model_validate", "model_dump", "model_copy", "__init__"):
        monkeypatch.setattr(FlatVulnerability, attribute, refuse)
    frame = flat_frame(findings)
    assert frame.height == 2 and frame["line_overflow"].to_list() == [False, True]


class _Toy(BaseModel):
    name: str
    ascii_label: Annotated[str, RawText()]
    wired: Annotated[str, WireText()]
    maybe: Optional[str] = None
    flag: bool = False
    first: Annotated[Optional[int], OverflowNullable("over")] = None
    second: Annotated[Optional[int], OverflowNullable("over")] = None
    lo: Annotated[Optional[int], RankEncoded("lines")] = None
    hi: Annotated[Optional[int], RankEncoded("lines")] = None
    level: Annotated[str, EnumColumn(("A", "B"))] = "A"
    skipped: Annotated[dict, NotInFrame()] = {}


def _toy(**fields):
    base = {"name": "n", "ascii_label": "HIGH", "wired": "w"}
    return _Toy(**{**base, **fields})


TOY_SPEC = FrameSpec(
    _Toy,
    (
        Position(),
        "name",
        "ascii_label",
        "wired",
        "maybe",
        "flag",
        "first",
        "second",
        "lo",
        "hi",
        "level",
        Computed("n_chars", "Int64", lambda t: len(t.name), reads=("name",)),
    ),
)


def test_a_toy_spec_derives_columns_dtypes_and_order():
    assert list(frame_schema(TOY_SPEC).items()) == [
        ("i", pl.Int64),
        ("name", pl.String),
        ("ascii_label", pl.String),
        ("wired", pl.String),
        ("maybe", pl.String),
        ("flag", pl.Boolean),
        ("first", pl.Int64),
        ("second", pl.Int64),
        ("over", pl.Boolean),
        ("lo", pl.Int64),
        ("hi", pl.Int64),
        ("level", pl.Enum(["A", "B"])),
        ("n_chars", pl.Int64),
    ]
    assert unaccounted(TOY_SPEC) == []


def test_text_is_wired_by_default_and_raw_text_opts_out():
    rows = [_toy(name="a/\udcff", ascii_label="é", wired="\udcfe")]
    frame = to_frame(rows, TOY_SPEC)
    assert frame["name"][0] == wire("a/\udcff") != "a/\udcff"
    assert unwire(frame["name"][0]) == "a/\udcff"
    assert frame["wired"][0] == wire("\udcfe")
    assert frame["ascii_label"][0] == "é"


def test_an_overflow_flag_is_shared_by_its_fields_and_nulls_what_does_not_fit():
    frame = to_frame(
        [
            _toy(first=1, second=2),
            _toy(first=2**63, second=5),
            _toy(first=None, second=-(2**63) - 1),
            _toy(),
        ],
        TOY_SPEC,
    )
    assert frame["first"].to_list() == [1, None, None, None]
    assert frame["second"].to_list() == [2, 5, None, None]
    assert frame["over"].to_list() == [False, True, True, False]


def test_rank_columns_of_one_group_share_one_collection_relative_ranking():
    big = 2**200
    rows = [_toy(lo=30, hi=big), _toy(lo=10, hi=30), _toy(lo=None, hi=10)]
    frame = to_frame(rows, TOY_SPEC)
    assert frame["lo"].to_list() == [1, 0, None]
    assert frame["hi"].to_list() == [2, 1, 0]
    # a different collection ranks the same values differently
    assert to_frame(rows[:1], TOY_SPEC)["lo"].to_list() == [0]


def test_position_is_the_index_and_an_empty_collection_keeps_the_schema():
    frame = to_frame([_toy(), _toy(), _toy()], TOY_SPEC)
    assert frame["i"].to_list() == [0, 1, 2]
    empty = to_frame([], TOY_SPEC)
    assert empty.height == 0 and dict(empty.schema) == frame_schema(TOY_SPEC)


def test_optional_fields_derive_nullable_and_required_ones_do_not():
    info = {c.name: c for c in frame_columns(TOY_SPEC)}
    assert info["maybe"].nullable and info["first"].nullable
    assert not info["name"].nullable and not info["flag"].nullable


def test_a_ranked_entry_projects_a_field_under_the_sites_rank_policy():
    # _Toy.first/.second carry OverflowNullable, the flat-frame-shaped policy; a
    # Ranked entry overrides it for a frame that only ever compares order.
    spec = FrameSpec(_Toy, (Ranked("first", "g"), Ranked("second", "g")))
    info = {c.name: c for c in frame_columns(spec)}
    assert info["first"].rank_group == "g"
    assert info["first"].overflow_flag is None
    # no flag column is appended, and the dtype is a rank's Int64
    assert list(frame_schema(spec)) == ["first", "second"]
    frame = to_frame(
        [_toy(first=2**70, second=5), _toy(first=None, second=2**70)], spec
    )
    assert frame["first"].to_list() == [1, None]  # a null value is a null rank
    assert frame["second"].to_list() == [0, 1]


def test_the_side_spec_line_columns_carry_the_diff_sides_rank_policy():
    info = {c.name: c for c in frame_columns(SIDE_SPEC)}
    for name in ("line_start", "line_end"):
        assert info[name].rank_group == "lines"
        assert info[name].overflow_flag is None
        assert info[name].nullable is True


class _Unbounded(BaseModel):
    count: int = 0


@pytest.mark.parametrize(
    "build",
    [
        lambda: FrameSpec(_Unbounded, ("count",)),
        lambda: FrameSpec(_Toy, ("nope",)),
        lambda: FrameSpec(_Toy, ("skipped",)),
        lambda: FrameSpec(_Toy, ("name", "name")),
        lambda: FrameSpec(_Toy, ("name", Computed("name", "String", str))),
        lambda: FrameSpec(_Toy, ("name",), {"no_such_name": "stale waiver"}),
        lambda: FrameSpec(
            _Toy, ("name", Computed("c", "String", str, reads=("no_such_attr",)))
        ),
        lambda: FrameSpec(_Toy, ("first", Computed("over", "Boolean", bool))),
        lambda: FrameSpec(_Toy, (Ranked("name"),)),  # a str field has no rank
        lambda: FrameSpec(_Toy, (Ranked("nope"),)),  # not a model field
        lambda: FrameSpec(_Toy, (Ranked("skipped"),)),  # marked NotInFrame
        lambda: FrameSpec(_Toy, ("first", Ranked("first"))),  # declared twice
        lambda: FrameSpec(_Toy, (3,)),  # type: ignore[arg-type]
    ],
)
def test_a_spec_that_cannot_derive_a_frame_is_refused_when_declared(build):
    with pytest.raises(FrameSpecError):
        build()


def test_an_unbounded_int_with_no_marker_names_the_trap():
    with pytest.raises(FrameSpecError, match="unbounded int"):
        FrameSpec(_Unbounded, ("count",))


def test_conflicting_markers_are_refused():
    class Both(BaseModel):
        text: Annotated[str, RawText(), WireText()] = ""
        number: Annotated[int, OverflowNullable(), RankEncoded()] = 0
        words: Annotated[str, RankEncoded()] = ""

    for name in ("text", "number", "words"):
        with pytest.raises(FrameSpecError):
            FrameSpec(Both, (name,))
