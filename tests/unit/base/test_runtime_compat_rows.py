# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The runtime-compatibility facet family: rows, range filters, resolution kinds.

A row says "this range of a tool's versions needs that range of its language
runtime's versions". The tests are the must-NOT half first (a row that carries
no evidence, or contradicts its own resolution kind, is refused at
construction, each refusal built from a valid control with one field mutated so
a passing refusal is the validator firing and not a malformed fixture), then the
range interface and the derivation the installers read.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.utils import runtime_compat_ranges as ranges

pytestmark = pytest.mark.unit

ISSUE = "https://github.com/example/tool/issues/1"


def _pin(**changes) -> opsf.RuntimeCompatRow:
    base = {
        "runtime": opsf.RuntimeName.PYTHON,
        "tool_versions": "",
        "runtime_request": ">=3.10,<3.15",
        "resolution": opsf.CompatResolution.PIN,
        "reason": "the tool breaks on 3.15; measured",
    }
    return opsf.RuntimeCompatRow(**{**base, **changes})


def _polyfill(**changes) -> opsf.RuntimeCompatRow:
    base = {
        "runtime": opsf.RuntimeName.PYTHON,
        "tool_versions": "",
        "runtime_request": ">=3.15",
        "resolution": opsf.CompatResolution.POLYFILL,
        "reason": "the tool breaks on 3.15; measured",
        "polyfill": "checkov_json_array_hook",
        "pin_insufficient": "no interpreter below 3.15 is installable on the host",
    }
    return opsf.RuntimeCompatRow(**{**base, **changes})


# ---- valid controls -------------------------------------------------------


def _open(**changes) -> opsf.RuntimeCompatRow:
    """A valid open-ended control: issue URL and the recorded constraint."""
    base = {
        "open_ended": True,
        "upstream_issue": ISSUE,
        "recorded_default_constraint": ">=3.2.0,<4.0.0",
    }
    return _pin(**{**base, **changes})


def test_the_controls_construct() -> None:
    assert _pin().resolution is opsf.CompatResolution.PIN
    assert _polyfill().resolution is opsf.CompatResolution.POLYFILL
    assert _open().open_ended


def test_an_empty_rows_tuple_constructs_without_a_reason() -> None:
    """No known incompatibility is the honest common state, not an unread one."""
    assert opsf.RuntimeCompatFacet(rows=()).rows == ()


# ---- the open-ended rule --------------------------------------------------


def test_an_open_ended_row_requires_an_upstream_issue_url() -> None:
    with pytest.raises(ValidationError, match="upstream_issue"):
        _pin(open_ended=True)
    with pytest.raises(ValidationError, match="upstream_issue"):
        _pin(open_ended=True, upstream_issue="   ")


def test_an_open_ended_row_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="reason"):
        _pin(open_ended=True, upstream_issue=ISSUE, reason=" ")


def test_an_upstream_issue_must_be_a_url() -> None:
    with pytest.raises(ValidationError, match="URL"):
        _pin(open_ended=True, upstream_issue="checkov#7777")
    with pytest.raises(ValidationError, match="URL"):
        _pin(upstream_issue="not a url")


def test_a_closed_row_needs_no_upstream_issue() -> None:
    assert _pin(open_ended=False).upstream_issue is None


def test_an_open_ended_row_without_an_issue_carries_a_recheck_note() -> None:
    """The URL-less escape: a genuinely unresolved gap with no upstream issue
    to cite (guarddog's yara-python wheel gap) is still declared open-ended,
    with the note saying what was searched and found absent."""
    row = _open(
        upstream_issue=None,
        recheck_note="searched the yara-python issues for a cp314 report; none "
        "exists to cite (a 'wheel' search returned issues, so the search works)",
    )
    assert row.open_ended and row.upstream_issue is None


def test_a_blank_recheck_note_does_not_satisfy_the_open_ended_rule() -> None:
    with pytest.raises(ValidationError, match="upstream_issue"):
        _open(upstream_issue=None, recheck_note="   ")


def test_a_recheck_note_on_a_closed_row_is_refused() -> None:
    with pytest.raises(ValidationError, match="recheck_note"):
        _pin(recheck_note="a note with nothing to re-check")


# ---- the open-ended re-check record -----------------------------------------


def test_an_open_ended_row_records_the_default_tool_constraint() -> None:
    """The record the re-check gate compares against; without it the gate
    cannot fire for a blank tool range or a range default constraint."""
    with pytest.raises(ValidationError, match="recorded_default_constraint"):
        _pin(open_ended=True, upstream_issue=ISSUE)


def test_a_closed_row_carries_no_recorded_constraint() -> None:
    with pytest.raises(ValidationError, match="recorded_default_constraint"):
        _pin(recorded_default_constraint=">=3.2.0,<4.0.0")


def test_a_recorded_constraint_must_parse_in_the_rows_grammar() -> None:
    with pytest.raises(ValidationError, match="PEP 440"):
        _open(recorded_default_constraint="^3.2")


def test_the_recheck_fires_when_the_default_constraint_moves() -> None:
    """The reachable red case the gate ships for: a BLANK tool range and a
    RANGE default constraint -- checkov's exact shape -- where ``applies_to``
    alone can never go red (a blank range applies everywhere, and a range
    constraint keeps the row the safe side). A default-constraint bump is
    precisely "the tool bumped -- re-read the row"."""
    row = _open()
    assert row.tool_versions == ""
    assert not row.recheck_fires(">=3.2.0,<4.0.0")
    assert row.recheck_fires(">=3.16.0"), "the bump the gate exists to catch"
    assert row.applies_to(">=3.16.0"), "applies_to alone cannot red here"
    assert row.recheck_fires(None), "a dropped default is a move too"


def test_the_recheck_never_fires_for_a_closed_row() -> None:
    assert not _pin().recheck_fires(">=9.0.0")


def test_an_empty_record_means_no_default_constraint_existed() -> None:
    row = _open(recorded_default_constraint="")
    assert not row.recheck_fires(None)
    assert row.recheck_fires("==1.2.3")


# ---- the resolution kinds, prefer PIN -------------------------------------


def test_a_pin_row_refuses_polyfill_evidence() -> None:
    with pytest.raises(ValidationError, match="PIN row"):
        _pin(polyfill="checkov_json_array_hook")
    with pytest.raises(ValidationError, match="PIN row"):
        _pin(pin_insufficient="because")


def test_a_polyfill_row_names_its_shim() -> None:
    with pytest.raises(ValidationError, match="shim directory"):
        _polyfill(polyfill=None)
    with pytest.raises(ValidationError, match="directory name"):
        _polyfill(polyfill="../escape")


def test_a_polyfill_row_states_why_pinning_cannot_serve() -> None:
    with pytest.raises(ValidationError, match="prefer a PIN"):
        _polyfill(pin_insufficient=None)
    with pytest.raises(ValidationError, match="prefer a PIN"):
        _polyfill(pin_insufficient="  ")


# ---- the range filter -----------------------------------------------------


def test_a_python_range_must_parse_as_pep440() -> None:
    with pytest.raises(ValidationError, match="PEP 440"):
        _pin(runtime_request="3.10..3.14")
    with pytest.raises(ValidationError, match="PEP 440"):
        _pin(tool_versions="^3.2.0")


def test_a_blank_runtime_request_is_refused() -> None:
    with pytest.raises(ValidationError, match="runtime_request"):
        _pin(runtime_request="")


def test_a_whitespace_runtime_request_is_refused() -> None:
    """The stored uv install command is one string split on whitespace."""
    with pytest.raises(ValidationError, match="whitespace"):
        _pin(runtime_request=">=3.10, <3.15")


def test_a_node_row_is_refused_until_its_grammar_lands() -> None:
    with pytest.raises(ValidationError, match="node"):
        _pin(runtime=opsf.RuntimeName.NODE, runtime_request=">=20.0.0")


def test_every_runtime_names_a_grammar() -> None:
    assert {r.value for r in opsf.RuntimeName} == set(ranges.RANGE_GRAMMARS)


def test_a_range_is_read_the_same_whatever_the_grammar() -> None:
    predicate = ranges.parse_range("python", ">=3.10,<3.15")
    assert predicate.contains("3.12.15")
    assert predicate.contains("3.14.6")
    assert not predicate.contains("3.15.0")
    assert not predicate.contains("3.15.0rc1")
    assert not predicate.contains("3.9.18")


def test_the_empty_range_is_the_universal_range() -> None:
    assert ranges.parse_range("python", "").contains("0.0.1")


def test_a_version_that_is_not_pep440_is_refused() -> None:
    with pytest.raises(ranges.RangeError):
        ranges.parse_range("python", ">=3.10").contains("three")


def test_an_unknown_runtime_is_refused_by_name() -> None:
    with pytest.raises(ranges.RangeError, match="rust"):
        ranges.parse_range("rust", ">=1.70")


def test_two_pin_rows_combine_as_one_specifier_set() -> None:
    combined = ranges.parse_range("python", ">=3.10,<3.15").combined(
        ranges.parse_range("python", ">=3.11,<3.14")
    )
    assert combined.as_request() == ">=3.10,<3.15,>=3.11,<3.14"
    assert combined.contains("3.12")
    assert not combined.contains("3.10.5")
    assert not combined.contains("3.14")


def test_a_request_keeps_the_clause_order_it_was_written_in() -> None:
    """``str(SpecifierSet)`` sorts; the argv a scanner passes must not move."""
    assert ranges.parse_range("python", ">=3.10,<3.14").as_request() == ">=3.10,<3.14"


def test_a_repeated_clause_is_not_repeated_in_the_request() -> None:
    one = ranges.parse_range("python", ">=3.10,<3.15")
    assert one.combined(one).as_request() == ">=3.10,<3.15"


@pytest.mark.parametrize(
    ("constraint", "version"),
    [
        ("==3.4.11", "3.4.11"),
        ("===3.4.11", "3.4.11"),
        ("3.4.11", "3.4.11"),
        (" ==3.4.11 ", "3.4.11"),
        (">=3.2.0,<4.0.0", None),
        ("==3.4.*", None),
        (">=3.4.11", None),
        ("", None),
        (None, None),
    ],
)
def test_exact_version_reads_only_a_single_named_version(constraint, version) -> None:
    assert ranges.exact_version(constraint) == version


# ---- applicability --------------------------------------------------------


def test_the_universal_row_applies_at_any_constraint() -> None:
    row = _pin(tool_versions="")
    assert row.applies_to(None)
    assert row.applies_to("==9.9.9")
    assert row.applies_to(">=3.2.0,<4.0.0")


def test_an_exact_tool_pin_outside_the_row_range_drops_the_row() -> None:
    row = _pin(tool_versions="<3.5")
    assert row.applies_to("==3.4.11")
    assert not row.applies_to("==3.6.0")


def test_a_range_constraint_keeps_the_row_the_safe_side() -> None:
    """No range intersection is attempted: a constraint that is a range keeps
    the row, an unnecessary interpreter bound rather than a missing one."""
    row = _pin(tool_versions="<3.5")
    assert row.applies_to(">=3.6,<4")
    assert row.applies_to(None)


# ---- the facet and its derivation -----------------------------------------


def test_a_duplicate_row_is_refused() -> None:
    with pytest.raises(ValidationError, match="once"):
        opsf.RuntimeCompatFacet(rows=(_pin(), _pin()))


def test_the_pin_request_is_the_applicable_pin_rows_combined() -> None:
    facet = opsf.RuntimeCompatFacet(
        rows=(
            _pin(runtime_request=">=3.10,<3.15"),
            _pin(tool_versions="<3.5", runtime_request="<3.14", reason="second"),
            _polyfill(),
        )
    )
    python = opsf.RuntimeName.PYTHON
    assert facet.pin_request(python, None) == ">=3.10,<3.15,<3.14"
    assert facet.pin_request(python, "==3.6.0") == ">=3.10,<3.15"


def test_no_applicable_pin_row_derives_no_request() -> None:
    python = opsf.RuntimeName.PYTHON
    assert opsf.RuntimeCompatFacet(rows=()).pin_request(python, None) is None
    only_polyfill = opsf.RuntimeCompatFacet(rows=(_polyfill(),))
    assert only_polyfill.pin_request(python, None) is None
    gone = opsf.RuntimeCompatFacet(rows=(_pin(tool_versions="<3.5"),))
    assert gone.pin_request(python, "==3.6.0") is None


def test_the_polyfills_are_the_applicable_polyfill_rows() -> None:
    facet = opsf.RuntimeCompatFacet(rows=(_pin(), _polyfill(tool_versions="<3.5")))
    assert [r.polyfill for r in facet.polyfills("==3.4.0")] == [
        "checkov_json_array_hook"
    ]
    assert facet.polyfills("==3.6.0") == ()


def test_a_class_with_no_register_row_declares_no_compat() -> None:
    class ThirdParty:
        pass

    assert opsf.declared_runtime_compat(ThirdParty) is None


def test_a_subclass_answers_with_the_nearest_declaring_base() -> None:
    facet = opsf.RuntimeCompatFacet(rows=(_pin(),))

    class Base:
        pass

    Base.operational_facets = _facets_with(facet)  # type: ignore[attr-defined]

    class Child(Base):
        pass

    assert opsf.declared_runtime_compat(Child) is facet
    # the register's own reader stays strict: an inherited row never answers
    assert opsf.declared_operational_facets(Child) is None


def _facets_with(compat: opsf.RuntimeCompatFacet) -> opsf.ScannerOperationalFacets:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScanner,
    )

    # Any real declaration is a valid control for the other dimensions.
    control = ZizmorScanner.operational_facets
    return control.model_copy(update={"runtime_compat": compat})
