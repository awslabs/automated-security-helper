"""A SARIF suppression written with the standard ``status`` field is read, not refused.

SARIF 2.1.0 names the field that says whether a suppression has taken effect
``status`` (``accepted``, ``underReview`` or ``rejected``) and has no ``state``.
ASH's model was generated with ``state`` and forbids any other key, so a scanner
that wrote a spec-conforming suppression lost its whole report to an
``extra_forbidden`` error on ``suppressions.0.status``. The model now reads
``status`` as ``state``; ASH still writes ``state``, and every reader of it keeps
working.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    State,
    Suppression,
)
from automated_security_helper.utils.sarif_utils import (
    is_result_suppressed,
    suppressions_in_effect,
)

pytestmark = pytest.mark.unit

_CAPTURE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "gitleaks"
    / "gitleaks-8.30.1.sarif"
)


def _state_of(suppression: Suppression) -> str | None:
    return None if suppression.state is None else State(suppression.state).value


def test_a_standard_status_is_read_as_the_state():
    suppression = Suppression.model_validate({"kind": "inSource", "status": "accepted"})

    assert _state_of(suppression) == "accepted"


@pytest.mark.parametrize("status", ["accepted", "underReview", "rejected"])
def test_every_status_the_spec_defines_is_read(status):
    suppression = Suppression.model_validate({"kind": "external", "status": status})

    assert _state_of(suppression) == status


def test_a_dump_writes_the_state_and_never_the_status():
    suppression = Suppression.model_validate(
        {"kind": "inSource", "status": "underReview", "justification": "why"}
    )

    dumped = suppression.model_dump(mode="json", exclude_none=True)

    assert dumped == {
        "kind": "inSource",
        "state": "underReview",
        "justification": "why",
    }


def test_the_mapping_a_caller_passes_is_not_changed():
    given = {"kind": "inSource", "status": "accepted"}

    Suppression.model_validate(given)

    assert given == {"kind": "inSource", "status": "accepted"}


def test_both_keys_with_the_same_value_keep_the_one():
    suppression = Suppression.model_validate(
        {"kind": "inSource", "state": "accepted", "status": "accepted"}
    )

    assert _state_of(suppression) == "accepted"


@pytest.mark.parametrize(
    ("state", "status", "kept"),
    [
        ("accepted", "rejected", "rejected"),
        ("accepted", "underReview", "underReview"),
        ("rejected", "accepted", "rejected"),
        ("underReview", "accepted", "underReview"),
        ("underReview", "rejected", "underReview"),
        ("rejected", "underReview", "rejected"),
    ],
)
def test_both_keys_with_different_values_keep_the_one_that_is_not_accepted(
    state, status, kept
):
    """A suppression in doubt shows its finding instead of hiding it."""
    suppression = Suppression.model_validate(
        {"kind": "inSource", "state": state, "status": status}
    )

    assert _state_of(suppression) == kept
    assert suppressions_in_effect([suppression]) == []


def test_a_status_next_to_an_empty_state_is_read():
    suppression = Suppression.model_validate(
        {"kind": "inSource", "state": None, "status": "rejected"}
    )

    assert _state_of(suppression) == "rejected"


@pytest.mark.parametrize("state", ["accepted", "rejected", "underReview"])
def test_a_null_status_never_replaces_a_state(state):
    """``status: null`` says nothing, so the state it sits next to is kept and an
    ``exclude_none`` dump still writes it."""
    suppression = Suppression.model_validate(
        {"kind": "inSource", "state": state, "status": None}
    )

    assert _state_of(suppression) == state
    dumped = suppression.model_dump(mode="json", exclude_none=True)
    assert dumped == {"kind": "inSource", "state": state}


def test_any_other_key_is_still_refused():
    with pytest.raises(ValidationError) as refused:
        Suppression.model_validate(
            {"kind": "inSource", "status": "accepted", "reason": "x"}
        )

    assert [e["type"] for e in refused.value.errors(include_input=False)] == [
        "extra_forbidden"
    ]


def test_a_status_the_spec_does_not_define_is_still_refused():
    with pytest.raises(ValidationError):
        Suppression.model_validate({"kind": "inSource", "status": "approved"})


def test_the_kind_is_still_required():
    with pytest.raises(ValidationError):
        Suppression.model_validate({"status": "accepted"})


@pytest.mark.parametrize(
    ("status", "in_effect"),
    [("accepted", True), ("underReview", False), ("rejected", False)],
)
def test_a_result_is_suppressed_only_when_the_standard_status_is_accepted(
    status, in_effect
):
    doc = json.loads(_CAPTURE.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["suppressions"] = [
        {"kind": "inSource", "status": status}
    ]

    report = SarifReport.model_validate(doc)

    first, second = report.runs[0].results[:2]
    assert is_result_suppressed(first) is in_effect
    assert is_result_suppressed(second) is False
    assert len(report.runs[0].results) == len(doc["runs"][0]["results"])


@pytest.mark.parametrize(
    ("suppression", "in_effect"),
    [
        ({"kind": "inSource", "status": "accepted"}, True),
        ({"kind": "inSource", "status": "underReview"}, False),
        ({"kind": "inSource", "status": "rejected"}, False),
        ({"kind": "inSource", "state": "rejected"}, False),
        ({"kind": "inSource", "state": "accepted"}, True),
        ({"kind": "inSource"}, True),
        ({"kind": "inSource", "state": "accepted", "status": "rejected"}, False),
        ({"kind": "inSource", "state": "rejected", "status": "accepted"}, False),
        ({"kind": "inSource", "state": None, "status": "rejected"}, False),
        ({"kind": "inSource", "state": "rejected", "status": None}, False),
        ({"kind": "inSource", "state": "accepted", "status": None}, True),
        ({"kind": "inSource", "state": "underReview", "status": None}, False),
        ({"kind": "inSource", "state": "rejected", "status": "underReview"}, False),
        ({"kind": "inSource", "state": "underReview", "status": "rejected"}, False),
    ],
)
def test_a_mapping_with_only_a_status_is_read_by_the_one_reading_of_suppressions(
    suppression, in_effect
):
    assert bool(suppressions_in_effect([copy.deepcopy(suppression)])) is in_effect


def test_the_one_reading_of_suppressions_reads_a_status_off_an_object_too():
    """A result read back through a stand-in with a ``status`` attribute only."""

    class Standard:
        status = "underReview"

    class Plain:
        state = None
        status = None

    assert suppressions_in_effect([Standard()]) == []
    assert len(suppressions_in_effect([Plain()])) == 1
