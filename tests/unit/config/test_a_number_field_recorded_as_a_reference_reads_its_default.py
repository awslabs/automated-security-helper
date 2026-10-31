# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A number field whose record holds a reference is read with its default and listed.

The record writes the reference a scan read from the environment in a number
field's place too (``record_of_config``), and a number field cannot hold the
text. ``without_unreadable_references`` admitted only a fixed-choice field's
refusal, so a record whose scan read a timeout from the environment was refused
as a whole and the results file could not be read. The number refusals are
admitted now, and the field is handled as ``severity_threshold`` is: read with
its default, listed as unreadable, supplied by the reader's own configuration.

Red at the base: ``kept`` was the data unchanged and ``found`` empty.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.config.recorded_config import (
    without_unreadable_references,
)

pytestmark = pytest.mark.unit


class _Numbers(BaseModel):
    timeout: int = 30
    ratio: float = 0.5
    level: str = "LOW"


class _Refusal:
    def __init__(self, items: list) -> None:
        self._items = items

    def errors(self) -> list:
        return self._items


def _refusal_of(data: dict) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        _Numbers.model_validate(data)
    return caught.value


def test_an_int_field_recorded_as_a_reference_is_taken_out_and_listed() -> None:
    data = {"timeout": "${ASH_X25_TIMEOUT}", "level": "HIGH"}

    kept, found = without_unreadable_references(data, _refusal_of(data))

    assert kept == {"level": "HIGH"}
    assert found == [("timeout", "${ASH_X25_TIMEOUT}")]
    # The record read with the data is the model's default for the field.
    assert _Numbers.model_validate(kept).timeout == 30
    # The input is left as it was.
    assert data["timeout"] == "${ASH_X25_TIMEOUT}"


def test_a_float_field_recorded_as_a_reference_is_taken_out_and_listed() -> None:
    data = {"ratio": "${ASH_X25_RATIO:0.25}"}

    kept, found = without_unreadable_references(data, _refusal_of(data))

    assert kept == {}
    assert found == [("ratio", "${ASH_X25_RATIO:0.25}")]


def test_a_number_and_a_choice_refused_together_are_both_listed() -> None:
    data = {"timeout": "${ASH_X25_TIMEOUT}", "policy": "${ASH_X25_POLICY}"}
    refusal = _Refusal(
        [
            {"type": "int_parsing", "loc": ("timeout",), "input": "${ASH_X25_TIMEOUT}"},
            {"type": "literal_error", "loc": ("policy",), "input": "${ASH_X25_POLICY}"},
        ]
    )

    kept, found = without_unreadable_references(data, refusal)

    assert kept == {}
    assert found == [
        ("timeout", "${ASH_X25_TIMEOUT}"),
        ("policy", "${ASH_X25_POLICY}"),
    ]


def test_a_number_field_refusing_plain_text_still_refuses_the_record() -> None:
    """The control: only a reference is taken out; other wrong text is the
    operator's error, and the whole record is refused as before."""
    data = {"timeout": "soon"}

    kept, found = without_unreadable_references(data, _refusal_of(data))

    assert kept is data
    assert found == []


def test_a_true_false_field_recorded_as_a_reference_still_refuses_the_record() -> None:
    """The control: a true/false field is not admitted; read as its default it
    would act on a value the scan never had."""
    data = {"fail_on_findings": "${ASH_X25_FAIL}"}
    refusal = _Refusal(
        [
            {
                "type": "bool_parsing",
                "loc": ("fail_on_findings",),
                "input": "${ASH_X25_FAIL}",
            }
        ]
    )

    kept, found = without_unreadable_references(data, refusal)

    assert kept is data
    assert found == []
