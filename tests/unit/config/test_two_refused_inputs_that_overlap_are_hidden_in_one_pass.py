# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two refused inputs that overlap in a message are hidden together, whichever
error each belongs to.

``redact_refused_input`` matches the input of an error pydantic wrote as it is
written and the input of an error a validator wrote ignoring case. It did so in
two ``redact_values`` passes, the exact inputs first, so an input of each set
that overlapped the other in the message left part of a value behind: the
first pass took "foo/bar" out of "foo/bar/baz-long", and the second no longer
found "bar/baz-long" whole. ``redact_values`` closes exactly that shape within
ONE pass (every match is found in the original text and overlapping matches
merge), so the validator-written inputs now ride that one pass as
case-insensitive needles (``CaseInsensitiveNeedle``).

Red at the base: "/baz-long" stayed readable.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import (
    REDACTED,
    make_case_insensitive_needle,
    redact_refused_input,
    redact_values,
)

pytestmark = pytest.mark.unit


def _exact(value: str) -> dict:
    """An error pydantic wrote: its input is matched as written."""
    return {"type": "string_type", "loc": ("x",), "msg": "m", "input": value}


def _written(value: str) -> dict:
    """An error a validator wrote: its input is matched ignoring case."""
    return {"type": "value_error", "loc": ("x",), "msg": "m", "input": value}


def test_an_exact_and_a_written_input_that_overlap_are_hidden_together() -> None:
    text, changed = redact_refused_input(
        "the value foo/bar/baz-long was refused",
        [_exact("foo/bar"), _written("bar/baz-long")],
    )

    assert text == f"the value {REDACTED} was refused"
    assert changed is False


def test_the_other_order_of_the_two_errors_reads_the_same() -> None:
    text, _ = redact_refused_input(
        "the value foo/bar/baz-long was refused",
        [_written("bar/baz-long"), _exact("foo/bar")],
    )

    assert text == f"the value {REDACTED} was refused"


def test_a_written_input_is_still_matched_in_any_case() -> None:
    """The control: the validator-written input keeps its ignore-case match."""
    text, _ = redact_refused_input(
        "SECRET-TEXT-VALUE was refused", [_written("secret-text-value")]
    )

    assert text == f"{REDACTED} was refused"


def test_an_exact_input_is_still_matched_as_written() -> None:
    """The control: a pydantic error's input keeps its as-written match, so a
    message that lists the values a field accepts keeps them readable."""
    text, _ = redact_refused_input(
        "Input should be 'LOWISH' or 'HIGH', got lowish",
        [_exact("lowish")],
    )

    assert text == f"Input should be 'LOWISH' or 'HIGH', got {REDACTED}"


def test_a_case_insensitive_needle_widens_one_value_of_a_whole_words_pass() -> None:
    text = redact_values(
        "Foo/Bar beside foo/bar and Zzzz/Qq beside zzzz/qq",
        [make_case_insensitive_needle("foo/bar"), "zzzz/qq"],
        whole_words=True,
    )

    assert text == f"{REDACTED} beside {REDACTED} and Zzzz/Qq beside {REDACTED}"


def test_a_plain_value_of_a_whole_words_pass_keeps_its_case() -> None:
    """The control: without the needle the same value is matched as written."""
    text = redact_values("Foo/Bar beside foo/bar", ["foo/bar"], whole_words=True)

    assert text == f"Foo/Bar beside {REDACTED}"


def test_the_needle_is_the_plain_value_to_every_other_reader() -> None:
    needle = make_case_insensitive_needle("foo/bar")

    assert needle == "foo/bar"
    assert str(needle) == "foo/bar"
    assert needle.ignore_case is True
