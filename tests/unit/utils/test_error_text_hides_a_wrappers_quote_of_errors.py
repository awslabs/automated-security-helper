# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An error raised from a ValidationError shows no refused input, however its
message quotes the ValidationError.

``error_text`` and ``traceback_text`` replace the ValidationError's own text
where a wrapper's message quotes it (``f"... {e}"``). A wrapper that quotes
``e.errors()`` or ``e.json()`` instead carries each refused input as pydantic
lists it (``'input': '...'``), and a validator's message in it (``'msg'``,
``ctx``) as the validator wrote it. Those are redacted as a model error's
message is: each input, in each form a message prints it, and a validator's
message with a changed form of its input is not shown.
"""

from __future__ import annotations

import logging
import re
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError, ValidationInfo, field_validator

from automated_security_helper.utils.error_text import (
    error_text,
    log_unexpected_error,
    traceback_text,
)

CANARY = "ash-canary-7f3e-0123456789"


class _Checked(BaseModel):
    name: str
    count: int = 0

    @field_validator("name")
    @classmethod
    def _refuse(cls, value: str, info: ValidationInfo) -> str:
        change = (info.context or {}).get("change", lambda v: v)
        raise ValueError(f"not a known name: {change(value)}")


#: How a wrapper's message might quote the ValidationError it was raised from.
QUOTES = {
    "errors": lambda e: f"config refused: {e.errors()}",
    "errors-without-url": lambda e: f"config refused: {e.errors(include_url=False)}",
    "json": lambda e: f"config refused: {e.json()}",
}

#: How the validator might write its input back.
CHANGES = {"as-given": lambda v: v, "upper": str.upper}


def _squeezed(text: str) -> str:
    return re.sub(r"[\W_]", "", text).casefold()


def _shows_the_value(text: str) -> bool:
    return _squeezed(CANARY) in _squeezed(text)


def _wrapper(quote, change, data=None) -> RuntimeError:
    try:
        try:
            _Checked.model_validate(
                data or {"name": CANARY}, context={"change": change}
            )
        except ValidationError as refused:
            raise RuntimeError(quote(refused)) from refused
    except RuntimeError as wrapper:
        return wrapper
    raise AssertionError("the model accepted the input")


@pytest.mark.parametrize("change", sorted(CHANGES))
@pytest.mark.parametrize("quote", sorted(QUOTES))
def test_error_text_shows_no_input(quote, change):
    text = error_text(_wrapper(QUOTES[quote], CHANGES[change]))
    # The control: this is the wrapper's text, which names the field.
    assert "config refused" in text or "RuntimeError" in text, "not the wrapper's text"
    assert "name" in text
    assert not _shows_the_value(text), f"{quote}/{change}: the input is shown"


@pytest.mark.parametrize("change", sorted(CHANGES))
@pytest.mark.parametrize("quote", sorted(QUOTES))
def test_traceback_text_shows_no_input(quote, change):
    text = traceback_text(_wrapper(QUOTES[quote], CHANGES[change]))
    assert "RuntimeError" in text, "not the wrapper's traceback"
    assert not _shows_the_value(text), f"{quote}/{change}: the input is shown"


@pytest.mark.parametrize("quote", sorted(QUOTES))
def test_a_logged_wrapper_shows_no_input(quote):
    logger = MagicMock(spec=logging.Logger)
    log_unexpected_error(
        logger, _wrapper(QUOTES[quote], str.upper), context="Error in x"
    )
    logged = " ".join(str(call) for call in logger.mock_calls)
    assert "Error in x" in logged, "nothing was logged"
    assert not _shows_the_value(logged), f"{quote}: the input is logged"


def test_the_wrapper_s_own_words_stay_where_the_input_is_replaced_in_place():
    text = error_text(_wrapper(QUOTES["errors"], str.upper))
    assert "config refused" in text, "the wrapper's words are gone"


def test_an_input_pydantic_refused_is_hidden_too():
    """A wrapper's quote of an error pydantic wrote: its input is listed even
    though its message does not quote it."""
    text = error_text(
        _wrapper(QUOTES["errors"], lambda v: v, {"name": "ok", "count": CANARY})
    )
    assert "count" in text
    assert not _shows_the_value(text), "the refused input is shown"


#: The quotes above, plus the wrapper quoting the error's own text (``f"...{e}"``).
QUOTES_WITH_STR = {**QUOTES, "str": lambda e: f"config refused: {e}"}


def _wrapper_from_another_error(quote) -> RuntimeError:
    """A wrapper raised from an error of its own while the ValidationError is
    handled: the ValidationError is only the error raised during
    (``__context__``), because ``raise ... from`` fills the raised-from link
    (``__cause__``) with the other error."""
    try:
        try:
            _Checked.model_validate({"name": CANARY})
        except ValidationError as refused:
            raise RuntimeError(quote(refused)) from KeyError("names")
    except RuntimeError as wrapper:
        return wrapper
    raise AssertionError("the model accepted the input")


@pytest.mark.parametrize("quote", sorted(QUOTES_WITH_STR))
def test_a_wrapper_raised_from_another_error_shows_no_input(quote):
    text = error_text(_wrapper_from_another_error(QUOTES_WITH_STR[quote]))
    assert "config refused" in text, "not the wrapper's text"
    assert not _shows_the_value(text), f"{quote}: the input is shown"


@pytest.mark.parametrize("quote", sorted(QUOTES_WITH_STR))
def test_a_wrapper_raised_from_another_error_tracebacks_no_input(quote):
    text = traceback_text(_wrapper_from_another_error(QUOTES_WITH_STR[quote]))
    assert "RuntimeError" in text, "not the wrapper's traceback"
    assert not _shows_the_value(text), f"{quote}: the input is shown"


def test_a_wrapper_raised_from_another_error_is_logged_without_the_input():
    logger = MagicMock(spec=logging.Logger)
    log_unexpected_error(
        logger,
        _wrapper_from_another_error(QUOTES_WITH_STR["str"]),
        context="Error in x",
    )
    logged = " ".join(str(call) for call in logger.mock_calls)
    assert "Error in x" in logged, "nothing was logged"
    assert not _shows_the_value(logged), "the input is logged"


def test_the_neutral_stderr_layer_strips_color_codes_before_matching():
    """``shown_tool_stderr`` removes SGR codes FIRST: a color code inside a
    value splits the contiguous text the redaction matches, so a layer that
    kept SGR would print both halves of the value in clear around the code."""
    from automated_security_helper.utils.error_text import shown_tool_stderr

    value = "SEKRET-7731"
    text = "tool wrote SEKR\x1b[31mET-7731\x1b[0m here"

    shown = shown_tool_stderr(text, [value])

    assert "\x1b[" not in shown, shown
    assert value not in shown, shown
    assert "ET-7731" not in shown, shown
    assert "here" in shown, shown
