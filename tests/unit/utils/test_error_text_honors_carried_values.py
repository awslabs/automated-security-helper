# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every error printer redacts the values an error carries, with no values passed.

``carry_environment_values`` records on an error the values the failing run
read from the environment, for a failure handler that holds no configuration
to redact the error's text with. A printer written later, or one that never
heard of the carrier (the MCP workspace tool's error response), passes no
values, so ``error_text``, ``traceback_text`` and ``log_unexpected_error``
read the carried values themselves and redact with them as well as with any
values the caller passes. An error in the chain counts: a wrapper raised from
the carrier, whose message quotes it, is redacted with the carrier's values.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.utils.error_text import (
    carry_environment_values,
    error_text,
    log_unexpected_error,
    traceback_text,
)

pytestmark = pytest.mark.unit

#: A value the run read from the environment, long enough to be redacted
#: anywhere in a text.
CARRIED = "zzcarried-secret-4471"
#: A value the caller passes, to show the two are merged rather than replaced.
PASSED = "zzpassed-secret-8812"


def _carrier() -> ValueError:
    """An error whose message quotes the carried value, as a plugin's crash
    text can, with that value recorded on it."""
    try:
        raise ValueError(f"cannot use {CARRIED}")
    except ValueError as error:
        carry_environment_values(error, [CARRIED])
        return error


def _wrapper() -> RuntimeError:
    """An error raised from the carrier, quoting it, that carries nothing itself."""
    inner = _carrier()
    try:
        raise RuntimeError(f"wrapped: {inner}") from inner
    except RuntimeError as error:
        return error


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.records: list = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def sink():
    logger = logging.getLogger("ash.test.carried")
    handler = _Sink()
    logger.addHandler(handler)
    logger.setLevel(1)
    logger.propagate = False
    yield logger, handler.records
    logger.removeHandler(handler)


def _logged_text(records: list) -> str:
    """Every record's message and its formatted traceback, as a handler writes
    them."""
    formatter = logging.Formatter("%(message)s")
    return "\n".join(formatter.format(record) for record in records)


def test_error_text_redacts_a_carried_value_with_no_values_passed():
    text = error_text(_carrier())

    assert CARRIED not in text, text
    assert "cannot use <value>" in text, text


def test_traceback_text_redacts_a_carried_value_with_no_values_passed():
    text = traceback_text(_carrier())

    assert CARRIED not in text, text
    assert "ValueError: cannot use <value>" in text, text


def test_traceback_text_of_the_error_being_handled_redacts_its_carried_value():
    """With no error given, the one being handled is formatted, and its
    carried values are read from it."""
    try:
        raise _carrier()
    except ValueError:
        text = traceback_text()

    assert CARRIED not in text, text


def test_log_unexpected_error_redacts_a_carried_value_with_no_values_passed(sink):
    logger, records = sink

    log_unexpected_error(logger, _carrier())

    logged = _logged_text(records)
    assert records, "nothing was logged"
    assert CARRIED not in logged, logged
    assert "cannot use <value>" in logged, logged


def test_a_wrapper_raised_from_a_carrier_is_redacted_with_its_values(sink):
    logger, records = sink
    error = _wrapper()

    log_unexpected_error(logger, error)

    for shown in (error_text(error), traceback_text(error), _logged_text(records)):
        assert CARRIED not in shown, shown


class _LooksUpEverything(Exception):
    """An error whose attribute lookup raises for any name it does not hold, as
    a proxying error class can: reading the carrier off it must not turn the
    printing of an error into a new one."""

    def __getattr__(self, name):
        raise RuntimeError(f"no attribute {name}")


def test_an_error_whose_lookup_raises_is_still_printed(sink):
    logger, records = sink
    error = _LooksUpEverything("the error's own text")

    assert error_text(error) == "the error's own text"
    assert "the error's own text" in traceback_text(error)
    log_unexpected_error(logger, error)
    assert "the error's own text" in _logged_text(records)


class _RefusesEveryAttribute(Exception):
    """An error whose attribute assignment raises something other than
    AttributeError."""

    def __setattr__(self, name, value):
        raise RuntimeError(f"cannot set {name}")


def test_carrying_onto_an_error_that_takes_no_attributes_leaves_it_as_it_is():
    """The carrier is set inside a handler that re-raises the error: raising
    from the carrier would replace the error being reported with its own."""
    error = _RefusesEveryAttribute("the error's own text")

    carry_environment_values(error, [CARRIED])

    assert error_text(error) == "the error's own text"


def test_the_callers_values_and_the_carried_ones_are_both_redacted():
    error = _carrier()
    error.args = (f"cannot use {CARRIED} or {PASSED}",)

    texts = (error_text(error, [PASSED]), traceback_text(error, [PASSED]))

    for text in texts:
        assert CARRIED not in text, text
        assert PASSED not in text, text


def test_a_bare_string_of_values_is_one_value_at_every_entry():
    """A bare string passed as ``values`` is one redaction value, never its
    characters, at every function that takes a caller's values.

    A str is an iterable of strings too, one per character; ``list()``,
    ``tuple()``, unpacking and ``dict.fromkeys`` of a value given on its own
    all give its characters, each shorter than any band redact_values
    replaces, so the value would print whole with nothing showing that
    redaction had stopped. ``environment_strings`` is the one normalizer every
    entry reads a caller's values through, so each entry is asserted on its
    output here.
    """
    from automated_security_helper.utils.error_text import text_without_values
    from automated_security_helper.utils.redacted_model import environment_strings

    # The normalizer's own contract.
    assert environment_strings(PASSED) == (PASSED,)

    # The error printers, with the bare string as the caller's values.
    try:
        raise ValueError(f"cannot use {PASSED}")
    except ValueError as plain_error:
        for text in (
            error_text(plain_error, PASSED),
            traceback_text(plain_error, PASSED),
        ):
            assert PASSED not in text, text
            assert "<value>" in text, text

    # A bare string recorded on an error is one carried value.
    try:
        raise ValueError(f"cannot use {CARRIED}")
    except ValueError as carrying_error:
        carry_environment_values(carrying_error, CARRIED)
        text = error_text(carrying_error)
        assert CARRIED not in text, text
        assert "cannot use <value>" in text, text

    # The plain-text sink.
    redacted = text_without_values(f"a tool printed {PASSED}", PASSED)
    assert PASSED not in redacted, redacted
    assert "<value>" in redacted, redacted
