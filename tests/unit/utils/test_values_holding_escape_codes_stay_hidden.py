# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value that itself holds escape codes stays hidden, glued or not.

The shown layers strip every complete CSI or OSC sequence from a tool's
text before matching, because a code in the TEXT can split a plain value's
contiguous match. But a value that itself holds such codes is a different
case: its as-written spelling is long and holds non-word characters, so it
is matched anywhere, while its stripped spelling is a short word, matched
only at word boundaries. Matching only the stripped text left a glued
occurrence of such a value in the clear. The text is therefore matched
twice: raw first (the as-written spelling in its own band), then stripped
(a text-split value re-joins and matches).

The corruption side of the same feature: a value made ONLY of codes strips
to the empty string, and the empty string's printed forms are the quoted
empty strings any message may hold, so an empty stripped spelling must add
no forms at all.
"""

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
)
from automated_security_helper.utils.error_text import (
    error_text,
    shown_tool_stderr,
    text_without_values,
    traceback_text,
)

pytestmark = pytest.mark.unit

SGR_ON = "\x1b[1m"
SGR_OFF = "\x1b[0m"
CSI_K = "\x1b[K"

#: id -> (value as written, its visible text that must not print).
#: Each visible text is a planted canary of 4-7 word characters, the
#: lengths matched only as whole words once the codes are stripped.
GLUED = {
    "six-char-word-in-sgr": (SGR_ON + "dovrek" + SGR_OFF, "dovrek"),
    "four-char-word-in-sgr": (SGR_ON + "zumq" + SGR_OFF, "zumq"),
    "seven-char-word-csi-k": ("beltrax" + CSI_K, "beltrax"),
}


def _glued_text(value):
    """The value printed glued to word characters on both sides."""
    return "token=zz" + value + "zz end"


@pytest.mark.parametrize("shape", sorted(GLUED))
def test_a_glued_code_holding_value_is_hidden_in_the_text(shape):
    """As written, the value is long and non-word, matched anywhere; only
    its stripped spelling is a short word. The raw pass must hide it even
    where word boundaries never line up."""
    value, visible = GLUED[shape]

    shown = text_without_values(_glued_text(value), [value])

    assert visible not in shown, repr(shown)


@pytest.mark.parametrize("shape", sorted(GLUED))
def test_a_glued_code_holding_value_is_hidden_in_an_errors_text(shape):
    value, visible = GLUED[shape]

    shown = error_text(RuntimeError(_glued_text(value)), [value])

    assert visible not in shown, repr(shown)


@pytest.mark.parametrize("shape", sorted(GLUED))
def test_a_space_bounded_code_holding_value_is_hidden(shape):
    """The control: at word boundaries the stripped spelling matches on its
    own, so this holds with or without the raw pass."""
    value, visible = GLUED[shape]

    shown = text_without_values("token " + value + " end", [value])

    assert visible not in shown, repr(shown)


@pytest.mark.parametrize("shape", sorted(GLUED))
def test_a_glued_code_holding_value_is_hidden_in_a_tools_stderr(shape):
    """The tool-stderr sink redacts the text as written and strips the
    result, so the raw pass sees the glued spelling."""
    value, visible = GLUED[shape]

    shown = shown_tool_stderr(_glued_text(value), [value])

    assert visible not in shown, repr(shown)
    assert "\x1b" not in shown, repr(shown)


@pytest.mark.parametrize("shape", sorted(GLUED))
def test_a_glued_code_holding_value_is_hidden_in_a_yarn_error_detail(shape):
    value, visible = GLUED[shape]

    detail = NpmAuditScanner._yarn_error_detail(
        "error " + _glued_text(value) + "\n", [value]
    )

    assert visible not in detail, repr(detail)
    assert "\x1b" not in detail, repr(detail)


def test_tool_stderr_without_the_value_is_still_stripped_and_readable():
    """The control: text that holds no carried value comes out without its
    codes, with and without values to hide."""
    text = SGR_ON + "plain failure" + SGR_OFF + " at step 3"

    assert shown_tool_stderr(text, []) == "plain failure at step 3"
    assert shown_tool_stderr(text, ["unrelated-secret"]) == "plain failure at step 3"
    detail = NpmAuditScanner._yarn_error_detail(
        "error " + text + "\n", ["unrelated-secret"]
    )
    assert detail == "error plain failure at step 3", repr(detail)


def test_a_value_split_by_a_code_in_the_tool_text_is_still_hidden():
    """The control for the stripped pass: the code sits in the TEXT, the
    value as given is plain."""
    value = "splitsecretvalue"
    text = "token=split" + CSI_K + "secretvalue end"

    assert "secretvalue" not in shown_tool_stderr(text, [value])
    assert "secretvalue" not in NpmAuditScanner._yarn_error_detail(
        "error " + text + "\n", [value]
    )


@pytest.mark.parametrize(
    "value", ["\x1b[0m", "\x1b]8;;\x1b\\"], ids=["sgr-reset", "osc-empty-link"]
)
def test_a_value_of_only_codes_costs_no_quoted_text(value):
    """A value made only of escape codes strips to "". The empty string's
    printed forms are the quoted empty strings ('' and "") any message may
    legitimately hold, so an empty stripped spelling must add no forms:
    ordinary text passes through unchanged."""
    text = "say '' and \"\" here, plain words stay"

    shown = text_without_values(text, [value])

    assert shown == text, repr(shown)


#: A value with a complete code between its two halves. Stripped it is the
#: six-character word "dovrek", matched only at word boundaries, so the
#: as-written spelling is what hides it where it is glued to other words.
SPLIT_HEAD = "dov"
SPLIT_TAIL = "rek"
SPLIT_VALUE = SPLIT_HEAD + CSI_K + SPLIT_TAIL


def _raised(error):
    try:
        raise error
    except BaseException as caught:
        return caught


def test_a_code_holding_value_is_hidden_in_a_traceback():
    """traceback_text redacts with the caller's values: the value, as written
    and as stripped, is not in the rendered traceback."""
    error = _raised(RuntimeError(_glued_text(SPLIT_VALUE)))

    shown = traceback_text(error, [SPLIT_VALUE])

    assert SPLIT_VALUE not in shown, repr(shown)
    assert SPLIT_HEAD + SPLIT_TAIL not in shown, repr(shown)


def test_a_code_free_line_beside_a_hidden_value_is_unchanged_in_a_traceback():
    """The control: the value's line is hidden and the line before it prints
    as written, and a traceback holding no value is the same with values."""
    error = _raised(RuntimeError("keep this line\n" + _glued_text(SPLIT_VALUE)))

    shown = traceback_text(error, [SPLIT_VALUE])

    assert "RuntimeError: keep this line\n" in shown, repr(shown)
    plain = _raised(RuntimeError("keep this line"))
    assert traceback_text(plain, [SPLIT_VALUE]) == traceback_text(plain, ())


def test_a_code_split_value_is_hidden_in_a_yarn_plain_line():
    """A plain yarn line holding HEAD, a complete code and TAIL of a
    configured value, glued to words: neither half prints."""
    detail = NpmAuditScanner._yarn_error_detail(
        "error " + _glued_text(SPLIT_VALUE) + "\n", [SPLIT_VALUE]
    )

    assert SPLIT_HEAD not in detail, repr(detail)
    assert SPLIT_TAIL not in detail, repr(detail)
    assert "\x1b" not in detail, repr(detail)


@pytest.mark.parametrize("values", [(), ["unrelated-secret"]], ids=["none", "other"])
def test_the_same_yarn_plain_line_with_no_matching_value_prints_whole(values):
    """The control: with no value configured, or one that matches nothing, the
    line prints with both halves together (the report layer drops the code)."""
    detail = NpmAuditScanner._yarn_error_detail(
        "error " + _glued_text(SPLIT_VALUE) + "\n", values
    )

    assert detail == "error token=zzdovrekzz end", repr(detail)


def test_the_stripped_spelling_alone_is_a_whole_word_form():
    """The mechanism this file rides on: a plain 4-7 character word value
    is matched only at word boundaries, so a glued occurrence is shown.
    That band is unchanged here; the raw pass matters because a
    code-holding value's AS-WRITTEN spelling earns a wider band."""
    shown = text_without_values("token=zzdovrekzz end", ["dovrek"])

    assert "dovrek" in shown, repr(shown)
