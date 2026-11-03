# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``_html_as_text`` reads a run of backslashes once.

The pattern that finds a "&" or "<" with the backslashes before it started a
match at every backslash of a run. When no "&" or "<" followed the run, each
start scanned to the end of the run and failed, so a run of n backslashes took
time quadratic in n. The model's answer is text the reporter does not control,
so a long run is possible. A lookbehind starts a match at the first backslash of
a run only; the matches are the same.
"""

import re
import time

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins import (
    bedrock_summary_reporter as reporter_module,
)

pytestmark = pytest.mark.unit

#: The pattern as it was before the lookbehind, kept here to show that the
#: change moves no match.
_PREVIOUS = re.compile(r"(\\*)([&<])")


def _previous_html_as_text(text):
    def entity(match):
        backslashes, character = match.group(1), match.group(2)
        if len(backslashes) % 2 == 1:
            return match.group(0)
        return backslashes + ("&amp;" if character == "&" else "&lt;")

    return _PREVIOUS.sub(entity, text)


CASES = [
    "",
    "plain text",
    "a & b",
    "a < b",
    "\\&",
    "\\<",
    "\\\\&",
    "\\\\<",
    "\\\\\\&",
    "\\\\\\<",
    "\\\\\\\\&",
    "x\\\\\\y&z",
    "\\\\\\\\\\\\ and then <",
    "&&<<",
    "\\&\\<&<",
    "a\\\\<b\\&c\\\\\\<d",
    "\\",
    "\\\\\\",
    "trailing backslashes \\\\\\",
]


@pytest.mark.parametrize("text", CASES)
def test_the_lookbehind_form_gives_the_same_text(text):
    """The control: every case reads as it did before the change."""
    assert reporter_module._html_as_text(text) == _previous_html_as_text(text)


def test_an_odd_run_before_the_character_leaves_it_as_written():
    assert reporter_module._html_as_text("\\<") == "\\<"
    assert reporter_module._html_as_text("\\\\<") == "\\\\&lt;"
    assert reporter_module._html_as_text("a & b") == "a &amp; b"


def test_a_long_run_with_no_character_after_it_is_read_once():
    """RED at the base, by time: 100,000 backslashes took quadratic time (tens
    of seconds); the bound is far above the linear reading and far below that."""
    text = "\\" * 100_000 + "x"

    started = time.monotonic()
    result = reporter_module._html_as_text(text)
    elapsed = time.monotonic() - started

    assert result == text
    assert elapsed < 5.0


def test_a_long_run_before_the_character_is_still_escaped_by_parity():
    even = "\\" * 100_000 + "<"
    odd = "\\" * 100_001 + "<"

    assert reporter_module._html_as_text(even) == "\\" * 100_000 + "&lt;"
    assert reporter_module._html_as_text(odd) == odd
