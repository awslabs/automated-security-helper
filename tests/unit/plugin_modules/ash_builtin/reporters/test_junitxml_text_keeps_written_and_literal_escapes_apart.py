# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JUnit report's text writes a forbidden character as an escape, unambiguously.

XML 1.0 forbids some characters, so the report writes each one as ``\\xNN`` or
``\\uNNNN``. A message that held those four or six characters as plain text read
the same as a message that held the forbidden character, because a backslash was
never doubled. The other reports double a backslash run before text that reads as
an escape they write; this one does the same, and only for the escapes it writes
(a Windows path's ``\\x64`` is no escape of it).
"""

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
    _xml_text,
)

pytestmark = pytest.mark.unit

BACKSLASH = "\\"


def test_a_forbidden_character_is_written_as_its_escape():
    assert _xml_text("a\x01b") == "a" + BACKSLASH + "x01" + "b"
    assert _xml_text(chr(0xFFFE)) == BACKSLASH + "ufffe"
    assert _xml_text(chr(0xD800)) == BACKSLASH + "ud800"


def test_the_text_of_an_escape_is_told_apart_from_the_character():
    """RED at the base: both read ``\\x01``."""
    written = _xml_text("\x01")
    literal = _xml_text(BACKSLASH + "x01")

    assert written == BACKSLASH + "x01"
    assert literal == BACKSLASH * 2 + "x01"
    assert written != literal


def test_a_run_of_backslashes_before_an_escape_text_is_doubled_whole():
    assert _xml_text(BACKSLASH * 3 + "ufffe") == BACKSLASH * 6 + "ufffe"


def test_a_backslash_before_a_forbidden_character_is_doubled():
    assert _xml_text(BACKSLASH + "\x01") == BACKSLASH * 2 + BACKSLASH + "x01"


@pytest.mark.parametrize(
    "text",
    [
        "C:" + BACKSLASH + "x64" + BACKSLASH + "app",
        BACKSLASH + "x41",
        BACKSLASH + "x09",
        BACKSLASH + "u00e9",
        "no backslash",
        "tab\tnewline\ncarriage\r",
    ],
)
def test_text_that_reads_as_no_escape_the_report_writes_is_unchanged(text):
    assert _xml_text(text) == text


def test_none_is_empty():
    assert _xml_text(None) == ""
