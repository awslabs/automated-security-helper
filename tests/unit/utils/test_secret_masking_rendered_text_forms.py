# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``mask_secret_values_in_text`` matches a value as rendered reports write it.

A rendered report cannot be re-rendered from masked results, so each value is
matched as a whole token in every text encoding the reporters use. Two forms
were missed: a value that follows a JSON or YAML escape ending in a letter or
hex digit (``\\n``, ``\\t``, ``\\uXXXX``, and YAML's ``\\xHH``, ``\\UHHHHHHHH``
and ``\\_``), whose whole-token boundary read that letter as part of a word;
and the Markdown reporter's spelling, HTML-escaped and
then backslash-escaped, so a value holding ``_``, ``*``, ``[``, ``]``, ``{``,
``}``, ``#``, ``|``, ``~`` or a backtick survived in a project's Markdown report.

The values here are derived at import time; none is a credential.
"""

import hashlib
import string

import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    _markdown_escaped as _as_markdown,
)
from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    _yaml_double_quoted,
    mask_secret_values_in_text,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("u27-text-value", 10)
#: Holds two characters the Markdown reporter escapes.
MARKDOWN_VALUE = VALUE[:6] + "_" + VALUE[6:] + "*"


class TestAValueAfterAnEscape:
    def test_after_a_newline_escape(self):
        text = '{"log": "line one\\n' + VALUE + '"}'

        masked = mask_secret_values_in_text(text, [VALUE])

        assert masked == '{"log": "line one\\n' + _mask_secret_value(VALUE) + '"}'

    def test_after_a_unicode_escape(self):
        text = '{"log": "caf\\u00e9' + VALUE + '"}'

        masked = mask_secret_values_in_text(text, [VALUE])

        assert masked == '{"log": "caf\\u00e9' + _mask_secret_value(VALUE) + '"}'

    def test_a_value_inside_a_longer_word_is_still_not_a_token(self):
        """Control."""
        text = "prefix" + VALUE + " and " + VALUE

        masked = mask_secret_values_in_text(text, [VALUE])

        assert masked == "prefix" + VALUE + " and " + _mask_secret_value(VALUE)

    @pytest.mark.parametrize(
        "character, escape",
        [
            (chr(0xAB), "\\xAB"),
            (chr(0xA0), "\\_"),
            (chr(0x85), "\\N"),
            (chr(0x2028), "\\L"),
            (chr(0x2029), "\\P"),
            (chr(0x1F600), "\\U0001F600"),
            ("\x00", "\\0"),
            ("\x07", "\\a"),
            ("\x0b", "\\v"),
            ("\x1b", "\\e"),
        ],
    )
    def test_after_a_yaml_escape_the_report_writes(self, character, escape):
        """The YAML report writes a non-breaking space as ``\\_``, a Latin-1
        character as ``\\xHH`` and the rest of YAML's escapes as a letter or
        ``\\UHHHHHHHH``; the letter or hex digit before the value is no word."""
        written = _yaml_double_quoted("caf" + character + VALUE)
        assert escape + VALUE in written
        text = 'description: "' + written + '"\n'

        masked = mask_secret_values_in_text(text, [VALUE])

        assert VALUE not in masked
        assert masked == text.replace(VALUE, _mask_secret_value(VALUE))

    def test_a_hex_digit_pair_with_no_backslash_before_it_is_a_word(self):
        """Control."""
        text = 'description: "xAB' + VALUE + '"\n'

        assert mask_secret_values_in_text(text, [VALUE]) == text


class TestTheMarkdownReportersSpelling:
    def test_an_escaped_value_is_masked_in_its_escaped_form(self):
        text = "| Finding | " + _as_markdown(MARKDOWN_VALUE) + " |"

        masked = mask_secret_values_in_text(text, [MARKDOWN_VALUE])

        assert masked == (
            "| Finding | " + _as_markdown(_mask_secret_value(MARKDOWN_VALUE)) + " |"
        )
        assert _as_markdown(MARKDOWN_VALUE) not in masked

    def test_the_spelling_masked_is_the_one_the_report_writes(self):
        """The masker takes its Markdown spelling from the reporter's own escaping;
        this writes the expected spelling out (a backslash before each of ``_``
        and ``*``), so a change to either side shows here."""
        written = VALUE[:6] + "\\_" + VALUE[6:] + "\\*"
        assert _as_markdown(MARKDOWN_VALUE) == written

        masked = mask_secret_values_in_text("| " + written + " |", [MARKDOWN_VALUE])

        assert written not in masked
        assert VALUE not in masked

    def test_a_second_pass_recognizes_its_own_escaped_output(self):
        """A Markdown report is re-masked on every workspace pass; the masked
        token, escaped by the reporter, is its own output and changes no more."""
        text = "| Finding | " + _as_markdown(MARKDOWN_VALUE) + " |"
        once = mask_secret_values_in_text(text, [MARKDOWN_VALUE])

        twice = mask_secret_values_in_text(once, [MARKDOWN_VALUE])

        assert twice == once
        assert _as_markdown(_mask_secret_value(MARKDOWN_VALUE)) in twice
