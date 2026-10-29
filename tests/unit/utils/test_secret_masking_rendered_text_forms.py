# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``mask_secret_values_in_text`` matches a value as rendered reports write it.

A rendered report cannot be re-rendered from masked results, so each value is
matched as a whole token in every text encoding the reporters use. Two forms
were missed: a value that follows a JSON or YAML escape ending in a letter or
hex digit (``\\n``, ``\\t``, ``\\uXXXX``), whose whole-token boundary read that
letter as part of a word; and the Markdown reporter's spelling, HTML-escaped and
then backslash-escaped, so a value holding ``_``, ``*``, ``[``, ``]``, ``{``,
``}``, ``#``, ``|``, ``~`` or a backtick survived in a project's Markdown report.

The values here are derived at import time; none is a credential.
"""

import hashlib
import html
import re
import string

import pytest

from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
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


def _as_markdown(value):
    """How ``markdown_reporter._text`` writes a value."""
    return re.sub(r"([\\`*_\[\]{}#|~])", r"\\\1", html.escape(value, quote=False))


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


class TestTheMarkdownReportersSpelling:
    def test_an_escaped_value_is_masked_in_its_escaped_form(self):
        text = "| Finding | " + _as_markdown(MARKDOWN_VALUE) + " |"

        masked = mask_secret_values_in_text(text, [MARKDOWN_VALUE])

        assert masked == (
            "| Finding | " + _as_markdown(_mask_secret_value(MARKDOWN_VALUE)) + " |"
        )
        assert MARKDOWN_VALUE not in masked
