# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``mask_secret_values_in_text`` matches three more forms the reports write.

The YAML report's dumper writes a character outside ASCII as an upper-case
escape (``\\xE9``), the HTML and text reports write snippets and descriptions as
the console shows them (``terminal_text.shown_not_obeyed``) and the JUnit report
writes an XML attribute with its tab as ``&#09;`` and its single quote as is;
none of the three was among the forms matched.

The values here are derived at import time; none is a credential.
"""

import hashlib
import html
import string

import pytest
import yaml

from automated_security_helper.utils.secret_masking import (
    _mask_secret_value,
    mask_secret_values_in_text,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


NON_ASCII_VALUE = _derived("yaml-value", 8) + "é" + "9"
CONTROL_VALUE = _derived("shown-value", 4) + "\x1b" + _derived("shown-value-2", 4) + "9"
TAB_VALUE = _derived("xml-value", 4) + "\t" + _derived("xml-value-2", 4) + "9"


def _as_yaml(value):
    """How PyYAML writes a double-quoted scalar with no unicode allowed."""
    return yaml.dump(value, default_style='"', width=2**31 - 1).strip()[1:-1]


def _as_xml_attribute(value):
    for character, reference in (
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ('"', "&quot;"),
        ("\r", "&#13;"),
        ("\n", "&#10;"),
        ("\t", "&#09;"),
    ):
        value = value.replace(character, reference)
    return value


class TestTheYamlReportsEscapes:
    def test_an_upper_case_escape_of_a_non_ascii_character_is_matched(self):
        assert "\\xE9" in _as_yaml(NON_ASCII_VALUE)
        text = 'description: "' + _as_yaml(NON_ASCII_VALUE) + '"\n'

        masked = mask_secret_values_in_text(text, [NON_ASCII_VALUE])

        assert _as_yaml(NON_ASCII_VALUE) not in masked
        assert masked == (
            'description: "' + _as_yaml(_mask_secret_value(NON_ASCII_VALUE)) + '"\n'
        )


class TestTheShownForm:
    def test_the_html_reports_shown_and_escaped_text_is_matched(self):
        shown = html.escape(str(shown_not_obeyed(CONTROL_VALUE)), quote=False)
        assert shown != CONTROL_VALUE
        text = "<pre><code>token = " + shown + "</code></pre>"

        masked = mask_secret_values_in_text(text, [CONTROL_VALUE])

        assert shown not in masked
        assert (
            html.escape(
                str(shown_not_obeyed(_mask_secret_value(CONTROL_VALUE))), quote=False
            )
            in masked
        )

    def test_the_text_reports_shown_form_is_matched(self):
        shown = str(shown_not_obeyed(CONTROL_VALUE))
        text = "token = " + shown + "\n"

        masked = mask_secret_values_in_text(text, [CONTROL_VALUE])

        assert shown not in masked


class TestAnXmlAttribute:
    def test_a_tab_written_as_a_character_reference_is_matched(self):
        attribute = _as_xml_attribute(TAB_VALUE)
        assert "&#09;" in attribute
        text = '<testcase name="' + attribute + '" />'

        masked = mask_secret_values_in_text(text, [TAB_VALUE])

        assert attribute not in masked
        assert (
            '<testcase name="'
            + _as_xml_attribute(_mask_secret_value(TAB_VALUE))
            + '" />'
            == masked
        )
