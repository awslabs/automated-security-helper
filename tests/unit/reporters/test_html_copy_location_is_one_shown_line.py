# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report's copyable finding location is one shown line.

A finding's location comes from a file name in the scanned repository. The
report offers it two ways to copy: the Copy button's ``data-copy-location``
value, and the ``<code>`` text beside the button, which the page selects when
the clipboard is unavailable. Both hold the location as text that is pasted
elsewhere, so a control character in the name is written as a visible escape
there, as ``shown_on_one_line`` writes one, and an ordinary name is unchanged.

A name with no control and no CI command form is copied as written, even when
it holds text that reads as an escape (a Windows path's ``\\x64``): showing it
would only double that backslash, and the copied name would then name no file.
With a control in the name, the doubling stays, so the escape written for the
control is told apart from the name's own text.
"""

import html
import re

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.terminal_text import is_shown_as_escape

pytestmark = pytest.mark.unit

#: The right-to-left override (a format character), named by code point.
RLO = chr(0x202E)
#: ESC, LF, a line-start CI command, CR, BEL, a C1 control and the
#: right-to-left override, inside an otherwise ordinary name.
CONTROLLED_NAME = f"src/a\x1b[201~\n::add-mask::next\r\x07\x9b{RLO}.py"
PLAIN_NAME = "src/app.py"
#: A Windows path whose "\x64" segment reads as an escape, and no control.
ESCAPE_TEXT_NAME = "C:\\build\\x64\\app.py"


def _render(test_plugin_context, uri):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": "bandit"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            }
        )
    ]
    model._flat_cache = None
    return HtmlReporter(context=test_plugin_context).report(model)


def _copyable(document):
    """Every copyable form of each location, as the browser decodes it: the
    attribute's value and the text of the ``<code>`` beside the button."""
    attributes = re.findall(r'data-copy-location="([^"]*)"', document)
    code_texts = re.findall(r"<span><code>(.*?)</code> <button", document, re.DOTALL)
    return [html.unescape(text) for text in attributes + code_texts]


def _controls(text):
    """Each character a terminal acts on rather than shows: controls, format
    characters such as the bidirectional overrides, and the separators."""
    return [char for char in text if is_shown_as_escape(char)]


def test_a_location_holding_controls_copies_as_one_shown_line(test_plugin_context):
    copyable = _copyable(_render(test_plugin_context, CONTROLLED_NAME))

    # The control: both copy paths are present for the one finding.
    assert len(copyable) == 2, copyable
    for text in copyable:
        assert _controls(text) == [], repr(text)
        # The name is still there to read, with each control written out.
        assert text.startswith("src/a"), repr(text)
        assert text.endswith(".py:3"), repr(text)
        assert "\\u202e" in text, repr(text)


def test_a_location_holding_only_a_format_character_copies_it_shown(
    test_plugin_context,
):
    """No C0 or C1 control, only the right-to-left override: still shown."""
    copyable = _copyable(_render(test_plugin_context, f"src/{RLO}evil.py"))

    assert len(copyable) == 2, copyable
    for text in copyable:
        assert _controls(text) == [], repr(text)
        assert text == "src/\\u202eevil.py:3", repr(text)


def test_a_location_that_starts_a_ci_command_copies_it_broken(test_plugin_context):
    """No control, but a name that is a line-start "::" command: shown with
    the command broken, not copied as written."""
    copyable = _copyable(_render(test_plugin_context, "::add-mask::x.py"))

    assert len(copyable) == 2, copyable
    for text in copyable:
        assert not text.startswith("::"), repr(text)
        assert text.endswith("add-mask::x.py:3"), repr(text)


def test_a_quote_in_a_location_is_escaped_in_the_copy_attribute(test_plugin_context):
    """A name copied as written still cannot close the attribute it is in."""
    document = _render(test_plugin_context, 'src/a"b.py')

    assert 'data-copy-location="src/a&quot;b.py:3"' in document


def test_an_ordinary_location_copies_as_written(test_plugin_context):
    copyable = _copyable(_render(test_plugin_context, PLAIN_NAME))

    assert copyable == [f"{PLAIN_NAME}:3", f"{PLAIN_NAME}:3"], copyable


def test_a_location_with_escape_text_and_no_control_copies_as_written(
    test_plugin_context,
):
    copyable = _copyable(_render(test_plugin_context, ESCAPE_TEXT_NAME))

    assert copyable == [f"{ESCAPE_TEXT_NAME}:3", f"{ESCAPE_TEXT_NAME}:3"], copyable


def test_a_location_holding_a_command_form_copies_it_broken(test_plugin_context):
    """No control, but a "##name[" form a CI runner acts on anywhere in a line:
    the name is shown, not copied as written."""
    copyable = _copyable(_render(test_plugin_context, "src/##[error]x.py"))

    assert len(copyable) == 2, copyable
    for text in copyable:
        assert "##[error]" not in text, repr(text)
        assert text.startswith("src/") and text.endswith("x.py:3"), repr(text)


def test_escape_text_beside_a_control_keeps_its_backslash_doubled(
    test_plugin_context,
):
    copyable = _copyable(_render(test_plugin_context, ESCAPE_TEXT_NAME + "\x1b"))

    # The name's own "\x64" is doubled, the ESC is one escape: the two read
    # apart.
    expected = "C:\\build\\\\x64\\app.py\\x1b:3"
    assert copyable == [expected, expected], copyable
