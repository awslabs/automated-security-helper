# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""controls_shown's ``lookalikes="ascii"`` leaves JSON's escape of an accented
letter as it is, for text shown_in_ascii then puts in ASCII.

Why this exists
---------------
On a Windows console that cannot write Unicode, WindowsSafeFilter shows a
message and puts it in ASCII: each character outside ASCII becomes its escape
(``\\xe9`` for "é"), and a backslash run before text that reads as an escape is
doubled, so the result reads back one to one. A warning that suggests a
``--config-overrides`` command quotes a JSON document, and JSON writes the "é"
of a path as ``\\u00e9``: the default (``"any"``) doubled that run, and the
pasted command read the text "u00e9" in place of the letter. In ASCII the
letter's form is ``\\xe9``, never ``\\u00e9``, so the run before JSON's text
need not be doubled for the result to read back; the ``"ascii"`` mode doubles a
run only before the text of an escape shown_in_ascii or shown_not_obeyed writes
there: a character outside ASCII, or one shown as an escape, in escape_for's
form.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.terminal_text import (
    ShownText,
    as_written,
    controls_shown,
    escape_for,
    shown_in_ascii,
    shown_not_obeyed,
)

pytestmark = pytest.mark.unit

BACKSLASH = chr(0x5C)
E_ACUTE = chr(0xE9)
ARROW = chr(0x2192)
ESC = chr(0x1B)

#: The escape text of a character beyond U+FFFF, assembled so the source holds
#: no long hex run.
GRINNING_FACE_TEXT = "U000" + "1f600"


@pytest.mark.parametrize(
    "escape_text",
    [
        pytest.param("u00e9", id="json-escape-of-a-letter-below-u0100"),
        pytest.param("u0041", id="long-form-of-an-ascii-letter"),
        pytest.param("x64", id="ascii-letter-in-a-windows-path"),
    ],
)
def test_a_run_before_text_no_ascii_sink_writes_is_kept(escape_text):
    text = "C:" + BACKSLASH + escape_text + "b"

    assert controls_shown(text, lookalikes="ascii") == text


@pytest.mark.parametrize(
    "character",
    [
        pytest.param(E_ACUTE, id="letter-outside-ascii"),
        pytest.param(ARROW, id="symbol-outside-ascii"),
        pytest.param(ESC, id="control-shown-as-escape"),
    ],
)
def test_a_run_before_the_text_an_ascii_sink_writes_is_doubled(character):
    escape_text = escape_for(character)
    text = "a" + escape_text + "b"

    shown = controls_shown(text, lookalikes="ascii")

    assert shown == "a" + BACKSLASH + escape_text + "b"
    assert as_written(shown_not_obeyed(text, lookalikes="ascii")) == text


def test_the_text_of_a_character_beyond_the_sixteen_bit_plane_is_doubled():
    text = "a" + BACKSLASH + GRINNING_FACE_TEXT + "b"

    shown = controls_shown(text, lookalikes="ascii")

    assert shown == "a" + BACKSLASH * 2 + GRINNING_FACE_TEXT + "b"
    assert as_written(shown_not_obeyed(text, lookalikes="ascii")) == text


def test_an_escape_text_beyond_any_code_point_is_left_as_text():
    text = "a" + BACKSLASH + "U" + "f" * 8 + "b"

    assert controls_shown(text, lookalikes="ascii") == text


def test_the_ascii_mode_is_not_read_back_one_to_one_by_as_written():
    """The convention: a ShownText made with ``lookalikes="ascii"`` is for the
    last sink, which nothing reads back. It leaves JSON's text single, and
    as_written, which reads a single backslash before escape text as the
    escape, returns the letter; the default mode's text reads back as it was."""
    text = "a" + BACKSLASH + "u00e9b"

    assert as_written(shown_not_obeyed(text)) == text
    assert as_written(shown_not_obeyed(text, lookalikes="ascii")) == "a" + E_ACUTE + "b"


def test_the_default_mode_still_doubles_a_run_before_json_escape_text():
    """Control: the one-to-one reading of the default is unchanged."""
    text = "a" + BACKSLASH + "u00e9b"

    assert controls_shown(text) == "a" + BACKSLASH * 2 + "u00e9b"
    assert shown_not_obeyed(text) == shown_not_obeyed(text, lookalikes="any")


def test_shown_not_obeyed_passes_a_shown_text_through_in_any_mode():
    shown = shown_not_obeyed("a::b")

    assert isinstance(shown, ShownText)
    assert shown_not_obeyed(shown, lookalikes="ascii") is shown


def test_text_put_in_ascii_after_the_ascii_mode_reads_back_where_the_sink_wrote():
    """A letter raw and the same letter's escape as text, side by side: the raw
    letter becomes its escape, the text keeps a doubled run, and the result
    reads back as it was."""
    text = "caf" + E_ACUTE + " " + BACKSLASH + "xe9 ::x"

    in_ascii = shown_in_ascii(shown_not_obeyed(text, lookalikes="ascii"), {})

    assert str(in_ascii) == "caf" + BACKSLASH + "xe9 " + BACKSLASH * 2 + "xe9 ::x"
    assert as_written(in_ascii) == text


def test_json_escape_text_beside_a_raw_letter_is_kept_through_the_ascii_sink():
    text = "caf" + E_ACUTE + " " + BACKSLASH + "u00e9"

    in_ascii = shown_in_ascii(shown_not_obeyed(text, lookalikes="ascii"), {})

    assert str(in_ascii) == "caf" + BACKSLASH + "xe9 " + BACKSLASH + "u00e9"
