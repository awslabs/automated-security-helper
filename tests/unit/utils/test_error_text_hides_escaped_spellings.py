# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``error_text`` and ``traceback_text`` hide a value's escaped spellings, as
``text_without_values`` does.

The three printers share one redaction pass (``_redacted_keeping_codes``, over
``redact_values``), and ``redact_values`` matches each value in every form a
message prints it in (``config_validator._printed_forms``), so a value a
message quotes with ``!r`` or as JSON is hidden whichever printer shows the
text. The distinguishing spelling here is JSON with ``ensure_ascii=False``: it
escapes a double quote and a backslash while keeping a non-ASCII character as
it is, a combination none of the other printed forms (as written, the ``repr``
body, ``unicode_escape``, default JSON) spells. The ``repr`` spelling of a
backslash-bearing value is matched by ``_printed_forms``' repr body and stays
hidden with or without the new form; it is kept here as a must-not-regress
control.

The values are fake data.
"""

from __future__ import annotations

import json

from automated_security_helper.utils.error_text import (
    error_text,
    text_without_values,
    traceback_text,
)

#: A non-ASCII character, a double quote and a backslash: JSON with
#: ``ensure_ascii=False`` escapes the quote and the backslash and keeps the
#: non-ASCII character raw, which no other printed form spells.
JSON_RAW_VALUE = "xsv-caf" + chr(0xE9) + '-"q\\slash"-4c1d'
#: One backslash: ``str(KeyError(v))`` is ``repr(v)``, which doubles it.
BACKSLASH_VALUE = "xsv-back\\slash-4c1d"


def _json_quoting_error() -> ValueError:
    """An error whose message embeds the value as a JSON body, as an HTTP client
    quoting the body it could not send does."""
    body = json.dumps({"token": JSON_RAW_VALUE}, ensure_ascii=False)
    return ValueError(f"cannot send the request body {body}")


def test_error_text_hides_the_json_spelling_a_message_quotes():
    text = error_text(_json_quoting_error(), [JSON_RAW_VALUE])
    assert "xsv-caf" not in text, text
    assert "cannot send the request body" in text, text


def test_traceback_text_hides_the_json_spelling_a_message_quotes():
    text = traceback_text(_json_quoting_error(), [JSON_RAW_VALUE])
    assert "xsv-caf" not in text, text


def test_text_without_values_hides_the_same_spelling():
    """The pass the two printers share is text_without_values' own."""
    body = json.dumps({"token": JSON_RAW_VALUE}, ensure_ascii=False)
    text = text_without_values(f"cannot send the request body {body}", [JSON_RAW_VALUE])
    assert "xsv-caf" not in text, text


def test_the_repr_spelling_of_a_backslash_value_stays_hidden():
    """The must-not-regress control: _printed_forms' repr body already matches
    the ``repr`` spelling, and the added JSON form must not lose that."""
    text = error_text(KeyError(BACKSLASH_VALUE), [BACKSLASH_VALUE])
    assert "xsv-back" not in text, text
