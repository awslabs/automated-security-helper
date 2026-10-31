# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``mask_secret_values_in_text`` matches a value in two more JSON spellings.

It matched neither pydantic's JSON spelling of a value that holds a non-ASCII
character beside an escaped one (non-ASCII written as it is, the quote escaped),
nor a value inside a JSON document that is itself a JSON string (GitLab SAST's
``raw_data``), so such a value survived a workspace re-mask of those reports.

The values here are derived at import time; none is a credential.
"""

import hashlib
import json
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


VALUE = _derived("u27-plain-value", 12)
#: Holds a quote, which JSON escapes, so its two JSON spellings differ from it.
QUOTED_VALUE = VALUE[:5] + '"' + VALUE[5:]
#: Holds a non-ASCII character beside the escaped quote.
ACCENTED_VALUE = VALUE[:4] + "é" + VALUE[4:] + '"'


class TestJsonSpellingsOfAValue:
    def test_pydantics_json_spelling_is_masked(self):
        text = (
            '{"message": "'
            + json.dumps(ACCENTED_VALUE, ensure_ascii=False)[1:-1]
            + '"}'
        )

        masked = mask_secret_values_in_text(text, [ACCENTED_VALUE])

        expected = json.dumps(_mask_secret_value(ACCENTED_VALUE), ensure_ascii=False)[
            1:-1
        ]
        assert masked == '{"message": "' + expected + '"}'

    def test_a_value_inside_a_json_document_in_a_json_string_is_masked(self):
        inner = json.dumps({"token": QUOTED_VALUE})
        text = json.dumps({"raw_data": inner})

        masked = mask_secret_values_in_text(text, [QUOTED_VALUE])

        expected_inner = json.dumps({"token": _mask_secret_value(QUOTED_VALUE)})
        assert masked == json.dumps({"raw_data": expected_inner})
        assert json.loads(json.loads(masked)["raw_data"])[
            "token"
        ] == _mask_secret_value(QUOTED_VALUE)

    def test_a_non_ascii_value_inside_a_json_document_in_a_json_string_is_masked(
        self,
    ):
        """The inner document writes the non-ASCII character as an escape and the
        quote escaped, and the outer string escapes every one of those
        backslashes again: the spelling of a value with both characters in
        GitLab SAST's ``raw_data``."""
        inner = json.dumps({"token": ACCENTED_VALUE})
        assert "é" not in inner
        text = json.dumps({"raw_data": inner})

        masked = mask_secret_values_in_text(text, [ACCENTED_VALUE])

        expected_inner = json.dumps({"token": _mask_secret_value(ACCENTED_VALUE)})
        assert masked == json.dumps({"raw_data": expected_inner})
        decoded = json.loads(json.loads(masked)["raw_data"])["token"]
        assert decoded == _mask_secret_value(ACCENTED_VALUE)
