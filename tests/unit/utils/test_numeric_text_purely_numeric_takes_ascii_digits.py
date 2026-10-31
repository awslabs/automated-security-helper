# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""purely_numeric (utils/numeric_text.py) reads ASCII decimal digits only.

str.isdigit is wider: a superscript two, a circled one and the digits of other
scripts pass it, while int() and float() refuse the first two, so a knob value
spelled with one was a bare number to the validator's derived-spelling rule and
the Bedrock knob exclusion, and a non-number to everything that parsed it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.numeric_text import purely_numeric

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("value", ["0", "0.50", "4000", "12.", ".5"])
def test_ascii_digits_with_at_most_one_dot_are_numeric(value):
    assert purely_numeric(value) is True


@pytest.mark.parametrize(
    "value",
    [
        chr(0xB2),  # superscript two, isdigit() True, int() refuses it
        "1" + chr(0xB2),
        chr(0x2460),  # circled digit one
        chr(0x663),  # a digit of another script: int() takes it, the knob does not
        "1.2.3",
        "",
        ".",
        "-1",
        "1e3",
    ],
)
def test_anything_but_ascii_digits_is_not_numeric(value):
    assert purely_numeric(value) is False
