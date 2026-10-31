# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``mask_secret_shapes_in_text`` masks tokens of recorded value shapes in rendered text.

``mask_secret_values_in_text`` takes the values themselves. A process that holds
only what a results file records, the ``secret_value_shapes`` written for an
``ash merge`` of shard results, had no text masker to call: a rendered report
re-read from disk kept a value whose shape was known. The shapes masker takes
the shapes, reads them as the tree masker does (a shape ASH did not write is
ignored, an ordinary word of the shape is kept) and returns the text with each
matching token masked, the same return shape as the values masker.

The values are derived at import time, so this source holds no string a secret
scanner would report.
"""

import hashlib
import string

import pytest

from automated_security_helper.utils.secret_masking import (
    SecretValueShape,
    _mask_secret_value,
    mask_secret_shapes_in_text,
    secret_value_shape,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


VALUE = _derived("shapes-in-text-value", 16)
OTHER = _derived("shapes-in-text-other", 16)


def test_a_token_of_a_recorded_shape_is_masked():
    text = f"token={VALUE}; next"

    out = mask_secret_shapes_in_text(text, [secret_value_shape(VALUE)])

    assert VALUE not in out
    assert out == f"token={_mask_secret_value(VALUE)}; next"


def test_a_shape_read_from_a_results_file_is_a_dict():
    recorded = secret_value_shape(VALUE).model_dump()

    out = mask_secret_shapes_in_text(f"[{VALUE}]", [recorded])

    assert out == f"[{_mask_secret_value(VALUE)}]"


def test_another_value_of_the_same_shape_is_masked_too():
    """The shape stands for every value that could have produced it; a
    second value with the same visible characters and length is masked, which
    is the accepted over-masking of a merge that no longer holds the value."""
    shape = secret_value_shape(VALUE)
    same_shape = VALUE[:2] + OTHER[2:-1] + VALUE[-1:]
    assert same_shape != VALUE

    out = mask_secret_shapes_in_text(f"a={same_shape}", [shape])

    assert out == f"a={_mask_secret_value(same_shape)}"


def test_an_ordinary_word_of_the_shape_is_kept():
    """A token that is letters alone, or repeats one character, is not a
    value the shape stands for (``_mask_match``)."""
    shape = secret_value_shape(VALUE)
    hidden = shape.length - len(shape.prefix) - len(shape.suffix)
    word = shape.prefix + "x" * hidden + shape.suffix

    out = mask_secret_shapes_in_text(f"a={word}", [shape])

    assert out == f"a={word}"


def test_a_shape_ash_did_not_write_is_ignored():
    """The visible lengths do not match what the masker shows for the length."""
    shape = SecretValueShape(prefix=VALUE[:3], suffix=VALUE[-1:], length=len(VALUE))

    out = mask_secret_shapes_in_text(f"a={VALUE}", [shape])

    assert out == f"a={VALUE}"


def test_a_token_inside_a_longer_word_is_kept():
    shape = secret_value_shape(VALUE)

    out = mask_secret_shapes_in_text(f"x{VALUE}y", [shape])

    assert out == f"x{VALUE}y"


def test_no_shapes_leaves_the_text_as_it_is():
    text = f"a={VALUE}"
    assert mask_secret_shapes_in_text(text, []) == text
    assert (
        mask_secret_shapes_in_text(text, [None, "not a shape", {"length": 3}]) == text
    )
