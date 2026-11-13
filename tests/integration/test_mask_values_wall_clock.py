# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking a text takes about as long with two thousand values as with twenty.

The wall-clock companion of ``tests/unit/utils/test_mask_values_is_single_pass.py``,
which pins the same thing in candidates compared. A clock reading depends on the
machine, so this one is in the slow tier; the old alternation took about 800 times
as long with two thousand values.
"""

import hashlib
import random
import string
import time
from typing import List, Tuple

import pytest

from automated_security_helper.utils.secret_masking import (
    _SecretIndex,
    secret_value_shape,
)

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_ALPHABET = string.ascii_lowercase + string.digits
_RATIO_BOUND = 3.0


def _derived(label: str, length: int) -> str:
    digest = hashlib.sha256(label.encode()).digest()
    while len(digest) < length:
        digest += hashlib.sha256(digest).digest()
    return "".join(_ALPHABET[byte % len(_ALPHABET)] for byte in digest)[:length]


def _prose(seed: int, size: int) -> str:
    """Ordinary words and word-like identifiers: nothing in it is a secret."""
    rng = random.Random(seed)
    words = [
        "".join(rng.choices(string.ascii_lowercase, k=rng.randint(2, 9)))
        for _ in range(400)
    ]
    parts: List[str] = []
    total = 0
    while total < size:
        if rng.random() < 0.4:
            token = rng.choice("._-").join(rng.choices(words, k=rng.randint(2, 4)))
        else:
            token = rng.choice(words)
        parts.append(token)
        total += len(token) + 1
    return " ".join(parts)


def _index_of(count: int, suffix: str = "") -> _SecretIndex:
    values = [
        _derived(f"scale-{number}", 11 + number % 28) + str(number % 10) + suffix
        for number in range(count)
    ]
    index = _SecretIndex()
    index.add_values(values)
    index.add_shapes(secret_value_shape(value) for value in values)
    assert len(index.values) == count
    return index


def _best_of_interleaved(
    first: _SecretIndex, second: _SecretIndex, text: str, repeats: int
) -> Tuple[float, float]:
    """The minimum of ``repeats`` runs per index, the two taken in alternation.

    A run that the machine deschedules is slow whatever the code does, and the
    minimum drops it. Alternating the indexes keeps a stretch of busy machine from
    landing on only one of them.
    """
    for index in (first, second):
        index.mask_values("a warm up text with 0123456789 in it")
    best = [float("inf"), float("inf")]
    for _ in range(repeats):
        for position, index in enumerate((first, second)):
            started = time.perf_counter()
            index.mask_values(text)
            best[position] = min(best[position], time.perf_counter() - started)
    return best[0], best[1]


#: A loose shape is tried once per different length it has with a first character,
#: and the lengths of the values here (11 to 38) are all there at 2,000 values but
#: about 20 of them at 20 values: measured 2.1x. The bound leaves room for that.
@pytest.mark.parametrize(
    ("suffix", "bound"),
    [("", _RATIO_BOUND), ("==", 4.0)],
    ids=["word-edged", "loose"],
)
def test_two_thousand_values_cost_about_what_twenty_cost(suffix, bound):
    # Twenty values (forty branches) are past the few that keep one alternation.
    text = _prose(7, 200_000)
    few, many = _best_of_interleaved(
        _index_of(20, suffix), _index_of(2_000, suffix), text, repeats=5
    )
    assert many <= bound * few, (few, many, many / few)
