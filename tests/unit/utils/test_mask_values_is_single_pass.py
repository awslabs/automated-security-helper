# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Masking a text for the values and shape tokens of a report is one pass over it.

``_SecretIndex.mask_values`` was one alternation with a branch per secret value
and per shape, applied to every string of the report model. The regex engine
tries the branches one after the other at every position, so the cost of a text
grew with the number of values times its length, and a report with a thousand
secret findings spent minutes in it.

These tests pin two things. The result is what the alternation gave: a value or
shape token is found where the alternation found it (inside a longer token, next
to punctuation, longest first), through a reference written the old way. And the
cost of a text does not grow with the number of values, counted in candidates
compared (``_MaskPlan.checks``) so that it does not depend on the machine. The
wall-clock version of that pin is in tests/integration. The values here are derived at
import time or at run time; none is a credential.
"""

import hashlib
import json
import random
import re
import string
import sys
from typing import Iterable, List, Set

import pytest

from automated_security_helper.utils import secret_masking
from automated_security_helper.utils.secret_masking import (
    _looks_like_a_secret,
    _mask_secret_value,
    _SecretIndex,
    _shape_pattern,
    _token_pattern,
    secret_value_shape,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _always_the_lookup_plan(monkeypatch):
    # A few values would use one alternation, which is the reference itself; the
    # tests are of the lookups.
    monkeypatch.setattr(secret_masking, "_ALTERNATION_MAX_BRANCHES", 0, raising=False)


_ALPHABET = string.ascii_lowercase + string.digits


def _derived(label: str, length: int) -> str:
    digest = hashlib.sha256(label.encode()).digest()
    while len(digest) < length:
        digest += hashlib.sha256(digest).digest()
    return "".join(_ALPHABET[byte % len(_ALPHABET)] for byte in digest)[:length]


def _index(
    values: Iterable[str] = (), shape_values: Iterable[str] = ()
) -> _SecretIndex:
    index = _SecretIndex()
    index.add_values(values)
    index.add_shapes(secret_value_shape(value) for value in shape_values)
    return index


def _reference(index: _SecretIndex, text: str) -> str:
    """``mask_values`` as it was: one alternation, longest alternative first."""
    alternatives = [
        (len(value), 1, _token_pattern(re.escape(value), value[0], value[-1]))
        for value in index.values
        if value
    ]
    alternatives.extend(
        (shape.length, 0, _shape_pattern(shape)) for shape in index.shapes
    )
    if not alternatives:
        return text
    alternatives.sort(reverse=True)
    pattern = re.compile("|".join(pattern for _, _, pattern in alternatives))

    def mask(match: "re.Match[str]") -> str:
        token = match.group(0)
        if token in index.values or _looks_like_a_secret(token):
            return _mask_secret_value(token)
        return token

    return pattern.sub(mask, text)


def _same_as_the_alternation(index: _SecretIndex, text: str) -> str:
    masked = index.mask_values(text)
    assert masked == _reference(index, text), text
    return masked


# ---------------------------------------------------------------------------
# The result is the alternation's
# ---------------------------------------------------------------------------


def test_a_value_between_punctuation_is_masked_inside_a_longer_token():
    value = _derived("inside-1", 14)
    index = _index([value])
    assert index.values == {value}
    masked = _mask_secret_value(value)
    assert _same_as_the_alternation(index, f"token={value};next") == (
        f"token={masked};next"
    )
    assert _same_as_the_alternation(index, f"'{value}'") == f"'{masked}'"
    assert _same_as_the_alternation(index, f"{value}") == masked
    assert _same_as_the_alternation(index, f"({value})") == f"({masked})"


def test_a_value_is_not_masked_inside_a_longer_word():
    value = _derived("inside-2", 14)
    index = _index([value])
    for text in (f"x{value}", f"{value}x", f"_{value}", f"{value}_", f"é{value}"):
        assert _same_as_the_alternation(index, text) == text


def test_a_value_that_starts_with_punctuation_has_no_left_boundary():
    value = "!" + _derived("lead-1", 12)
    index = _index([value])
    assert index.values == {value}
    masked = _mask_secret_value(value)
    assert _same_as_the_alternation(index, f"a{value} b") == f"a{masked} b"
    assert _same_as_the_alternation(index, f"a{value}b") == f"a{value}b"


def test_a_value_that_ends_with_punctuation_has_no_right_boundary():
    value = _derived("trail-1", 12) + "!"
    index = _index([value])
    assert index.values == {value}
    masked = _mask_secret_value(value)
    assert _same_as_the_alternation(index, f"a {value}b") == f"a {masked}b"
    assert _same_as_the_alternation(index, f"a{value} b") == f"a{value} b"


def test_a_value_with_punctuation_inside_is_found_whole():
    value = _derived("middle-1", 6) + "!" + _derived("middle-2", 6) + "$x"
    index = _index([value])
    assert index.values == {value}
    masked = _mask_secret_value(value)
    assert _same_as_the_alternation(index, f"[{value}]") == f"[{masked}]"
    assert _same_as_the_alternation(index, f"{value[:-1]}") == value[:-1]


def test_a_shape_token_that_is_an_ordinary_word_is_kept():
    secret = "p" + _derived("word-1", 6) + "d"
    assert _looks_like_a_secret(secret)
    index = _index(shape_values=[secret])
    other = "p" + _derived("word-2", 6) + "d"
    assert _looks_like_a_secret(other)
    text = f"the password was provided as {other}."
    assert _same_as_the_alternation(index, text) == (
        f"the password was provided as {_mask_secret_value(other)}."
    )


def test_the_longer_alternative_wins_whether_it_is_a_value_or_a_shape():
    head = _derived("long-1", 5) + "!" + _derived("long-2", 4)
    tail = "$" + _derived("long-3", 8)
    full = head + tail
    assert len(full) > len(head)
    value_only = _index([head])
    assert value_only.values == {head}
    assert _same_as_the_alternation(value_only, full) == (
        _mask_secret_value(head) + tail
    )
    both = _index([head], shape_values=[full])
    assert _same_as_the_alternation(both, full) == _mask_secret_value(full)
    assert _same_as_the_alternation(both, f"x {full} y") == (
        f"x {_mask_secret_value(full)} y"
    )


def test_a_shape_token_found_next_to_punctuation_inside_a_run():
    secret = _derived("run-1", 12)
    index = _index(shape_values=[secret])
    other = secret[:1] + _derived("run-2", 10) + secret[-1:]
    assert _looks_like_a_secret(other)
    masked = _mask_secret_value(other)
    for text in (
        f"a.{other}.b",
        f"path/{other}",
        f"{other}:12",
        f"k={other},v",
        f"x{other}",
    ):
        _same_as_the_alternation(index, text)
    assert _same_as_the_alternation(index, f"a.{other}.b") == f"a.{masked}.b"
    assert _same_as_the_alternation(index, f"x{other}") == f"x{other}"


def test_a_shape_that_spans_whitespace_matches_across_it():
    value = f"{_derived('ws-1', 5)} {_derived('ws-2', 5)} {_derived('ws-3', 4)}"
    shape = secret_value_shape(value)
    assert shape.spans_whitespace
    index = _index(shape_values=[value])
    assert index.shapes == {shape}
    across = value[:2] + "q r s t u v w" + value[-1:]
    assert len(across) == len(value)
    flat = value[:2] + _derived("ws-4", len(value) - 3) + value[-1:]
    broken = value[:2] + "q r s\nt u v w" + value[-1:]
    assert len(broken) == len(value)
    for text in (f"a {across} b", f"a {flat} b", f"a {broken} b", across, value):
        _same_as_the_alternation(index, text)
    assert _same_as_the_alternation(index, f"a {flat} b") == (
        f"a {_mask_secret_value(flat)} b"
    )
    assert _same_as_the_alternation(index, f"a {broken} b") == f"a {broken} b"


def test_values_and_shapes_next_to_escapes():
    value = _derived("escape-1", 14)
    index = _index([value], shape_values=[value, _derived("escape-2", 13)])
    for text in (
        json.dumps({"k": value}),
        json.dumps({value: value}),
        f'\\"{value}\\"',
        f"\\u0027{value}\\u0027",
        f"\\n{value}\\n",
        f"%22{value}%22",
        f"&quot;{value}&quot;",
        f"\\{value}",
        f"{value}\\",
    ):
        _same_as_the_alternation(index, text)
    assert _same_as_the_alternation(index, json.dumps({"k": value})) == (
        json.dumps({"k": _mask_secret_value(value)})
    )


def test_matches_are_taken_left_to_right_without_overlap():
    first = _derived("order-1", 12) + "!" + _derived("order-2", 6)
    second = first[8:] + _derived("order-3", 8)
    third = _derived("order-4", 12)
    index = _index([first, second, third])
    for text in (
        f"{first},{third}",
        f"{first} {third} {first}",
        f"{first}{third}",
        f"{first[:8]}{second}",
        f"{third}.{third}",
        f"{third}{third}",
        f"{second} {first}",
    ):
        _same_as_the_alternation(index, text)


def test_values_set_directly_are_masked_whatever_they_look_like():
    index = _SecretIndex()
    word = "ab"
    punctuation = "!@#$%^&*"
    spaced = "ab cd ef"
    line = _derived("direct-1", 6) + "\n" + _derived("direct-2", 6)
    index.values = {word, punctuation, spaced, line}
    for text in (
        f"{word} {word}x x{word} {word}",
        f"[{punctuation}] {punctuation}{punctuation} a{punctuation}b",
        f"say {spaced} again {spaced}x",
        f"[{line}] {line}",
        "",
    ):
        _same_as_the_alternation(index, text)


def test_adding_after_masking_is_seen_by_the_next_text():
    first = _derived("add-1", 12)
    second = _derived("add-2", 12)
    index = _index([first])
    text = f"{first} {second}"
    assert index.mask_values(text) == f"{_mask_secret_value(first)} {second}"
    index.add_values([second])
    assert index.mask_values(text) == (
        f"{_mask_secret_value(first)} {_mask_secret_value(second)}"
    )
    index.values = {second}
    assert index.mask_values(text) == f"{first} {_mask_secret_value(second)}"
    index.add_shapes([secret_value_shape(first)])
    assert index.mask_values(text) == (
        f"{_mask_secret_value(first)} {_mask_secret_value(second)}"
    )


def test_an_index_with_nothing_to_mask_returns_the_text():
    text = "nothing here"
    assert _SecretIndex().mask_values(text) is text


def test_a_long_run_of_short_pieces_is_masked_like_the_alternation():
    value = _derived("dots-1", 12) + "." + _derived("dots-2", 9)
    index = _index([value], shape_values=[value])
    pieces = [_derived(f"dots-{n}", 3) for n in range(3, 400)]
    text = ".".join(pieces[:200] + [value] + pieces[200:])
    masked = _same_as_the_alternation(index, text)
    assert _mask_secret_value(value) in masked


def test_the_word_test_is_the_regex_word_class():
    word = re.compile(r"\w")
    disagreements: List[int] = []
    for code in range(sys.maxunicode + 1):
        character = chr(code)
        if bool(word.match(character)) != secret_masking._is_word(character):
            disagreements.append(code)
    assert disagreements == []


_RANDOM_ALPHABET = (
    string.ascii_letters[:12] + string.digits[:4] + "_-.!$#@=:;,'\"/\\ \t" + "éß中"
)


def _random_text(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(_RANDOM_ALPHABET) for _ in range(length))


def _random_index(rng: random.Random) -> _SecretIndex:
    index = _SecretIndex()
    values: Set[str] = set()
    for _ in range(rng.randint(1, 5)):
        length = rng.randint(8, 16)
        value = _random_text(rng, length)
        if "\n" not in value and value.strip():
            values.add(value)
    index.values = values
    shapes = []
    for _ in range(rng.randint(0, 4)):
        length = rng.randint(8, 20)
        shapes.append(secret_value_shape(_random_text(rng, length)))
    index.add_shapes(shapes)
    return index


def _random_haystack(rng: random.Random, index: _SecretIndex) -> str:
    pieces: List[str] = []
    for _ in range(rng.randint(1, 8)):
        choice = rng.random()
        if choice < 0.35 and index.values:
            pieces.append(rng.choice(sorted(index.values)))
        elif choice < 0.6 and index.shapes:
            shape = rng.choice(sorted(index.shapes, key=lambda s: (s.length, s.prefix)))
            hidden = shape.length - len(shape.prefix) - len(shape.suffix)
            middle = "".join(
                rng.choice(string.ascii_lowercase + string.digits + "!.-")
                for _ in range(hidden)
            )
            pieces.append(shape.prefix + middle + shape.suffix)
        else:
            pieces.append(_random_text(rng, rng.randint(0, 14)))
    glue = [rng.choice(["", " ", ".", ",", "\n", "=", "(", "é"]) for _ in pieces]
    return "".join(piece + glue[number] for number, piece in enumerate(pieces))


@pytest.mark.parametrize("seed", range(40))
def test_random_texts_are_masked_like_the_alternation(seed):
    rng = random.Random(20261110 + seed)
    index = _random_index(rng)
    for _ in range(25):
        _same_as_the_alternation(index, _random_haystack(rng, index))


# ---------------------------------------------------------------------------
# The cost of a text does not grow with the number of values
# ---------------------------------------------------------------------------


def _words(seed: int, count: int) -> List[str]:
    rng = random.Random(seed)
    return [
        "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 9)))
        for _ in range(count)
    ]


def _checks(index: _SecretIndex, text: str) -> int:
    """How many candidates the plan compared to mask ``text``."""
    index.mask_values("a warm up text")
    plan = index._plan
    assert plan is not None
    before = plan.checks
    index.mask_values(text)
    return plan.checks - before


def test_values_that_share_their_first_word_run_cost_no_more_checks():
    # Real secrets of one family start alike (an API key prefix, a token
    # header); they differ in their longest word run. Looking a value up by its
    # first run made every occurrence of the shared run compare every value.
    def values_of(count: int) -> List[str]:
        return [
            f"sk-proj-{_derived(f'family-{number}', 20 + number % 3)}"
            for number in range(count)
        ]

    few_values, many_values = values_of(2), values_of(2_000)
    words = _words(3, 300)
    text = " ".join(f"sk-proj-{word}" for word in words)
    text += f" and {few_values[0]} and ({few_values[1]})"
    few = _checks(_index(few_values), text)
    many_index = _index(many_values)
    many = _checks(many_index, text)
    assert many_index.mask_values(text) == _reference(many_index, text)
    assert many <= few + 2, (few, many)


def test_a_few_values_use_one_alternation_and_more_use_the_lookups(monkeypatch):
    monkeypatch.setattr(secret_masking, "_ALTERNATION_MAX_BRANCHES", 8)

    def index_of(count):
        values = [_derived(f"switch-{number}", 14) for number in range(count)]
        return _index(values, shape_values=values)

    text = " ".join(f"x {_derived(f'switch-{n}', 14)}." for n in range(6)) + " tail"
    for count, plan_type in (
        (1, secret_masking._AlternationPlan),
        (4, secret_masking._AlternationPlan),
        (5, secret_masking._MaskPlan),
        (6, secret_masking._MaskPlan),
    ):
        index = index_of(count)
        masked = _same_as_the_alternation(index, text)
        assert type(index._plan) is plan_type, count
        assert masked != text, count


def test_a_value_whose_longest_run_is_inside_keeps_its_edge_boundaries():
    value = "3a\th#" + _derived("inside-edge", 12) + "!"
    index = _index([value])
    assert index.values == {value}
    masked = _mask_secret_value(value)
    assert _same_as_the_alternation(index, f"({value})") == f"({masked})"
    assert _same_as_the_alternation(index, f"é{value}") == f"é{value}"
    assert _same_as_the_alternation(index, f"_{value}") == f"_{value}"
    assert _same_as_the_alternation(index, f"{value}x") == f"{masked}x"


def test_values_that_share_a_run_in_the_middle_are_still_found():
    shared = _derived("middle-run", 16)
    values = [
        f"{_derived(f'edge-{n}', 5)}-{shared}-{_derived(f'tail-{n}', 6)}"
        for n in range(30)
    ]
    index = _index(values)
    assert len(index.values) == 30
    for value in values[::7]:
        _same_as_the_alternation(index, f"x [{value}] y")
    _same_as_the_alternation(index, " ".join(values))


def test_loose_shapes_cost_checks_that_do_not_grow_with_their_number():
    # A secret that ends in punctuation (base64 padding) makes a shape that
    # is looked up by its first character, then by length. The checks at a
    # position are bounded by the different lengths, here three, and not by the
    # number of shapes with that first character.
    def values_of(count: int) -> List[str]:
        return [
            _derived(f"loose-{number}", (12, 16, 20)[number % 3]) + "=="
            for number in range(count)
        ]

    text = " ".join(
        "".join(random.Random(number).choices(_ALPHABET, k=14 + number % 17))
        for number in range(400)
    )
    positions = sum(len(found.group()) - 7 for found in re.finditer(r"\S{8,}", text))
    for count in (6, 60, 2_000):
        index = _index(values_of(count), shape_values=values_of(count))
        assert index._plan is None
        assert _checks(index, text) <= 3 * positions, count
        assert index.mask_values(text) == _reference(index, text)


def test_the_plan_for_many_values_holds_no_alternation_over_them():
    values = [
        _derived(f"scale-{number}", 11 + number % 28) + str(number % 10)
        for number in range(2_000)
    ]
    index = _index(values, shape_values=values)
    assert len(index.values) == 2_000
    assert index.mask_values("warm up") == "warm up"
    plan = index._plan
    assert plan is not None
    assert plan.fallback_branches == 0
    ws = _index(
        shape_values=[
            f"{_derived('plan-1', 5)} {_derived('plan-2', 5)} {_derived('plan-3', 4)}"
        ]
    )
    assert ws.mask_values("warm up") == "warm up"
    assert ws._plan is not None and ws._plan.fallback_branches == 1
