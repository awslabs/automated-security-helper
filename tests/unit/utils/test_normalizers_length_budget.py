# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A normalized name can be given a length budget.

The escapes make a name longer than its input (``_`` takes two characters, a space
four), where a run of non-word characters was once a single ``-``. A path with many
of them ran past the 255 bytes a file name may take, and the directory made from
its name failed to be made, so the input was never scanned. ``max_bytes`` cuts a
long name and ends it in a digest of the whole input.
"""

import hashlib
import re

import pytest

from automated_security_helper.utils.normalizers import get_normalized_filename

pytestmark = pytest.mark.unit

DIGEST_TAIL = re.compile(r"_z[0-9a-f]{12}$")
#: U+00E9: a word character, so it passes through as two bytes of UTF-8.
E_ACUTE = chr(0xE9)


def test_a_name_that_fits_is_returned_as_it_is():
    assert get_normalized_filename("dir/nb.ipynb", max_bytes=200) == (
        get_normalized_filename("dir/nb.ipynb")
    )
    assert get_normalized_filename("a" * 200, max_bytes=200) == "a" * 200


def test_a_long_name_is_cut_and_ends_in_a_digest():
    source = "_ " * 120
    name = get_normalized_filename(source, max_bytes=200)

    # Seven hundred and twenty characters of escapes, cut to the budget.
    assert len(get_normalized_filename(source)) == 720
    assert len(name.encode("utf-8")) <= 200
    assert DIGEST_TAIL.search(name)
    assert name.startswith("_0_x20_0_x20")


def test_the_budget_is_met_at_its_edge():
    name = get_normalized_filename("a" * 201, max_bytes=200)

    assert len(name.encode("utf-8")) <= 200
    assert DIGEST_TAIL.search(name)


def test_two_long_names_that_share_their_first_bytes_stay_apart():
    shared = "_ " * 150
    first = get_normalized_filename(shared + "tail-one", max_bytes=200)
    second = get_normalized_filename(shared + "tail-two", max_bytes=200)

    assert first != second
    assert len(first.encode("utf-8")) <= 200
    assert len(second.encode("utf-8")) <= 200


def test_an_input_spelled_like_a_cut_name_does_not_take_its_name():
    # A cut name was ``<first bytes>-<digest>``, and ``-`` passes through the
    # escaper as it is, so an input spelled that way came back as the same name.
    budget = 40
    long_input = "a" * 60
    digest = hashlib.sha256(long_input.encode("utf-8")).hexdigest()[:12]
    lookalike = "a" * 27 + "-" + digest

    cut = get_normalized_filename(long_input, max_bytes=budget)
    uncut = get_normalized_filename(lookalike, max_bytes=budget)

    assert len(lookalike.encode("utf-8")) == budget
    assert uncut == lookalike
    assert cut != uncut
    assert len(cut.encode("utf-8")) <= budget
    assert DIGEST_TAIL.search(cut)


def test_a_cut_that_ends_in_an_escape_does_not_read_as_a_longer_token():
    # Escaped, ``.`` is ``__`` and a following ``z`` is not part of the token, so
    # an uncut name can hold ``__z``. A cut that ended on one ``_`` must not
    # join the separator into that spelling.
    budget = 30
    long_input = "a" * 15 + "." + "b" * 40
    cut = get_normalized_filename(long_input, max_bytes=budget)
    digest = cut[-12:]
    lookalike = get_normalized_filename("a" * 15 + ".z" + digest)

    assert len(cut.encode("utf-8")) <= budget
    assert DIGEST_TAIL.search(cut)
    assert cut != lookalike


def test_a_cut_through_a_multibyte_character_leaves_valid_text():
    name = get_normalized_filename(E_ACUTE * 150, max_bytes=200)

    assert len(name.encode("utf-8")) <= 200
    assert name.encode("utf-8").decode("utf-8") == name
    assert DIGEST_TAIL.search(name)


def test_without_a_budget_the_name_is_as_long_as_it_is():
    assert len(get_normalized_filename("_ " * 120)) == 720


def test_a_budget_too_small_for_a_digest_is_refused():
    with pytest.raises(ValueError, match="max_bytes"):
        get_normalized_filename("a.yaml", max_bytes=10)
