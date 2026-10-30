# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_normalized_filename maps distinct paths to distinct names.

The converters and the cfn-nag scanner name a per-input output after the
normalized input path. Two inputs with one normalized name share that output,
so one input's converted file or results directory overwrites the other's and
the first is never scanned. The mapping therefore has to be injective: every
character that is not a plain word character is escaped behind ``_``, and a
literal ``_`` is escaped too, so the escaped form can always be read back.
"""

from pathlib import PurePosixPath, PureWindowsPath
import re

import pytest

from automated_security_helper.utils.normalizers import get_normalized_filename

pytestmark = pytest.mark.unit


_FIXED_TOKENS = {"__": ".", "_0": "_", "_s": "/"}


def decode(normalized: str) -> str:
    """Read a normalized name back to the path it was made from.

    This is the inverse the escape scheme promises: a literal character stands
    for itself, and ``_`` starts a token whose second character fixes its
    length (``_`` ``0`` ``s`` for the fixed tokens, ``x`` ``u`` ``U`` for two,
    four and eight hex digits). A name that cannot be read back is a defect.
    """
    out = []
    i = 0
    while i < len(normalized):
        ch = normalized[i]
        if ch != "_":
            out.append(ch)
            i += 1
            continue
        token = normalized[i : i + 2]
        if token in _FIXED_TOKENS:
            out.append(_FIXED_TOKENS[token])
            i += 2
            continue
        width = {"_x": 2, "_u": 4, "_U": 8}[token]
        digits = normalized[i + 2 : i + 2 + width]
        assert re.fullmatch(r"[0-9a-f]+", digits) and len(digits) == width, (
            normalized,
            i,
        )
        out.append(chr(int(digits, 16)))
        i += 2 + width
    return "".join(out)


# Pairs the previous mapping folded to one name: ``/`` and ``.`` both became
# ``__``, every other run of non-word characters became ``-``, and a leading
# ``-`` was dropped. The ``x_0y`` pair is the escape of the escape character:
# a literal ``_0`` in an input must not read as an escaped ``_``.
COLLIDING_PAIRS = [
    ("a/b.ipynb", "a.b.ipynb"),
    ("dir/nb.ipynb", "dir.nb.ipynb"),
    ("a b.zip", "a-b.zip"),
    ("x__y.ipynb", "x.y.ipynb"),
    ("x_0y.ipynb", "x_y.ipynb"),
    ("-nb.ipynb", "nb.ipynb"),
    ("a--b.yaml", "a-b.yaml"),
    ("a.b/c.yaml", "a/b.c.yaml"),
]


@pytest.mark.parametrize(("left", "right"), COLLIDING_PAIRS)
def test_distinct_paths_get_distinct_names(left, right):
    assert get_normalized_filename(left) != get_normalized_filename(right)


def test_names_made_only_of_word_characters_and_dots_keep_their_shape():
    """The shape every converted-file and results-directory test pins."""
    assert get_normalized_filename("nb.ipynb") == "nb__ipynb"
    assert get_normalized_filename("real.yaml") == "real__yaml"
    assert get_normalized_filename("a.b.c") == "a__b__c"
    assert get_normalized_filename("main.py") == "main__py"


def test_separators_and_the_escape_character_have_their_own_tokens():
    assert get_normalized_filename("dir/nb.ipynb") == "dir_snb__ipynb"
    assert get_normalized_filename("my_nb.ipynb") == "my_0nb__ipynb"
    assert get_normalized_filename("/tmp/a.yaml") == "_stmp_sa__yaml"


def test_other_characters_are_hex_escaped_and_hyphens_pass_through():
    assert get_normalized_filename("a b.zip") == "a_x20b__zip"
    assert get_normalized_filename("a-b.zip") == "a-b__zip"
    assert get_normalized_filename("-nb.ipynb") == "-nb__ipynb"
    assert get_normalized_filename("caf\u00e9.ipynb") == "caf\u00e9__ipynb"
    assert get_normalized_filename("a\u2603b.py") == "a_u2603b__py"
    grinning = chr(0x1F600)
    assert get_normalized_filename(f"a{grinning}b.py") == f"a_U{0x1F600:08x}b__py"
    assert get_normalized_filename("a\\b:c.yaml") == "a_x5cb_x3ac__yaml"


def test_output_holds_only_filename_safe_characters():
    for text in ["a/b.c", "a b", '\\x:y*?"<>|', "\u00e9\u2603" + chr(0x1F600), "_-"]:
        normalized = get_normalized_filename(text)
        assert re.fullmatch(r"[\w-]*", normalized), normalized
        assert "/" not in normalized


ROUND_TRIP_INPUTS = [
    "",
    "nb.ipynb",
    "a/b.ipynb",
    "a.b.ipynb",
    "a b.zip",
    "a-b.zip",
    "x__y.ipynb",
    "x_0y.ipynb",
    "x_s.ipynb",
    "_x20.ipynb",
    "-nb.ipynb",
    "/tmp/pytest/nb.ipynb",
    "a\\b:c.yaml",
    "caf\u00e9/\u2603/" + chr(0x1F600) + ".ipynb",
    "trailing/",
    "...",
    "___",
    "\udcff.ipynb",
]


@pytest.mark.parametrize("text", ROUND_TRIP_INPUTS)
def test_every_name_reads_back_to_its_input(text):
    assert decode(get_normalized_filename(text)) == text


def test_all_inputs_in_a_corpus_get_unique_names():
    inputs = ROUND_TRIP_INPUTS + [left for left, _ in COLLIDING_PAIRS]
    inputs += [right for _, right in COLLIDING_PAIRS]
    unique = sorted(set(inputs))
    names = [get_normalized_filename(text) for text in unique]
    assert len(set(names)) == len(unique)


def test_a_pure_path_is_normalized_like_its_string():
    path = PurePosixPath("dir/nb.ipynb")
    assert get_normalized_filename(str(path)) == "dir_snb__ipynb"
    # The pure path itself, not only its string: a PurePosixPath is not a Path,
    # so it is escaped as its text, with no shortest-name step.
    assert get_normalized_filename(path) == "dir_snb__ipynb"


def test_a_pure_windows_path_is_escaped_as_written_backslash_included():
    """Only a concrete ``Path`` goes through get_shortest_name; a PureWindowsPath
    is text to the normalizer, so its backslash is escaped as the byte ``_x5c``
    and reads back to the same spelling. Whether separators should be folded
    first is a design question, pinned here as the behavior it has."""
    path = PureWindowsPath("dir\\nb.ipynb")

    name = get_normalized_filename(path)

    assert name == "dir_x5cnb__ipynb"
    assert decode(name) == "dir\\nb.ipynb"
    assert name != get_normalized_filename(PurePosixPath("dir/nb.ipynb"))
