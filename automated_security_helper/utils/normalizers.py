# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import re

from automated_security_helper.utils.get_shortest_name import get_shortest_name

# ``_`` is the escape character. Every token it starts has a length fixed by
# its second character, so a normalized name reads back to exactly one input
# and two distinct inputs never share a name.
_FIXED_ESCAPES = {
    ".": "__",
    "_": "_0",
    "/": "_s",
}

_WORD_CHARACTER = re.compile(r"\w")


def _escape(character: str) -> str:
    fixed = _FIXED_ESCAPES.get(character)
    if fixed is not None:
        return fixed
    if character == "-" or _WORD_CHARACTER.fullmatch(character):
        return character
    code_point = ord(character)
    if code_point < 0x100:
        return f"_x{code_point:02x}"
    if code_point < 0x10000:
        return f"_u{code_point:04x}"
    return f"_U{code_point:08x}"


def get_normalized_filename(str_to_normalize: str | Path) -> str:
    """Returns a normalized filename for the given string.

    The result holds only word characters and ``-``. ``.`` becomes ``__``,
    ``/`` becomes ``_s``, a literal ``_`` becomes ``_0`` and any other
    character becomes ``_x``, ``_u`` or ``_U`` followed by its code point in
    hex. Distinct inputs get distinct names, so an output file or directory
    named after one input is never shared with another.

    Args:
        str_to_normalize (str | Path): The string to normalize.

    Returns:
        str: The normalized filename.
    """
    if isinstance(str_to_normalize, Path):
        str_to_normalize = get_shortest_name(input=str_to_normalize)

    return "".join(_escape(character) for character in str(str_to_normalize))
