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


def _escape(character: str, fold_case: bool = False) -> str:
    fixed = _FIXED_ESCAPES.get(character)
    if fixed is not None:
        return fixed
    # With fold_case a letter that has a lower-case form is escaped, so every
    # character left as it is already is lower-case and no two names differ in
    # case alone.
    keeps_its_case = not (fold_case and character.lower() != character)
    if character == "-" or (_WORD_CHARACTER.fullmatch(character) and keeps_its_case):
        return character
    code_point = ord(character)
    if code_point < 0x100:
        return f"_x{code_point:02x}"
    if code_point < 0x10000:
        return f"_u{code_point:04x}"
    # ``_U`` differs from ``_u`` in case only, and the two never collide when
    # case is ignored: a four-digit token never begins ``0001`` or ``0010``,
    # since code points below 0x100 take the two-digit token.
    return f"_U{code_point:08x}"


def get_normalized_filename(
    str_to_normalize: str | Path, *, fold_case: bool = False
) -> str:
    """Returns a normalized filename for the given string.

    The result holds only word characters and ``-``. ``.`` becomes ``__``,
    ``/`` becomes ``_s``, a literal ``_`` becomes ``_0`` and any other
    character becomes ``_x``, ``_u`` or ``_U`` followed by its code point in
    hex. Distinct inputs get distinct names, so an output file or directory
    named after one input is never shared with another.

    That holds for the strings. On a filesystem that ignores case (APFS and
    NTFS by default) ``A.yaml`` and ``a.yaml`` are still one directory, since
    letters pass through as they are. A caller that names a file or directory on
    such a filesystem from the result passes ``fold_case=True``: every letter
    that has a lower-case form is then escaped as its code point (``A`` is
    ``_x41``), so two names that differ in case alone are no longer the same once
    case is ignored. The names are different from the default ones, so a caller
    turns it on from the start rather than for a name it has already written.

    Args:
        str_to_normalize (str | Path): The string to normalize.
        fold_case (bool): Escape letters that have a lower-case form, so the
            result is unique on a case-insensitive filesystem too.

    Returns:
        str: The normalized filename.
    """
    if isinstance(str_to_normalize, Path):
        str_to_normalize = get_shortest_name(input=str_to_normalize)

    return "".join(_escape(character, fold_case) for character in str(str_to_normalize))
