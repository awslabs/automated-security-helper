# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import hashlib
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
    # With fold_case a character is left as it is only when it is its own case
    # folding and folding its upper-case form gives it back, so no two names
    # that are left as they are fold to one. Lower-casing was not enough: the
    # final sigma, the long s, the micro sign and the dotless i are lower-case
    # already and still share a folding or an upper-case form with the sigma, s,
    # mu and i, which a case-insensitive filesystem reads as one name.
    keeps_its_case = not fold_case or (
        character == character.casefold() and character.upper().casefold() == character
    )
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


#: How many characters of the input's SHA-256 a cut name carries.
_DIGEST_CHARS = 12

#: What joins a cut name to its digest. ``_z`` is not one of the tokens the
#: escaper writes (``__``, ``_0``, ``_s``, ``_x``, ``_u``, ``_U``), so a cut name
#: holds a token no uncut name holds and the two never meet, whatever the input
#: spells. A plain ``-`` could not do this: ``-`` passes through as it is, so an
#: input spelled like a cut name was returned as the very same name.
_DIGEST_SEPARATOR = "_z"


def _cut_with_digest(name: str, source: str, max_bytes: int) -> str:
    """*name* when it fits *max_bytes* of UTF-8, else its first bytes and a digest
    of *source*, ``<cut>_z<digest>``, at most *max_bytes* in all."""
    encoded = name.encode("utf-8")
    if len(encoded) <= max_bytes:
        return name
    digest = hashlib.sha256(source.encode("utf-8", "surrogateescape")).hexdigest()[
        :_DIGEST_CHARS
    ]
    room = max_bytes - len(digest) - len(_DIGEST_SEPARATOR)
    # A cut that ends in an escape character would join the separator into a
    # token of its own (``_`` and ``_z`` read as ``__`` and ``z``), so it is
    # dropped; a cut through the rest of a token leaves a token no name holds.
    cut = encoded[:room].decode("utf-8", "ignore").rstrip("_")
    return f"{cut}{_DIGEST_SEPARATOR}{digest}"


def get_normalized_filename(
    str_to_normalize: str | Path,
    *,
    fold_case: bool = False,
    max_bytes: int | None = None,
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
    that is not its own case folding, or whose upper-case form does not fold back
    to it, is then escaped as its code point (``A`` is ``_x41``, the final sigma
    is ``_u03c2``), so two names that differ in case alone, or whose letters fold
    to one, are no longer the same once case is ignored. The names are different
    from the default ones, so a caller turns it on from the start rather than for
    a name it has already written.

    The escapes make a name longer than the input: ``_`` and ``.`` take two
    characters, a space or other ASCII punctuation four, another non-word
    character in the basic plane six and one outside it ten, where a run of any
    of them was once a single ``-``. A path with many of them can run past the 255 bytes a file
    name may take, and the directory made for it then fails to be made. A caller
    that makes a name of the result passes ``max_bytes`` (UTF-8 bytes): a longer
    name is cut and ends in ``_z`` and a digest of the whole input, so two long
    names that share their first bytes stay apart, and the name is never longer
    than ``max_bytes``. ``_z`` is a token the escaper never writes, so no input
    has an uncut name equal to a cut one. A name that fits is returned as it is.

    Args:
        str_to_normalize (str | Path): The string to normalize.
        fold_case (bool): Escape every letter that is not its own case folding,
            or whose upper-case form does not fold back to it, so the result is
            unique on a case-insensitive filesystem too.
        max_bytes (int | None): The most bytes the name may take, at least 16
            when given. None puts no limit on it.

    Returns:
        str: The normalized filename.

    Raises:
        ValueError: ``max_bytes`` is too small to hold a digest and a cut.
    """
    if max_bytes is not None and max_bytes < _DIGEST_CHARS + 4:
        raise ValueError(
            f"max_bytes must be at least {_DIGEST_CHARS + 4} to hold a digest "
            f"and a cut of the name, not {max_bytes}"
        )
    if isinstance(str_to_normalize, Path):
        str_to_normalize = get_shortest_name(input=str_to_normalize)

    source = str(str_to_normalize)
    name = "".join(_escape(character, fold_case) for character in source)
    if max_bytes is None:
        return name
    return _cut_with_digest(name, source, max_bytes)
