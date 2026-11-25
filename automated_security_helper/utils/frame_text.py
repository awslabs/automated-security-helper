# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Carrying text and integers that a polars column cannot hold, through one.

Polars strings are UTF-8 and polars integers here are 64-bit. Finding fields are
neither: a path can hold a lone surrogate (an ``os.fsdecode`` of undecodable
bytes), and a line number is an unbounded Python int. Both used to flow through
``Counter`` and ``list.sort``; these helpers keep that true on a frame.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


def wire(text: str | None) -> str | None:
    """*text* as a string polars can hold, with its equality and its order kept.

    The UTF-8 bytes of the text, surrogates passed through, read as Latin-1 are
    one-to-one with the text, and sorting them sorts as the text's code points do.
    """
    if text is None:
        return None
    return text.encode("utf-8", "surrogatepass").decode("latin-1")


def unwire(text: str) -> str:
    """The text :func:`wire` made *text* from."""
    return text.encode("latin-1").decode("utf-8", "surrogatepass")


def wire_cell(value: Any) -> Optional[str]:
    """*value* as a frame cell: null for None, else its text through :func:`wire`.

    A value that is not a string is read as its ``str``.
    """
    return (
        None if value is None else wire(value if isinstance(value, str) else str(value))
    )


def unwire_cell(text: Optional[str]) -> Optional[str]:
    """The text :func:`wire_cell` made *text* from; null stays null."""
    return None if text is None else unwire(text)


def ranks(values: Iterable[Optional[int]]) -> Dict[int, int]:
    """Dense ranks of the distinct ints in *values*, so order and ties survive.

    A rank is a small non-negative int a 64-bit column holds, whatever the value.
    """
    return {
        value: rank
        for rank, value in enumerate(sorted({v for v in values if v is not None}))
    }
