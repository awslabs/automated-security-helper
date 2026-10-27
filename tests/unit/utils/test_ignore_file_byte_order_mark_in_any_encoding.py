# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignore file's byte order mark is skipped whatever encoding it is read with.

Ignore files are read with the locale's encoding. On Windows, Python 3.10 to 3.14
without UTF-8 mode uses the ANSI code page, where the three bytes of a UTF-8 byte
order mark decode as "\\xef\\xbb\\xbf" (cp1252) rather than U+FEFF. Only U+FEFF was
skipped, so there the mark stayed in the first pattern, which then matched no
file. That is where files with a mark come from: PowerShell 5.1 writes one with
-Encoding utf8. git skips the mark's bytes before the first pattern
(skip_utf8_bom in dir.c), whatever they decode to.

The handles here are made with an explicit encoding, so these run on any platform.
"""

from __future__ import annotations

import io

import pytest

from automated_security_helper.utils.get_scan_set import (
    IGNORE_FILE_NEWLINE,
    ignore_file_lines,
)

BOM = b"\xef\xbb\xbf"

#: The mark as UTF-8 decodes it. Spelled with chr() so the source holds no
#: invisible character.
U_FEFF = chr(0xFEFF)


def _handle(data: bytes, encoding: str, errors: str = "strict") -> io.TextIOWrapper:
    return io.TextIOWrapper(
        io.BytesIO(data), encoding=encoding, errors=errors, newline=IGNORE_FILE_NEWLINE
    )


@pytest.mark.parametrize("encoding", ["utf-8", "cp1252", "cp932"])
def test_the_mark_is_skipped_as_a_surrogateescape_handle_decodes_it(encoding):
    """Ignore files are read with surrogateescape, as git reads any bytes. Under
    cp932 the mark's bytes do not decode strictly at all."""
    lines = ignore_file_lines(
        _handle(BOM + b"bomdir/\n", encoding, errors="surrogateescape")
    )

    assert lines == ["bomdir/\n"]


@pytest.mark.parametrize("encoding", ["utf-8", "cp1252", "latin-1"])
def test_the_mark_is_skipped_as_the_handle_decodes_it(encoding):
    lines = ignore_file_lines(_handle(BOM + b"bomdir/\nother.py\n", encoding))

    assert lines == ["bomdir/\n", "other.py\n"]


@pytest.mark.parametrize("encoding", ["utf-8", "cp1252"])
def test_only_the_first_mark_is_skipped(encoding):
    """git skips one mark; a second one is part of the first pattern."""
    lines = ignore_file_lines(_handle(BOM + BOM + b"twice.py\n", encoding))

    assert lines == [BOM.decode(encoding) + "twice.py\n"]


@pytest.mark.parametrize("encoding", ["utf-8", "cp1252"])
def test_a_mark_on_a_later_line_is_kept(encoding):
    lines = ignore_file_lines(_handle(b"first.py\n" + BOM + b"second.py\n", encoding))

    assert lines == ["first.py\n", BOM.decode(encoding) + "second.py\n"]


def test_an_encoding_that_cannot_decode_the_mark_reads_the_file_whole():
    """ASCII cannot hold the mark's bytes, so a file read with it holds none."""
    assert ignore_file_lines(_handle(b"x.py\n", "ascii")) == ["x.py\n"]


def test_lines_with_no_encoding_lose_a_leading_u_feff_only():
    assert ignore_file_lines([U_FEFF + "x.py\n", "y.py\n"]) == ["x.py\n", "y.py\n"]
