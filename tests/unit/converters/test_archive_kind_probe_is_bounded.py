# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Telling a tar from a file that only has an archive's name reads one block.

``archive_kind`` decides how the converter extracts a file before the bounded tar
stream exists. It used to ask ``tarfile.is_tarfile``, which opens the archive and
reads its first member's header whole: a pax header or a GNU long name is read to
the size its block declares, decompressed where the archive is compressed, with
nothing bounding it. The probe now reads the first block through the same
decompressor and bounded stream the listing uses, and judges the kind from that
block alone, so a tar whose first header declares megabytes costs the probe 512
bytes of content.

The archives here open with a pax header that declares 2 MiB and carries 2 MiB
of data that does not compress, so the bytes the probe takes from the file say
which way it read: all of the header, or one block of it.
"""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from tests.utils.archive_builders import MEBIBYTE, incompressible

pytestmark = pytest.mark.unit

PAX_BYTES = 2 * MEBIBYTE
#: Far below the pax header's size, far above one block plus a decompressor's
#: read-ahead (gzip reads its input in chunks of at most 128 KiB).
PROBE_BUDGET = MEBIBYTE


class CountingHandle(io.BytesIO):
    """A file whose reads are counted, as the converter's open handle would be."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        self.bytes_read += len(data)
        return data


def _padded(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % tarfile.BLOCKSIZE)


def _header(info: tarfile.TarInfo) -> bytes:
    return info.tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape")


def pax_first_tar() -> bytes:
    """A tar whose first block is a pax header declaring PAX_BYTES of records.

    The records start with a letter, so tarfile parses none of them and moves on
    to the member after them; what it reads to get there is the whole header.
    """
    pax = tarfile.TarInfo("././@PaxHeader")
    pax.type = tarfile.XHDTYPE
    pax.size = PAX_BYTES
    records = b"x" + incompressible(PAX_BYTES - 1, seed=7)
    member = tarfile.TarInfo("a.js")
    payload = b"a = 1\n"
    member.size = len(payload)
    return (
        _header(pax)
        + _padded(records)
        + _header(member)
        + _padded(payload)
        + b"\0" * (2 * tarfile.BLOCKSIZE)
    )


@pytest.mark.parametrize(
    ("name", "compress"),
    [
        pytest.param("lib/b.tar", False, id="tar"),
        pytest.param("lib/b.tar.gz", True, id="tar-gz"),
    ],
)
def test_the_kind_of_a_tar_with_a_large_first_header_is_read_from_one_block(
    name, compress
):
    content = pax_first_tar()
    if compress:
        content = gzip.compress(content, mtime=0)
    handle = CountingHandle(content)
    handle.seek(3)

    assert archive_converter.archive_kind(name, handle) == "tar"

    assert handle.bytes_read < PROBE_BUDGET, (
        f"the probe read {handle.bytes_read} bytes of a file whose first header "
        f"declares {PAX_BYTES}; one block through the bounded stream was expected"
    )
    # Left at its start, for the caller that reads the file next.
    assert handle.tell() == 0


@pytest.mark.parametrize(
    ("content", "kind"),
    [
        # A file NAMED as a tar whose first block is zeros is an empty tar, as
        # tarfile.open reads it (is_tarfile says True); the plain-gzip decision
        # reads the same block the other way, below.
        pytest.param(b"\0" * (2 * tarfile.BLOCKSIZE), "tar", id="end-blocks-only"),
        pytest.param(
            gzip.compress(b"\0" * (300 * 1024), mtime=0),
            "tar",
            id="gz-of-zeros-named-tar",
        ),
        pytest.param(b"\0" * 100, None, id="short-zeros"),
        pytest.param(b"x" * tarfile.BLOCKSIZE, None, id="a-block-of-text"),
        pytest.param(gzip.compress(b"x" * 600, mtime=0), None, id="gz-of-text"),
        pytest.param(b"\x1f\x8b" + b"\0" * 600, None, id="gz-magic-damaged"),
    ],
)
def test_content_that_is_not_a_tar_header_is_not_a_tar(content, kind):
    handle = CountingHandle(content)

    assert archive_converter.archive_kind("lib/b.tar", handle) == kind
    assert handle.tell() == 0


@pytest.mark.parametrize(
    ("content", "holds"),
    [
        pytest.param(b"\0" * (300 * 1024), False, id="zeros-are-one-file"),
        pytest.param(b"x" * 600, False, id="text-is-one-file"),
        pytest.param(pax_first_tar(), True, id="a-tar-is-a-tarball"),
    ],
)
def test_the_plain_gzip_decision_reads_a_zero_block_as_a_file(content, holds):
    """A ``.gz`` whose content starts with zeros is one file of zeros and goes to
    the plain-gzip path; the same block in a file NAMED as a tar is an empty tar
    (the test above). The two readings are the two callers of the header check."""
    handle = io.BytesIO(gzip.compress(content, mtime=0))

    assert archive_converter._gzip_holds_a_tar(handle) is holds
    assert handle.tell() == 0


def _header_with_negative_size(member_type: bytes) -> bytes:
    """A one-member tar whose header is of ``member_type`` with a size field of
    base-256 -1, followed by end blocks."""
    info = tarfile.TarInfo("entry")
    info.type = member_type
    raw = bytearray(_header(info))
    raw[124:136] = b"\xff" * 12
    checksum = sum(raw[:148]) + 8 * 32 + sum(raw[156:512])
    raw[148:156] = b"%06o\0 " % checksum
    return bytes(raw) + b"\0" * (2 * tarfile.BLOCKSIZE)


@pytest.mark.parametrize(
    "member_type",
    [
        pytest.param(tarfile.DIRTYPE, id="directory"),
        pytest.param(tarfile.SYMTYPE, id="symlink"),
        pytest.param(tarfile.REGTYPE, id="regular"),
    ],
)
def test_a_negative_size_is_refused_exactly_where_tarfile_refuses_it(member_type):
    """tarfile reads a size for a regular file and an extended header and never
    for a directory or a link, so a directory header with a negative size opens;
    the probe follows tarfile type by type (the expected value is what tarfile
    itself does with the same bytes)."""
    data = _header_with_negative_size(member_type)
    try:
        with tarfile.open(fileobj=io.BytesIO(data)):
            tarfile_opens = True
    except tarfile.TarError:
        tarfile_opens = False

    kind = archive_converter.archive_kind("lib/b.tar", io.BytesIO(data))

    assert (kind == "tar") is tarfile_opens
