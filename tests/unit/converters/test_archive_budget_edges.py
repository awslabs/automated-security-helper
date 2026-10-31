# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two paths the other archive tests reach only through stand-ins.

A member size below zero is refused for ``max_member_bytes``. The tarfile of a
current Python release already refuses a header whose size field is negative, so the
budget is tested with a crafted ``TarInfo``, and the parser's own refusal with a
crafted header, which the converter then records as an archive it cannot read. A
tarfile from before that fix (3.10.11, 3.11.9 and 3.12.10 on the macOS runners)
hands the member back with size -1, and the budget refuses the archive instead.

The tar copy path, used where tarfile has no "data" filter, is checked with a real
tar whose member is larger than one copy chunk, so the chunked copy has to loop to
write it whole.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfigOptions,
)
from tests.utils.archive_builders import incompressible

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


def test_a_negative_member_size_is_refused_for_max_member_bytes():
    member = tarfile.TarInfo("n.py")
    member.size = -1
    budget = archive_converter._ExtractionBudget(
        ArchiveConverterConfigOptions(), archive_size=10240
    )

    with pytest.raises(archive_converter._ExtractionLimitExceeded) as refused:
        archive_converter._tar_members_within([member], budget)

    assert refused.value.option == "max_member_bytes"
    assert "-1 bytes" in refused.value.reason


def negative_size_tar() -> bytes:
    """A one-member tar whose size field is the base-256 encoding of -1."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        archive.addfile(tarfile.TarInfo("n.py"), io.BytesIO(b""))
    raw = bytearray(buffer.getvalue())
    raw[124:136] = b"\xff" * 12
    checksum = sum(raw[:148]) + 8 * 32 + sum(raw[156:512])
    raw[148:156] = b"%06o\0 " % checksum
    return bytes(raw)


def tarfile_returns_a_negative_size() -> bool:
    """Whether this Python's tarfile hands back the member of ``negative_size_tar``.

    Newer releases make ``TarInfo._block`` raise InvalidHeaderError for a negative
    count, so ``tarfile.open`` raises ReadError on the archive. Older ones return a
    member of size -1 and read on to the next block.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(negative_size_tar())) as archive:
            return [member.size for member in archive.getmembers()] == [-1]
    except tarfile.TarError:
        return False


def convert(context, monkeypatch, name: str, data: bytes, no_data_filter=False):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / name
    archive.write_bytes(data)
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    if no_data_filter:
        monkeypatch.setattr(f"{ARCHIVE_MODULE}._TAR_HAS_DATA_FILTER", False)
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def test_a_tar_header_with_a_negative_size_is_an_archive_that_cannot_be_read(
    test_plugin_context, monkeypatch
):
    converter, results = convert(
        test_plugin_context, monkeypatch, "neg.tar", negative_size_tar()
    )

    assert results == []
    if tarfile_returns_a_negative_size():
        # The parser did not refuse the header, so the budget does, at the member.
        assert [(r.path, r.limit) for r in converter.refused_inputs] == [
            ("neg.tar", "max_member_bytes")
        ]
        assert "-1 bytes" in converter.refused_inputs[0].reason
        assert converter.failed_inputs == []
    else:
        assert [r.path for r in converter.failed_inputs] == ["neg.tar"]
        assert converter.refused_inputs == []


def test_the_kind_of_a_tar_with_a_negative_size_follows_tarfile():
    """The probe takes a first header as ``tarfile.open`` does: where this
    Python's tarfile refuses the negative size, the file is not a tar it reads,
    and the converter records it as an archive that cannot be read; where tarfile
    returns the member, the file is a tar and the budget refuses the member."""
    expected = "tar" if tarfile_returns_a_negative_size() else None

    handle = io.BytesIO(negative_size_tar())

    assert archive_converter.archive_kind("neg.tar", handle) == expected


def test_the_copy_path_writes_a_member_larger_than_one_chunk_whole(
    test_plugin_context, monkeypatch
):
    data = incompressible(archive_converter._COPY_CHUNK * 2 + 513, seed=3)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("big.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    converter, results = convert(
        test_plugin_context,
        monkeypatch,
        "big.tar",
        buffer.getvalue(),
        no_data_filter=True,
    )

    (extracted,) = results
    assert (extracted / "big.py").read_bytes() == data
    assert converter.refused_inputs == []
