# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two paths the other archive tests reach only through stand-ins.

A member size below zero is refused for ``max_member_bytes``. The tarfile in this
Python already refuses a header whose size field is negative, so the budget is
tested with a crafted ``TarInfo``, and the parser's own refusal with a crafted
header, which the converter then records as an archive it cannot read.

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
    assert [r.path for r in converter.failed_inputs] == ["neg.tar"]
    assert converter.refused_inputs == []


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
