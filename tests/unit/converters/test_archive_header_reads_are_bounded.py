# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What tarfile reads to parse an archive's headers is bounded, before any limit check.

tarfile reads an extended (pax) header, a GNU long name or a sparse map into memory
whole while it parses the header, before the converter sees the member and can
check it against the extraction limits. The tar stream is now read through a
reader that refuses any single read over a cap and bounds the bytes the header
pass reads, a base plus an allowance per member; the decompressor is chosen by the
archive's leading bytes rather than by trying each one. An archive over either is
refused as one the converter cannot read.

Every archive here is a few kilobytes. The caps are lowered for each test, so a
header a little over the lowered cap stands for one over the real cap.
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)
READ_CAP = 4096
HEADER_BASE = 2048
HEADER_PER_MEMBER = 1024


@pytest.fixture
def lowered_caps(monkeypatch):
    """The caps lowered for the test. A cap that is renamed fails the setup."""
    monkeypatch.setattr(f"{ARCHIVE_MODULE}._TAR_READ_CAP", READ_CAP, raising=True)
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}._TAR_HEADER_BYTES_BASE", HEADER_BASE, raising=True
    )
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}._TAR_HEADER_BYTES_PER_MEMBER",
        HEADER_PER_MEMBER,
        raising=True,
    )


def tar_of(
    entries: List[tarfile.TarInfo],
    data: Dict[str, bytes],
    fmt: int = tarfile.PAX_FORMAT,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=fmt) as archive:
        for info in entries:
            payload = data.get(info.name, b"")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def member(name: str, pax: Optional[Dict[str, str]] = None) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    if pax:
        info.pax_headers = dict(pax)
    return info


def convert(context, monkeypatch, name: str, raw: bytes):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / name
    archive.write_bytes(raw)
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def assert_refused_for_header_reads(converter, results, name: str) -> None:
    assert results == []
    assert [r.path for r in converter.failed_inputs] == [name], converter.failed_inputs
    assert "header" in converter.failed_inputs[0].reason, converter.failed_inputs
    assert converter.refused_inputs == []


def test_an_extended_header_over_the_read_cap_is_refused(
    lowered_caps, test_plugin_context, monkeypatch
):
    raw = tar_of(
        [member("a.py", {"comment": "x" * (READ_CAP + 512)})], {"a.py": b"a = 1\n"}
    )

    converter, results = convert(test_plugin_context, monkeypatch, "pax.tar", raw)

    assert_refused_for_header_reads(converter, results, "pax.tar")


def test_an_extended_header_under_the_read_cap_is_extracted(
    lowered_caps, test_plugin_context, monkeypatch
):
    raw = tar_of([member("a.py", {"comment": "x" * 1024})], {"a.py": b"a = 1\n"})

    converter, results = convert(test_plugin_context, monkeypatch, "pax.tar", raw)

    (extracted,) = results
    assert (extracted / "a.py").read_bytes() == b"a = 1\n"
    assert converter.refused_inputs == []


def test_a_long_name_over_the_read_cap_is_refused(
    lowered_caps, test_plugin_context, monkeypatch
):
    name = "/".join(["d" * 100] * 45) + "/a.py"
    raw = tar_of([member(name)], {name: b"a = 1\n"}, fmt=tarfile.GNU_FORMAT)

    converter, results = convert(test_plugin_context, monkeypatch, "long.tar", raw)

    assert_refused_for_header_reads(converter, results, "long.tar")


def test_header_reads_past_the_per_member_allowance_are_refused(
    lowered_caps, test_plugin_context, monkeypatch
):
    """Ten members, each reading about 1.5 KiB of headers against 1 KiB allowed."""
    names = [f"m{i}.py" for i in range(10)]
    raw = tar_of(
        [member(n, {"comment": "c" * 300}) for n in names],
        dict.fromkeys(names, b"x = 1\n"),
    )

    converter, results = convert(test_plugin_context, monkeypatch, "many.tar", raw)

    assert_refused_for_header_reads(converter, results, "many.tar")


def test_members_with_plain_headers_fit_the_per_member_allowance(
    lowered_caps, test_plugin_context, monkeypatch
):
    names = [f"m{i}.py" for i in range(10)]
    raw = tar_of(
        [member(n) for n in names],
        dict.fromkeys(names, b"x = 1\n"),
        tarfile.USTAR_FORMAT,
    )

    converter, results = convert(test_plugin_context, monkeypatch, "many.tar", raw)

    assert len(results) == 1
    assert converter.refused_inputs == []


def _compressors():
    """bzip2 and xz, and zstd where this Python has it."""
    found = [
        pytest.param(bz2.compress, id="bzip2"),
        pytest.param(lzma.compress, id="xz"),
    ]
    try:
        from compression import zstd
    except ImportError:
        return found
    return found + [pytest.param(zstd.compress, id="zstd")]


@pytest.mark.parametrize("compress", _compressors())
def test_a_compressed_tar_is_read_by_its_leading_bytes(
    compress, lowered_caps, test_plugin_context, monkeypatch
):
    raw = compress(tar_of([member("a.py")], {"a.py": b"a = 1\n"}))

    converter, results = convert(test_plugin_context, monkeypatch, "data.tar", raw)

    (extracted,) = results
    assert (extracted / "a.py").read_bytes() == b"a = 1\n"
    assert converter.refused_inputs == []


def sparse_tar(sparse_map: str) -> bytes:
    """A GNU sparse 0.1 member of 8 bytes whose 8 stored bytes follow ``sparse_map``."""
    info = member("s.py", {"GNU.sparse.map": sparse_map, "GNU.sparse.size": "8"})
    return tar_of([info], {"s.py": b"abcdefgh"})


def test_a_sparse_map_whose_entries_overlap_is_refused(
    test_plugin_context, monkeypatch
):
    converter, results = convert(
        test_plugin_context, monkeypatch, "sparse.tar", sparse_tar("0,4,0,4")
    )

    (extracted,) = results
    assert not (extracted / "s.py").exists()
    assert [(r.member, r.limit) for r in converter.refused_inputs] == [("s.py", None)]
    assert converter.failed_inputs == []


def test_a_sparse_map_in_order_is_extracted(test_plugin_context, monkeypatch):
    converter, results = convert(
        test_plugin_context, monkeypatch, "sparse.tar", sparse_tar("0,4,4,4")
    )

    (extracted,) = results
    assert (extracted / "s.py").read_bytes() == b"abcdefgh"
    assert converter.refused_inputs == []
