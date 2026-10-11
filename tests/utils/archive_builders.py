# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Archives built in memory for the archive converter's extraction-limit tests.

The limits are on what an archive declares and on what extracting it writes, so the
tests need archives whose headers claim large sizes. None of these carries large
content. A declared size is written into the zip central directory after the
member's real, small content, and zipfile stops a member's output at the end of its
compressed data, so whatever reads one of these archives, with limits or without,
writes a few kilobytes.

The one exception is ``sparse_tar_bytes``, built to show that CPython's tarfile can
write more for a member than the member declares. It writes at most ``trailing``
bytes, which the tests keep at 1 MiB.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Mapping, Optional, Union

Content = Union[bytes, str]

#: The extraction-limit options of ``ArchiveConverterConfigOptions``.
LIMIT_OPTIONS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_compression_ratio",
)

#: Limits no test archive comes near, for a test about one of the others.
GENEROUS_LIMITS = {
    "max_members": 1_000_000,
    "max_member_bytes": 1 << 40,
    "max_total_bytes": 1 << 40,
    "max_compression_ratio": 1_000_000,
}

TEBIBYTE = 1 << 40
GIBIBYTE = 1 << 30
MEBIBYTE = 1 << 20

#: The archive formats the converter reads, by the suffix it selects them on.
KINDS = ("zip", "tar", "tar.gz")


def _data(value: Content) -> bytes:
    return value.encode() if isinstance(value, str) else value


def zip_bytes(
    members: Mapping[str, Content],
    declared_sizes: Optional[Mapping[str, int]] = None,
) -> bytes:
    """A deflated zip of ``members``.

    ``declared_sizes`` replaces a member's uncompressed size in the central directory,
    which is where zipfile reads it from, after the member's real content has been
    written. A size above 4 GiB is written with the zip64 extra field, as zipfile
    does for a real member that large.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, _data(value))
        for info in archive.filelist:
            if declared_sizes and info.filename in declared_sizes:
                info.file_size = declared_sizes[info.filename]
    return buffer.getvalue()


def tar_bytes(members: Mapping[str, Content], gz: bool = False) -> bytes:
    """A tar, or a gzip-compressed tar, of regular-file ``members``."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz" if gz else "w") as archive:
        for name, value in members.items():
            data = _data(value)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def archive_bytes(kind: str, members: Mapping[str, Content]) -> bytes:
    """``members`` as an archive of ``kind``: "zip", "tar" or "tar.gz"."""
    if kind == "zip":
        return zip_bytes(members)
    if kind == "tar":
        return tar_bytes(members)
    if kind == "tar.gz":
        return tar_bytes(members, gz=True)
    raise ValueError(f"unknown archive kind {kind!r}")


def sparse_tar_bytes(
    name: str,
    declared_size: int,
    map_length: int,
    trailing: int,
    gz: bool = False,
) -> bytes:
    """A tar whose one member declares ``declared_size`` bytes and copies more.

    The member is a GNU sparse file (PAX format 0.1). tarfile takes its size from
    ``GNU.sparse.size`` and its data blocks from ``GNU.sparse.map``, and nothing ties
    the two together: ``TarFile.extractall`` copies ``map_length`` bytes from the
    archive stream at the member's data offset, then truncates the file to the
    declared size. The member stores no data, the archive ends right after it, and
    ``trailing`` zero bytes follow the end-of-archive blocks. With ``map_length``
    larger than what the stream still holds, the copy writes everything the stream
    holds and then raises ``ReadError``, and the truncation never happens, so the
    file is left at about ``trailing`` bytes for a member that declares
    ``declared_size``. ``TarFile.extractfile`` reads the same member as exactly
    ``declared_size`` bytes.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.size = 0
        info.pax_headers = {
            "GNU.sparse.map": f"0,{map_length}",
            "GNU.sparse.size": str(declared_size),
        }
        archive.addfile(info)
    body = raw.getvalue() + bytes(trailing)
    return gzip.compress(body, mtime=0) if gz else body


def sparse_tar_with_data_bytes(
    name: str, declared_size: int, map_length: int, gz: bool = False
) -> bytes:
    """A tar whose one sparse member maps and stores ``map_length`` zero bytes.

    Unlike ``sparse_tar_bytes``, the data the map points at is in the stream, so
    tarfile's ``extractall`` copies all ``map_length`` bytes without an error and
    only then truncates the file to ``declared_size``: the final file size cannot
    show the copy, and a check that refuses the member before extraction is the
    only thing that prevents it. Zeros keep the gzip-compressed form small.
    """
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.size = map_length
        info.pax_headers = {
            "GNU.sparse.map": f"0,{map_length}",
            "GNU.sparse.size": str(declared_size),
        }
        archive.addfile(info, io.BytesIO(bytes(map_length)))
    body = raw.getvalue()
    return gzip.compress(body, mtime=0) if gz else body


def incompressible(size: int, seed: int = 0) -> bytes:
    """``size`` bytes that deflate and gzip cannot shrink."""
    return random.Random(seed).randbytes(size)


def compressible_text(size: int) -> bytes:
    """``size`` bytes of source-like text that compresses about as well as code does."""
    lines = []
    total = 0
    index = 0
    while total < size:
        line = f"value_{index} = compute({index}, {index * 7 % 13}, 'item-{index}')\n"
        lines.append(line)
        total += len(line)
        index += 1
    return "".join(lines).encode()[:size]


def ordinary_source_files(
    budget: int = 2 * MEBIBYTE, largest: int = 32 * 1024
) -> Dict[str, bytes]:
    """ASH's own Python sources of up to ``largest`` bytes, in path order, up to ``budget``.

    Real source code, in real directory nesting, stands in for an ordinary archive a
    repository might carry: about 170 files and 2 MiB.
    """
    import automated_security_helper

    root = Path(automated_security_helper.__file__).parent
    files: Dict[str, bytes] = {}
    total = 0
    for path in sorted(root.rglob("*.py")):
        data = path.read_bytes()
        if len(data) > largest:
            continue
        if total + len(data) > budget:
            break
        files[f"src/{path.relative_to(root).as_posix()}"] = data
        total += len(data)
    return files
