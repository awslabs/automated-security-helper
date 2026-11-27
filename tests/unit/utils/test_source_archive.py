# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A source zip is read under one set of rules by ``ash scan fs --archive`` and by MCP.

Why this exists
---------------
``extract_source_archive`` is the engine behind ``ash scan fs --archive FILE``, and
the MCP finalize (``set_source_zip_finalize``) extracts an upload with the same rules,
from ``utils/source_archive.py``. The rows below pin each rule on the shared function
with the real limits (100 MiB of archive, 500 MiB extracted, 50,000 members), and then
give every one of those archives to the MCP finalize as well: it has to reach the same
verdict in the same words, so the two entry points cannot drift apart. The one
difference is the noun of the link refusal, which names each entry point's archives.

Archives past a limit are cheap to build: an oversized archive is a sparse file, a
large uncompressed total is a deflated run of zeros (about half a megabyte), and the
member count is 50,001 empty members. Names zipfile will not write as given (a NUL,
which it cuts at, and a backslash, which it turns into a slash on Windows) are written
as a placeholder of the same length and swapped into the archive's bytes afterwards.

Archives zipfile cannot read are built the same way, by changing the bytes of a good
one where the zip format puts the field: a central directory entry that needs a newer
reader, a damaged compressed stream, and a local header whose name is not the UTF-8 it
claims. Every one of them has to reach the caller of ``extract_source_archive`` as a
refusal.

A file has to be one zip and nothing else (rule 6). zipfile reads the zip whose end
record it finds last and lets the rest of the file pass, while a reader that starts at
the first byte reads what is there, so the rows hand both entry points each shape that
gives the two readers two trees: two zips end to end, a tar whose last member is a zip,
a program before the archive, bytes after its end record, a member the central
directory leaves out, and local headers and data descriptors that disagree with the
central directory. Some are written byte by byte (``_Raw``), since no zip writer makes
them. The controls hand both entry points every layout a writer does make: data
descriptors with and without their signature, in four-byte and eight-byte sizes, zip64
end records, an archive comment and an empty archive.

The module reads the Unicode path field itself (rule 3), so its verdict cannot depend on
whether this Python's zipfile applies the field, as it does from 3.12. The rows that
turn on it run twice: under this zipfile, and under one made to ignore the field, as
zipfile did before 3.12.

What zipfile cannot read is classified once, for both entry points (``open_zip`` and
``extract_zip_members``). The rows of ``UNREADABLE`` give both an archive that needs a
newer reader than zipfile implements, a name in the central directory that is not the
UTF-8 it claims, a member with damaged data, a method whose module this Python lacks
and a link whose data cannot be read, and each has to reach one verdict, in one set of
words, with the refused upload removed. An encrypted member, a link too, is a row of
``REFUSED``, since its flag is read before anything else. What the module's own code
raises is not about the archive and is not caught.
"""

from __future__ import annotations

import base64
import copy
import errno
import gzip
import hashlib
import io
import os
import struct
import tarfile
import warnings
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import clear_all_session_state
from automated_security_helper.utils import source_archive as sa
from automated_security_helper.utils.source_archive import SourceArchiveRefusal as Kind

pytestmark = pytest.mark.unit

MiB = 1024 * 1024
SESSION = "source-archive-parity"
UPLOAD = "upload"


# ---------------------------------------------------------------------------
# Archive builders.
# ---------------------------------------------------------------------------


def _zip(entries: Dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    """A zip holding ``entries``, name to content, in order."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _zip_members(entries: Sequence[Tuple[str, bytes]]) -> bytes:
    """A zip holding ``entries``, name and content, in order, a repeated name included."""
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        # zipfile warns on a name it already wrote, and writes it again as asked.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries:
                archive.writestr(name, content)
    return buffer.getvalue()


def _unicode_path_field(
    spelled: bytes,
    name: Union[str, bytes],
    *,
    version: int = 1,
    crc_of: Optional[bytes] = None,
) -> bytes:
    """A Unicode path extra field (0x7075) giving ``name`` to a member spelled ``spelled``.

    By default version 1 and the CRC-32 of the spelled name's bytes, as Info-ZIP writes
    it, then the name in UTF-8 (or the bytes given). zipfile from 3.12 applies the field
    only when both hold, so ``version`` and ``crc_of`` (the bytes whose CRC-32 the field
    carries) make one it skips.
    """
    crc = zlib.crc32(spelled if crc_of is None else crc_of)
    encoded = name.encode("utf-8") if isinstance(name, str) else name
    data = struct.pack("<BL", version, crc) + encoded
    return struct.pack("<HH", 0x7075, len(data)) + data


def _zip_with_extra(name: str, extra: bytes, content: bytes) -> bytes:
    """A zip of one stored member ``name`` whose local header and central entry carry
    ``extra`` as its extra field."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.extra = extra
        archive.writestr(info, content)
    return buffer.getvalue()


def _zip_with_unicode_paths(
    entries: Sequence[Tuple[str, Optional[str], bytes]],
) -> bytes:
    """A zip of ``(name, the name its Unicode path field gives or None, content)``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, unicode_path, content in entries:
            info = zipfile.ZipInfo(name)
            if unicode_path is not None:
                info.extra = _unicode_path_field(name.encode("ascii"), unicode_path)
            archive.writestr(info, content)
    return buffer.getvalue()


def _info_zip_utf8_name(name: str, content: bytes) -> bytes:
    """One stored member named ``name`` as Info-ZIP writes a name outside ASCII.

    On a UTF-8 system it stores the name's UTF-8 bytes without the UTF-8 flag, so
    zipfile reads the spelled name as cp437, and restates the name in a Unicode path
    field. zipfile sets the flag for any name outside ASCII, so a placeholder of the
    same length is written and the bytes are swapped in afterwards.
    """
    spelled = name.encode("utf-8")
    placeholder = "X" * len(spelled)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(placeholder)
        info.extra = _unicode_path_field(spelled, name)
        archive.writestr(info, content)
    return _renamed(buffer.getvalue(), placeholder, spelled)


def _zipfile_reads_unicode_paths() -> bool:
    """Whether this Python's zipfile extracts a member under its Unicode path field.

    From 3.12 it does; before, the field is ignored and the spelled name is used.
    """
    payload = _zip_with_unicode_paths([("a.py", "b.py", b"")])
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return archive.infolist()[0].filename == "b.py"


ZIPFILE_READS_UNICODE_PATHS = _zipfile_reads_unicode_paths()
_NEEDS_UNICODE_PATHS = pytest.mark.skipif(
    not ZIPFILE_READS_UNICODE_PATHS,
    reason="zipfile before Python 3.12 ignores the Unicode path field",
)


def _as_zipfile_before_3_12(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make this Python's zipfile ignore the Unicode path field, as it did before 3.12.

    zipfile applies the field in ``ZipInfo._decodeExtra`` while it reads the central
    directory. This keeps everything else that method reads and then puts back the name
    ``ZipInfo`` makes of the spelled one, which is the name zipfile before 3.12 kept.
    On a zipfile that ignores the field already it changes nothing.
    """
    decode = getattr(zipfile.ZipInfo, "_decodeExtra")

    def ignoring_unicode_paths(info: zipfile.ZipInfo, *args: object) -> None:
        decode(info, *args)
        info.filename = zipfile.ZipInfo(info.orig_filename).filename

    monkeypatch.setattr(zipfile.ZipInfo, "_decodeExtra", ignoring_unicode_paths)


@pytest.fixture(params=["this-zipfile", "a-zipfile-that-ignores-the-field"])
def zipfile_reading(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """This Python's zipfile, then one that ignores the Unicode path field."""
    if request.param == "a-zipfile-that-ignores-the-field":
        _as_zipfile_before_3_12(monkeypatch)
    return request.param


def _zip_with_modes(entries: Dict[str, Tuple[bytes, int]]) -> bytes:
    """A zip whose members carry the Unix mode given beside each content."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, (content, mode) in entries.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, content)
    return buffer.getvalue()


def _renamed(payload: bytes, placeholder: str, name: bytes) -> bytes:
    """``payload``, whose one member is named ``placeholder``, with ``name`` swapped in.

    The name is replaced in the local header and in the central directory, the two
    places a zip spells it; the placeholder has to appear in nothing else.
    """
    spelled = placeholder.encode("ascii")
    assert len(spelled) == len(name)
    assert payload.count(spelled) == 2, "the placeholder must name the member only"
    return payload.replace(spelled, name)


def _flagged_encrypted(payload: bytes) -> bytes:
    """``payload``, a zip of one member, with that member's encrypted flag set.

    Bit 0 of the general purpose flags, at offset 6 of the local header and offset 8
    of the central directory header. zipfile writes no encrypted member, so the bit is
    set in the bytes; its data stays readable plain text, which is beside the point.
    """
    data = bytearray(payload)
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    assert local == 0 and central > 0
    data[local + 6] |= 0x01
    data[central + 8] |= 0x01
    return bytes(data)


def _with_damaged_data(payload: bytes, content: bytes) -> bytes:
    """``payload`` with one byte of a stored member's ``content`` changed.

    Stored members keep their bytes as they are, so the change lands in the member's
    data and its checksum no longer matches: zipfile finds it only when it reads the
    member to its end.
    """
    at = payload.index(content)
    damaged = bytearray(payload)
    damaged[at] ^= 0xFF
    return bytes(damaged)


def _with_version_needed(payload: bytes, version: int) -> bytes:
    """``payload``, a zip of one member, whose central directory entry needs ``version``.

    "Version needed to extract" is at offset 6 of the entry, in tenths (63 is 6.3);
    zipfile reads it when it opens the archive and implements up to 6.3.
    """
    data = bytearray(payload)
    central = data.find(b"PK\x01\x02")
    assert central > 0
    data[central + 6 : central + 8] = struct.pack("<H", version)
    return bytes(data)


def _with_first_data_byte_flipped(payload: bytes) -> bytes:
    """``payload``, a zip of one member, with the first byte of that member's data changed.

    The data starts after the 30-byte local header, the name and the extra field, whose
    lengths are at offsets 26 and 28 of the header.
    """
    data = bytearray(payload)
    assert data[:4] == b"PK\x03\x04"
    name_length, extra_length = struct.unpack("<HH", data[26:30])
    data[30 + name_length + extra_length] ^= 0xFF
    return bytes(data)


def _with_local_name_not_utf8(payload: bytes, name: str) -> bytes:
    """``payload``, whose one member is named ``name``, with a local header that lies.

    The local header's copy of the name gets a first byte that starts no UTF-8
    sequence, and the header claims UTF-8 (flag bit 11, offset 6). The central
    directory still spells ``name``, so the archive opens; reading the member decodes
    the local name and fails.
    """
    spelled = name.encode("ascii")
    data = bytearray(payload)
    assert data[:4] == b"PK\x03\x04" and payload.count(spelled) == 2
    at = data.index(spelled)
    data[at] = 0xFF
    (flags,) = struct.unpack("<H", data[6:8])
    data[6:8] = struct.pack("<H", flags | 0x800)
    return bytes(data)


def _with_central_name_not_utf8(payload: bytes, name: str) -> bytes:
    """``payload``, whose one member is named ``name``, with a central entry that lies.

    The central directory entry's copy of the name gets a first byte that starts no
    UTF-8 sequence, and the entry claims UTF-8 (flag bit 11, offset 8 of the entry).
    zipfile decodes the name as it opens the archive, so the archive does not open.
    """
    spelled = name.encode("ascii")
    data = bytearray(payload)
    central = data.find(b"PK\x01\x02")
    assert central > 0 and data[central + 46 : central + 46 + len(spelled)] == spelled
    data[central + 46] = 0xFF
    (flags,) = struct.unpack("<H", data[central + 8 : central + 10])
    data[central + 8 : central + 10] = struct.pack("<H", flags | 0x800)
    return bytes(data)


def _with_central_directory_moved_on(payload: bytes, by: int) -> bytes:
    """``payload`` with the end record's central directory offset ``by`` bytes too far.

    zipfile takes the excess as data concatenated before the archive and subtracts it
    from every member's header offset, so the first member's comes out negative.
    """
    data = bytearray(payload)
    end = data.rfind(b"PK\x05\x06")
    (offset,) = struct.unpack("<I", data[end + 16 : end + 20])
    data[end + 16 : end + 20] = struct.pack("<I", offset + by)
    return bytes(data)


def _with_zip64_header_offset(payload: bytes, offset: int) -> bytes:
    """``payload``, a zip of one member, whose header offset is ``offset`` by zip64.

    The central directory entry's offset (at 42) is set to 0xFFFFFFFF and a zip64 extra
    field carries the real one, as zipfile writes for an archive past 4 GiB; the entry's
    extra length (at 30) and the end record's central directory size grow to match.
    """
    data = bytearray(payload)
    central = data.find(b"PK\x01\x02")
    name_length, extra_length, comment_length = struct.unpack(
        "<HHH", data[central + 28 : central + 34]
    )
    assert extra_length == 0 and comment_length == 0
    extra = struct.pack("<HHQ", 0x0001, 8, offset)
    data[central + 42 : central + 46] = struct.pack("<I", 0xFFFFFFFF)
    data[central + 30 : central + 32] = struct.pack("<H", len(extra))
    name_end = central + 46 + name_length
    data[name_end:name_end] = extra
    end = data.rfind(b"PK\x05\x06")
    (size,) = struct.unpack("<I", data[end + 12 : end + 16])
    data[end + 12 : end + 16] = struct.pack("<I", size + len(extra))
    return bytes(data)


def _tar(gzipped: bool) -> bytes:
    """A tar (or a gzip-compressed tar) of one small source file.

    Compressed with a fixed timestamp, so the bytes are the same on every run.
    """
    buffer = io.BytesIO()
    data = b"print('hello')\n"
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("app/main.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    tar = buffer.getvalue()
    return gzip.compress(tar, mtime=0) if gzipped else tar


def _tar_ending_in_a_zip() -> Tuple[bytes, int]:
    """A tar whose last member is a stored zip, and the byte at which that zip ends.

    tarfile pads the member to its 512-byte block and closes the archive with zero
    blocks to a 10240-byte record, so the zip's end record is followed by the tar's own
    zeros, and the tar's headers and first member come before the zip.
    """
    inner = _zip({"app.py": b"EVIL = False\n"}, compression=zipfile.ZIP_STORED)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in (
            ("readme.md", b"# a tar of two members\n"),
            ("payload.zip", inner),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    tar = buffer.getvalue()
    return tar, tar.index(inner) + len(inner)


def _patched(payload: bytes, at: int, value: bytes) -> bytes:
    """``payload`` with ``value`` written over the bytes at ``at``."""
    return payload[:at] + value + payload[at + len(value) :]


def _end_record_at(payload: bytes) -> int:
    end = payload.rfind(b"PK\x05\x06")
    assert end > 0
    return end


def _central_entry_at(payload: bytes, index: int) -> int:
    """Where the central directory entry of member ``index`` starts."""
    at = payload.find(b"PK\x01\x02")
    for _ in range(index):
        at = payload.find(b"PK\x01\x02", at + 4)
    assert at > 0
    return at


def _with_comment_length(payload: bytes, length: int) -> bytes:
    """``payload`` whose end record claims a comment of ``length`` bytes (at 20)."""
    return _patched(payload, _end_record_at(payload) + 20, struct.pack("<H", length))


def _with_end_record_counts(payload: bytes, on_this_disk: int, in_all: int) -> bytes:
    """``payload`` whose end record counts ``on_this_disk`` members on this disk (at 8)
    and ``in_all`` in all (at 10)."""
    return _patched(
        payload, _end_record_at(payload) + 8, struct.pack("<HH", on_this_disk, in_all)
    )


def _with_compressed_size(payload: bytes, size: int) -> bytes:
    """``payload``, a zip of one member, whose local header (at 18) and central entry
    (at 20) both give ``size`` for its compressed size."""
    entry = _central_entry_at(payload, 0)
    patched = _patched(payload, entry + 20, struct.pack("<L", size))
    return _patched(patched, 18, struct.pack("<L", size))


def _with_header_offset(payload: bytes, index: int, offset: int) -> bytes:
    """``payload`` whose central directory places member ``index`` at ``offset`` (at 42
    of its entry)."""
    entry = _central_entry_at(payload, index)
    return _patched(payload, entry + 42, struct.pack("<L", offset))


def _with_entry_comment_length(payload: bytes, index: int, length: int) -> bytes:
    """``payload`` whose central directory entry ``index`` claims a comment of
    ``length`` bytes (at 32 of the entry) that is not there."""
    entry = _central_entry_at(payload, index)
    return _patched(payload, entry + 32, struct.pack("<H", length))


def _zip_with_comment(entries: Dict[str, bytes], comment: bytes) -> bytes:
    """A zip of ``entries`` whose end record carries ``comment``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.comment = comment
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class _Pipe(io.RawIOBase):
    """A stream that takes writes and cannot seek back, as a pipe zipfile writes into."""

    def __init__(self) -> None:
        super().__init__()
        self.written = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        self.written += data
        return len(data)


def _zip_written_to_a_pipe(entries: Dict[str, bytes], *, zip64: bool = False) -> bytes:
    """A zip of ``entries`` as zipfile writes it where it cannot seek back.

    Each member's local header then gives no CRC-32 or sizes, flag bit 3 says so, and a
    data descriptor after the data carries them: with its signature, in four-byte sizes,
    or in eight-byte ones for a member written with ``force_zip64``.
    """
    pipe = _Pipe()
    with zipfile.ZipFile(pipe, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            with archive.open(name, "w", force_zip64=zip64) as member:
                member.write(content)
    return bytes(pipe.written)


@dataclass(frozen=True)
class _Raw:
    """One stored member, written byte by byte, with what each of its headers says.

    The local header gives the member's true CRC-32 and sizes, or zeros when its flags
    say a data descriptor follows the data, unless ``local_sizes`` gives others;
    ``local_flags`` defaults to ``flags``. ``descriptor`` is written after the data.
    """

    name: bytes
    data: bytes
    flags: int = 0
    local_flags: Optional[int] = None
    local_sizes: Optional[Tuple[int, int, int]] = None
    local_extra: bytes = b""
    descriptor: bytes = b""

    def local_record(self) -> bytes:
        flags = self.flags if self.local_flags is None else self.local_flags
        if self.local_sizes is not None:
            crc, compressed, size = self.local_sizes
        elif flags & 0x8:
            crc = compressed = size = 0
        else:
            crc, compressed, size = (
                zlib.crc32(self.data),
                len(self.data),
                len(self.data),
            )
        header = struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04",
            20,
            flags,
            zipfile.ZIP_STORED,
            0,
            0x21,
            crc,
            compressed,
            size,
            len(self.name),
            len(self.local_extra),
        )
        return header + self.name + self.local_extra + self.data + self.descriptor

    def central_entry(self, offset: int) -> bytes:
        size = len(self.data)
        entry = struct.pack(
            "<4s4B4HL2L5H2L",
            b"PK\x01\x02",
            20,
            3,
            20,
            0,
            self.flags,
            zipfile.ZIP_STORED,
            0,
            0x21,
            zlib.crc32(self.data),
            size,
            size,
            len(self.name),
            0,
            0,
            0,
            0,
            0o100644 << 16,
            offset,
        )
        return entry + self.name


def _descriptor(data: bytes, *, signature: bool = True, zip64: bool = False) -> bytes:
    """The data descriptor of a stored member holding ``data``: with or without its
    signature, in four-byte or eight-byte sizes."""
    sizes = struct.pack("<QQ" if zip64 else "<LL", len(data), len(data))
    head = b"PK\x07\x08" if signature else b""
    return head + struct.pack("<L", zlib.crc32(data)) + sizes


def _raw_zip(
    members: Sequence[_Raw],
    *,
    before: bytes = b"",
    listed: Optional[Sequence[int]] = None,
    zip64_end: bool = False,
) -> bytes:
    """A zip of ``members`` written after ``before``, every offset counted from byte 0.

    ``listed`` names, by position, the members the central directory lists; the rest are
    written and left out of it. ``zip64_end`` writes the zip64 end record and its locator
    before the end record, whose own fields then say to read them, as zip64 writers do.
    """
    out = bytearray(before)
    offsets: List[int] = []
    for member in members:
        offsets.append(len(out))
        out += member.local_record()
    directory_at = len(out)
    chosen = list(range(len(members))) if listed is None else list(listed)
    for position in chosen:
        out += members[position].central_entry(offsets[position])
    directory_size = len(out) - directory_at
    count = len(chosen)
    if zip64_end:
        record_at = len(out)
        out += struct.pack(
            "<4sQ2H2L4Q",
            b"PK\x06\x06",
            44,
            45,
            45,
            0,
            0,
            count,
            count,
            directory_size,
            directory_at,
        )
        out += struct.pack("<4sLQL", b"PK\x06\x07", 0, record_at, 1)
        out += struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
    else:
        out += struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            count,
            count,
            directory_size,
            directory_at,
            0,
        )
    return bytes(out)


def _sparse(path: Path, size: int) -> Path:
    """A file of ``size`` bytes that takes no space where the filesystem allows it."""
    with path.open("wb") as handle:
        handle.truncate(size)
    return path


def _zeros_member(total: int) -> bytes:
    """One deflated member of ``total`` zero bytes, named ``zeros.bin``."""
    buffer = io.BytesIO()
    block = bytes(MiB)
    left = total
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("zeros.bin", "w", force_zip64=True) as member:
            while left:
                piece = block[: min(left, MiB)]
                member.write(piece)
                left -= len(piece)
    return buffer.getvalue()


def _empty_members(count: int) -> bytes:
    """``count`` empty members, ``m/0`` onwards."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(count):
            archive.writestr(f"m/{index}", b"")
    return buffer.getvalue()


@pytest.fixture(scope="module")
def over_the_extracted_total() -> bytes:
    return _zeros_member(500 * MiB + 1)


@pytest.fixture(scope="module")
def over_the_member_count() -> bytes:
    return _empty_members(50_001)


#: A source tree with nested directories, an empty directory, an empty file, binary
#: content, and two names whose dots are not a ``..`` component.
NESTED: Dict[str, bytes] = {
    "app/main.py": b"print('main')\n",
    "app/pkg/__init__.py": b"",
    "app/pkg/deep/module.py": b"VALUE = 1\n",
    "docs/guide.md": b"# Guide\n",
    "data/blob.bin": bytes(range(256)),
    "..config/settings.toml": b"[tool]\nname = 'x'\n",
    "notes..txt": b"two dots inside a name\n",
}


def _nested_tree(root: Path) -> Path:
    for name, content in NESTED.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "empty").mkdir()
    return root


def _zip_of(root: Path) -> bytes:
    """A zip of every file and directory under ``root``, as ``zipfile.write`` adds them."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            archive.write(path, path.relative_to(root).as_posix())
    return buffer.getvalue()


def _tree(root: Path) -> Dict[str, Optional[bytes]]:
    """Every entry under ``root``: a file's bytes, None for a directory."""
    return {
        path.relative_to(root).as_posix(): None if path.is_dir() else path.read_bytes()
        for path in sorted(root.rglob("*"))
    }


# ---------------------------------------------------------------------------
# The two entry points.
# ---------------------------------------------------------------------------


def _archive_file(tmp_path: Path, payload: bytes) -> Path:
    archive = tmp_path / "archive.zip"
    archive.write_bytes(payload)
    return archive


def _extraction_refusal(archive: Path, destination: Path) -> sa.SourceArchiveRefused:
    with pytest.raises(sa.SourceArchiveRefused) as refused:
        sa.extract_source_archive(archive, destination)
    return refused.value


def _upload(payload: bytes, workspace: Path) -> None:
    """Send ``payload`` to the MCP delivery in chunks it accepts, the last marked."""
    workspace.mkdir(exist_ok=True)
    size = sd._MAX_CHUNK_BYTES
    chunks = [payload[at : at + size] for at in range(0, len(payload), size)]
    for sequence, chunk in enumerate(chunks):
        sd.set_source_zip_chunk(
            upload_id=UPLOAD,
            sequence=sequence,
            data_b64=base64.b64encode(chunk).decode("ascii"),
            last=sequence == len(chunks) - 1,
            workspace_root=workspace,
            session_id=SESSION,
        )


def _finalize(payload: bytes, workspace: Path) -> Path:
    return sd.set_source_zip_finalize(
        upload_id=UPLOAD,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=workspace,
        session_id=SESSION,
    )


def _finalize_refusal(payload: bytes, workspace: Path) -> sa.SourceArchiveRefused:
    """What the finalize raises for ``payload``, an upload it removes as refused.

    It raises the shared refusal for everything that is about the archive: a rule, and
    what zipfile cannot read, alike. Bytes that are not a zip are a refusal that is a
    ``zipfile.BadZipFile`` as well, as the finalize has always raised for them.
    """
    _upload(payload, workspace)
    with pytest.raises(sa.SourceArchiveRefused) as refused:
        _finalize(payload, workspace)
    assert not sd._final_zip_path(workspace / SESSION, UPLOAD).exists(), (
        "a refused upload was kept"
    )
    return refused.value


def _verdict(error: sa.SourceArchiveRefused) -> Tuple[Kind, str]:
    """The rule and the words of a refusal from either entry point."""
    return error.kind, str(error)


def _in_the_finalizes_words(message: str) -> str:
    """A shared-function message as the finalize words it: the link noun differs."""
    return message.replace(sa.SOURCE_ARCHIVES, sd._DELIVERY_ARCHIVES)


@pytest.fixture(autouse=True)
def _forget_sessions():
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    clear_all_session_state()


# ---------------------------------------------------------------------------
# One row per rule: (archive, or the fixture that builds it; rule; message).
# ---------------------------------------------------------------------------

#: Two stored zips, each with an app.py. Joined end to end, zipfile reads the second,
#: whose app.py says EVIL = False, while a reader that walks the local headers from
#: byte 0 reads the first, whose app.py says EVIL = True; Info-ZIP's unzip warns of
#: extra bytes at the start and exits 1.
_FIRST_OF_TWO = _zip({"app.py": b"EVIL = True\n"}, compression=zipfile.ZIP_STORED)
_SECOND_OF_TWO = _zip(
    {"app.py": b"EVIL = False\n", "readme.md": b"# ok\n"},
    compression=zipfile.ZIP_STORED,
)
_TAR_OF_A_ZIP, _END_OF_THE_ZIP_IN_THE_TAR = _tar_ending_in_a_zip()
#: What a self-extracting archive, or a script that carries one, puts before the zip.
_STUB = b'#!/bin/sh\nexec unzip -o "$0"\n'
_AFTER_THE_END = b"not part of the zip\n"
#: A member a row writes into the file and leaves out of the central directory.
_HIDDEN = _Raw(b"evil.py", b"EVIL = True\n")
_STORED = b"print('stored as it is')\n"


def _stored(content: bytes = _STORED) -> bytes:
    """A zip of one stored member, ``a.py``, whose local header starts at byte 0."""
    return _zip({"a.py": content}, compression=zipfile.ZIP_STORED)


REFUSED = [
    pytest.param(
        "over_the_extracted_total",
        Kind.EXTRACTED_TOO_LARGE,
        f"extracted size exceeds {500 * MiB} bytes (at entry 'zeros.bin')",
        id="uncompressed-total-over-500-mib",
    ),
    pytest.param(
        "over_the_member_count",
        Kind.TOO_MANY_MEMBERS,
        "too many files in zip: 50001 > 50000",
        id="over-50000-members",
    ),
    pytest.param(
        _zip_with_modes({"evil": (b"/outside/the/tree", 0o120777)}),
        Kind.SYMLINK_MEMBER,
        "symlink 'evil' -> '/outside/the/tree': "
        "symlinks are not allowed in source archives",
        id="symlink-member",
    ),
    pytest.param(
        _zip_with_modes(
            {
                "docs/guide.md": (b"# Guide\n", 0o100644),
                "guide.md": (b"docs/guide.md", 0o120644),
            }
        ),
        Kind.SYMLINK_MEMBER,
        "symlink 'guide.md' -> 'docs/guide.md': "
        "symlinks are not allowed in source archives",
        id="refused-for-its-type-though-it-points-inside",
    ),
    pytest.param(
        _zip({"/abs/escape.py": b"x"}),
        Kind.ABSOLUTE_PATH,
        "absolute path in zip: '/abs/escape.py'",
        id="absolute-path",
    ),
    pytest.param(
        _zip({"src/../../escape.py": b"x"}),
        Kind.PATH_TRAVERSAL,
        "path traversal in zip: 'src/../../escape.py'",
        id="dotdot-component",
    ),
    pytest.param(
        _zip({"../escape.py": b"x"}),
        Kind.PATH_TRAVERSAL,
        "path traversal in zip: '../escape.py'",
        id="leading-dotdot",
    ),
    pytest.param(
        _renamed(_zip({"toolX.py": b"x"}), "toolX.py", b"tool\x00.py"),
        Kind.NUL_IN_NAME,
        "NUL in zip entry name: 'tool\\x00.py'",
        id="nul-in-a-name",
    ),
    pytest.param(
        _renamed(_zip({"pkgXmod.py": b"x"}), "pkgXmod.py", b"pkg\\mod.py"),
        Kind.BACKSLASH_IN_NAME,
        "backslash in zip entry name: 'pkg\\\\mod.py'",
        id="backslash-in-a-name",
    ),
    pytest.param(
        # Written byte by byte: zipfile before 3.12 cannot write a member with no
        # name (an IndexError), so a zipfile-built row kept this module from loading
        # on Python 3.11 at all.
        _raw_zip([_Raw(b"", b"x")]),
        Kind.EMPTY_NAME,
        "zip entry has empty name",
        id="empty-name",
    ),
    # zipfile drops "." and empty components when it extracts, so each of these
    # lands on a path the archive spells another way: probe_mod.py beside
    # ./probe_mod.py is one file on disk and two members to a reader that looks
    # members up by name, as zipimport does. Red at the base: all three were admitted.
    pytest.param(
        _zip({"./app.py": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: './app.py'",
        id="leading-dot-component",
    ),
    pytest.param(
        _zip({"a/./b.py": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: 'a/./b.py'",
        id="inner-dot-component",
    ),
    pytest.param(
        # Red at the base as the raw ValueError("Empty filename.") of the extraction.
        _zip({".": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: '.'",
        id="a-name-that-is-one-dot",
    ),
    pytest.param(
        _zip({"pkg//mod.py": b"x"}),
        Kind.EMPTY_COMPONENT,
        "empty component in zip entry name: 'pkg//mod.py'",
        id="empty-component",
    ),
    pytest.param(
        _zip({"pkg//": b""}),
        Kind.EMPTY_COMPONENT,
        "empty component in zip entry name: 'pkg//'",
        id="a-directory-with-two-trailing-slashes",
    ),
    # One path, one member. Red at the base: the first two were extracted the later
    # over the earlier, and the rest ended in the OSError of the clash on disk.
    pytest.param(
        _zip_members([("app.py", b"EVIL = True\n"), ("app.py", b"EVIL = False\n")]),
        Kind.PATH_COLLISION,
        "zip entries 'app.py' and 'app.py' are extracted to one path",
        id="two-members-of-one-name",
    ),
    pytest.param(
        _zip_members([("pkg/", b""), ("pkg/", b"")]),
        Kind.PATH_COLLISION,
        "zip entries 'pkg/' and 'pkg/' are extracted to one path",
        id="two-directory-members-of-one-name",
    ),
    pytest.param(
        _zip_members([("pkg", b"a file"), ("pkg/", b"")]),
        Kind.PATH_COLLISION,
        "zip entries 'pkg' and 'pkg/' are extracted to one path",
        id="a-file-and-a-directory-of-one-path",
    ),
    pytest.param(
        _zip_members([("pkg", b"a file"), ("pkg/mod.py", b"x")]),
        Kind.PATH_COLLISION,
        "zip entry 'pkg/mod.py' is under 'pkg', which the archive holds as a file",
        id="a-member-under-an-earlier-file",
    ),
    pytest.param(
        _zip_members([("pkg/mod.py", b"x"), ("pkg", b"a file")]),
        Kind.PATH_COLLISION,
        "zip entry 'pkg/mod.py' is under 'pkg', which the archive holds as a file",
        id="a-file-at-the-directory-of-an-earlier-member",
    ),
    pytest.param(
        # "a-b" sorts between "a" and "a/c" when "/" is compared as itself; the rule
        # has to find "a/c" under the file "a" anyway.
        _zip_members([("a", b"a file"), ("a-b", b"x"), ("a/c", b"y")]),
        Kind.PATH_COLLISION,
        "zip entry 'a/c' is under 'a', which the archive holds as a file",
        id="a-member-under-a-file-with-a-sibling-between",
    ),
    pytest.param(
        b"plain text, not an archive\n",
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="not-a-zip",
    ),
    pytest.param(
        _tar(gzipped=False),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="tar-refused-naming-zip",
    ),
    pytest.param(
        _tar(gzipped=True),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="gzipped-tar-refused-naming-zip",
    ),
    pytest.param(
        gzip.compress(b"print('hello')\n", mtime=0),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="gzip-refused-naming-zip",
    ),
    # Rule 6: one zip, and nothing else in the file. Red at the base: zipfile read each
    # of these as the zip whose end record it found last, and the archive was admitted,
    # or ended in what zipfile raised for a local header once extraction reached it.
    pytest.param(
        _FIRST_OF_TWO + _SECOND_OF_TWO,
        Kind.NOT_A_ZIP,
        f"{len(_FIRST_OF_TWO)} bytes come before the archive",
        id="two-zips-end-to-end",
    ),
    pytest.param(
        # Read by zipfile as the zip at its end, and by `ash scan image --archive` as
        # the tar it is. The tar's zeros after the zip are what this rule meets first.
        _TAR_OF_A_ZIP,
        Kind.NOT_A_ZIP,
        f"{len(_TAR_OF_A_ZIP) - _END_OF_THE_ZIP_IN_THE_TAR} bytes follow "
        "the archive's end record",
        id="a-tar-whose-last-member-is-a-zip",
    ),
    pytest.param(
        _STUB + _zip({"app.py": b"x"}),
        Kind.NOT_A_ZIP,
        f"{len(_STUB)} bytes come before the archive",
        id="a-program-before-the-archive",
    ),
    pytest.param(
        # The same, written by a tool that counts the program into every offset.
        _raw_zip([_Raw(b"app.py", b"x")], before=_STUB),
        Kind.NOT_A_ZIP,
        f"{len(_STUB)} bytes come before the archive's first member",
        id="a-program-before-an-archive-whose-offsets-count-it",
    ),
    pytest.param(
        # zipfile finds no zip64 end record where the locator puts it, looks just
        # before the locator, and takes the difference for bytes before the archive.
        b"junk" + _raw_zip([_Raw(b"app.py", b"x")], zip64_end=True),
        Kind.NOT_A_ZIP,
        "4 bytes come before the archive",
        id="bytes-before-a-zip64-archive",
    ),
    pytest.param(
        _raw_zip([], before=b"junk"),
        Kind.NOT_A_ZIP,
        "4 bytes come before the archive's central directory",
        id="bytes-before-an-empty-archive",
    ),
    pytest.param(
        _zip({"app.py": b"x"}) + _AFTER_THE_END,
        Kind.NOT_A_ZIP,
        f"{len(_AFTER_THE_END)} bytes follow the archive's end record",
        id="bytes-after-the-end-record",
    ),
    pytest.param(
        _with_comment_length(_zip({"app.py": b"x"}), 10),
        Kind.NOT_A_ZIP,
        "the archive's end record claims a 10-byte comment, and 0 bytes follow it",
        id="a-comment-longer-than-the-file-holds",
    ),
    pytest.param(
        # A reader that walks the local headers extracts evil.py; zipfile, which
        # reads the central directory, never sees it.
        _raw_zip(
            [_Raw(b"a.py", b"A = 1\n"), _HIDDEN, _Raw(b"b.py", b"B = 2\n")],
            listed=[0, 2],
        ),
        Kind.NOT_A_ZIP,
        f"{len(_HIDDEN.local_record())} bytes lie between zip entries 'a.py' and "
        "'b.py'",
        id="a-member-the-central-directory-leaves-out",
    ),
    pytest.param(
        _raw_zip([_Raw(b"a.py", b"A = 1\n"), _HIDDEN], listed=[0]),
        Kind.NOT_A_ZIP,
        f"{len(_HIDDEN.local_record())} bytes lie between zip entry 'a.py' and the "
        "central directory",
        id="a-member-left-out-before-the-central-directory",
    ),
    pytest.param(
        _with_header_offset(_zip_members([("a.py", b"x"), ("b.py", b"y")]), 1, 0),
        Kind.NOT_A_ZIP,
        "zip entries 'a.py' and 'b.py' overlap",
        id="two-entries-on-one-local-header",
    ),
    pytest.param(
        # zipfile took the excess for bytes before the archive and placed the member
        # 1000 bytes before the file: an OSError (EINVAL) at the base.
        _with_central_directory_moved_on(_zip({"a.py": b"x"}), 1000),
        Kind.NOT_A_ZIP,
        "the archive's end record places its central directory 1000 bytes past "
        "where it lies",
        id="a-central-directory-offset-past-where-it-lies",
    ),
    pytest.param(
        # A zip64 offset of 2**63, which no seek takes: an OverflowError or an OSError
        # at the base.
        _with_zip64_header_offset(_stored(b"x"), 2**63),
        Kind.NOT_A_ZIP,
        f"the central directory places zip entry 'a.py' at byte {2**63}, which is "
        "not before the central directory",
        id="a-header-offset-past-the-central-directory",
    ),
    pytest.param(
        _patched(_zip({"a.py": b"x"}), 0, b"XX"),
        Kind.NOT_A_ZIP,
        "zip entry 'a.py' has no local header at byte 0",
        id="a-member-without-its-local-header",
    ),
    pytest.param(
        # The sizes at 18 and 22 of the local header: a reader of the local headers
        # takes 4 bytes for the member and looks for the next header after them.
        _patched(_stored(), 18, struct.pack("<LL", 4, 4)),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'a.py' gives another size than the central "
        "directory",
        id="a-local-header-that-gives-another-size",
    ),
    pytest.param(
        _patched(_stored(), 14, struct.pack("<L", 0)),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'a.py' gives another CRC-32 than the central "
        "directory",
        id="a-local-header-that-gives-another-crc",
    ),
    pytest.param(
        # The method at 8: deflated, where the central directory says stored.
        _patched(_stored(), 8, struct.pack("<H", zipfile.ZIP_DEFLATED)),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'a.py' gives another compression method than "
        "the central directory",
        id="a-local-header-that-gives-another-method",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"a.py",
                    _STORED,
                    flags=0x8,
                    local_flags=0,
                    descriptor=_descriptor(_STORED),
                )
            ]
        ),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'a.py' gives another data descriptor flag "
        "than the central directory",
        id="a-local-header-without-the-data-descriptor-flag",
    ),
    pytest.param(
        _raw_zip(
            [_Raw(b"a.py", _STORED, flags=0x8, descriptor=_descriptor(b"another"))]
        ),
        Kind.NOT_A_ZIP,
        "zip entry 'a.py' is not followed by a data descriptor that restates its "
        "CRC-32 and sizes",
        id="a-data-descriptor-that-does-not-restate-its-member",
    ),
    pytest.param(
        _raw_zip([_Raw(b"a.py", _STORED, flags=0x8)]),
        Kind.NOT_A_ZIP,
        "zip entry 'a.py' is not followed by a data descriptor that restates its "
        "CRC-32 and sizes",
        id="a-member-flagged-for-a-data-descriptor-without-one",
    ),
    pytest.param(
        # A reader that counts members by the end record reads one of two, or two of
        # one, while zipfile reads the central directory to its end.
        _with_end_record_counts(_zip({"a.py": b"x"}), 2, 2),
        Kind.NOT_A_ZIP,
        "the archive's end record counts 2 members, and its central directory holds 1",
        id="an-end-record-that-counts-another-number-of-members",
    ),
    pytest.param(
        _with_end_record_counts(_zip({"a.py": b"x"}), 2, 1),
        Kind.NOT_A_ZIP,
        "the archive's end record counts 2 members, and its central directory holds 1",
        id="an-end-record-that-counts-another-number-on-this-disk",
    ),
    pytest.param(
        # Both headers agree on a compressed size ten bytes longer than the data,
        # which takes the member's data into the central directory.
        _with_compressed_size(_stored(), len(_STORED) + 10),
        Kind.NOT_A_ZIP,
        "zip entry 'a.py' runs into the central directory",
        id="a-member-whose-data-runs-into-the-central-directory",
    ),
    pytest.param(
        # zipfile reads the comment from what is left of the central directory,
        # nothing; a reader of the file reads it from the end record that follows.
        _with_entry_comment_length(_zip({"a.py": b"x"}), 0, 10),
        Kind.NOT_A_ZIP,
        "the central directory entry of zip entry 'a.py' runs past the central "
        "directory",
        id="a-central-directory-entry-that-runs-past-the-directory",
    ),
    # Rule 7: the flag is read right after the members are counted.
    pytest.param(
        _flagged_encrypted(_zip({"a.py": b"print(1)\n"})),
        Kind.ENCRYPTED_MEMBER,
        "zip entry 'a.py' is encrypted: an encrypted member cannot be read",
        id="an-encrypted-member",
    ),
    pytest.param(
        # One kind and one precedence: the flag is read before the link is.
        _flagged_encrypted(_zip_with_modes({"evil": (b"/outside/the/tree", 0o120777)})),
        Kind.ENCRYPTED_MEMBER,
        "zip entry 'evil' is encrypted: an encrypted member cannot be read",
        id="an-encrypted-link",
    ),
    pytest.param(
        # The flags are read before the names are judged.
        _raw_zip([_Raw(b"../escape.py", b"x"), _Raw(b"a.py", b"y", flags=0x1)]),
        Kind.ENCRYPTED_MEMBER,
        "zip entry 'a.py' is encrypted: an encrypted member cannot be read",
        id="an-encrypted-member-after-a-name-that-is-refused",
    ),
]

#: Rule 3, run under this Python's zipfile and under one that ignores the field.
SECOND_NAMES = [
    pytest.param(
        # zipfile from 3.12 extracts the second member as app.py, over the first;
        # zipimport and every reader that ignores the field keep the first.
        _zip_with_unicode_paths(
            [
                ("app.py", None, b"EVIL = True\n"),
                ("zzz.py", "app.py", b"EVIL = False\n"),
            ]
        ),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'zzz.py' is named 'app.py' by its Unicode path field: the field "
        "names another file",
        id="a-unicode-path-onto-another-member",
    ),
    pytest.param(
        # Scanned as text while `import app` runs it.
        _zip_with_unicode_paths([("app.py", "app.txt", b"EVIL = True\n")]),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.py' is named 'app.txt' by its Unicode path field: the field "
        "names another file",
        id="a-unicode-path-that-renames-the-member",
    ),
    pytest.param(
        # Python 3.11's zipfile wrote app.txt, which no Python scanner reads, and
        # Info-ZIP's unzip extracts app.py. Red at the base under a zipfile that
        # ignores the field: admitted.
        _zip_with_unicode_paths([("app.txt", "app.py", b"EVIL = True\n")]),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.txt' is named 'app.py' by its Unicode path field: the field "
        "names another file",
        id="a-unicode-path-that-gives-a-text-file-a-python-name",
    ),
    # Whatever the field's version or CRC-32 says, since readers differ in which
    # fields they apply. Red at the base on every Python: zipfile skips both fields,
    # so they were admitted.
    pytest.param(
        _zip_with_extra(
            "app.txt",
            _unicode_path_field(b"app.txt", "app.py", version=2),
            b"EVIL = True\n",
        ),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.txt' is named 'app.py' by its Unicode path field: the field "
        "names another file",
        id="a-unicode-path-field-of-another-version",
    ),
    pytest.param(
        _zip_with_extra(
            "app.txt",
            _unicode_path_field(b"app.txt", "app.py", crc_of=b"other.txt"),
            b"EVIL = True\n",
        ),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.txt' is named 'app.py' by its Unicode path field: the field "
        "names another file",
        id="a-unicode-path-field-with-another-names-crc",
    ),
    pytest.param(
        # zipfile never reads a local header's extra field; a reader that walks the
        # local headers does.
        _raw_zip(
            [
                _Raw(
                    b"app.txt",
                    b"EVIL = True\n",
                    local_extra=_unicode_path_field(b"app.txt", "app.py"),
                )
            ]
        ),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.txt' is named 'app.py' by the Unicode path field of its "
        "local header: the field names another file",
        id="a-unicode-path-field-in-the-local-header-alone",
    ),
    # A field that cannot be read is refused in the central directory in the words
    # zipfile from 3.12 uses as it opens the archive, so every Python refuses it alike.
    # Red at the base before 3.12, where zipfile ignores the field: admitted.
    pytest.param(
        _zip_with_extra("app.py", struct.pack("<HH", 0x7075, 3) + b"\x01ab", b"x"),
        Kind.NOT_A_ZIP,
        "Corrupt unicode path extra field (0x7075)",
        id="a-unicode-path-field-too-short-to-read",
    ),
    pytest.param(
        _zip_with_extra("app.py", _unicode_path_field(b"app.py", b"\xff\xfe"), b"x"),
        Kind.NOT_A_ZIP,
        "Corrupt unicode path extra field (0x7075): invalid utf-8 bytes",
        id="a-unicode-path-field-that-is-not-utf8",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"app.py",
                    b"x",
                    local_extra=struct.pack("<HH", 0x7075, 3) + b"\x01ab",
                )
            ]
        ),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'app.py' holds a corrupt Unicode path field "
        "(0x7075)",
        id="a-local-unicode-path-field-too-short-to-read",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"app.py",
                    b"x",
                    local_extra=_unicode_path_field(b"app.py", b"\xff\xfe"),
                )
            ]
        ),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'app.py' holds a corrupt Unicode path field "
        "(0x7075): invalid utf-8 bytes",
        id="a-local-unicode-path-field-that-is-not-utf8",
    ),
    pytest.param(
        # A block that claims 40 bytes of data and holds 1.
        _raw_zip(
            [
                _Raw(
                    b"app.py",
                    b"x",
                    local_extra=struct.pack("<HH", 0x7075, 40) + b"\x01",
                )
            ]
        ),
        Kind.NOT_A_ZIP,
        "the local header of zip entry 'app.py' holds a corrupt extra field",
        id="a-corrupt-extra-field-in-a-local-header",
    ),
]

#: Every layout a zip writer makes, which rule 6 has to admit: (archive, tree).
_PIPED = {"app.py": b"print('written to a pipe')\n", "pkg/mod.py": b"VALUE = 1\n"}
_PIPED_TREE = {
    "app.py": _PIPED["app.py"],
    "pkg": None,
    "pkg/mod.py": _PIPED["pkg/mod.py"],
}
ADMITTED = [
    pytest.param(
        _zip_written_to_a_pipe(_PIPED),
        _PIPED_TREE,
        id="data-descriptors-as-zipfile-writes-them-to-a-pipe",
    ),
    pytest.param(
        _zip_written_to_a_pipe(_PIPED, zip64=True),
        _PIPED_TREE,
        id="zip64-data-descriptors-as-zipfile-writes-them-to-a-pipe",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"a.py",
                    _STORED,
                    flags=0x8,
                    descriptor=_descriptor(_STORED, signature=False),
                )
            ]
        ),
        {"a.py": _STORED},
        id="a-data-descriptor-without-its-signature",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"a.py",
                    _STORED,
                    flags=0x8,
                    descriptor=_descriptor(_STORED, signature=False, zip64=True),
                )
            ]
        ),
        {"a.py": _STORED},
        id="a-zip64-data-descriptor-without-its-signature",
    ),
    pytest.param(
        _raw_zip(
            [
                _Raw(
                    b"a.py",
                    _STORED,
                    flags=0x8,
                    local_sizes=(zlib.crc32(_STORED), len(_STORED), len(_STORED)),
                    descriptor=_descriptor(_STORED),
                )
            ]
        ),
        {"a.py": _STORED},
        id="a-data-descriptor-whose-local-header-gives-the-sizes-too",
    ),
    pytest.param(
        _raw_zip(
            [_Raw(b"a.py", b"A = 1\n"), _Raw(b"b.py", b"B = 2\n")], zip64_end=True
        ),
        {"a.py": b"A = 1\n", "b.py": b"B = 2\n"},
        id="zip64-end-records",
    ),
    pytest.param(
        _zip_with_comment({"app.py": b"x"}, b"an archive comment"),
        {"app.py": b"x"},
        id="an-archive-comment",
    ),
    pytest.param(_zip({}), {}, id="an-empty-archive"),
]


def _payload(request: pytest.FixtureRequest, source: Union[str, bytes]) -> bytes:
    return request.getfixturevalue(source) if isinstance(source, str) else source


class TestEachRuleRefusesBeforeAnythingIsWritten:
    @pytest.mark.parametrize("source,kind,message", REFUSED)
    def test_the_shared_function_refuses_it(
        self, request, tmp_path, source, kind, message
    ):
        destination = tmp_path / "tree"
        refused = _extraction_refusal(
            _archive_file(tmp_path, _payload(request, source)), destination
        )

        assert refused.kind is kind
        assert str(refused) == message
        assert not destination.exists(), "a refused archive made the destination"

    @pytest.mark.parametrize("source,kind,message", REFUSED)
    def test_the_finalize_refuses_it_in_the_same_words(
        self, request, tmp_path, source, kind, message
    ):
        """Red at the base for the NUL row: the finalize extracted ``tool<NUL>.py``
        as ``tool``, which no Python scanner reads."""
        payload = _payload(request, source)
        shared = _verdict(
            _extraction_refusal(_archive_file(tmp_path, payload), tmp_path / "tree")
        )
        delivered = _verdict(_finalize_refusal(payload, tmp_path / "workspace"))

        assert delivered == (shared[0], _in_the_finalizes_words(shared[1]))
        assert delivered[0] is kind

    def test_the_finalize_keeps_its_own_words_for_a_link(self, tmp_path):
        payload = _zip_with_modes({"evil": (b"/outside/the/tree", 0o120777)})
        refused = _finalize_refusal(payload, tmp_path / "workspace")

        assert str(refused) == (
            "symlink 'evil' -> '/outside/the/tree': "
            "symlinks are not allowed in MCP source delivery zips"
        )

    def test_an_archive_over_100_mib_is_refused_before_it_is_read(self, tmp_path):
        destination = tmp_path / "tree"
        refused = _extraction_refusal(
            _sparse(tmp_path / "big.zip", 100 * MiB + 1), destination
        )

        assert refused.kind is Kind.ARCHIVE_TOO_LARGE
        assert str(refused) == f"zip too large: {100 * MiB + 1} > {100 * MiB} bytes"
        assert not destination.exists()

    def test_the_finalize_refuses_the_same_oversized_archive_in_the_same_words(
        self, tmp_path
    ):
        """The chunks cannot carry an archive past the limit, so the finalized file is
        grown in place, as an archive put there some other way would be."""
        workspace = tmp_path / "workspace"
        small = _zip({"a.py": b"x"})
        _upload(small, workspace)
        os.truncate(sd._final_zip_path(workspace / SESSION, UPLOAD), 100 * MiB + 1)
        with pytest.raises(ValueError) as delivered:
            _finalize(small, workspace)

        shared = _extraction_refusal(
            _sparse(tmp_path / "big.zip", 100 * MiB + 1), tmp_path / "tree"
        )
        assert _verdict(delivered.value) == _verdict(shared)


class TestASecondNameIsRefusedWhicheverNameZipfileTakes:
    """Rule 3 reads the Unicode path field itself, so this zipfile cannot change it.

    Each row runs under this Python's zipfile and under one made to ignore the field,
    as zipfile did before 3.12 (``zipfile_reading``), and has to reach one verdict,
    in one set of words, from both entry points.
    """

    @pytest.mark.parametrize("source,kind,message", SECOND_NAMES)
    def test_the_shared_function_refuses_it(
        self, zipfile_reading, tmp_path, source, kind, message
    ):
        destination = tmp_path / "tree"
        refused = _extraction_refusal(_archive_file(tmp_path, source), destination)

        assert (refused.kind, str(refused)) == (kind, message)
        assert not destination.exists(), "a refused archive made the destination"

    @pytest.mark.parametrize("source,kind,message", SECOND_NAMES)
    def test_the_finalize_refuses_it_in_the_same_words(
        self, zipfile_reading, tmp_path, source, kind, message
    ):
        delivered = _verdict(_finalize_refusal(source, tmp_path / "workspace"))

        assert delivered == (kind, message)

    def test_the_zipfile_made_to_ignore_the_field_keeps_the_spelled_name(
        self, monkeypatch
    ):
        """Control for the second run of each row: what it simulates is what zipfile
        before 3.12 did, here as on any Python."""
        _as_zipfile_before_3_12(monkeypatch)
        payload = _zip_with_unicode_paths([("a.py", "b.py", b"")])

        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            assert archive.infolist()[0].filename == "a.py"


class TestTheBoundariesAreAdmitted:
    """Controls for the limits: each one admits the value at the limit itself."""

    def test_an_archive_of_exactly_100_mib_passes_the_size_rule(self, tmp_path):
        refused = _extraction_refusal(
            _sparse(tmp_path / "edge.zip", 100 * MiB), tmp_path / "tree"
        )

        # It is not a zip, the next rule: the size rule let it through.
        assert refused.kind is Kind.NOT_A_ZIP

    def test_exactly_500_mib_uncompressed_is_admitted(self):
        with zipfile.ZipFile(io.BytesIO(_zeros_member(500 * MiB))) as archive:
            members = sa.admit_zip_members(archive)

        assert [member.file_size for member in members] == [500 * MiB]

    def test_exactly_50000_members_are_admitted(self):
        with zipfile.ZipFile(io.BytesIO(_empty_members(50_000))) as archive:
            assert len(sa.admit_zip_members(archive)) == 50_000

    def test_a_closed_archive_is_a_value_error_not_a_refusal(self):
        """Rule 6 reads the file the archive was opened on, which a closed one no
        longer holds: that is the caller's mistake, in zipfile's own words."""
        archive = zipfile.ZipFile(io.BytesIO(_zip({"a.py": b"x"})))
        archive.close()

        with pytest.raises(ValueError) as failed:
            sa.admit_zip_members(archive)

        assert not isinstance(failed.value, sa.SourceArchiveRefused)
        assert str(failed.value) == "Attempt to use ZIP archive that was already closed"

    def test_the_limits_are_the_deliverys(self):
        limits = (sa.MAX_ARCHIVE_BYTES, sa.MAX_EXTRACTED_BYTES, sa.MAX_MEMBERS)

        assert limits == (100 * MiB, 500 * MiB, 50_000)
        assert limits == (sd._MAX_ZIP_BYTES, sd._MAX_EXTRACTED_BYTES, sd._MAX_FILES)
        assert sa.SUPPORTED_ARCHIVE_FORMATS == ("zip",)


# ---------------------------------------------------------------------------
# What is extracted.
# ---------------------------------------------------------------------------


class TestTheTreeIsExtractedAsArchived:
    def test_a_nested_tree_extracts_to_the_same_files(self, tmp_path):
        source = _nested_tree(tmp_path / "source")
        archive = _archive_file(tmp_path, _zip_of(source))
        destination = tmp_path / "tree"

        assert sa.extract_source_archive(archive, destination) == destination
        assert _tree(destination) == _tree(source)

    def test_the_finalize_delivers_the_same_tree(self, tmp_path):
        source = _nested_tree(tmp_path / "source")
        payload = _zip_of(source)
        extracted = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        _upload(payload, tmp_path / "workspace")
        delivered = _finalize(payload, tmp_path / "workspace")

        assert _tree(delivered) == _tree(extracted) == _tree(source)

    def test_members_without_a_unix_file_type_are_regular_files(self, tmp_path):
        """Control for the link rule: Windows zip tools write no type bits, and
        ``writestr`` writes a mode with none either."""
        payload = _zip_with_modes(
            {"a.py": (b"print(1)\n", 0), "b.py": (b"print(2)\n", 0o644)}
        )

        destination = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert _tree(destination) == {"a.py": b"print(1)\n", "b.py": b"print(2)\n"}

    def test_an_empty_existing_destination_is_used(self, tmp_path):
        destination = tmp_path / "tree"
        destination.mkdir()

        sa.extract_source_archive(
            _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
        )

        assert _tree(destination) == {"a.py": b"x"}

    def test_a_destination_that_holds_anything_is_left_as_it_was(self, tmp_path):
        """Extracting into a tree that is already there would scan files the
        archive never held, so the call is refused, as the caller's error."""
        destination = tmp_path / "tree"
        destination.mkdir()
        (destination / "kept.txt").write_bytes(b"already here")

        with pytest.raises(OSError) as refused:
            sa.extract_source_archive(
                _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
            )

        assert not isinstance(refused.value, sa.SourceArchiveRefused)
        assert _tree(destination) == {"kept.txt": b"already here"}

    def test_paths_that_share_a_head_but_not_a_directory_are_admitted(self, tmp_path):
        """Control for the one-path rule: a file ``pkg`` and the members ``pkg-x/a.py``
        and ``pkg.py`` beside it name three paths, none under another."""
        entries = [("pkg", b"a file"), ("pkg-x/a.py", b"x"), ("pkg.py", b"y")]
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip_members(entries)), tmp_path / "tree"
        )

        assert _tree(destination) == {
            "pkg": b"a file",
            "pkg-x": None,
            "pkg-x/a.py": b"x",
            "pkg.py": b"y",
        }

    def test_a_directory_member_with_members_under_it_is_admitted(self, tmp_path):
        """Control: a directory and the files under it are one tree, not a clash."""
        entries = [("pkg/", b""), ("pkg/mod.py", b"x"), ("pkg/sub/", b"")]
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip_members(entries)), tmp_path / "tree"
        )

        assert _tree(destination) == {
            "pkg": None,
            "pkg/mod.py": b"x",
            "pkg/sub": None,
        }


class TestOneZipIsAdmittedHoweverItsWriterLaysItOut:
    """Controls for rule 6: each layout a zip writer makes is one zip, and admitted.

    A data descriptor in each of the four shapes the format allows (its signature or
    none, four-byte or eight-byte sizes), one whose local header gives the sizes as
    well, zip64 end records, an archive comment, and no members at all.
    """

    @pytest.mark.parametrize("payload,tree", ADMITTED)
    def test_both_entry_points_extract_it(self, tmp_path, payload, tree):
        extracted = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )
        _upload(payload, tmp_path / "workspace")
        delivered = _finalize(payload, tmp_path / "workspace")

        assert _tree(extracted) == tree
        assert _tree(delivered) == tree


class TestAUnicodePathField:
    """Rule 3: the name zipfile extracts a member under has to be the member's own."""

    def test_one_that_restates_a_utf8_name_is_admitted(self, zipfile_reading, tmp_path):
        """Info-ZIP's own shape for a name outside ASCII, from a UTF-8 system, with the
        field in the local header too: the member is extracted under the name zipfile
        reads, by both entry points, whether that zipfile applies the field or not."""
        payload = _info_zip_utf8_name("docs/café.md", b"# Notes\n")
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            (written,) = archive.namelist()

        extracted = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )
        _upload(payload, tmp_path / "workspace")
        delivered = _finalize(payload, tmp_path / "workspace")

        assert _tree(extracted) == {"docs": None, written: b"# Notes\n"}
        assert _tree(delivered) == _tree(extracted)

    @_NEEDS_UNICODE_PATHS
    def test_the_restated_name_is_the_utf8_one(self):
        """What the row above extracts, from 3.12: the field's name, not cp437 text."""
        payload = _info_zip_utf8_name("docs/café.md", b"# Notes\n")
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            (info,) = sa.admit_zip_members(archive)

        assert info.filename == "docs/café.md"
        assert info.orig_filename != info.filename

    def test_where_zipfile_ignores_the_field_it_is_refused_all_the_same(
        self, monkeypatch, tmp_path
    ):
        """Re-pinned from an admission. zipfile before 3.12 extracts the member under
        the name the archive spells, app.py, and Info-ZIP's unzip under the field's,
        app.txt: not one name that every reader sees, but two. The module reads the
        field itself, so a zipfile that ignores it changes nothing. Red at the base
        under such a zipfile, real on 3.11 and simulated here on any Python: admitted,
        and written as app.py."""
        _as_zipfile_before_3_12(monkeypatch)
        payload = _zip_with_unicode_paths([("app.py", "app.txt", b"x")])
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is Kind.UNICODE_PATH_MISMATCH
        assert str(refused) == (
            "zip entry 'app.py' is named 'app.txt' by its Unicode path field: the "
            "field names another file"
        )
        assert not destination.exists()


#: Names Windows cannot hold as spelled, and the component that makes each so.
WINDOWS_RESERVED = [
    pytest.param("a:b.py", "a:b.py", id="colon"),
    pytest.param("pkg/q?.py", "q?.py", id="question-mark"),
    pytest.param("star*.py", "star*.py", id="asterisk"),
    pytest.param("pipe|.py", "pipe|.py", id="pipe"),
    pytest.param('quote".py', 'quote".py', id="double-quote"),
    pytest.param("lt<gt>.py", "lt<gt>.py", id="angle-brackets"),
    pytest.param("tab\there.py", "tab\there.py", id="control-character"),
    pytest.param("pkg/x.py.", "x.py.", id="trailing-dot"),
    pytest.param("dir./x.py", "dir.", id="trailing-dot-on-a-directory"),
    pytest.param("x.py ", "x.py ", id="trailing-space"),
    pytest.param("nul.py", "nul.py", id="device-name-with-an-extension"),
    pytest.param("pkg/CON", "CON", id="device-name"),
    pytest.param("aux/x.py", "aux", id="device-name-as-a-directory"),
    pytest.param("COM1.txt", "COM1.txt", id="numbered-device-name"),
    pytest.param("lpt\xb9.txt", "lpt\xb9.txt", id="superscript-device-name"),
    pytest.param("nul .txt", "nul .txt", id="device-name-and-a-space"),
]


class TestNamesWindowsCannotHold:
    """Rule 2 on Windows: zipfile would rewrite these, or Windows would open a device."""

    @pytest.mark.parametrize("name,component", WINDOWS_RESERVED)
    def test_on_windows_each_is_refused(self, monkeypatch, name, component):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)

        with pytest.raises(sa.SourceArchiveRefused) as refused:
            sa.validate_member_name(name)

        assert refused.value.kind is Kind.RESERVED_NAME
        assert str(refused.value) == (
            f"reserved name on Windows in zip entry name {name!r}: {component!r}"
        )

    @pytest.mark.parametrize("name,component", WINDOWS_RESERVED)
    def test_elsewhere_each_is_a_plain_name(self, monkeypatch, name, component):
        monkeypatch.setattr(sa, "_ON_WINDOWS", False)

        sa.validate_member_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "app.py",
            "docs/guide.md",
            "..config/settings.toml",
            "notes..txt",
            "pkg/",
            "connect.py",
            "console.log",
            "nul_device.md",
            "com10.txt",
            "lpt0",
            "auxiliary/x.py",
        ],
    )
    def test_on_windows_names_it_can_hold_are_admitted(self, monkeypatch, name):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)

        sa.validate_member_name(name)

    def test_on_windows_the_finalize_refuses_one_in_the_same_words(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)
        payload = _zip({"a:b.py": b"x"})

        shared = _verdict(
            _extraction_refusal(_archive_file(tmp_path, payload), tmp_path / "tree")
        )
        delivered = _verdict(_finalize_refusal(payload, tmp_path / "workspace"))

        assert delivered == shared
        assert shared[0] is Kind.RESERVED_NAME

    def test_on_windows_the_name_a_unicode_path_field_gives_is_judged_too(
        self, zipfile_reading, monkeypatch, tmp_path
    ):
        """The field restates COM² from its UTF-8 bytes, which zipfile spells as
        cp437 text no rule refuses; extracted under the field's name, by zipfile from
        3.12 or by a reader that applies it, it is the device COM². Judged whether or
        not this zipfile applies the field: red at the base under one that ignores it."""
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)
        payload = _info_zip_utf8_name("COM\xb2.py", b"x")

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.RESERVED_NAME
        assert str(refused) == (
            "reserved name on Windows in zip entry name 'COM\xb2.py': 'COM\xb2.py'"
        )

    @pytest.mark.skipif(os.name == "nt", reason="Windows cannot create the name")
    def test_elsewhere_a_colon_name_is_extracted_as_spelled(self, tmp_path):
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip({"a:b.py": b"x"})), tmp_path / "tree"
        )

        assert _tree(destination) == {"a:b.py": b"x"}

    def test_the_rule_follows_the_platform(self):
        assert sa._ON_WINDOWS is (os.name == "nt")


# ---------------------------------------------------------------------------
# What extract_source_archive adds, since it opens and extracts the file itself.
# ---------------------------------------------------------------------------


class TestTheFileItselfIsChecked:
    def test_a_path_that_is_not_a_regular_file_is_refused(self, tmp_path):
        directory = tmp_path / "a-directory.zip"
        directory.mkdir()

        refused = _extraction_refusal(directory, tmp_path / "tree")

        assert refused.kind is Kind.NOT_A_FILE
        assert str(refused) == f"{str(directory)!r} is not a regular file"

    def test_a_path_that_cannot_be_read_is_refused(self, tmp_path):
        missing = tmp_path / "missing.zip"

        refused = _extraction_refusal(missing, tmp_path / "tree")

        assert refused.kind is Kind.UNREADABLE_ARCHIVE
        assert str(refused).startswith(f"{str(missing)!r} cannot be read: ")

    def test_a_path_holding_a_nul_is_refused(self, tmp_path):
        """A ``--cli-json-input`` document can carry one; a command line cannot."""
        refused = _extraction_refusal(
            Path(f"{tmp_path}/bad\x00name.zip"), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_ARCHIVE
        assert "is not a valid path" in str(refused)

    def test_an_encrypted_member_is_refused_before_anything_is_written(self, tmp_path):
        payload = _flagged_encrypted(_zip({"a.py": b"print(1)\n"}))
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is Kind.ENCRYPTED_MEMBER
        assert "'a.py'" in str(refused)
        assert not destination.exists()

    def test_a_member_whose_data_fails_its_checksum_is_refused(self, tmp_path):
        content = b"VALUE = 'stored as it is'\n"
        payload = _with_damaged_data(
            _zip({"a.py": content}, compression=zipfile.ZIP_STORED), content
        )

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert "'a.py'" in str(refused)
        assert "Bad CRC-32" in str(refused)

    @pytest.mark.skipif(
        not Path("/proc/self/status").is_file(), reason="needs Linux /proc"
    )
    def test_a_file_longer_than_it_measured_is_refused_once_read_past_the_limit(
        self, monkeypatch, tmp_path
    ):
        """The size is checked before the read and again after it: a file that grew
        in between is refused, not read whole. A /proc file is a regular file that
        measures 0 bytes and holds more, which is the same shape."""
        monkeypatch.setattr(sa, "MAX_ARCHIVE_BYTES", 64)

        refused = _extraction_refusal(Path("/proc/self/status"), tmp_path / "tree")

        assert refused.kind is Kind.ARCHIVE_TOO_LARGE
        assert str(refused) == "zip too large: 65 > 64 bytes"
        assert not (tmp_path / "tree").exists()

    @pytest.mark.skipif(
        os.name == "nt" or os.geteuid() == 0,
        reason="needs POSIX permissions that bind the process",
    )
    def test_a_destination_that_cannot_be_written_is_an_os_error(self, tmp_path):
        """The other half of the contract: what goes wrong writing the tree is the
        destination's, and is not reported as the archive's."""
        destination = tmp_path / "tree"
        destination.mkdir()
        destination.chmod(0o500)
        try:
            with pytest.raises(OSError) as failed:
                sa.extract_source_archive(
                    _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
                )
        finally:
            destination.chmod(0o700)

        assert not isinstance(failed.value, sa.SourceArchiveRefused)
        assert isinstance(failed.value, PermissionError)


class TestWhatZipfileCannotReadIsARefusal:
    """Every way zipfile fails on a crafted archive reaches the caller as a refusal.

    ``extract_source_archive`` says every problem with the archive is a
    ``SourceArchiveRefused`` and an ``OSError`` is the destination's or the disk's, so
    a caller that tells them apart can show a refusal and stop. Each row is an
    exception zipfile raises that is neither. Red at the base: each reached the caller
    as it was raised. Two shapes this class held, header offsets that point before the
    file or past what a seek can reach, are refused by rule 6 now, before zipfile reads
    a member, and are rows of ``REFUSED`` so the finalize is given them too.
    """

    def test_a_member_that_needs_a_newer_zip_reader_is_refused(self, tmp_path):
        """NotImplementedError from ``zipfile.ZipFile`` itself, as it opens the file."""
        payload = _with_version_needed(_zip({"a.py": b"x"}), 64)
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused) == "the archive cannot be read: zip file version 6.4"
        assert not destination.exists()

    def test_control_the_newest_version_zipfile_reads_is_admitted(self, tmp_path):
        payload = _with_version_needed(_zip({"a.py": b"x"}), 63)

        destination = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert _tree(destination) == {"a.py": b"x"}

    @pytest.mark.skipif(
        getattr(zipfile, "zstd", None) is None,
        reason="this zipfile has no Zstandard support (Python 3.14 adds it)",
    )
    def test_a_damaged_zstandard_member_is_refused(self, tmp_path):
        """compression.zstd.ZstdError, neither a ValueError nor an OSError."""
        content = b"print('a source line')\n" * 50
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.py", content, compress_type=zipfile.ZIP_ZSTANDARD)
        payload = _with_first_data_byte_flipped(buffer.getvalue())

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'a.py' cannot be read: ")

    def test_a_method_whose_module_this_python_lacks_is_refused(
        self, monkeypatch, tmp_path
    ):
        """RuntimeError, which zipfile raises for an LZMA member when the lzma module
        is missing: a Python built without it reads the archive this way."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_LZMA) as archive:
            archive.writestr("a.py", b"print(1)\n")
        archive_path = _archive_file(tmp_path, buffer.getvalue())
        monkeypatch.setattr(zipfile, "lzma", None)

        refused = _extraction_refusal(archive_path, tmp_path / "tree")

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused) == (
            "zip entry 'a.py' cannot be read: "
            "Compression requires the (missing) lzma module"
        )

    def test_a_local_header_whose_name_is_not_the_utf8_it_claims_is_refused(
        self, tmp_path
    ):
        """UnicodeDecodeError: a ValueError, but not a refusal."""
        payload = _with_local_name_not_utf8(_zip({"aa.py": b"x"}), "aa.py")

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'aa.py' cannot be read: ")
        assert "can't decode byte 0xff" in str(refused)


# ---------------------------------------------------------------------------
# What zipfile cannot read is classified once, for both entry points.
# ---------------------------------------------------------------------------

_LINK_TARGET = b"/outside/the/tree"


def _lzma_member() -> bytes:
    """A zip of one LZMA member, ``a.py``; built when a row runs, because a Python built
    without lzma cannot write one."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_LZMA) as archive:
        archive.writestr("a.py", b"print(1)\n")
    return buffer.getvalue()


def _damaged_zstandard_member() -> bytes:
    """A zip of one Zstandard member, ``a.py``, whose first data byte is changed."""
    content = b"print('a source line')\n" * 50
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.py", content, compress_type=zipfile.ZIP_ZSTANDARD)
    return _with_first_data_byte_flipped(buffer.getvalue())


def _without_lzma(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Python built without the lzma module, as zipfile sees it."""
    monkeypatch.setattr(zipfile, "lzma", None)


def _payload_of(source: Union[bytes, Callable[[], bytes]]) -> bytes:
    """The archive of a row: the bytes, or what builds them when the row runs."""
    return source() if callable(source) else source


#: What zipfile cannot read, or what cannot be read of a member, and the verdict both
#: entry points reach: the archive (or a function that builds it), the rule, the start
#: of the words (zipfile's own text follows), whether the refusal is made before
#: anything is written, and what the row changes about zipfile before the archive is
#: read. Red at the base for the finalize: it raised what zipfile raised, or what the
#: shared function would not have, and kept the upload.
UNREADABLE = [
    pytest.param(
        _with_version_needed(_zip({"a.py": b"x"}), 64),
        Kind.UNREADABLE_MEMBER,
        "the archive cannot be read: zip file version 6.4",
        True,
        None,
        id="an-archive-that-needs-a-newer-zip-reader",
    ),
    pytest.param(
        # zipfile decodes the central directory's names as it opens the archive.
        _with_central_name_not_utf8(_zip({"aa.py": b"x"}), "aa.py"),
        Kind.NOT_A_ZIP,
        "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
        True,
        None,
        id="a-central-directory-name-that-is-not-the-utf8-it-claims",
    ),
    pytest.param(
        # Admission reads a link's target, and what zipfile raises for it is refused.
        _with_damaged_data(
            _zip_with_modes({"evil": (_LINK_TARGET, 0o120777)}), _LINK_TARGET
        ),
        Kind.UNREADABLE_MEMBER,
        "the archive cannot be read: Bad CRC-32 for file 'evil'",
        True,
        None,
        id="a-link-whose-data-fails-its-checksum",
    ),
    pytest.param(
        _with_damaged_data(_stored(), _STORED),
        Kind.UNREADABLE_MEMBER,
        "zip entry 'a.py' cannot be read: Bad CRC-32 for file 'a.py'",
        False,
        None,
        id="a-member-whose-data-fails-its-checksum",
    ),
    pytest.param(
        _with_local_name_not_utf8(_zip({"aa.py": b"x"}), "aa.py"),
        Kind.UNREADABLE_MEMBER,
        "zip entry 'aa.py' cannot be read: 'utf-8' codec can't decode byte 0xff in "
        "position 0: invalid start byte",
        False,
        None,
        id="a-local-header-whose-name-is-not-the-utf8-it-claims",
    ),
    pytest.param(
        _lzma_member,
        Kind.UNREADABLE_MEMBER,
        "zip entry 'a.py' cannot be read: "
        "Compression requires the (missing) lzma module",
        False,
        _without_lzma,
        id="a-method-whose-module-this-python-lacks",
    ),
    pytest.param(
        _damaged_zstandard_member,
        Kind.UNREADABLE_MEMBER,
        "zip entry 'a.py' cannot be read: ",
        False,
        None,
        marks=pytest.mark.skipif(
            getattr(zipfile, "zstd", None) is None,
            reason="this zipfile has no Zstandard support (Python 3.14 adds it)",
        ),
        id="a-damaged-zstandard-member",
    ),
]


class TestWhatZipfileCannotReadIsRefusedAlikeByBothEntryPoints:
    """``open_zip`` and ``extract_zip_members`` take what zipfile raises through one
    classification, so ``extract_source_archive`` and the finalize refuse each of
    these in the same words, and the finalize removes the upload as it does for every
    refusal."""

    @pytest.mark.parametrize("source,kind,start,before_writing,setup", UNREADABLE)
    def test_the_shared_function_refuses_it(
        self, monkeypatch, tmp_path, source, kind, start, before_writing, setup
    ):
        payload = _payload_of(source)
        if setup is not None:
            setup(monkeypatch)
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is kind
        assert str(refused).startswith(start)
        if before_writing:
            assert not destination.exists(), "a refused archive made the destination"

    @pytest.mark.parametrize("source,kind,start,before_writing,setup", UNREADABLE)
    def test_the_finalize_refuses_it_in_the_same_words(
        self, monkeypatch, tmp_path, source, kind, start, before_writing, setup
    ):
        payload = _payload_of(source)
        if setup is not None:
            setup(monkeypatch)
        shared = _verdict(
            _extraction_refusal(_archive_file(tmp_path, payload), tmp_path / "tree")
        )

        delivered = _verdict(_finalize_refusal(payload, tmp_path / "workspace"))

        assert delivered == shared
        assert delivered[0] is kind
        assert delivered[1].startswith(start)


class _FailingHandle:
    """A binary handle whose first seek raises ``error``, as the first read of an
    archive does when it fails."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def seek(self, *args: object) -> int:
        raise self.error


class TestOpeningAnArchive:
    """What zipfile raises as it opens a file, whichever it is, is refused by
    ``open_zip`` in the one set of words. Red at the base: ``open_zip`` did not exist,
    and the finalize opened the file with zipfile itself."""

    @pytest.mark.parametrize(
        "error,kind,message",
        [
            pytest.param(
                OverflowError("Python int too large to convert to C ssize_t"),
                Kind.UNREADABLE_MEMBER,
                "the archive cannot be read: "
                "Python int too large to convert to C ssize_t",
                id="an-overflow-from-a-seek",
            ),
            pytest.param(
                RuntimeError("a compression module is missing"),
                Kind.UNREADABLE_MEMBER,
                "the archive cannot be read: a compression module is missing",
                id="a-runtime-error",
            ),
            pytest.param(
                RuntimeError(),
                Kind.UNREADABLE_MEMBER,
                "the archive cannot be read: RuntimeError",
                id="an-error-with-no-words-is-named-by-its-type",
            ),
            pytest.param(
                NotImplementedError("zip file version 6.4"),
                Kind.UNREADABLE_MEMBER,
                "the archive cannot be read: zip file version 6.4",
                id="a-version-zipfile-does-not-implement",
            ),
            pytest.param(
                zipfile.BadZipFile("File is not a zip file"),
                Kind.NOT_A_ZIP,
                "File is not a zip file",
                id="bytes-that-are-not-a-zip",
            ),
            pytest.param(
                EOFError("Ran out of input"),
                Kind.NOT_A_ZIP,
                "Ran out of input",
                id="an-end-of-file",
            ),
            pytest.param(
                ValueError("negative seek value"),
                Kind.NOT_A_ZIP,
                "negative seek value",
                id="a-value-error",
            ),
        ],
    )
    def test_what_zipfile_raises_is_refused(self, error, kind, message):
        with pytest.raises(sa.SourceArchiveRefused) as refused:
            sa.open_zip(_FailingHandle(error))

        assert (refused.value.kind, str(refused.value)) == (kind, message)
        assert isinstance(refused.value, zipfile.BadZipFile) is (kind is Kind.NOT_A_ZIP)

    def test_a_memory_error_is_raised_as_it_is(self):
        with pytest.raises(MemoryError):
            sa.open_zip(_FailingHandle(MemoryError()))

    def test_a_zip_is_opened(self):
        with sa.open_zip(io.BytesIO(_zip({"a.py": b"x"}))) as archive:
            assert archive.namelist() == ["a.py"]


class TestBytesThatAreNotAZipAreABadZipFileToo:
    """The finalize raised ``zipfile.BadZipFile`` for them before it shared this module,
    and documents it. Now that both entry points raise the shared refusal for them, the
    refusal is a ``BadZipFile`` as well, so a caller that catches that still does."""

    NOT_ONE_ZIP = [
        pytest.param(b"plain text, not an archive\n", id="plain-text"),
        pytest.param(_tar(gzipped=False), id="a-tar"),
        pytest.param(_zip({"app.py": b"x"}) + _AFTER_THE_END, id="bytes-after-the-zip"),
    ]

    @pytest.mark.parametrize("payload", NOT_ONE_ZIP)
    def test_the_shared_function_raises_one(self, tmp_path, payload):
        with pytest.raises(zipfile.BadZipFile) as refused:
            sa.extract_source_archive(
                _archive_file(tmp_path, payload), tmp_path / "tree"
            )

        assert isinstance(refused.value, sa.SourceArchiveRefused)
        assert refused.value.kind is Kind.NOT_A_ZIP

    @pytest.mark.parametrize("payload", NOT_ONE_ZIP)
    def test_the_finalize_raises_one(self, tmp_path, payload):
        workspace = tmp_path / "workspace"
        _upload(payload, workspace)

        with pytest.raises(zipfile.BadZipFile) as refused:
            _finalize(payload, workspace)

        assert isinstance(refused.value, sa.SourceArchiveRefused)
        assert refused.value.kind is Kind.NOT_A_ZIP

    def test_a_refusal_for_another_rule_is_not_one(self, tmp_path):
        refused = _extraction_refusal(
            _archive_file(tmp_path, _zip({"../escape.py": b"x"})), tmp_path / "tree"
        )

        assert not isinstance(refused, zipfile.BadZipFile)


class _OurDefect(Exception):
    """A defect of ASH's own code, as a test makes one."""


def _a_defect_of_ours(*args: object) -> None:
    raise _OurDefect("a defect of ours")


class TestADefectOfOursIsNotTheArchives:
    """Admission was wrapped in ``except Exception``, so a defect of this module's own
    code was refused as an unreadable archive. Only the read of a link's target, which
    is zipfile's, is classified now; what else is raised is raised as it is. Red at the
    base for ``extract_source_archive``."""

    def test_extraction_raises_it_as_it_is(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sa, "_refuse_shared_paths", _a_defect_of_ours)
        destination = tmp_path / "tree"

        with pytest.raises(_OurDefect):
            sa.extract_source_archive(
                _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
            )

        assert not destination.exists()

    def test_the_finalize_raises_it_as_it_is_and_keeps_the_upload(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(sa, "_refuse_shared_paths", _a_defect_of_ours)
        payload = _zip({"a.py": b"x"})
        workspace = tmp_path / "workspace"
        _upload(payload, workspace)

        with pytest.raises(_OurDefect):
            _finalize(payload, workspace)

        assert sd._final_zip_path(workspace / SESSION, UPLOAD).exists()


def _a_file_with_a_zip64_locator(record_at: int, before: int) -> Tuple[io.BytesIO, int]:
    """``before`` zero bytes, a zip64 end record locator that places the record at
    ``record_at``, and the end record of an empty archive; and where that begins."""
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, record_at, 1)
    end_record = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
    return io.BytesIO(bytes(before) + locator + end_record), before + len(locator)


class TestARecordTheArchiveGivesIsNotTrusted:
    """An offset or a length from the archive's own records can be larger than any seek
    takes, or point at nothing. Admission refuses what it cannot find, as not a zip: it
    no longer lets the error of a seek or an unpack out, now that only the read of a
    link's target is classified. Current zipfile releases refuse these archives as they
    open them, so the cases call the readers of the records."""

    @pytest.mark.parametrize("offset", [2**63, 2**64 - 1, 2**100])
    def test_an_offset_no_seek_takes_reads_nothing(self, offset):
        assert sa._read_at(io.BytesIO(b"abc"), offset, 4) == b""

    def test_a_length_no_read_takes_reads_nothing(self):
        assert sa._read_at(io.BytesIO(b"abc"), 0, 2**63) == b""

    def test_an_offset_the_filesystem_cannot_hold_reads_nothing(self):
        """A seek on a file raises an ``OSError`` (EINVAL) for an offset past what the
        filesystem holds, which the finalize's handle, unlike a copy in memory, can."""

        class Refusing(io.BytesIO):
            def seek(self, offset, whence=0):
                if offset > 2**40:
                    raise OSError(errno.EINVAL, "Invalid argument")
                return super().seek(offset, whence)

        assert sa._read_at(Refusing(b"abc"), 2**44, 4) == b""

    def test_a_read_that_fails_is_raised_as_it_is(self):
        class Failing(io.BytesIO):
            def read(self, size=-1):
                raise OSError(errno.EIO, "Input/output error")

        with pytest.raises(OSError):
            sa._read_at(Failing(b"abc"), 0, 4)

    @pytest.mark.parametrize(
        "record_at,before",
        [
            pytest.param(2**63, 100, id="an-offset-no-seek-takes"),
            pytest.param(2**64 - 1, 100, id="the-largest-offset"),
            pytest.param(4, 100, id="an-offset-with-no-record"),
            pytest.param(0, 10, id="a-file-too-short-for-a-record"),
        ],
    )
    def test_a_locator_with_no_record_is_refused_as_not_a_zip(self, record_at, before):
        handle, end = _a_file_with_a_zip64_locator(record_at, before)

        with pytest.raises(sa.SourceArchiveRefused) as refused:
            sa._zip64_end_record(handle, end)

        assert refused.value.kind is Kind.NOT_A_ZIP
        assert str(refused.value) == "Zip64 end of central directory record not found"

    def test_a_locator_with_its_record_gives_the_record(self):
        payload = _raw_zip([_Raw(b"a.py", b"A = 1\n")], zip64_end=True)
        handle = io.BytesIO(payload)

        record = sa._zip64_end_record(
            handle, sa._end_record_position(handle, len(payload))
        )

        assert record is not None
        assert record[0] == b"PK\x06\x06"
        assert record[6:8] == (1, 1)


class TestTheRefusal:
    def test_it_is_a_value_error_whose_kind_and_words_survive_a_copy(self):
        refused = sa.SourceArchiveRefused(Kind.PATH_TRAVERSAL, "path traversal in zip")

        copied = copy.deepcopy(refused)

        assert isinstance(copied, ValueError)
        assert copied.kind is Kind.PATH_TRAVERSAL
        assert str(copied) == "path traversal in zip"

    def test_a_not_a_zip_refusal_survives_a_copy_as_a_bad_zip_file_too(self):
        with pytest.raises(sa.SourceArchiveRefused) as refused:
            sa.open_zip(io.BytesIO(b"plain text, not an archive\n"))

        copied = copy.deepcopy(refused.value)

        assert isinstance(copied, zipfile.BadZipFile)
        assert copied.kind is Kind.NOT_A_ZIP
        assert str(copied) == "File is not a zip file"

    def test_every_kind_is_a_stable_string(self):
        assert {kind.value for kind in Kind} == {
            "archive-too-large",
            "too-many-members",
            "extracted-too-large",
            "empty-name",
            "backslash-in-name",
            "absolute-path",
            "path-traversal",
            "dot-component",
            "empty-component",
            "nul-in-name",
            "reserved-name",
            "unicode-path-mismatch",
            "path-collision",
            "symlink-member",
            "not-a-zip",
            "not-a-file",
            "unreadable-archive",
            "encrypted-member",
            "unreadable-member",
        }
