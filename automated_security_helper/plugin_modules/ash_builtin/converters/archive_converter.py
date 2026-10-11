# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the ArchiveConverter implementation."""

import bz2
import contextlib
import gzip
import importlib
import io
import lzma
import os
import re
import shutil
import stat
from pathlib import Path, PurePosixPath
import tarfile
from typing import (
    Annotated,
    Any,
    BinaryIO,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Tuple,
)
import zipfile

from pydantic import Field, PositiveInt

from automated_security_helper.core.constants import (
    KNOWN_SCANNABLE_EXTENSIONS,
)
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    relative_display,
)
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches as path_matches_pattern,
)


#: The suffixes the converter selects archives in the tree on. Compared lowercased
#: against the last one only, so ``.tar.gz`` is ``gz`` and ``.tgz`` is not selected.
ARCHIVE_SUFFIXES = ("zip", "tar", "gz")

#: The suffixes that mark a file as an archive or compressed file. Kept apart from
#: ARCHIVE_SUFFIXES, which decides what is extracted: any of these inside an archive
#: is recorded as not scanned, because extraction is one level deep, and one in the
#: tree that ARCHIVE_SUFFIXES does not select is recorded as not extracted.
#: Compared lowercased against the last suffix, after trailing dots and spaces
#: (which Windows drops from a name) are removed.
NESTED_ARCHIVE_SUFFIXES = (
    *ARCHIVE_SUFFIXES,
    "tgz",
    "bz2",
    "tbz",
    "tbz2",
    "xz",
    "txz",
    "zst",
    "tzst",
    "lzma",
    "lz",
    "tlz",
    "lz4",
    "z",
    "tz",
    "7z",
    "rar",
    "cpio",
    "jar",
    "war",
    "ear",
    "aar",
    "apk",
    "whl",
    "egg",
    "nupkg",
    "deb",
    "rpm",
)

#: The options of ArchiveConverterConfigOptions that bound what extracting an archive
#: can write. A config file inside the scanned tree can lower them but not raise
#: them; see config/archive_limits.py.
EXTRACTION_LIMIT_OPTIONS = (
    "max_members",
    "max_member_bytes",
    "max_total_bytes",
    "max_compression_ratio",
)


class ArchiveConverterConfigOptions(ConverterOptionsBase):
    """Limits on what extracting one archive may write.

    Each is an inclusive maximum, checked against what the archive declares, for
    every member, before anything is written. An archive over any of them is not
    extracted at all. The defaults are far above an ordinary source archive. Set
    inside the scanned tree (``.ash/.ash.yaml``), by a config an MCP client
    supplied, or by a workspace project's own config, a value can only lower a
    limit; raise one with ``--config-overrides`` or a config file outside the tree.
    """

    max_members: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most members an archive may have, directories included. An "
                "archive with more is not extracted. All the archives one scan "
                "extracts may hold four times this many together."
            )
        ),
    ] = 100_000
    max_member_bytes: Annotated[
        PositiveInt,
        Field(
            description=(
                "The largest size in bytes one member of an archive may declare. An "
                "archive with a larger member is not extracted. Default 256 MiB."
            )
        ),
    ] = 256 * 1024 * 1024
    max_total_bytes: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most bytes an archive's members may declare added up, each "
                "counted as at least 512. An archive whose members declare more is "
                "not extracted. All the archives one scan extracts may declare four "
                "times this together. Default 1 GiB."
            )
        ),
    ] = 1024 * 1024 * 1024
    max_compression_ratio: Annotated[
        PositiveInt,
        Field(
            description=(
                "The most times its own size on disk that an archive's members may "
                "declare added up. An archive that declares more is not extracted. "
                "Checked only once the members declare more than 512 KiB in all."
            )
        ),
    ] = 100


#: The compression ratio is checked only once an archive's members declare more
#: than this many bytes added up. Below it an archive writes at most this much,
#: whatever it compresses to, and small archives of repetitive text (a fixtures
#: directory of indented JSON) routinely compress better than 100 to 1: 313 KiB of
#: JSON in a 2.3 KB zip is 139. Apache POI's ZipSecureFile skips its inflate-ratio
#: check for an entry of 100 KiB or less; the ratio here is over a whole archive, a
#: sum of entries, so the floor is higher.
RATIO_FLOOR_BYTES = 512 * 1024


#: Every member counts as at least this many bytes toward max_total_bytes and the
#: scan's budget: the size of a tar header, which reading the member costs whatever
#: it holds. Without it an archive of empty members was free in bytes.
MEMBER_FLOOR_BYTES = 512

#: The archives one conversion extracts share a budget of this many times
#: max_members members and max_total_bytes bytes. Four archives at the
#: per-archive limits fit, which with the defaults is 400,000 members and 4 GiB,
#: under the 5 GB GitHub strongly recommends a whole repository stays below. It
#: follows the per-archive limits, so an operator who raises those raises it too.
SCAN_BUDGET_ARCHIVES = 4


class _ScanBudget:
    """What the archives already extracted in one conversion have used of its budget."""

    def __init__(self) -> None:
        self.members = 0
        self.total = 0

    def commit(self, budget: "_ExtractionBudget") -> None:
        self.members += budget.members
        self.total += budget.total


class _ExtractionLimitExceeded(Exception):
    """An archive declares more than one of the extraction limits allows."""

    def __init__(self, option: str, reason: str):
        super().__init__(reason)
        self.option = option
        self.reason = reason


class _UnreadableArchive(Exception):
    """An archive the converter cannot read, with why, for its refusal record."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _ExtractionBudget:
    """Admits an archive's members one at a time against the extraction limits.

    Every member counts, whether or not it would be extracted: reading a compressed
    tar means decompressing every member to reach the next header, and the ratio is
    a property of the archive as a whole. A tar is read one header at a time through
    this, so an archive over a limit is refused at the header that takes it over,
    without reading the rest.
    """

    def __init__(
        self,
        options: ArchiveConverterConfigOptions,
        archive_size: int,
        scan: Optional[_ScanBudget] = None,
    ):
        self.options = options
        self.archive_size = max(archive_size, 1)
        self.scan = scan
        self.members = 0
        # Bytes counted toward the totals, each member at least MEMBER_FLOOR_BYTES.
        self.total = 0
        # Bytes the members declare, which the compression ratio is taken over.
        self.declared = 0

    def room(self) -> int:
        """The most bytes one more member could declare and still be admitted.

        For a member whose size is known only by reading it, such as the content of
        a plain gzip file: read at most this plus one byte, then ``admit`` what was
        read, which names the limit when it is over.
        """
        options = self.options
        limits = [
            options.max_member_bytes,
            options.max_total_bytes - self.total,
            max(RATIO_FLOOR_BYTES, options.max_compression_ratio * self.archive_size)
            - self.declared,
        ]
        if self.scan is not None:
            limits.append(
                SCAN_BUDGET_ARCHIVES * options.max_total_bytes
                - self.scan.total
                - self.total
            )
        return max(0, min(limits))

    def admit(self, name: str, size: int) -> None:
        options = self.options
        self.members += 1
        if self.members > options.max_members:
            raise _ExtractionLimitExceeded(
                "max_members",
                f"it has more than {options.max_members} members, the max_members "
                "extraction limit",
            )
        if size < 0 or size > options.max_member_bytes:
            raise _ExtractionLimitExceeded(
                "max_member_bytes",
                f"its member '{name}' declares {size} bytes, outside the "
                f"max_member_bytes extraction limit of {options.max_member_bytes}",
            )
        self.total += max(size, MEMBER_FLOOR_BYTES)
        self.declared += size
        if self.total > options.max_total_bytes:
            raise _ExtractionLimitExceeded(
                "max_total_bytes",
                f"its members declare more than {options.max_total_bytes} bytes, the "
                "max_total_bytes extraction limit (each member counts at least "
                f"{MEMBER_FLOOR_BYTES} bytes)",
            )
        if (
            self.declared > RATIO_FLOOR_BYTES
            and self.declared > options.max_compression_ratio * self.archive_size
        ):
            raise _ExtractionLimitExceeded(
                "max_compression_ratio",
                f"its members declare more than {options.max_compression_ratio} times "
                f"its own size of {self.archive_size} bytes, the "
                "max_compression_ratio extraction limit",
            )
        if self.scan is None:
            return
        scan_members = SCAN_BUDGET_ARCHIVES * options.max_members
        if self.scan.members + self.members > scan_members:
            raise _ExtractionLimitExceeded(
                "max_members",
                "together with the archives this scan extracted before it, it would "
                f"make more than {scan_members} members, {SCAN_BUDGET_ARCHIVES} "
                "times the max_members extraction limit",
            )
        scan_total = SCAN_BUDGET_ARCHIVES * options.max_total_bytes
        if self.scan.total + self.total > scan_total:
            raise _ExtractionLimitExceeded(
                "max_total_bytes",
                "together with the archives this scan extracted before it, it would "
                f"declare more than {scan_total} bytes, {SCAN_BUDGET_ARCHIVES} times "
                "the max_total_bytes extraction limit",
            )


#: The most bytes tarfile may ask for in one read while it parses headers. tarfile
#: reads an extended (pax) header, a GNU long name or long link name whole, so this
#: bounds what one header can make it hold. Far above any real header.
_TAR_READ_CAP = 1024 * 1024

#: What the header pass may read in all: this much, plus _TAR_HEADER_BYTES_PER_MEMBER
#: for every member read so far. A member costs 512 bytes of header, and with a pax
#: header (GNU tar's pax format writes one per member) about 1.5 KiB; a GNU sparse
#: 1.0 map is read from the archive here too.
_TAR_HEADER_BYTES_BASE = 4 * 1024 * 1024
_TAR_HEADER_BYTES_PER_MEMBER = 2048


def _zstd_file_class() -> Any:
    """``compression.zstd.ZstdFile`` where this Python has it (3.14 on), else None."""
    try:
        return importlib.import_module("compression.zstd").ZstdFile
    except ImportError:
        return None


class _BoundedTarStream(io.RawIOBase):
    """A tar stream that bounds what tarfile reads while it parses the headers.

    During the header pass a single read over _TAR_READ_CAP is refused, and so is a
    read that takes the pass over its allowance: _TAR_HEADER_BYTES_BASE plus
    _TAR_HEADER_BYTES_PER_MEMBER per member admitted. Member data is skipped by
    seeking, which reads nothing here, and its size is what the extraction limits
    bound. Once the header pass ends, reads go through unbounded: extraction reads
    in chunks tarfile and _copy_tar_members choose, at most the admitted sizes.
    """

    def __init__(self, raw: Any):
        super().__init__()
        self._raw = raw
        self._allowance: Optional[int] = (
            _TAR_HEADER_BYTES_BASE + _TAR_HEADER_BYTES_PER_MEMBER
        )
        # Where the header pass's last read started, and what it returned.
        self._last_read: Tuple[int, bytes] = (-1, b"")

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._raw.tell()

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._raw.seek(offset, whence)

    def allow_another_member(self) -> None:
        if self._allowance is not None:
            self._allowance += _TAR_HEADER_BYTES_PER_MEMBER

    def end_header_pass(self) -> None:
        self._allowance = None

    def block_at(self, offset: int) -> bytes:
        """The tar block at ``offset``: up to 512 bytes, fewer where the stream ends.

        Taken from the header pass's last read when that read was this block, which
        it is when tarfile stopped there, so a compressed stream is not decompressed
        again from the start to seek back to it.
        """
        start, data = self._last_read
        if start == offset and len(data) == tarfile.BLOCKSIZE:
            return data
        self._raw.seek(offset)
        return self._raw.read(tarfile.BLOCKSIZE)

    def read(self, size: Optional[int] = -1) -> bytes:
        if self._allowance is None:
            return self._raw.read(size)
        if size is None or size < 0 or size > _TAR_READ_CAP:
            raise _UnreadableArchive(
                f"its headers ask for a read of {size} bytes, more than the "
                f"{_TAR_READ_CAP} ASH reads at once for an archive header"
            )
        start = self._raw.tell()
        data = self._raw.read(size)
        self._last_read = (start, data)
        self._allowance -= len(data)
        if self._allowance < 0:
            raise _UnreadableArchive(
                "its headers take more than ASH reads for an archive's headers: "
                f"{_TAR_HEADER_BYTES_BASE} bytes plus "
                f"{_TAR_HEADER_BYTES_PER_MEMBER} per member"
            )
        return data


@contextlib.contextmanager
def _tar_stream(handle: BinaryIO) -> Iterator[_BoundedTarStream]:
    """The archive's tar stream, decompressed by its leading bytes, and bounded.

    Chosen from the magic bytes rather than by letting tarfile try each
    decompressor in turn: gzip, bzip2, xz, and zstd where this Python has it. Any
    other content is read as an uncompressed tar.
    """
    head = handle.read(6)
    handle.seek(0)
    with contextlib.ExitStack() as stack:
        inner: Any = handle
        if head[:2] == b"\x1f\x8b":
            inner = stack.enter_context(gzip.GzipFile(fileobj=handle, mode="rb"))
        elif head[:3] == b"BZh":
            inner = stack.enter_context(bz2.BZ2File(handle))
        elif head == b"\xfd7zXZ\x00":
            inner = stack.enter_context(lzma.LZMAFile(handle))
        elif head[:4] == b"\x28\xb5\x2f\xfd" and _zstd_file_class() is not None:
            inner = stack.enter_context(_zstd_file_class()(handle))
        yield _BoundedTarStream(inner)


def _tar_members_within(
    tar_ref: Any,
    budget: _ExtractionBudget,
    stream: Optional[_BoundedTarStream] = None,
) -> List[tarfile.TarInfo]:
    """Every member of ``tar_ref``, each admitted to ``budget`` as its header is read.

    A member's extended header has been applied to it by the time it is returned,
    so it is dropped rather than kept for every member until extraction.

    tarfile ends the member list without an error where a header after the first
    has a bad checksum, is cut short or is missing, so a damaged or truncated tar
    would read as one with fewer members. The list has to end at an end-of-archive
    block (512 zero bytes, which every tar writer puts after the last member), or
    the archive is unreadable.
    """
    members = []
    for member in tar_ref:
        budget.admit(member.name, member.size)
        member.pax_headers = {}
        members.append(member)
        if stream is not None:
            stream.allow_another_member()
    if stream is not None:
        if stream.block_at(tar_ref.offset) != tarfile.NUL * tarfile.BLOCKSIZE:
            raise _UnreadableArchive(
                "its members stop before the end-of-archive block, so it is "
                "truncated or one of its headers is damaged"
            )
    return members


#: The first line of a Git LFS pointer file, one per version URL git-lfs reads
#: (v1Aliases in its lfs/pointer.go): the current one; the pre-release one, which its
#: docs/spec.md shows for "Blobs created with the pre-release version of the tool";
#: and the alpha one. git-lfs compares the URL as a plain string, and so does this.
_LFS_POINTER_FIRST_LINES = (
    b"version https://git-lfs.github.com/spec/v1\n",
    b"version https://hawser.github.com/spec/v1\n",
    b"version http://git-media.io/v/2\n",
)
#: "Pointer files must be less than 1024 bytes in size", in the LFS spec.
_LFS_POINTER_MAX_BYTES = 1024
#: ``key value``: the spec's key characters, and a value of printable ASCII. The
#: spec forbids only CR and LF in a value, but every value LFS writes (the version
#: URL, ``sha256:<hex>``, a decimal size, extension oids) is printable ASCII, and
#: allowing other bytes let a readable zip be taken for a pointer.
_LFS_POINTER_LINE = re.compile(rb"[a-z0-9.-]+ [\x20-\x7e]*\n")
_LFS_POINTER_OID = re.compile(rb"^oid sha256:[0-9a-f]{64}\n", re.MULTILINE)
_LFS_POINTER_SIZE = re.compile(rb"^size [0-9]+\n", re.MULTILINE)
_LFS_POINTER_REASON = (
    "it is a Git LFS pointer file, not the archive it stands for, so the archive's "
    "contents are not scanned; fetch the LFS objects (git lfs pull) before the scan "
    "to have them scanned"
)


def _is_git_lfs_pointer(head: bytes, size: int) -> bool:
    """Whether a file is a Git LFS pointer: the whole file, in the pointer format.

    Strict on purpose, because a pointer is reported rather than failing the scan:
    under 1024 bytes, the version line first, every line ``key value`` in printable
    ASCII, and an ``oid sha256:`` and a ``size`` line. No archive the converter
    extracts can meet it. Every zip entry header zipfile reads holds a zero byte
    (the high byte of its compression method, for every method zipfile can
    extract), gzip starts with 0x1f 0x8b, and a tar under 1024 bytes holds no
    member with content, whose header and data block alone take 1024.
    """
    if size >= _LFS_POINTER_MAX_BYTES or len(head) != size:
        return False
    if not head.startswith(_LFS_POINTER_FIRST_LINES):
        return False
    lines = head.splitlines(keepends=True)
    if not all(_LFS_POINTER_LINE.fullmatch(line) for line in lines):
        return False
    return bool(_LFS_POINTER_OID.search(head) and _LFS_POINTER_SIZE.search(head))


def _plain_gzip_name(archive_file: str) -> Optional[str]:
    """The file a ``.gz`` would decompress to, or None when its name says tarball.

    ``data.json.gz`` is ``data.json``. A name ending ``.tar.gz`` says the content is
    a tarball, so it is read as one and never as a single compressed file.
    """
    base = archive_file.replace("\\", "/").rsplit("/", 1)[-1]
    lowered = base.lower()
    if not lowered.endswith(".gz") or lowered.endswith(".tar.gz"):
        return None
    inner = base[: -len(".gz")]
    return inner or None


def _gzip_holds_a_tar(handle: BinaryIO) -> bool:
    """Whether a gzip file's content starts with a tar header.

    Reads one block of the decompressed content. A damaged stream raises, and the
    archive is then refused as unreadable.
    """
    handle.seek(0)
    with gzip.GzipFile(fileobj=handle, mode="rb") as stream:
        block = stream.read(tarfile.BLOCKSIZE)
    handle.seek(0)
    try:
        tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def _is_archive_name(name: str) -> bool:
    """Whether a name marks a file as an archive or compressed file.

    Trailing dots and spaces are dropped first, as Windows drops them, so
    ``lib.zip.`` is a zip there and is one here.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(". ")
    return "." in base and base.rsplit(".", 1)[-1].lower() in NESTED_ARCHIVE_SUFFIXES


# tarfile's "data" extraction filter refuses links that leave the destination, device
# files and absolute names, and drops unsafe mode bits. It is in 3.12 and was
# backported to 3.10.12 and 3.11.4, so it is detected rather than inferred from the
# version. The member checks below apply whether or not it is present.
_TAR_HAS_DATA_FILTER = hasattr(tarfile, "data_filter")

_MEMBER_ABSOLUTE = "its path is absolute"
_MEMBER_PARENT = "its path contains a '..' component"
_MEMBER_ESCAPES = "it would be extracted outside the destination directory"
_MEMBER_LINK = "it is a symbolic or hard link"
_MEMBER_NOT_REGULAR = "it is not a regular file"
_MEMBER_SPARSE_BEYOND_SIZE = (
    "it is a sparse file whose map places data beyond the size it declares, or "
    "writes the same bytes twice"
)
_NOT_EXTRACTED = (
    "it is an archive or compressed file of a format that is not extracted (the "
    "archive converter extracts .zip, .tar and .gz), so its contents are not scanned"
)
_MEMBER_NESTED_ARCHIVE = (
    "it is named as an archive or compressed file (such as .zip, .tar.gz, .jar or "
    ".7z), and an archive inside an archive is not extracted, so its contents are "
    "not scanned"
)

_COPY_CHUNK = 1024 * 1024

#: How many refused members of one archive are listed one by one for each reason.
#: The rest are counted in one record, so an archive of many links or nested
#: archives does not produce a record, a warning and a SARIF notification apiece.
MEMBER_REFUSALS_LISTED = 20


def _sparse_map_problem(member: tarfile.TarInfo) -> Optional[str]:
    """Why a sparse tar member's map cannot be extracted within its size, or None.

    ``TarFile.extractall`` writes each map entry at its offset and only truncates
    the file to the declared size once every entry is written, and nothing in
    tarfile ties the map to that size. An entry past the size leaves a file larger
    than the member declares, which is what the size limits were checked against,
    and when the copy stops with ReadError the truncation never happens at all.
    With every entry inside the size, the file never grows past it. Entries must
    also come in order without overlapping: each one is copied from the archive,
    so entries that overlap copy more data than the member's size, writing the
    same bytes again.
    """
    # Read with getattr: typeshed declares TarInfo.sparse as an int, while tarfile
    # sets it to a list of (offset, length) pairs, or None for a member that is not
    # sparse.
    entries: List[Tuple[int, int]] = getattr(member, "sparse", None) or []
    end = 0
    for offset, length in entries:
        if offset < end or length < 0 or offset + length > member.size:
            return _MEMBER_SPARSE_BEYOND_SIZE
        end = offset + length
    return None


def _copy_at_most(source: BinaryIO, out: BinaryIO, limit: int) -> None:
    """Copy from ``source`` to ``out`` until ``limit`` bytes or the end of ``source``."""
    remaining = limit
    while remaining > 0:
        chunk = source.read(min(_COPY_CHUNK, remaining))
        if not chunk:
            return
        out.write(chunk)
        remaining -= len(chunk)


def _decompress_plain_gzip(
    handle: BinaryIO, destination: Path, name: str, budget: "_ExtractionBudget"
) -> None:
    """Decompress a single-file gzip to ``destination`` within ``budget``.

    Its size is known only by reading it (the size in the gzip trailer is the
    writer's claim, modulo 4 GiB), so at most ``budget.room()`` plus one byte is
    written and then admitted, which refuses it, naming the limit, when it is over.
    The file is created without following a link at its name.
    """
    handle.seek(0)
    room = budget.room()
    fd = os.open(
        destination,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
        0o644,
    )
    with gzip.GzipFile(fileobj=handle, mode="rb") as source, os.fdopen(fd, "wb") as out:
        _copy_at_most(source, out, room + 1)
        written = out.tell()
        if written <= room:
            # Read to the end, so a damaged stream or a bad CRC raises here.
            if source.read(1):
                written += 1
    budget.admit(name, written)


def _copy_tar_members(
    tar_ref: tarfile.TarFile, members: List[tarfile.TarInfo], target_path: Path
) -> None:
    """Write each member's bytes under ``target_path``, applying none of its metadata.

    For a Python whose tarfile has no "data" filter. ``extractall`` without one applies
    each member's mode, owner and times, so a setuid bit or a foreign owner (when ASH
    runs as root) would carry over. The members reaching here are regular files whose
    names inspect_members has already checked, so copying their content is all there
    is to do. Each file is created without following a link at its name, and no more
    than the member's declared size is copied into it, whatever its stream yields:
    the declared sizes are what the extraction limits admitted.
    """
    for member in members:
        source = tar_ref.extractfile(member)
        if source is None:
            continue
        destination = target_path.joinpath(*PurePosixPath(member.name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            0o644,
        )
        with source, os.fdopen(fd, "wb") as out:
            _copy_at_most(source, out, member.size)


def _unused_target(results_dir: Path, name: str) -> Path:
    """``results_dir / name``, or with ``-2``, ``-3`` ... appended if that exists.

    The name comes from get_normalized_filename, which folds ``/`` and ``.`` to
    ``__`` and other runs of non-word characters to ``-``, so two archives can map
    to one name (``a b.zip`` and ``a-b.zip``). Each archive is extracted into a
    directory no other archive wrote, so removing it on a failure removes only what
    this archive wrote, and two archives never overwrite each other's members.
    """
    target = results_dir / name
    counter = 2
    while target.exists():
        target = results_dir / f"{name}-{counter}"
        counter += 1
    return target


def _member_name_problem(member_name: str) -> Optional[str]:
    """Why an archive member's name is unsafe to extract, or None.

    Read on the text with both separators, so a name written on Windows is judged
    the same way on every platform.
    """
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return _MEMBER_ABSOLUTE
    if ".." in PurePosixPath(normalized).parts:
        return _MEMBER_PARENT
    return None


class ArchiveConverterConfig(ConverterPluginConfigBase):
    """Archive (ZIP/TAR/GZIP/etc) converter configuration."""

    name: Literal["archive"] = "archive"
    enabled: bool = True
    options: Annotated[
        ArchiveConverterConfigOptions,
        Field(description="Configure Archive converter"),
    ] = ArchiveConverterConfigOptions()


@ash_converter_plugin
class ArchiveConverter(ConverterPluginBase[ArchiveConverterConfig]):
    """Converter implementation for Archive file extraction."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = ArchiveConverterConfig()
        return super().model_post_init(context)

    @staticmethod
    def _open_tar(
        handle: BinaryIO, stack: contextlib.ExitStack
    ) -> Tuple[tarfile.TarFile, _BoundedTarStream]:
        """``handle`` opened as a tar through a bounded stream, or _UnreadableArchive."""
        stream = stack.enter_context(_tar_stream(handle))
        try:
            tar_ref = tarfile.open(fileobj=stream, mode="r:", encoding="utf-8")
        except tarfile.ReadError as error:
            raise _UnreadableArchive(
                f"it is not a zip or tar archive that can be read ({error})"
            ) from error
        return tar_ref, stream

    def _extraction_limits(self) -> ArchiveConverterConfigOptions:
        """The extraction limits from this converter's options, defaults where unset."""
        options = getattr(self.config, "options", None)
        if isinstance(options, ArchiveConverterConfigOptions):
            return options
        if hasattr(options, "model_dump"):
            options = options.model_dump()
        return ArchiveConverterConfigOptions.model_validate(dict(options or {}))

    def validate_plugin_dependencies(self):
        # Return True since this scanner is entirely within the same Python module,
        # so there is nothing further to validate in terms of availability.
        return True

    @staticmethod
    def _is_path_traversal(member_path: str, target_path: Path) -> bool:
        """Check if a member path would escape the target extraction directory.

        Args:
            member_path: The path of the archive member.
            target_path: The intended extraction directory.

        Returns:
            True if the path is unsafe (traversal detected), False if safe.
        """
        # Reject absolute paths
        if os.path.isabs(member_path):
            return True

        # Resolve the full extraction path and verify it stays within target
        resolved = (target_path / member_path).resolve()
        target_resolved = target_path.resolve()

        # Check that the resolved path is within the target directory
        try:
            resolved.relative_to(target_resolved)
        except ValueError:
            return True

        return False

    def _skipped(self, path: str) -> bool:
        """Whether ``path`` from the scan set is a directory or under an ignore path."""
        if Path(path).is_dir():
            ASH_LOGGER.debug(f"Skipping directory: {path}")
            return True
        for ignore_path in self.context.config.global_settings.ignore_paths:
            rel_path = Path(path).relative_to(self.context.source_dir).as_posix()
            if path_matches_pattern(rel_path, ignore_path.path):
                ASH_LOGGER.debug(
                    f"Skipping conversion of ignored path: {path} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                )
                return True
        return False

    def _refuse_member(self, archive: Optional[str], member: str, reason: str) -> None:
        if archive is None:
            ASH_LOGGER.warning(f"Skipped archive member '{member}': {reason}")
        else:
            self.record_refused_input(TreeInputRefused(archive, reason), member=member)

    def inspect_members(
        self,
        members: List[str | zipfile.ZipInfo | tarfile.TarInfo],
        target_path: Optional[Path] = None,
        archive: Optional[str] = None,
    ):
        """The members worth extracting: scannable, regular files that stay inside.

        A member is refused, with a warning naming it, when it is a link (a tar
        symlink or hard link, or a zip entry whose mode marks it a symlink), is not a
        regular file, is a sparse tar member whose map reaches past its declared
        size, or has a name that is absolute, contains ``..`` or would land outside
        ``target_path``. A member named as an archive or compressed file (a suffix in
        ``NESTED_ARCHIVE_SUFFIXES``, in any case) is refused as well: extraction is
        one level deep, and the refusal is what reports its contents as not scanned. Members without a
        scannable extension are left out silently, as before, so a refusal is only
        reported for a member that would otherwise have been extracted.

        Args:
            members: The archive's members.
            target_path: The extraction directory. The escape check needs it, so it
                is skipped when this is None.
            archive: The archive's path relative to the scanned tree. When given, each
                refusal is also recorded in the converter's results row.
        """
        ASH_LOGGER.verbose(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        # Refusals by reason: how many were listed, and how many more were not.
        listed: Dict[str, int] = {}
        unlisted: Dict[str, int] = {}
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                member_name = member.name
                if member.isdir():
                    continue
                is_link = member.issym() or member.islnk()
                is_regular = member.isreg()
                content_problem = _sparse_map_problem(member)
            elif isinstance(member, zipfile.ZipInfo):
                member_name = member.filename
                if member.is_dir():
                    continue
                # Unix mode bits live in the high 16 bits of external_attr. zipfile
                # writes a symlink entry out as a file holding the link's target, so
                # it would not become a link, but it is not a file either.
                is_link = stat.S_ISLNK(member.external_attr >> 16)
                is_regular = True
                content_problem = None
            elif isinstance(member, str):
                member_name = member
                is_link = False
                is_regular = True
                content_problem = None
            else:
                ASH_LOGGER.debug(
                    f"Skipping uknown extension from archive: {type(member)}"
                )
                continue

            nested = _is_archive_name(member_name)
            member_ext = member_name.split(".")[-1]
            if not nested and member_ext not in KNOWN_SCANNABLE_EXTENSIONS:
                continue

            problem = _member_name_problem(member_name)
            if problem is None and target_path is not None:
                if self._is_path_traversal(member_name, target_path):
                    problem = _MEMBER_ESCAPES
            if problem is None and is_link:
                problem = _MEMBER_LINK
            if problem is None and not is_regular:
                problem = _MEMBER_NOT_REGULAR
            if problem is None:
                problem = content_problem
            if problem is None and nested:
                problem = _MEMBER_NESTED_ARCHIVE
            if problem is not None:
                if listed.get(problem, 0) < MEMBER_REFUSALS_LISTED:
                    listed[problem] = listed.get(problem, 0) + 1
                    self._refuse_member(archive, member_name, problem)
                else:
                    unlisted[problem] = unlisted.get(problem, 0) + 1
                continue

            ASH_LOGGER.verbose(f"Found .{member_ext} file: {member}")
            filtered_members.append(member)
        for problem, count in unlisted.items():
            if archive is None:
                ASH_LOGGER.warning(f"Skipped {count} more archive members: {problem}")
            else:
                self.record_refused_input(
                    TreeInputRefused(archive, problem), unlisted_members=count
                )
        return filtered_members

    def convert(self) -> List[Path]:
        """Convert archive files by extracting their contents.

        Args:
            target: Optional target path to convert. If None, all archives in source_dir are extracted.

        Returns:
            List[Path]: List of paths to extracted files
        """
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for archive files in search_path within the ASH scan set: {self.context.source_dir}"
        )

        # Find all archive files to scan from the scan set
        archive_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
        )
        candidates = [f.strip() for f in archive_files]
        archive_files = [
            f for f in candidates if f.split(".")[-1].lower() in ARCHIVE_SUFFIXES
        ]
        selected = set(archive_files)
        # Named as an archive the converter does not extract (a .tgz, .jar, .7z
        # ...): recorded, so the summaries show it was not scanned, without
        # failing the completeness gate, as the same name inside an archive is.
        for path in candidates:
            if path in selected or not _is_archive_name(path):
                continue
            if self._skipped(path):
                continue
            self.record_refused_input(
                TreeInputRefused(
                    relative_display(path, self.context.source_dir),
                    _NOT_EXTRACTED,
                )
            )

        ASH_LOGGER.debug(f"Found {len(archive_files)} files to convert in scan set.")
        results: List[Path] = []

        # Add warning if no archive files found
        if not archive_files:
            ASH_LOGGER.info(
                f"No archive files (.zip, .tar, .gz) found in {self.context.source_dir}"
            )
            return results

        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Shared by every archive below; only an archive that is extracted uses it.
        scan_budget = _ScanBudget()
        for archive_file in archive_files:
            # The target directory once this iteration has made it: a directory
            # no other archive wrote (see _unused_target), so a failure part way
            # through removes what this archive wrote and nothing else.
            created_target: Optional[Path] = None
            archive_display = relative_display(archive_file, self.context.source_dir)
            try:
                if self._skipped(archive_file):
                    continue

                short_archive_file = get_shortest_name(archive_file)
                normalized_archive_file = get_normalized_filename(short_archive_file)
                target_path = _unused_target(
                    Path(self.results_dir), normalized_archive_file
                )
                ASH_LOGGER.verbose(
                    f"Extracting {archive_file} contents to target_path: {Path(target_path).as_posix()}"
                )

                # Opened under the scanned-tree rule, and everything below reads from
                # this handle rather than reopening the path, so the archive that is
                # extracted is the one that was checked.
                try:
                    archive_handle = self.open_source_file(archive_file)
                except TreeInputRefused as refused:
                    self.record_refused_input(refused)
                    continue

                with archive_handle, contextlib.ExitStack() as stack:
                    archive_size = os.fstat(archive_handle.fileno()).st_size
                    # Every member is admitted against the extraction limits before
                    # anything is written, and the target directory is created only
                    # after that, so a refused archive leaves nothing behind.
                    budget = _ExtractionBudget(
                        self._extraction_limits(),
                        archive_size,
                        scan=scan_budget,
                    )

                    # A checkout without its LFS objects holds a pointer where each
                    # LFS-tracked archive should be. Reported, naming the remedy,
                    # and not counted as lost coverage: the archive is not in the
                    # tree to scan.
                    head = archive_handle.read(_LFS_POINTER_MAX_BYTES)
                    archive_handle.seek(0)
                    if _is_git_lfs_pointer(head, archive_size):
                        self.record_refused_input(
                            TreeInputRefused(archive_display, _LFS_POINTER_REASON)
                        )
                        continue

                    plain_gzip = _plain_gzip_name(archive_file)
                    if (
                        plain_gzip is not None
                        and head[:2] == b"\x1f\x8b"
                        and not _gzip_holds_a_tar(archive_handle)
                    ):
                        # One compressed file, not an archive of files.
                        if not self.inspect_members(
                            [plain_gzip],
                            target_path=target_path,
                            archive=archive_display,
                        ):
                            continue
                        target_path.mkdir()
                        created_target = target_path
                        _decompress_plain_gzip(
                            archive_handle, target_path / plain_gzip, plain_gzip, budget
                        )
                        results.append(target_path)
                        scan_budget.commit(budget)
                        continue

                    # Extract ZIP to target path after inspecting members
                    is_zip = archive_file.lower().endswith(
                        ".zip"
                    ) and zipfile.is_zipfile(archive_handle)
                    archive_handle.seek(0)
                    if is_zip:
                        with zipfile.ZipFile(archive_handle, "r") as zip_ref:
                            zip_members = zip_ref.infolist()
                            for info in zip_members:
                                budget.admit(info.filename, info.file_size)
                            target_path.mkdir()
                            created_target = target_path
                            # zipfile stops each member's output at the size its
                            # entry declares, so the declared sizes admitted above
                            # bound what is written.
                            zip_ref.extractall(
                                path=target_path,
                                members=self.inspect_members(
                                    zip_members,
                                    target_path=target_path,
                                    archive=archive_display,
                                ),
                            )
                    # Extract Tarball to target path after inspecting members. Read
                    # through _tar_stream, which bounds what parsing the headers can
                    # read; a file tarfile cannot open as a tar is refused below.
                    else:
                        tar_ref, stream = self._open_tar(archive_handle, stack)
                        with tar_ref:
                            tar_members = _tar_members_within(tar_ref, budget, stream)
                            stream.end_header_pass()
                            target_path.mkdir()
                            created_target = target_path
                            # Both paths below write no more than each member
                            # declares: _copy_tar_members copies at most that, and
                            # extractall does once inspect_members has refused a
                            # sparse map that reaches past the declared size.
                            safe_members = self.inspect_members(
                                tar_members,
                                target_path=target_path,
                                archive=archive_display,
                            )
                            if _TAR_HAS_DATA_FILTER:
                                tar_ref.extractall(  # nosec B202
                                    path=target_path,
                                    members=safe_members,
                                    filter="data",
                                )
                            else:
                                _copy_tar_members(tar_ref, safe_members, target_path)

                # Add the extracted directory to results
                results.append(target_path)
                scan_budget.commit(budget)
            except _ExtractionLimitExceeded as exceeded:
                # The whole archive, not a member: none of it reaches the scanners,
                # so the record carries the limit, which the completeness gate
                # reads. A plain gzip file is admitted as it is decompressed, so
                # what it wrote before going over is removed.
                if created_target is not None:
                    shutil.rmtree(created_target, ignore_errors=True)
                self.record_refused_input(
                    TreeInputRefused(archive_display, exceeded.reason),
                    limit=exceeded.option,
                )
            except Exception as e:
                # Named for the converter, a .zip, .tar or .gz it could not read: a
                # bad CRC, a truncated or damaged stream, a gzip-compressed file
                # that is not a tarball, an empty file, or members that cannot all
                # be written (a file named like a directory an earlier member
                # made raises IsADirectoryError). None of it is scanned, and
                # whatever was written before the failure is removed, so the
                # scanners do not read a partial extraction as the archive.
                # Recorded, not only logged: the completeness gate reads
                # failed_inputs, and an archive that could not be extracted is
                # coverage lost.
                if created_target is not None:
                    shutil.rmtree(created_target, ignore_errors=True)
                reason = (
                    e.reason
                    if isinstance(e, _UnreadableArchive)
                    else f"{type(e).__name__}: {e}"
                )
                self.record_failed_input(archive_file, reason)

        return results
