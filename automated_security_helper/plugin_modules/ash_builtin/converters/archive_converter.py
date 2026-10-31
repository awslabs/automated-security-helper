# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the ArchiveConverter implementation."""

import bz2
import contextlib
import errno
import gzip
import hashlib
import importlib
import io
import lzma
import os
import re
import shutil
import stat
import struct
from pathlib import Path, PurePosixPath
import tarfile
from typing import (
    Annotated,
    Any,
    BinaryIO,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)
import zipfile
import zlib

from pydantic import Field, PositiveInt

from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.core.constants import (
    KNOWN_SCANNABLE_EXTENSIONS,
)
from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.converter_refusals import inert_text
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.scan_output_dirs import record_converted_sources
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    relative_display,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
    ignore_path_matches as path_matches_pattern,
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

#: Member names with no extension that scanners read, so KNOWN_SCANNABLE_EXTENSIONS,
#: which admits members by their extension, cannot name them: container and build
#: files (checkov, semgrep, opengrep), dependency manifests (grype, syft),
#: private keys (detect-secrets, gitleaks: the ``id_*`` names and ``identity``,
#: OpenSSH's legacy default name for a private key) and a README, a text file the
#: secret scanners read like any other. Compared against the member's base name
#: as read through ``_base_name``, case-folded; a name with a variant suffix
#: (``Dockerfile.prod``, ``Makefile_linux``, ``id_rsa.old``, ``.env.local``) is
#: admitted by its stem (_SCANNABLE_MEMBER_STEMS, _SCANNABLE_DOTFILE_STEMS).
SCANNABLE_MEMBER_NAMES = frozenset(
    {
        "Dockerfile",
        "Containerfile",
        "Jenkinsfile",
        "Makefile",
        "Pipfile",
        "Gemfile",
        "Rakefile",
        "Vagrantfile",
        "Procfile",
        "Brewfile",
        "Podfile",
        "README",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "identity",
        "credentials",
        ".git-credentials",
        ".pgpass",
        ".htpasswd",
        ".env",
        "authorized_keys",
        "known_hosts",
    }
)
#: Compared case-folded: ``dockerfile`` and ``MAKEFILE`` are the same files.
_SCANNABLE_MEMBER_NAMES_FOLDED = frozenset(n.casefold() for n in SCANNABLE_MEMBER_NAMES)
#: Names admitted by their first word before a ``.``, ``-`` or ``_``: a Dockerfile,
#: Containerfile or Makefile with a stage or variant suffix (``Dockerfile.prod``,
#: ``Dockerfile-prod``, ``Makefile_linux``), and a key file with a backup suffix
#: (``id_rsa.old``, ``id_ed25519-2024``). Case-folded.
_SCANNABLE_MEMBER_STEMS = frozenset(
    {
        "dockerfile",
        "containerfile",
        "makefile",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)
#: Dotfiles admitted by the name up to their second ``.``: an environment file
#: with a stage suffix (``.env.local``, ``.env.production``), which detect-secrets
#: reads as it reads ``.env``. A dotfile's stem starts at its leading ``.``, so
#: the split _SCANNABLE_MEMBER_STEMS is read with would leave it empty.
#: Case-folded.
_SCANNABLE_DOTFILE_STEMS = frozenset({".env"})

#: Extensions scanners read that KNOWN_SCANNABLE_EXTENSIONS leaves out: ES module
#: and TypeScript module spellings and component files (semgrep, opengrep), C++
#: spellings beside .cpp and .h, key and certificate material, credential and
#: registry settings files, and dependency lockfiles and Go module files (grype,
#: syft, the npm and pnpm audits). Compared lowercased, through _archive_suffix.
SCANNABLE_MEMBER_SUFFIXES = frozenset(
    {
        "mjs",
        "cjs",
        "mts",
        "cts",
        "vue",
        "svelte",
        "cc",
        "cxx",
        "hh",
        "hxx",
        "pem",
        "key",
        "crt",
        "cer",
        "pub",
        "p12",
        "pfx",
        "jks",
        "npmrc",
        "yarnrc",
        "netrc",
        "pypirc",
        "lock",
        "mod",
        "sum",
        "dockerfile",
        "containerfile",
    }
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
from automated_security_helper.utils.tar_listing import (
    SKIPPED_BYTES_LIMIT,
    SkippedBlocksBudget,
    open_tar_listing,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line


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


def _too_many_members(max_members: int) -> "_ExtractionLimitExceeded":
    return _ExtractionLimitExceeded(
        "max_members",
        f"it has more than {max_members} members, the max_members extraction limit",
    )


_ZIP_DIRECTORY_ENTRY = b"PK\x01\x02"
_ZIP_DIRECTORY_ENTRY_BYTES = 46


def _zipfile_private(name: str) -> Any:
    """A private name of zipfile's, looked up so a Python without it raises KeyError.

    The type stubs do not declare zipfile's private names. Looked up at call time,
    a missing one fails the archive it is needed for, a failed input, rather than
    the converter's import.
    """
    return vars(zipfile)[name]


def _zip_end_record(handle: BinaryIO) -> Optional[List[Any]]:
    """The zip's end-of-central-directory record as zipfile reads it, or None.

    zipfile's own reader, ``_EndRecData``, so the directory located from it is the
    one ``ZipFile()`` reads: the record is searched for back from the end of the
    file (a byte after it is read past), and whenever a zip64 locator is there the
    counts, size and location come from the zip64 end record, saturated or not and
    with any extensible data allowed for. It is private to zipfile and the same in
    every Python ASH supports, 3.10 to 3.14; a Python without it fails the archive.
    """
    try:
        return _zipfile_private("_EndRecData")(handle)
    except (OSError, zipfile.BadZipFile):
        return None


def _zip_directory_start(
    handle: BinaryIO, end_record: List[Any], directory_bytes: int
) -> Optional[int]:
    """Where the central directory starts, as this Python's zipfile starts reading
    it, or None where zipfile would build no entry.

    The directory ends where the end record says (``_ECD_LOCATION``) and is
    ``directory_bytes`` long, which allows for data before the zip. For a zip64
    archive the two shapes of zipfile ASH runs under disagree about the
    location: the current ``_EndRecData64`` moves it to the zip64 end record,
    right after the directory, while the releases before that fix leave it at
    the plain end record and have ``_RealGetContents`` take the zip64 end record
    and its locator (76 bytes) off the start itself. Whichever this interpreter
    does, the directory's first entry carries the entry signature, so the start
    tried is the one that does. Before this the walk began 76 bytes into the
    directory on the older shape, met no signature there and counted nothing,
    so the member pre-count never refused a zip64 archive.
    """
    location = end_record[_zipfile_private("_ECD_LOCATION")]
    candidates = [location - directory_bytes]
    if end_record[_zipfile_private("_ECD_SIGNATURE")] == _zipfile_private(
        "stringEndArchive64"
    ):
        candidates.append(
            candidates[0]
            - _zipfile_private("sizeEndCentDir64")
            - _zipfile_private("sizeEndCentDir64Locator")
        )
    for start in candidates:
        if start < 0:
            continue
        handle.seek(start)
        if handle.read(len(_ZIP_DIRECTORY_ENTRY)) == _ZIP_DIRECTORY_ENTRY:
            return start
    return None


def _zip_has_more_entries_than(handle: BinaryIO, limit: int) -> bool:
    """Whether opening a zip would make zipfile build more than ``limit`` entries.

    ``zipfile.ZipFile()`` builds a ZipInfo for every central-directory entry as it
    opens the archive, so the entries are counted first, holding none of them, the
    way its ``_RealGetContents`` reads them: the directory starts at the end
    record's location less the directory's size (which allows for data before the
    zip), and is read entry by entry while under that size, each a 46-byte header
    with the lengths of the name, extra field and comment after it. The count the
    record declares is checked first, then the entries, since zipfile reads the
    whole directory whatever that count says. zipfile stops at a short or bad
    header only after building every entry before it, so those are counted too.
    False where zipfile would build none: no end record, or a directory that would
    start before the file does.
    """
    end_record = _zip_end_record(handle)
    if not end_record:
        return False
    if end_record[_zipfile_private("_ECD_ENTRIES_TOTAL")] > limit:
        return True
    directory_bytes = end_record[_zipfile_private("_ECD_SIZE")]
    start = _zip_directory_start(handle, end_record, directory_bytes)
    if start is None:
        return False
    handle.seek(start)
    counted = 0
    walked = 0
    while walked < directory_bytes:
        header = handle.read(_ZIP_DIRECTORY_ENTRY_BYTES)
        if (
            len(header) != _ZIP_DIRECTORY_ENTRY_BYTES
            or header[:4] != _ZIP_DIRECTORY_ENTRY
        ):
            break
        (name, extra, comment) = struct.unpack_from("<HHH", header, 28)
        handle.seek(name + extra + comment, io.SEEK_CUR)
        walked += _ZIP_DIRECTORY_ENTRY_BYTES + name + extra + comment
        counted += 1
        if counted > limit:
            return True
    return False


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
            raise _too_many_members(options.max_members)
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
#: header (GNU tar's pax format writes one per member) about 1.5 KiB; one that
#: carries extended attributes, ACLs or a long path runs to several KiB, and a GNU
#: sparse 1.0 map is read from the archive here too. The per-member allowance
#: covers a pax header of up to about 7 KiB on its own: at 2048 it covered 1 KiB,
#: and every member over that drew on the base, so a tar of thousands of such
#: members was refused as unreadable once the base was spent.
_TAR_HEADER_BYTES_BASE = 4 * 1024 * 1024
_TAR_HEADER_BYTES_PER_MEMBER = 8192


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

    def allow_skipped_blocks(self, size: int) -> None:
        """Credit the header pass's allowance for a skipped block's bytes.

        Under ``open_tar_listing`` (utils/tar_listing.py) the zero and damaged
        blocks a listing skips are read through this stream during the header
        pass, spending the allowance as they are read. The listing calls this
        with each such block's size as it classifies it, crediting those bytes
        back, so skipped blocks are charged to the listing's own budgets and
        never to the header allowance: a skip-free tar is bounded by exactly
        the base plus the per-member allowance, and a skipping tar gets only
        the headroom its skips used, bounded by the listing's limits.
        """
        if self._allowance is not None:
            self._allowance += size

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


#: How much of a gzip file _GzipMembersStream reads and decompresses at a time.
_GZIP_READ_CHUNK = 64 * 1024


class _GzipMembersStream(io.RawIOBase):
    """A gzip file's decompressed bytes, member after member, read through zlib.

    ``gzip.GzipFile`` reads a file as a run of gzip members and fails the whole
    read at bytes after the last member that are not another member's header
    (BadGzipFile), and the tar listing reads every byte there is
    (utils/tar_listing.py), so a .tar.gz followed by anything, a few bytes of
    padding or a signature a tool appended, lost every member it held. Here the
    bytes after the last member end the stream, as gzip(1) ends it ("trailing
    garbage ignored"); a member cut short still raises (EOFError, as GzipFile
    raises), and zlib checks each member's CRC and length as it ends. At most
    _GZIP_READ_CHUNK compressed and _COPY_CHUNK decompressed bytes are held at a
    time. Seekable as GzipFile is: forward by reading, backward by starting over.
    """

    def __init__(self, raw: BinaryIO) -> None:
        super().__init__()
        self._raw = raw
        self._start = raw.tell()
        self._rewind()

    def _rewind(self) -> None:
        self._raw.seek(self._start)
        self._decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self._pending = b""
        self._pos = 0
        self._ended = False

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self._pos
        elif whence != io.SEEK_SET:
            raise ValueError("Seek from end not supported")
        if offset < self._pos:
            self._rewind()
        while self._pos < offset:
            if not self.read(min(_COPY_CHUNK, offset - self._pos)):
                break
        return self._pos

    def read(self, size: Optional[int] = -1) -> bytes:
        wanted = None if size is None or size < 0 else size
        out = bytearray()
        while wanted is None or len(out) < wanted:
            if not self._pending and (self._ended or not self._fill()):
                break
            take = len(self._pending) if wanted is None else wanted - len(out)
            out += self._pending[:take]
            self._pending = self._pending[take:]
        self._pos += len(out)
        return bytes(out)

    def _fill(self) -> bool:
        """Decompress the next piece into ``_pending``; False at the stream's end."""
        decompressor = self._decompressor
        if not decompressor.eof:
            data = decompressor.unconsumed_tail or self._raw.read(_GZIP_READ_CHUNK)
            if not data:
                raise EOFError(
                    "Compressed file ended before the end-of-stream marker was reached"
                )
            self._pending = decompressor.decompress(data, _COPY_CHUNK)
            return True
        rest = decompressor.unused_data
        if len(rest) < 2:
            rest += self._raw.read(_GZIP_READ_CHUNK)
        if rest[:2] != b"\x1f\x8b":
            # The gzip data ends here: nothing follows, or bytes that are not
            # another member's, which gzip(1) ignores too.
            self._ended = True
            return False
        self._decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self._pending = self._decompressor.decompress(rest, _COPY_CHUNK)
        return True


def _is_bzip2_head(head: bytes) -> bool:
    """Whether ``head``, a file's first six bytes, starts a bzip2 stream: the
    ``BZh`` signature, a block size of 1 to 9, and the start of the magic that
    follows, a block's (the digits of pi) or, for a stream of no blocks, the end
    of stream's (the digits of the square root of pi). ``BZh`` alone is three
    printable bytes, and an uncompressed tar whose first member is named
    ``BZh...`` starts with them too: read as bzip2, that tar failed to
    decompress and was recorded as unreadable, though it was a tar through and
    through.
    """
    return (
        len(head) >= 6
        and head[:3] == b"BZh"
        and head[3] in b"123456789"
        and head[4:6] in (b"\x31\x41", b"\x17\x72")
    )


def _spells_a_tar_header(block: bytes) -> bool:
    """Whether ``block`` holds a tar member header whose checksum holds.

    The test that reads a stream as an uncompressed tar before any compressor's
    magic is consulted. A short block, a block of zeros (the end-of-archive
    block) and a block whose checksum fails all read False here, so those
    streams keep the magic sniff; how an end-of-archive block counts for a
    caller that asks "is this a tar" is _is_tar_header's decision, not this one.
    """
    try:
        tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


@contextlib.contextmanager
def _tar_stream(handle: BinaryIO) -> Iterator[_BoundedTarStream]:
    """The archive's tar stream, decompressed by its leading bytes, and bounded.

    A first block that is a tar header (_spells_a_tar_header: its checksum
    holds) is an uncompressed tar whatever its first bytes spell, since a member name is
    free to start with a compressor's signature (``BZh91AY&SY-notes.txt`` spells
    bzip2's whole head) and no compressed stream carries a valid tar checksum.
    Otherwise the decompressor is chosen from the magic bytes rather than by
    letting tarfile try each in turn: gzip (through _GzipMembersStream, which
    ends at bytes after the gzip data instead of failing on them), bzip2 (by
    its six-byte head, _is_bzip2_head), xz, and zstd where this Python has it.
    Any other content is read as an uncompressed tar. archive_kind probes a tar
    through this same stream, so what it accepts and what is extracted agree.
    """
    block = handle.read(tarfile.BLOCKSIZE)
    handle.seek(0)
    head = block[:6]
    with contextlib.ExitStack() as stack:
        inner: Any = handle
        if _spells_a_tar_header(block):
            pass
        elif head[:2] == b"\x1f\x8b":
            inner = stack.enter_context(_GzipMembersStream(handle))
        elif _is_bzip2_head(head):
            inner = stack.enter_context(bz2.BZ2File(handle))
        elif head == b"\xfd7zXZ\x00":
            inner = stack.enter_context(lzma.LZMAFile(handle))
        elif head[:4] == b"\x28\xb5\x2f\xfd" and _zstd_file_class() is not None:
            inner = stack.enter_context(_zstd_file_class()(handle))
        yield _BoundedTarStream(inner)


def _admitted_size(member: tarfile.TarInfo, tar_ref: Any) -> int:
    """The bytes ``member`` is admitted to the extraction limits for.

    Its declared size, as tarfile reports it once the member's pax or GNU sparse
    header has been applied, or the extent of stored data tarfile skips past to
    reach the next header where that is larger. For a sparse member the reported
    size is its real size and the stored data is shorter, which the declared size
    covers. A header that declares a small real size over a long stored extent
    (an old GNU sparse header with its real-size field at 0) would be admitted at
    the small size while the header pass seeks past the long extent, decompressing
    it for a compressed tar, with no limit counting it; the extent counts then.
    ``tar_ref.offset`` is the next header's position, set by tarfile as the member
    is read; a ``tar_ref`` without one (a plain list) admits the declared size.
    """
    offset = getattr(tar_ref, "offset", None)
    offset_data = getattr(member, "offset_data", None)
    if not isinstance(offset, int) or not isinstance(offset_data, int):
        return member.size
    extent = offset - offset_data
    occupied = -(-member.size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
    return extent if extent > occupied else member.size


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
        budget.admit(member.name, _admitted_size(member, tar_ref))
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
    base = _base_name(archive_file)
    lowered = base.lower()
    if not lowered.endswith(".gz") or lowered.endswith(".tar.gz"):
        return None
    inner = base[: -len(".gz")]
    return inner or None


def _is_tar_header(block: bytes, *, empty_is_tar: bool) -> bool:
    """Whether ``block``, the first 512 bytes of a stream, is a tar header that
    ``tarfile.open`` would open the stream on.

    A header whose checksum holds, whatever its type (a member, a pax header, a
    GNU long name), with a size this Python's tarfile takes: ``TarInfo._block``
    refuses a negative one where tarfile does, and the member is then not read.
    A short block, or one whose checksum fails, is not a header.

    An end-of-archive block of zeros is the one block the two callers read
    differently, and ``empty_is_tar`` says which way. ``tarfile.open`` opens an
    archive on it (a tar of end blocks only is an empty tar; ``is_tarfile`` says
    True), which is what a file NAMED as a tar is held to (_holds_a_tar). A
    ``.gz`` of one file is told from a tarball by its content, and a gzip whose
    content starts with zeros is a file of zeros, not a tarball
    (_gzip_holds_a_tar), the reading the plain-gzip decision has always made.
    """
    try:
        info = tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
        block_of = getattr(info, "_block", None)
        if block_of is not None and _tarfile_sizes(info):
            block_of(info.size)
    except tarfile.EOFHeaderError:  # type: ignore[attr-defined]  # missing from the typeshed stub
        return empty_is_tar
    except tarfile.HeaderError:
        return False
    return True


#: The header types tarfile reads a body for by the size field, through
#: ``TarInfo._block``: an extended header (pax, a GNU long name or link, a GNU
#: sparse member) is read whole; a regular file's data, or an unknown type's, is
#: seeked past. tarfile sizes nothing else (a directory, a link, a device, a fifo),
#: so a negative size on one of those opens.
_SIZED_HEADER_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.GNUTYPE_SPARSE,
    }
)


def _tarfile_sizes(info: tarfile.TarInfo) -> bool:
    """Whether tarfile applies ``_block`` to this header's size when it reads the
    member: for a regular file or an unknown type (``_proc_builtin``) and for an
    extended header (``_proc_pax``, ``_proc_gnulong``, ``_proc_sparse``), and not
    for a directory, link, device or fifo, whose size field it never reads. The
    probe refuses a negative size exactly where tarfile would.
    """
    return (
        info.isreg()
        or info.type not in tarfile.SUPPORTED_TYPES
        or info.type in _SIZED_HEADER_TYPES
    )


def _gzip_holds_a_tar(handle: BinaryIO) -> bool:
    """Whether a gzip file's content starts with a tar header.

    Reads one block of the decompressed content. A damaged stream raises, and the
    archive is then refused as unreadable. Content that starts with a block of
    zeros is one file of zeros, not a tarball (``empty_is_tar=False``): the
    decision that sends a ``.gz`` to the plain-gzip path.
    """
    handle.seek(0)
    with gzip.GzipFile(fileobj=handle, mode="rb") as stream:
        block = stream.read(tarfile.BLOCKSIZE)
    handle.seek(0)
    return _is_tar_header(block, empty_is_tar=False)


def _holds_a_tar(handle: BinaryIO) -> bool:
    """Whether ``handle`` holds a tar, compressed or not: its first block is a tar
    header.

    One block is read, through the same decompressor and bounded stream the
    listing reads through (_tar_stream), so the probe decompresses and holds no
    more than that block. ``tarfile.is_tarfile`` would open the archive and read
    its first member's header whole: a pax header or a GNU long name is read to
    the size it declares, before any bound the converter puts on header reads
    exists. Content the decompressor or the stream refuses is not a tar the
    converter reads; the caller records why when the name says it should be one.
    The handle is left at its start.
    """
    handle.seek(0)
    try:
        with _tar_stream(handle) as stream:
            block = stream.read(tarfile.BLOCKSIZE)
    except Exception:
        return False
    finally:
        handle.seek(0)
    # A file named as a tar whose first block is zeros is an empty tar, as
    # tarfile.open reads it (``is_tarfile`` says True): extracted to nothing.
    return _is_tar_header(block, empty_is_tar=True)


def _base_name(name: str) -> str:
    """A path's last component, read with both separators, without trailing dots
    and spaces, which Windows drops from a name: ``lib.zip.`` is ``lib.zip`` there,
    so it is read as that here too.
    """
    return name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(". ")


def _archive_suffix(name: str) -> str:
    """A path's last suffix, lowercased, after _base_name; empty when it has none."""
    base = _base_name(name)
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _member_is_scannable(member_name: str) -> bool:
    """Whether some scanner reads an archive member of this name, so extracting it
    puts it before one: by its extension (KNOWN_SCANNABLE_EXTENSIONS and
    SCANNABLE_MEMBER_SUFFIXES), or by its name where it has no extension
    (SCANNABLE_MEMBER_NAMES), or by its stem where the name carries a variant
    suffix: a Dockerfile, Containerfile or Makefile with a stage or variant
    (``Dockerfile.prod``, ``Makefile_linux``), a key file with a backup suffix
    (``id_rsa.old``), an environment file with a stage (``.env.local``). Names
    are read through ``_base_name`` and ``_archive_suffix``, the spelling
    authorities, and compared case-folded."""
    suffix = _archive_suffix(member_name)
    if suffix in KNOWN_SCANNABLE_EXTENSIONS or suffix in SCANNABLE_MEMBER_SUFFIXES:
        return True
    base = _base_name(member_name).casefold()
    if base in _SCANNABLE_MEMBER_NAMES_FOLDED:
        return True
    if base.startswith("."):
        # A dotfile's stem runs to its second ".": .env.local is an .env file.
        return "." + base[1:].split(".", 1)[0] in _SCANNABLE_DOTFILE_STEMS
    stem = base.split(".", 1)[0]
    if stem in _SCANNABLE_MEMBER_STEMS:
        return True
    if stem.startswith("id_"):
        # A key name carries its own underscore, so a variant is read before
        # "-" only (id_ed25519-2024); id_rsa.old was admitted by the "." split.
        return stem.split("-", 1)[0] in _SCANNABLE_MEMBER_STEMS
    # Dockerfile-prod, Makefile_linux: the first word before "-" or "_".
    return re.split(r"[-_]", stem, maxsplit=1)[0] in _SCANNABLE_MEMBER_STEMS


def _is_archive_name(name: str) -> bool:
    """Whether a name marks a file as an archive or compressed file."""
    return _archive_suffix(name) in NESTED_ARCHIVE_SUFFIXES


# tarfile's "data" extraction filter refuses links that leave the destination, device
# files and absolute names, and drops unsafe mode bits. It is in 3.12 and was
# backported to 3.10.12 and 3.11.4, so it is detected rather than inferred from the
# version. The member checks below apply whether or not it is present.
_TAR_HAS_DATA_FILTER = hasattr(tarfile, "data_filter")

#: The extensions of the files the converter opens as archives.
ARCHIVE_EXTENSIONS = ("zip", "tar", "gz")

#: The PluginContext attribute convert() records the archives it extracted whole in.
_EXTRACTED_WHOLE = "archives_extracted_whole"

#: The tars one conversion lists share a budget of this many times
#: SKIPPED_BYTES_LIMIT bytes of skipped blocks, past each tar's ordinary end
#: (utils/tar_listing.py, SkippedBlocksBudget). Four tars at one listing's limit
#: fit; once it is spent, a later tar's listing stops at the first block past its
#: ordinary end, and that tar is extracted only in part.
SKIPPED_BLOCKS_BUDGET_TARS = 4


def archives_extracted_whole(context: object) -> FrozenSet[str]:
    """The archives this run's archive converter extracted whole, as paths relative
    to the scanned tree with ``/``: opened and extracted with no member refused, and
    none left out because no scanner reads its extension. A member left out because
    an ignore path names it still counts, since it is left out on purpose.

    For a consumer that copies the source whole, such as snyk-code's upload: such
    a copy may leave out exactly these, because their members reach the scanner
    with the converted files, where ignore paths apply member by member. No
    scanner in this tree reads the record yet, so every archive still goes in
    such a copy as it is. The record lives on the run's PluginContext, so it is
    empty when this run's convert phase did not run the converter (it is off, or
    the phase was left out) and holds no archive the converter refused, failed on
    or could not read; each of those is for the copy to keep.
    """
    return frozenset(getattr(context, _EXTRACTED_WHOLE, None) or ())


def is_archive_name(name: str) -> bool:
    """Whether the converter opens the file *name* as an archive, by its extension.

    The extension is read through ``_archive_suffix``, so ``_base_name`` is the
    spelling authority: trailing dots and spaces are part of the name on disk
    but not of the suffix (Windows drops them), as the suffix constants say.
    """
    return _archive_suffix(name) in ARCHIVE_EXTENSIONS


def archive_kind(name: str, handle: BinaryIO) -> Optional[Literal["zip", "tar"]]:
    """How the converter extracts the file *name*, open as *handle*: "zip" for a
    .zip that is a zip file, "tar" for a file with an archive's name that is a tar
    file, compressed or not, and None for one it does not extract (a .gz of one
    file, or a file that only has an archive's name).

    convert() extracts by this, and a consumer that copies the source whole may
    leave out each file it accepts (archives_extracted_whole): the members reach
    the scanner with the converted files, where ignore paths apply to them one by
    one. The handle is left at its start. Names are
    read through ``_base_name``, the spelling authority, so a trailing dot or
    space does not change the kind. A tar is told by its first block, read
    through the bounded stream (_holds_a_tar), not by opening it with tarfile,
    which reads the first header whole.
    """
    try:
        if not is_archive_name(name):
            return None
        handle.seek(0)
        if _base_name(name).lower().endswith(".zip") and zipfile.is_zipfile(handle):
            return "zip"
        handle.seek(0)
        return "tar" if _holds_a_tar(handle) else None
    finally:
        handle.seek(0)


def _named_kind(name: str) -> Optional[str]:
    """The archive *name* is named as, for one archive_kind could not read: a .zip
    is extracted as a zip or a tar, and a .tar or .tar.gz as a tar. None for any
    other name the converter opens, a .gz of one file. The name is read through
    ``_base_name``, the spelling authority, as archive_kind reads it."""
    lowered = _base_name(name).lower()
    if lowered.endswith(".zip"):
        return "a zip"
    if lowered.endswith((".tar", ".tar.gz")):
        return "a tar"
    return None


_MEMBER_ABSOLUTE = "its path is absolute"
_MEMBER_NUL = "its path holds a NUL character, which no file name can"
_MEMBER_PARENT = "its path contains a '..' component"
_MEMBER_ENCRYPTED = "it is encrypted, and an encrypted member is not extracted"
_MEMBER_ESCAPES = "it would be extracted outside the destination directory"
_MEMBER_LINK = "it is a symbolic or hard link"
_MEMBER_NOT_REGULAR = "it is not a regular file"
_MEMBER_SPARSE_BEYOND_SIZE = (
    "it is a sparse file whose map places data beyond the size it declares, or "
    "writes the same bytes twice"
)
#: How a later member bound for the path an earlier member took is told apart: it
#: is written beside the earlier one under a numbered name, so both are scanned.
#: One unpacker keeps the first of two members with one name and another keeps
#: the last, so scanning only one would leave out the bytes a consumer may get.
_MEMBER_RENAMED = (
    "an earlier member of the archive is extracted to the same path, so this one "
    "is written as '{renamed}' and both are scanned"
)
#: The same case for a member given as a bare name: there is no member object to
#: rename, so the later name is refused instead of being written over the earlier.
_MEMBER_SAME_PATH = (
    "an earlier member of the archive is extracted to the same path, and a member "
    "given by name alone cannot be renamed beside it"
)
#: A member whose path runs through a path an earlier member of the archive is
#: written to as a file (``x.js`` before ``x.js/y.js``), and a member written as a
#: file to a path earlier members are extracted below (``a/b.js`` before ``a``).
#: Each is refused alone: the extractor fails on it, and an archive holding such a
#: pair used to lose every member, those already written included, so anyone who
#: could commit an archive could keep all of its content from being scanned by
#: adding ``a`` and ``a/b``. inspect_members reads every name before anything is
#: written, so the pair is known in time.
_MEMBER_UNDER_A_FILE = (
    "its path runs through '{path}', which an earlier member of the archive is "
    "extracted to as a file"
)
_MEMBER_OVER_A_DIRECTORY = (
    "earlier members of the archive are extracted below its path, so it cannot "
    "be written there as a file"
)
#: The one line that stands for the renamed members past MEMBER_REFUSALS_LISTED,
#: so an archive of thousands of repeated names does not log a line apiece.
_MEMBERS_RENAMED_UNLISTED = (
    "{count} more members are each extracted to the same path as an earlier "
    "member of the archive, so each is written under a numbered name beside it "
    "and all are scanned"
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
    The file is created with fs_guard.open_for_write, which below the output
    directory follows no link at any component of its path, and elsewhere none at
    its name.
    """
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    handle.seek(0)
    room = budget.room()
    with (
        gzip.GzipFile(fileobj=handle, mode="rb") as source,
        open_for_write(destination, binary=True, mode=0o644) as out,
    ):
        # A copy that stops short of room + 1 bytes stopped because the stream
        # ended, and GzipFile checks the CRC and length before it reports the end,
        # so a damaged stream or a bad CRC has raised by then.
        _copy_at_most(source, out, room + 1)
        written = out.tell()
    budget.admit(name, written)


def _copy_tar_members(
    tar_ref: tarfile.TarFile, members: List[tarfile.TarInfo], target_path: Path
) -> None:
    """Write each member's bytes under ``target_path``, applying none of its metadata.

    For a Python whose tarfile has no "data" filter. ``extractall`` without one applies
    each member's mode, owner and times, so a setuid bit or a foreign owner (when ASH
    runs as root) would carry over. The members reaching here are regular files whose
    names inspect_members has already checked, so copying their content is all there
    is to do. Each file is created with fs_guard.open_for_write, which below the
    output directory follows no link at any component of its path, and elsewhere
    none at its name; no more than the member's declared size is copied into it,
    whatever its stream yields: the declared sizes are what the extraction limits
    admitted.
    """
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    for member in members:
        source = tar_ref.extractfile(member)
        if source is None:
            continue
        destination = target_path.joinpath(*PurePosixPath(member.name).parts)
        with (
            source,
            open_for_write(
                destination, binary=True, mode=0o644, make_parents=True
            ) as out,
        ):
            _copy_at_most(source, out, member.size)


def _failure_reason(error: Exception, target: Optional[Path]) -> str:
    """Why an archive could not be extracted, as recorded in its failed input.

    An OS error's message carries the absolute path it was raised for, which is
    in the work directory, and the record goes to the results file, the reports
    and the MCP client. Its path is shown relative to the archive's target
    directory instead, which is the member's path inside the archive.
    """
    if isinstance(error, _UnreadableArchive):
        return error.reason
    if isinstance(error, OSError) and error.filename is not None:
        path = Path(os.fsdecode(error.filename))
        try:
            shown = path.relative_to(target).as_posix() if target else path.name
        except ValueError:
            shown = path.name
        return f"{type(error).__name__}: {error.strerror or 'error'}: {shown}"
    return f"{type(error).__name__}: {error}"


#: The errors that say the ARCHIVE cannot be read: a damaged or truncated zip, tar
#: or compressed stream, a compression method zipfile does not implement, or
#: names that are not text. An error of any other type during extraction (no
#: space or no permission in the work directory, a link the filesystem guard
#: refused, a resource limit, a defect) is the run's, not the archive's.
_ARCHIVE_UNREADABLE_ERRORS: Tuple[type, ...] = (
    _UnreadableArchive,
    zipfile.BadZipFile,
    tarfile.TarError,
    EOFError,
    gzip.BadGzipFile,
    zlib.error,
    lzma.LZMAError,
    UnicodeDecodeError,
    NotImplementedError,
)

#: The OSError numbers that say the RUN could not write: the work directory is
#: full, over quota, read-only, or not this user's to write, the process or the
#: host is out of file descriptors or memory, the device failed, or a path is
#: busy. Every other OSError raised while an archive is extracted comes from the
#: archive: a member name a filesystem refuses (too long, not valid in its
#: encoding), a member that names a file where an earlier member made a directory
#: or the reverse, a decompressor's "Invalid data stream" (BZ2File raises OSError
#: for a damaged bz2 stream). A run's failure is never accepted by a suppression,
#: so an errno left out of this set would let the host's own fault be waived.
_RUN_ERRNOS = frozenset(
    {
        errno.ENOSPC,
        errno.EDQUOT,
        errno.EACCES,
        errno.EPERM,
        errno.EROFS,
        errno.EMFILE,
        errno.ENFILE,
        errno.EIO,
        errno.ENOMEM,
        errno.EBUSY,
    }
)

#: Decompressor error classes read by name: the zstd module is optional and its
#: error class is imported only where it is used (_zstd_file_class).
_DECOMPRESSOR_ERROR_NAMES = frozenset({"ZstdError"})


def _failure_kind(error: Exception) -> Literal["input", "tool"]:
    """Whether a failure to extract an archive is about the archive ("input") or
    about the run ("tool").

    The kind decides who may waive the completeness gate: an ``ash-unconverted-input``
    suppression on the archive's path accepts an INPUT error, an archive the
    operator has reviewed and knows cannot be read, and never a TOOL error, which
    says this run could not do its work (the work directory full or unwritable,
    a guard refusing a path, memory exhausted, a defect): accepting that would
    hide a loss of coverage no review of the archive explains, and the record
    would say the archive was at fault. An OSError is read by its number: the
    run's when it names the work directory's state (_RUN_ERRNOS), the archive's
    otherwise.
    """
    if isinstance(error, _ARCHIVE_UNREADABLE_ERRORS):
        return "input"
    if type(error).__name__ in _DECOMPRESSOR_ERROR_NAMES:
        return "input"
    if isinstance(error, OSError):
        return "tool" if error.errno in _RUN_ERRNOS else "input"
    return "tool"


#: The most bytes of UTF-8 an archive's folded path may take in the name of the
#: directory it is extracted into (_target_name). A file name is 255 bytes at most
#: on the common filesystems, and the rest of the name is a digest where one is
#: added and the counter _unused_target may append.
_TARGET_NAME_MAX_BYTES = 200
#: How many characters of the archive path's SHA-256 tell two cut names apart.
_TARGET_DIGEST_CHARS = 12


def _target_name(archive_file: str, archive_display: str) -> str:
    """The name of the directory ``archive_file`` is extracted into, under
    ``results_dir``: ``archive_display``, its path relative to the scanned tree,
    folded into one component (get_normalized_filename), and where that is
    longer than _TARGET_NAME_MAX_BYTES, cut to that and given a digest of the
    same path, so two cut names stay apart. The folded path was the one relative
    to the process working directory, so a run from outside the tree wrote the
    host's absolute path into the directory's name and two runs named one
    archive two ways; and a deep or absolute path ran past the 255 bytes a file
    name may take, so making the directory failed and the archive was recorded
    as a failed input for the length of its own path.
    """
    folded = get_normalized_filename(archive_display)
    if len(folded.encode("utf-8")) <= _TARGET_NAME_MAX_BYTES:
        return folded
    cut = (
        folded.encode("utf-8")[:_TARGET_NAME_MAX_BYTES]
        .decode("utf-8", "ignore")
        .rstrip("-_")
    )
    digest = hashlib.sha256(
        archive_display.encode("utf-8", "surrogateescape")
    ).hexdigest()[:_TARGET_DIGEST_CHARS]
    ASH_LOGGER.debug(
        shown_on_one_line(
            f"Extracting {archive_display} under {cut}-{digest}: its folded "
            "path is longer than a file name may be"
        )
    )
    return f"{cut}-{digest}"


def _unused_target(results_dir: Path, name: str) -> Path:
    """``results_dir / name``, or with ``-2``, ``-3`` ... appended if that exists.

    The name comes from _target_name: get_normalized_filename, which folds ``/``
    and ``.`` to ``__`` and other runs of non-word characters to ``-``, so two
    archives can map to one name (``a b.zip`` and ``a-b.zip``), cut where it is
    too long for a file name. Each archive is extracted into a directory no
    other archive wrote, so removing it on a failure removes only what this
    archive wrote, and two archives never overwrite each other's members.
    """
    target = results_dir / name
    counter = 2
    while target.exists():
        target = results_dir / f"{name}-{counter}"
        counter += 1
    return target


def member_source_path(
    archive: str, member_name: str, kind: Optional[Literal["zip", "tar"]] = None
) -> str:
    """The path an ignore path names an archive member by, in the scanned tree's
    own terms: the archive's path and then the member's, as if the archive were a
    directory (``lib/bundle.zip/vendor/m.js``).

    *archive* is the archive's path relative to the scanned tree, with ``/``. The
    member's extracted path, ``archive/<the archive's folded name>/<member>`` below
    ASH's work directory, is ASH's own layout, not the tree's; an ignore path is
    written in the tree's terms, so this is the path it is matched against.

    The member is named by the file its extraction writes on this host. Its name is
    split where the extractor splits it, on ``/`` and on the host's separators, and
    its empty and ``.`` parts go, as do a leading ``/`` and a leading ``./``:
    zipfile and the tar "data" filter both write ``vendor//m.js``, ``vendor/./m.js``
    and ``/vendor/m.js`` to ``vendor/m.js``. For a zip (*kind*), ``..`` parts go
    too, as zipfile drops them; the converter refuses a member with one before
    extracting it (_member_name_problem), so this only keeps the two in step. On
    POSIX a backslash is part of the name, so ``a\\b.js`` is one file at the
    archive's top, as it would be in the tree; on Windows it separates.

    The member is not also named by its path as if the archive were unpacked where
    it is (``lib/vendor/m.js``). That is a path in the tree, so an ignore path
    written for the file there, or a tree pattern such as ``vendor/**``, would
    silently leave a different file inside the archive out of the scan.
    """
    return f"{archive}/{_member_written_path(member_name, kind)}"


def _member_written_path(
    member_name: str, kind: Optional[Literal["zip", "tar"]] = None
) -> str:
    """The path below the extraction directory that a member of this name is
    written to, with ``/`` separators: the member's name split where the
    extractor splits it, less its empty and ``.`` parts, a leading ``/``, and for a
    zip its ``..`` parts, as zipfile drops them. See member_source_path. Two
    members whose names read the same here are written to one file.
    """
    parts = [member_name]
    for separator in _written_separators():
        parts = [piece for part in parts for piece in part.split(separator)]
    dropped = {"", ".", ".."} if kind == "zip" else {"", "."}
    if kind == "zip" and _on_windows():
        # zipfile writes the member's name on Windows with the characters the
        # host forbids replaced and each part's trailing dots and spaces taken
        # off (its _sanitize_windows_name), so the file written is named by
        # that spelling, and an ignore path written for it has to match it.
        parts = [part.translate(_WINDOWS_NAME_TABLE).rstrip(" .") for part in parts]
    return "/".join(part for part in parts if part not in dropped)


def _written_separators() -> Set[str]:
    """The characters the extractor splits a member's name on, on this host: ``/``
    and the host's own separators. On POSIX that is ``/`` alone, so a backslash is
    part of a name there (_member_written_path)."""
    return {"/", os.sep} | ({os.altsep} if os.altsep else set())


def _written_key(member_name: str, kind: Optional[Literal["zip", "tar"]]) -> str:
    """The key two members are compared by to tell whether they are written to one
    file: the written path (_member_written_path), as the host compares names
    (os.path.normcase) and case-folded, since the output directory may sit on a
    case-insensitive filesystem (APFS, NTFS), where ``X.js`` and ``x.js`` are one
    file. On a case-sensitive one the fold only renames a member that would have
    been a second file, so nothing is lost either way.
    """
    return os.path.normcase(_member_written_path(member_name, kind)).casefold()


def _written_prefix_keys(
    member_name: str, kind: Optional[Literal["zip", "tar"]]
) -> List[str]:
    """The keys (_written_key) of the directories a member of this name is written
    below, the top first: ``a`` and ``a/b`` for ``a/b/c.js``, none for ``c.js``.
    A member written to one of them as a file, or a member whose own key is one
    of another member's, cannot be extracted beside that member: the extractor
    fails on whichever comes later (NotADirectoryError, IsADirectoryError), so
    inspect_members refuses that one alone instead.
    """
    parts = _member_written_path(member_name, kind).split("/")
    return [
        _written_key("/".join(parts[:count]), kind) for count in range(1, len(parts))
    ]


def _named_member(
    member: "str | zipfile.ZipInfo | tarfile.TarInfo",
) -> Optional[Tuple[str, Optional[Literal["zip", "tar"]]]]:
    """The member's name and the archive kind it comes from, or None for a member
    of a type inspect_members does not read."""
    if isinstance(member, tarfile.TarInfo):
        return member.name, "tar"
    if isinstance(member, zipfile.ZipInfo):
        return member.filename, "zip"
    if isinstance(member, str):
        return member, None
    return None


def _renamed_member_name(
    member_name: str,
    kind: Optional[Literal["zip", "tar"]],
    taken: Set[str],
    written: Dict[str, str],
    counters: Dict[str, int],
) -> str:
    """``member_name`` with a counter before its extension (``vendor/m~2.js``,
    ``Dockerfile~2``): the first such name that no member of the archive is named
    by (``taken``, every member's _written_key, read before any is renamed) and no
    earlier member is written to (``written``). A name only ``written`` was checked
    against could be a later member's own, which then lost its name to the rename.

    The directory part is kept, split where the extractor splits it
    (_written_separators), so the member lands beside the one it would have
    overwritten: on POSIX ``a\\b.js`` is one file at the archive's top and is
    renamed ``a\\b~2.js``, not moved under a directory ``a``.

    ``counters`` holds, per written key, the counter the next rename of that key
    starts from, so N members bound for one path cost N names, not N squared.
    """
    cut = max(member_name.rfind(separator) for separator in _written_separators())
    head, base = member_name[: cut + 1], member_name[cut + 1 :]
    stem, dot, extension = base.rpartition(".")
    key = _written_key(member_name, kind)
    counter = counters.get(key, 2)
    while True:
        if stem and dot:
            renamed_base = f"{stem}~{counter}.{extension}"
        else:
            renamed_base = f"{base}~{counter}"
        renamed = f"{head}{renamed_base}"
        counter += 1
        renamed_key = _written_key(renamed, kind)
        if renamed_key not in taken and renamed_key not in written:
            counters[key] = counter
            return renamed


#: The characters Windows forbids in a file name; zipfile writes each as ``_``.
_WINDOWS_ILLEGAL_NAME_CHARACTERS = ':<>|"?*'
_WINDOWS_NAME_TABLE = str.maketrans(
    dict.fromkeys(_WINDOWS_ILLEGAL_NAME_CHARACTERS, "_")
)


def _on_windows() -> bool:
    """Whether the extractor writes names as Windows takes them (see
    _member_written_path); a function, so a test can read the other host's shape."""
    return os.name == "nt"


#: The zip general-purpose flag that marks a member as encrypted.
_ZIP_ENCRYPTED_FLAG = 0x1

#: The compression methods zipfile extracts; anything else (Deflate64, PPMd,
#: an implode or shrink of old tools) raises NotImplementedError out of
#: extractall.
_ZIP_METHODS_EXTRACTED = frozenset(
    method
    for method in (
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
        zipfile.ZIP_LZMA,
        getattr(zipfile, "ZIP_ZSTANDARD", None),
    )
    if method is not None
)


def _zip_member_problem(member: zipfile.ZipInfo) -> Optional[str]:
    """Why zipfile could not extract this member's content, or None: it is
    encrypted (zipfile asks for a password and the converter has none), or its
    compression method is one zipfile does not implement. ``extractall`` raised
    on the first such member and the converter then removed every member it had
    already written, so one such member lost the whole archive; refused one by
    one here, the rest of the archive is extracted and the refusal is recorded.
    """
    if member.flag_bits & _ZIP_ENCRYPTED_FLAG:
        return _MEMBER_ENCRYPTED
    if member.compress_type not in _ZIP_METHODS_EXTRACTED:
        return (
            f"its compression method ({member.compress_type}) is not one zipfile "
            "can extract"
        )
    return None


def _member_name_problem(member_name: str) -> Optional[str]:
    """Why an archive member's name is unsafe to extract, or None.

    Read on the text with both separators, so a name written on Windows is judged
    the same way on every platform. A NUL in the name is refused first: no file
    system takes one, and the escape check below (Path.resolve) raised
    ValueError on it, which failed the whole archive rather than the member.
    """
    if "\x00" in member_name:
        return _MEMBER_NUL
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return _MEMBER_ABSOLUTE
    if ".." in PurePosixPath(normalized).parts:
        return _MEMBER_PARENT
    return None


#: Why a member whose name was not read as UTF-8 is refused while ignore paths are set.
MEMBER_NOT_UTF_8 = (
    "its name is not UTF-8, so no ignore path can be relied on to name it"
)

#: The zip flag that says a member's name is UTF-8; zipfile reads it as cp437 without.
_ZIP_UTF_8_FLAG = 0x800


def member_name_not_utf_8(member: "zipfile.ZipInfo | tarfile.TarInfo | str") -> bool:
    """Whether an archive member's name was not read as UTF-8, so an ignore path,
    written in UTF-8, cannot be compared with it: a zip member's name that is not
    ASCII and whose flag does not say UTF-8, which zipfile reads as cp437, or a name
    holding the surrogates tarfile reads undecodable bytes as."""
    if isinstance(member, zipfile.ZipInfo):
        return not member.flag_bits & _ZIP_UTF_8_FLAG and not member.filename.isascii()
    name = member.name if isinstance(member, tarfile.TarInfo) else member
    return any("\ud800" <= character <= "\udfff" for character in name)


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
        # Without a config, ConverterPluginBase would give a nameless one, and the
        # work directory would be named for the class (work/ArchiveConverter)
        # rather than for the converter (work/archive), as configured runs use.
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

    def _ignore_paths_skipping_scanning(self) -> List[IgnorePathWithReason]:
        """The ignore paths that keep an archive, or a member of one, out of the scan.

        One reading for the archive itself (_skipped) and for its members
        (inspect_members): an expired entry no longer applies
        (active_ignore_paths); of the rest, only the entries the operator supplied
        skip extraction, and --ignore-suppressions lifts them all
        (ignore_paths_that_skip_scanning). A client-supplied entry skips nothing
        here: a delivered tree's own config must not keep its members out of the
        scan, so the member is extracted and scanned and its findings are
        reported. For a file in the tree the SARIF step then marks such a finding
        suppressed under the client's entry; for an archive member it does not,
        because the finding sits at the member's extracted path under the work
        directory and the step has no mapping from that path back to the
        member's source path (member_source_path), so the finding is reported as
        an ordinary result. That is the safe side (nothing the client's config
        names is hidden), and the mapping is a recorded gap.
        """
        return ignore_paths_that_skip_scanning(
            active_ignore_paths(self.context.config.global_settings.ignore_paths),
            ignore_suppressions=self.context.ignore_suppressions,
        )

    def _skipped(self, path: str) -> bool:
        """Whether ``path`` from the scan set is a directory or under an ignore path."""
        if Path(path).is_dir():
            ASH_LOGGER.debug(f"Skipping directory: {path}")
            return True
        ignore_paths = self._ignore_paths_skipping_scanning()
        if not ignore_paths:
            return False
        try:
            rel_path = Path(path).relative_to(self.context.source_dir).as_posix()
        except ValueError:
            # Not lexically under the tree (reached through a link, or spelled
            # another way): an ignore path is written relative to the tree and
            # names no such path. Raising here made the archive a failed input
            # of the run's kind with nothing wrong with the archive.
            return False
        for ignore_path in ignore_paths:
            if ignore_path_matches(rel_path, ignore_path.path):
                ASH_LOGGER.debug(
                    f"Skipping conversion of ignored path: {path} due to global ignore_path '{ignore_path.path}' with reason '{ignore_path.reason}'"
                )
                return True
        return False

    @staticmethod
    def _ignore_path_naming(
        archive: Optional[str],
        member_name: str,
        ignore_paths: Optional[List[IgnorePathWithReason]],
        kind: Optional[Literal["zip", "tar"]] = None,
    ) -> Optional[IgnorePathWithReason]:
        """The first ignore path matching the member's source path, or None."""
        if archive is None or not ignore_paths:
            return None
        source_path = member_source_path(archive, member_name, kind)
        for ignore_path in ignore_paths:
            if path_matches_pattern(source_path, ignore_path.path):
                return ignore_path
        return None

    def _refuse_member(self, archive: Optional[str], member: str, reason: str) -> None:
        # The member's name as read: record_refused_input shows it, and the warning
        # here is shown whole, so a surrogate tarfile read a byte as is an escape.
        if archive is None:
            ASH_LOGGER.warning(
                shown_on_one_line(f"Skipped archive member '{member}': {reason}")
            )
        else:
            self.record_refused_input(TreeInputRefused(archive, reason), member=member)

    def _record_extracted_in_part(
        self,
        archive: str,
        unreadable: List[int],
        stopped: List[int],
        budget_spent: bool = False,
        ended: Optional[List[int]] = None,
        archive_file: Optional[str] = None,
    ) -> None:
        """Record ``archive``, a tar, as extracted only in part. Where the header at
        byte ``unreadable[0]`` (the first that could not be read) named a member,
        that member is unknown, so it was not extracted; the members around it were.
        Where the listing stopped at byte ``stopped[0]``, past SKIPPED_BYTES_LIMIT
        bytes of blocks it skipped (utils/tar_listing.py), or on the conversion's
        shared budget of them (``budget_spent``), nothing after that was.

        Its results row names the byte, and the archive is then not recorded whole
        (archives_extracted_whole), so a consumer that copies the source whole
        keeps it. The warning names the archive on one line, since its name comes
        from the scanned tree.
        """
        parts = []
        if unreadable:
            parts.append(
                f"the tar header at byte {unreadable[0]} could not be read, so the "
                "member it named was not extracted"
            )
        if stopped and budget_spent:
            parts.append(
                f"its listing stopped at byte {stopped[0]}, where the tar listings "
                f"of this run had skipped more than "
                f"{SKIPPED_BLOCKS_BUDGET_TARS * SKIPPED_BYTES_LIMIT} bytes of blocks that "
                "hold no member past each tar's ordinary end, so what follows was "
                "not extracted"
            )
        elif stopped:
            parts.append(
                f"its listing stopped at byte {stopped[0]}, past more than "
                f"{SKIPPED_BYTES_LIMIT} bytes of blocks that hold no member, so what "
                "follows was not extracted"
            )
        if ended:
            # The honest uncertainty: an out-of-spec-but-complete tar reads
            # the same as a truncated one, and silence would leave a
            # truncation class unreported.
            parts.append(
                "it ends without an end-of-archive block, so members past "
                f"byte {ended[0]} may be missing"
            )
        detail = "; ".join(parts)
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"Archive '{archive}' was extracted only in part: {detail}"
            )
        )
        # One record per archive, in the category the completeness gate reads:
        # the unextracted remainder is tried-and-could-not coverage lost, so it
        # is a FAILED input (a refusal without a limit is invisible to the
        # gate). The extracted members stay, and archives_extracted_whole
        # holds the archive back from whole-archive consumers. Recorded by the
        # path the scan set gave, as every failed input is: record_failed_input
        # relativizes it against the tree, and the display name, relativized
        # again, would resolve against the working directory instead. An
        # archive that cannot be read whole is an INPUT error (there is no tool
        # here), which an ash-unconverted-input suppression on the archive's
        # path may accept. A listing stopped by the RUN's shared budget of
        # skipped blocks is the run's doing, not the archive's: that record is
        # a TOOL error, which no suppression accepts.
        self.record_failed_input(
            archive if archive_file is None else archive_file,
            f"it was extracted only in part: {detail}",
            kind="tool" if (stopped and budget_spent) else "input",
        )

    def inspect_members(
        self,
        members: List[str | zipfile.ZipInfo | tarfile.TarInfo],
        target_path: Optional[Path] = None,
        archive: Optional[str] = None,
        ignore_paths: Optional[List[IgnorePathWithReason]] = None,
        unscannable: Optional[List[str]] = None,
    ):
        """The members worth extracting: scannable, regular files that stay inside.

        A member is refused, with a warning naming it, when it is a link (a tar
        symlink or hard link, or a zip entry whose mode marks it a symlink), is not a
        regular file, is a sparse tar member whose map reaches past its declared
        size, is a zip entry zipfile cannot extract (encrypted, or compressed by a
        method it does not implement; _zip_member_problem), or has a name that is
        absolute, holds a NUL, contains ``..`` or would land outside
        ``target_path``, or, with ignore paths set, one that was not read as
        UTF-8 (``member_name_not_utf_8``), which no ignore path can be compared with.
        A member named as an archive or compressed file (a suffix in
        ``NESTED_ARCHIVE_SUFFIXES``, in any case) is refused as well: extraction is
        one level deep, and the refusal is what reports its contents as not scanned.
        Members no scanner reads (_member_is_scannable: not by their extension,
        and not by their name where they have none) are left out
        without a refusal, so a refusal is only reported for a member that would
        otherwise have been extracted; each one no ignore path names is added to
        ``unscannable``, when it is given, since its archive was then not extracted
        whole. A notebook member is extracted as it is and added there too: the
        jupyter converter reads the scan set, not this converter's output, so its
        code cells reach no scanner as code. A member an ignore path names in the
        scanned tree's terms (member_source_path) is left out too: it is never
        extracted, so no scanner reads it, snyk-code included, which would upload
        it. A member written to the same path as an earlier member of the archive
        (``vendor//m.js`` after ``vendor/m.js``, a tar's repeated name, or two
        spellings of one name on a case-insensitive filesystem) is written beside
        the earlier one under a numbered name (``vendor/m~2.js``,
        _renamed_member_name) that no member of the archive is named by, with a
        warning naming both, so neither silently overwrites the other and both are
        scanned; past MEMBER_REFUSALS_LISTED such members one line counts the rest.

        Args:
            members: The archive's members.
            target_path: The extraction directory. The escape check needs it, so it
                is skipped when this is None.
            archive: The archive's path relative to the scanned tree. When given, each
                refusal is also recorded in the converter's results row, and the
                ignore paths are matched against the member's source path.
            ignore_paths: The active global ignore paths.
            unscannable: Where to add the name of each member left out only because
                no scanner reads its extension.
        """
        ASH_LOGGER.verbose(f"Inspecting {len(members)} members from archive")
        filtered_members = []
        # Refusals by reason: how many were listed, and how many more were not.
        listed: Dict[str, int] = {}
        unlisted: Dict[str, int] = {}
        # The path each admitted member is written to (_written_key: as the host
        # compares names, case-folded), so a later member bound for the same
        # file is written beside the earlier one under a numbered name, and both
        # are scanned, rather than one written over the other.
        written: Dict[str, str] = {}
        # The directories the admitted members are written below (every prefix
        # of their written paths, _written_prefix_keys), so a later member bound
        # for one of them as a file, or one whose path runs through an admitted
        # member's file, is refused alone instead of failing the whole archive
        # at extraction (NotADirectoryError, IsADirectoryError).
        directories: Set[str] = set()
        # Every member's key before any is renamed, so a renamed member never
        # takes the name of a member that comes later in the archive.
        taken: Set[str] = set()
        for member in members:
            named = _named_member(member)
            if named is not None:
                taken.add(_written_key(*named))
        # Per written key, where the next rename of it starts counting.
        rename_counters: Dict[str, int] = {}
        renamed_count = 0
        for member in members:
            kind: Optional[Literal["zip", "tar"]] = None
            if isinstance(member, tarfile.TarInfo):
                member_name = member.name
                kind = "tar"
                if member.isdir():
                    continue
                is_link = member.issym() or member.islnk()
                is_regular = member.isreg()
                content_problem = _sparse_map_problem(member)
            elif isinstance(member, zipfile.ZipInfo):
                member_name = member.filename
                kind = "zip"
                if member.is_dir():
                    continue
                # Unix mode bits live in the high 16 bits of external_attr. zipfile
                # writes a symlink entry out as a file holding the link's target, so
                # it would not become a link, but it is not a file either.
                is_link = stat.S_ISLNK(member.external_attr >> 16)
                is_regular = True
                content_problem = _zip_member_problem(member)
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

            ignored_by = self._ignore_path_naming(
                archive, member_name, ignore_paths, kind
            )
            nested = _is_archive_name(member_name)
            # Through _archive_suffix (the spelling authority), so a member's
            # trailing dot or case does not hide a scannable file.
            member_ext = _archive_suffix(member_name)
            if not nested and not _member_is_scannable(member_name):
                if ignored_by is None and unscannable is not None:
                    unscannable.append(member_name)
                continue
            if member_ext == "ipynb" and ignored_by is None and unscannable is not None:
                # Extracted below as it is, but not converted: the jupyter
                # converter reads the scan set, so no scanner reads this
                # notebook's code as code, and the archive is not whole.
                unscannable.append(member_name)

            if ignored_by is not None:
                ASH_LOGGER.debug(
                    shown_on_one_line(
                        f"Skipping archive member {member_name} of {archive} due to "
                        f"global ignore_path '{ignored_by.path}' with reason "
                        f"'{ignored_by.reason}'"
                    )
                )
                continue

            problem = _member_name_problem(member_name)
            if problem is None and ignore_paths and member_name_not_utf_8(member):
                problem = MEMBER_NOT_UTF_8
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
            if problem is None:
                destination = _written_key(member_name, kind)
                prefixes = _written_prefix_keys(member_name, kind)
                through = next((key for key in prefixes if key in written), None)
                if through is not None:
                    # x.js before x.js/y.js: the later member cannot be written
                    # under a file, and is refused alone, naming the file.
                    problem = _MEMBER_UNDER_A_FILE.format(path=written[through])
                elif destination in directories:
                    # a/b.js before a: the later member cannot be written as a
                    # file where the earlier members' directory stands.
                    problem = _MEMBER_OVER_A_DIRECTORY
                elif destination in written and isinstance(member, str):
                    # A bare name has no member object whose name the extractor
                    # would read, so it cannot be renamed beside the earlier
                    # member; the later name is refused, as every duplicate was
                    # before members were renamed.
                    problem = _MEMBER_SAME_PATH
                elif destination in written:
                    # Renamed on the member object itself: zipfile and tarfile
                    # write each member to the path its name holds, so the
                    # renamed member lands beside the earlier one and the scan
                    # reads both, whichever of the two a consumer's unpacker
                    # keeps. The notice names the archive when inspect_members
                    # knows it.
                    renamed = _renamed_member_name(
                        member_name, kind, taken, written, rename_counters
                    )
                    renamed_count += 1
                    if renamed_count <= MEMBER_REFUSALS_LISTED:
                        ASH_LOGGER.warning(
                            shown_on_one_line(
                                f"Archive member '{member_name}'"
                                + (f" of '{archive}'" if archive is not None else "")
                                + ": "
                                + _MEMBER_RENAMED.format(renamed=renamed)
                            )
                        )
                    if isinstance(member, tarfile.TarInfo):
                        member.name = renamed
                    else:
                        member.filename = renamed
                    member_name = renamed
                    destination = _written_key(renamed, kind)
                if problem is None:
                    written[destination] = member_name
                    # A rename changes the base name alone, so the prefixes of
                    # the name as read are the renamed member's too.
                    directories.update(prefixes)
            if problem is not None:
                if listed.get(problem, 0) < MEMBER_REFUSALS_LISTED:
                    listed[problem] = listed.get(problem, 0) + 1
                    self._refuse_member(archive, member_name, problem)
                else:
                    unlisted[problem] = unlisted.get(problem, 0) + 1
                continue

            # The member's name, not the member object: its str is the repr,
            # which spells the name tar's or zip's own way beside an address.
            label = f".{member_ext} file" if member_ext else "file"
            ASH_LOGGER.verbose(shown_on_one_line(f"Found {label}: {member_name}"))
            filtered_members.append(member)
        for problem, count in unlisted.items():
            if archive is None:
                ASH_LOGGER.warning(f"Skipped {count} more archive members: {problem}")
            else:
                self.record_refused_input(
                    TreeInputRefused(archive, problem), unlisted_members=count
                )
        if renamed_count > MEMBER_REFUSALS_LISTED:
            ASH_LOGGER.warning(
                shown_on_one_line(
                    (f"Archive '{archive}': " if archive is not None else "")
                    + _MEMBERS_RENAMED_UNLISTED.format(
                        count=renamed_count - MEMBER_REFUSALS_LISTED
                    )
                )
            )
        return filtered_members

    def convert(self) -> List[Path]:
        """Extract every archive in the scan set under ``self.context.source_dir``.

        Each archive extracted with no member refused, and none left out because no
        scanner reads its extension, is recorded on the context
        (archives_extracted_whole), as it completes, so a failure later in the run
        leaves only the archives that were.

        Returns:
            List[Path]: List of paths to extracted files
        """
        extracted_whole: List[str] = []
        setattr(self.context, _EXTRACTED_WHOLE, extracted_whole)
        # TODO : Convert utils/identifyipynb.sh script to python using nbconvert as lib
        ASH_LOGGER.debug(
            f"Searching for archive files in search_path within the ASH scan set: {self.context.source_dir}"
        )

        # Find all archive files to scan from the scan set. The workspace's output
        # directory goes with the scan's own: when this run's recorded list cannot
        # be read back, the walk here leaves it out as the orchestrator's did,
        # instead of extracting archives from another project's output.
        workspace_output_dir = getattr(self.context, "workspace_output_dir", None)
        archive_files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
            run_id=getattr(self.context, "run_id", None),
            workspace_output_dir=(
                None if workspace_output_dir is None else str(workspace_output_dir)
            ),
        )
        # Paths as the scan set gives them: stripping them would turn a file whose
        # name ends in a space into one that does not exist.
        candidates = list(archive_files)
        archive_files = [
            f for f in candidates if _archive_suffix(f) in ARCHIVE_SUFFIXES
        ]
        selected = set(archive_files)
        # Named as an archive the converter does not extract (a .tgz, .jar, .7z
        # ...): recorded, so the summaries show it was not scanned, without
        # failing the completeness gate, as the same name inside an archive is.
        for path in candidates:
            if path in selected or not _is_archive_name(path):
                continue
            try:
                if self._skipped(path):
                    continue
            except (OSError, ValueError) as error:
                # A path the ignore check cannot place in the tree: recorded all
                # the same, since a record is all that is done with it.
                ASH_LOGGER.debug(
                    f"Could not check {inert_text(path)} against ignore_paths: {error}"
                )
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
        # The members are filtered by the same ignore paths as the archives
        # themselves (_skipped): a client-supplied entry and, under
        # --ignore-suppressions, every entry leaves a member in, so its findings
        # are reported instead of the member never reaching a scanner (a
        # member's finding under a client-supplied entry is reported unmarked;
        # see _ignore_paths_skipping_scanning).
        ignore_paths = self._ignore_paths_skipping_scanning()
        # Shared by every tar this conversion lists, so many small compressed
        # tars that each decompress to one listing's limit of blocks cost what a
        # few do.
        skipped_blocks = SkippedBlocksBudget(
            SKIPPED_BLOCKS_BUDGET_TARS * SKIPPED_BYTES_LIMIT
        )

        # Shared by every archive below; only an archive that is extracted uses it.
        scan_budget = _ScanBudget()
        # Each extraction directory and the archive it came from, recorded beside
        # the output once the loop ends (record_converted_sources): a finding in
        # an extracted member is placed by the archive under --changed-files-only.
        sources: Dict[Path, str] = {}
        for archive_file in archive_files:
            # The target directory once this iteration has made it: a directory
            # no other archive wrote (see _unused_target), so a failure part way
            # through removes what this archive wrote and nothing else.
            created_target: Optional[Path] = None
            refused_before = len(self.refused_inputs)
            # The in-part record is a FAILED input (the category the
            # completeness gate reads), so the whole-recording gate below
            # watches this count too, or a partially-extracted archive would
            # be recorded whole for whole-archive consumers.
            failed_before = len(self.failed_inputs)
            unscannable: List[str] = []
            archive_display = relative_display(archive_file, self.context.source_dir)
            try:
                if self._skipped(archive_file):
                    continue

                target_path = _unused_target(
                    Path(self.results_dir), _target_name(archive_file, archive_display)
                )
                ASH_LOGGER.verbose(
                    shown_on_one_line(
                        f"Extracting {archive_file} contents to target_path: {Path(target_path).as_posix()}"
                    )
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
                        # One compressed file, not an archive of files. Its one
                        # member is named by the ignore paths as any other is,
                        # by the archive's path and then its own
                        # (member_source_path), so an entry written for the
                        # decompressed file keeps it out of the scan.
                        if not self.inspect_members(
                            [plain_gzip],
                            target_path=target_path,
                            archive=archive_display,
                            ignore_paths=ignore_paths,
                        ):
                            continue
                        target_path.mkdir()
                        created_target = target_path
                        _decompress_plain_gzip(
                            archive_handle, target_path / plain_gzip, plain_gzip, budget
                        )
                        results.append(target_path)
                        sources[target_path] = archive_display
                        scan_budget.commit(budget)
                        continue

                    # Extract ZIP to target path after inspecting members
                    kind = archive_kind(archive_file, archive_handle)
                    if kind == "zip":
                        # Counted before zipfile builds a ZipInfo for every entry.
                        max_members = budget.options.max_members
                        if _zip_has_more_entries_than(archive_handle, max_members):
                            raise _too_many_members(max_members)
                        archive_handle.seek(0)
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
                                    ignore_paths=ignore_paths,
                                    unscannable=unscannable,
                                ),
                            )
                    # Extract Tarball to target path after inspecting members. The
                    # listing reads all of the tar's bytes (utils/tar_listing.py), so
                    # members past zero blocks are extracted too; the first header it
                    # could not read is in `unreadable`, and where it stopped, past
                    # its own limit of skipped blocks or the conversion's shared
                    # budget of them, in `stopped`. The stream is decompressed by its
                    # leading bytes and bounded while the headers are parsed
                    # (_tar_stream): member data is seek-skipped, the skipped blocks
                    # past an ordinary end are charged to the shared
                    # SkippedBlocksBudget, and the header reads to the per-archive
                    # header allowance; a file tarfile cannot open as a tar at all is
                    # refused below (_named_kind).
                    elif kind == "tar":
                        unreadable: List[int] = []
                        stopped: List[int] = []
                        ended: List[int] = []
                        tar_stream = stack.enter_context(_tar_stream(archive_handle))
                        # The blocks the listing skips are read through the
                        # bounded stream; the listing credits each one back
                        # to the header allowance as it classifies it
                        # (allow_skipped_blocks), so its budgets bound them,
                        # not the header allowance, and a skip-free tar keeps
                        # the strict base-plus-per-member bound.
                        with open_tar_listing(
                            tar_stream,
                            unreadable,
                            stopped,
                            budget=skipped_blocks,
                            # The stream is already decompressed and
                            # byte-budgeted; "r:" keeps tarfile's
                            # compression sniff (an 8 KiB read-ahead)
                            # off the header allowance.
                            mode="r:",
                            ended=ended,
                            encoding="utf-8",
                        ) as tar_ref:
                            # Every member is admitted against the extraction limits
                            # as its header is read; its extended header has been
                            # applied to it by then, so it is dropped rather than
                            # kept for every member until extraction. Admitted for
                            # the stored extent the pass skips where that exceeds
                            # the declared size (_admitted_size).
                            tar_members = []
                            for member in tar_ref:
                                budget.admit(
                                    member.name, _admitted_size(member, tar_ref)
                                )
                                member.pax_headers = {}
                                tar_members.append(member)
                                tar_stream.allow_another_member()
                            tar_stream.end_header_pass()
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
                                ignore_paths=ignore_paths,
                                unscannable=unscannable,
                            )
                            if _TAR_HAS_DATA_FILTER:
                                tar_ref.extractall(  # nosec B202
                                    path=target_path,
                                    members=safe_members,
                                    filter="data",
                                )
                            else:
                                _copy_tar_members(tar_ref, safe_members, target_path)
                        if unreadable or stopped or ended:
                            # Nothing is charged after a listing stops, and a spent
                            # budget stops a listing well before its own limit, so
                            # for a listing that stopped, a spent budget is what
                            # stopped it (or both were passed at one block).
                            self._record_extracted_in_part(
                                archive_display,
                                unreadable,
                                stopped,
                                budget_spent=skipped_blocks.spent,
                                ended=ended,
                                archive_file=archive_file,
                            )
                    elif _named_kind(archive_file) is not None:
                        # Named as an archive the converter extracts, and none can
                        # be read from it (a tar's first header is damaged, a .zip
                        # holds neither a zip nor a tar): none of it is read, and
                        # it is not recorded whole, so its results row says that
                        # no scanner reads it. A .gz of one file is no such
                        # name, and is left to the scanners as it is. Recorded as
                        # a FAILED input, not a refusal: the completeness gate
                        # reads failed_inputs, and an archive that could not be
                        # read is coverage lost; a refusal without a limit is
                        # invisible to it. An input error, by the scan-set path
                        # (see _record_extracted_in_part): no tool is involved,
                        # and a reviewed ash-unconverted-input suppression may
                        # accept the file.
                        self.record_failed_input(
                            archive_file,
                            f"it is named as {_named_kind(archive_file)} but "
                            "could not be read as one",
                            kind="input",
                        )
                        continue
                    else:
                        ASH_LOGGER.debug(
                            shown_on_one_line(
                                f"Skipping unsupported archive format: {archive_file}"
                            )
                        )
                        continue

                # Add the extracted directory to results
                results.append(target_path)
                sources[target_path] = archive_display
                scan_budget.commit(budget)
                if unscannable:
                    ASH_LOGGER.debug(
                        shown_on_one_line(
                            f"{archive_display} not extracted whole: no scanner "
                            f"reads {len(unscannable)} of its members as they are"
                        )
                    )
                if (
                    len(self.refused_inputs) == refused_before
                    and len(self.failed_inputs) == failed_before
                    and not unscannable
                ):
                    extracted_whole.append(archive_display)
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
            except (IsADirectoryError, NotADirectoryError) as e:
                # IsADirectoryError: a member named like a directory an earlier
                # member made; NotADirectoryError: a member under a path an
                # earlier member made a file (``x.js`` before ``x.js/y.js``).
                # Both are the archive's layout.
                if Path(archive_file).is_dir():
                    # The scan-set entry is a directory: nothing to extract.
                    ASH_LOGGER.debug(
                        shown_on_one_line(f"Skipping directory: {archive_file}")
                    )
                else:
                    # A file named like a directory an earlier member made: the
                    # archive was not extracted whole, and what was written is
                    # removed so the scanners do not read a partial extraction.
                    if created_target is not None:
                        shutil.rmtree(created_target, ignore_errors=True)
                    self.record_failed_input(
                        archive_file, _failure_reason(e, created_target), kind="input"
                    )
            except Exception as e:
                # Named for the converter, a .zip, .tar or .gz it could not read: a
                # bad CRC, a truncated or damaged stream, a gzip-compressed file
                # that is not a tarball, an empty file, or members that cannot all
                # be written. None of it is scanned, and
                # whatever was written before the failure is removed, so the
                # scanners do not read a partial extraction as the archive.
                # Recorded, not only logged: the completeness gate reads
                # failed_inputs, and an archive that could not be extracted is
                # coverage lost. As an INPUT error where the error says the
                # archive cannot be read (_failure_kind): this converter runs no
                # tool, so the default kind, "tool", told the operator to fix a
                # tool that does not exist and let no ash-unconverted-input
                # suppression accept the archive. An error of the run (no space
                # or permission in the work directory, a guard's refusal, a
                # defect) stays a TOOL error, which no suppression accepts.
                if created_target is not None:
                    shutil.rmtree(created_target, ignore_errors=True)
                self.record_failed_input(
                    archive_file,
                    _failure_reason(e, created_target),
                    kind=_failure_kind(e),
                )

        if sources:
            record_converted_sources(self.results_dir, self.context.work_dir, sources)
        return results
