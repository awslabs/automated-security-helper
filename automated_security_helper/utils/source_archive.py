# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read a zip of source code under one set of limits and member rules.

Why this module exists
----------------------
A source tree reaches ASH as a zip it did not make in two ways: an MCP client
uploads one (``set_source_zip_finalize`` in ``cli/mcp/source_delivery.py``), and an
operator names one with ``ash scan fs --archive FILE``. Either archive is read before
anything in it is scanned, and both are held to the rules here, so the two entry
points cannot drift apart: an archive one of them refuses, the other refuses in the
same words. The rules are the ones the MCP delivery enforced, moved here, with
additions that hold for both: a NUL, a ``.`` or an empty component in a member name,
a Unicode path field that renames a member, two members on one path (names that differ
only in case or Unicode normalization count as one on Windows and macOS), an
encrypted member, a compression method other than stored and deflate, a member whose
data is not the size it declares, and a file that holds anything besides one zip
(below).

What is refused
---------------
Every rule is decided from the archive's end records, its central directory, its
members' local headers and, for rule 9, their data, before anything is written, so a
refused archive leaves the destination as it was.

1. Size. At most 100 MiB of archive, 500 MiB of members once uncompressed, and
   50,000 members, directories included. The uncompressed total is the sum of the
   sizes the members declare, which also bounds what extraction writes: zipfile
   stops reading a member at its declared size, and rule 9 refuses a member whose
   data is any other size.
2. Names, judged as the archive spells them (``ZipInfo.orig_filename``) rather than
   as zipfile rewrites them, so one spelling is judged on every platform: an empty
   name; a backslash, since ``/`` is the zip separator and a backslash name lands on
   POSIX as one flat file whose directories a scanner never sees; an absolute name;
   a ``..`` component; a ``.`` component or an empty one (``./app.py``,
   ``a/./b.py``, ``pkg//mod.py``; a directory's trailing ``/`` is not one), which
   zipfile drops when it extracts the member, so it lands on a path the archive
   spells another way; and a NUL. zipfile cuts a name at its first NUL when it
   extracts the member, so a member spelled ``tool<NUL>.py`` was judged under that
   name and written as ``tool``, a file no Python scanner reads. On Windows a name
   Windows cannot hold as spelled is refused as well: a component that ends in a dot
   or a space, holds a control character or one of ``"*:<>?|``, or is a device name
   such as ``CON``, ``NUL`` or ``COM1``, with or without an extension. zipfile
   rewrites the first three there, and a device name is written to the device.
3. A second name. A member can carry a Unicode path field (extra field 0x7075), in its
   central directory entry or its local header, and readers differ in whether they
   extract the member under the name in it or the one the archive spells: Info-ZIP's
   ``unzip`` takes the field's, and so does zipfile from Python 3.12 for a field of
   version 1 whose CRC-32 matches the spelled name, while zipfile before 3.12 and
   ``zipimport`` keep the spelled one. The field is admitted only when it restates the
   name: the UTF-8 reading of the bytes the archive spells the name with, which is
   what Info-ZIP writes for a name outside ASCII. One that names another file is
   refused whatever its version and CRC-32 say, since readers differ in which fields
   they apply, so a member spelled ``app.txt`` is not scanned as ``app.txt`` and
   extracted by ``unzip`` as ``app.py``. This module reads the field itself rather
   than through zipfile, so the rule is the same on every supported Python, and the
   name an admitted field gives is judged by rule 2 too. A field too short to hold its
   version and CRC-32, or whose name is not UTF-8, is refused as not a zip, in the
   central directory in the words zipfile from 3.12 refuses it with.
4. One path for each member. Two members extracted to one path are refused,
   whatever each is (two members of one name, a file and a directory), and so is a
   member under a path the archive holds as a file. zipfile writes the later of two
   members over the earlier, so the tree scanned would hold one of two files, while
   a reader that looks members up by name, as ``zipimport`` and ``python app.zip``
   do, can run the other. On Windows and macOS, whose usual filesystems keep one file
   for names that differ only in case (``app.py`` and ``APP.py``), and on macOS also
   for names that differ only in Unicode normalization (a letter with an accent
   written as one character, or as the letter and a combining accent), paths are
   compared after NFC normalization and case folding on both; elsewhere they are
   compared as the archive spells them.
5. Links. Every symbolic link is refused, wherever it points. Resolving a target
   before extraction races the extraction (an earlier member can make the directory
   a later link's path runs through), and a source tree needs none. The refusal
   quotes at most the first 256 bytes of the target.
6. One zip, and nothing else. zipfile reads the zip whose end record it finds last
   and lets the rest of the file pass: bytes before it, which it takes for data the zip
   was appended to, bytes after its end record, and bytes between its members, which
   its central directory does not list. A reader that starts at the first byte reads
   what is there, so one file could give the scan one tree and that reader another:
   two zips end to end are the second to zipfile and the first from byte 0, and a tar
   whose last member is a zip reads as that zip. The file therefore has to be one zip
   from its first byte to its last: the members' local records one after another from
   byte 0, each its header, name, extra field, data and, when its flags say so, a data
   descriptor that restates its CRC-32 and sizes; then the central directory, holding
   as many entries as the end record counts and none that runs past it; then, for a
   zip64 archive, its end record and the locator that places that record where it
   lies, since readers differ in where they look for it; then the end record and its
   comment.
   A local header that gives another name (the bytes, or the UTF-8 flag that says how
   they are decoded), compression method, data descriptor flag, CRC-32 or size than
   its central directory entry is refused too, since a reader of the local headers
   would extract that member under another name, or find its data, and the next
   member, elsewhere. Each of these is refused as not a zip.
   The zip64 locator is judged as the file is opened (``open_zip``), before zipfile
   reads it: some zipfile releases refuse a locator that misplaces the zip64 end record
   as they open the archive, in words of their own, and others admit it, so the rule is
   decided first, and its verdict and words are the same on every Python.
7. Encryption. A member whose data is encrypted is refused, a link included: its data
   cannot be read, so no rule could judge it and no scan read it. The members are
   checked for it right after they are counted, before any other rule but the zip64
   locator's reads the file, so an archive that holds one is refused in the same words
   by both entry points, whatever else it holds but a locator that misplaces the zip64
   end record.
8. Compression. A member is stored or deflated; one in any other method (bzip2, LZMA,
   Zstandard, and the few others some tools write) is refused whatever size it
   declares, a link included. zipfile gives the decompressor of the first three all the
   data it has read, with no limit on the output, and cuts what it returns to the
   declared size only after the call, so a few kilobytes of data can ask for gigabytes
   of memory under a member that declares ten bytes, and rule 1's limit on the total
   does not bound the process. Stored and deflated are what Info-ZIP, ``git archive``
   and zipfile write, and zipfile bounds each call it makes to a deflate decompressor.
   The method is read from the central directory right after the encryption flag, so
   both entry points refuse such a member in the same words, on every Python, whether
   or not it was built with the method's module.
9. Data that is the size it declares. zipfile cuts a member at the size it declares and
   checks the CRC-32 of what it returned, so data past that size is invisible to it; a
   reader that takes the member's whole data, as ``zipimport`` and ``python app.zip``
   do, gets all of it, so a member that declares 10 bytes and holds 200 gives the scan
   the first and that reader the rest. A stored member's data is as long as its size. A
   deflated member is inflated by this module, which reads at most 64 KiB of its
   compressed data and makes at most 64 KiB of output in a step, and never more than a
   byte past the size the member declares, so memory stays at the step and the work at
   the declared total, which rule 1 holds to 500 MiB: its stream has to end exactly at
   that size, and to be the whole of its compressed data. The CRC-32 is zipfile's check,
   made as it extracts the member. A stream zlib cannot read is refused as an
   unreadable member, here, in the words extraction used for it, so no member is
   written before it.

A malformed member is refused, never repaired: an archive that has to be rewritten to
be safe is not the tree its sender meant to send.

Formats
-------
Zip only. A tar, a gzip file or anything else is refused as not a zip, and so is a zip
with anything before, between or after its members (rule 6), a tar whose last member
is a zip among them. Nothing sniffs the content to decide what an archive holds,
because the command names it: ``ash scan fs --archive`` reads source, and ``ash scan
image --archive`` reads an image tarball. A tar reader would need member rules of its
own (hard links, devices, sparse members) before it could be admitted here.

Entry points
------------
* ``extract_source_archive(archive, destination)`` reads the zip at a path, for
  ``ash scan fs --archive``. Besides the rules above it refuses a path that is not a
  regular file or cannot be read, and a member zipfile cannot read back whole:
  damaged data, or a zip version it does not implement. It reads the file once, into
  memory, and zipfile reads that copy, so nothing zipfile raises is about the disk.
  Every problem with the archive is a ``SourceArchiveRefused``; an ``OSError`` is a
  problem with the destination or the disk.
* ``open_zip(handle)`` opens an archive its caller holds open, and
  ``extract_zip_members(archive, destination, rules)`` extracts it. The MCP finalize
  hashes an upload before extracting it, and has to extract the bytes it hashed, so it
  passes the handle it read, with its own limits (``ZipRules``).
  ``admit_zip_members`` is the checking half of the extraction.

Both entry points read the archive through one classification of what zipfile raises,
so an archive one of them refuses, the other refuses with the same kind and words.
What zipfile raises as it opens the file, reads a link's target or extracts a member
is about the archive, and is a refusal. Bytes it does not open as a zip are refused as
not a zip, in its own words, and the refusal is a ``zipfile.BadZipFile`` as well, which
is what the MCP finalize has always raised for them. Anything else it raises while it
opens the archive or reads a link's target is refused as unreadable ("the archive
cannot be read: ..."), and while it extracts a member, as unreadable with the member
named ("zip entry '...' cannot be read: ..."). An ``OSError`` is raised as it is, since
it is a problem with the destination or the disk, and so is a ``MemoryError``, which
is the process's. What ASH's own code raises is not caught.

A refusal is a ``SourceArchiveRefused``, a ``ValueError`` whose ``kind``
(``SourceArchiveRefusal``) names the rule. Import this module where an archive is
read, not at the top of a CLI module, so ``ash --version`` and ``ash scan --help``
do not load it.

Limits
------
* Rule 4 folds names only on Windows and macOS (``_names_fold_together`` decides it).
  Elsewhere it compares them as the archive spells them, so a tree extracted on Linux
  and copied onto a filesystem that ignores case can still lose a file. The fold is
  Unicode's, NFC and then case folding; a filesystem that equates more names than
  that, or answers to a second name for a file (the 8.3 short names NTFS can keep for
  long names), can still hold two members' paths as one. Where that happens zipfile
  writes the later of two files over the earlier, and a file and a directory end the
  extraction with the ``OSError`` the filesystem raises.
* A member whose data does not match its CRC-32 is found when extraction reaches it,
  after the members before it were written: admission inflates a deflated member to its
  end and counts what it makes, but does not check the CRC-32 over it, and reads no
  stored member's data. The caller removes the destination on any failure.
* A Unicode path field that restates its name from a legacy code page rather than
  from UTF-8 bytes (Info-ZIP under a locale that is not UTF-8, for a name outside
  ASCII) is refused as naming another file.
* So is a stale field: one a tool left behind when it renamed the member without
  rewriting the field. Readers that check the field's CRC-32 ignore it and keep the
  new name, but rule 3 does not rely on a reader doing so.
* A member whose flags say a data descriptor follows its data gives no sizes in its
  local header, so a reader of the local headers finds where that member ends from its
  data: where its compressed stream stops, or, for a stored member, where it finds a
  data descriptor. Rule 6 places the end by the compressed size in the central
  directory, as zipfile does, and rule 9 checks that a deflated stream stops exactly
  there, so what is left is a stored member whose data holds what reads as its own
  descriptor, which can end that member somewhere else for such a reader.
* Admission inflates each deflated member once and extraction inflates it again, so
  an archive of deflated members costs its declared total twice, bounded as above.
"""

from __future__ import annotations

import contextlib
import errno
import io
import os
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Callable, Iterator, List, Optional, Tuple, Type

#: The largest archive admitted, in bytes on disk.
MAX_ARCHIVE_BYTES: int = 100 * 1024 * 1024
#: The most the members of one archive may hold together once uncompressed.
MAX_EXTRACTED_BYTES: int = 500 * 1024 * 1024
#: The most members, files and directories together, one archive may hold.
MAX_MEMBERS: int = 50_000
#: How much of a refused link's target its refusal quotes.
SYMLINK_TARGET_EXCERPT_BYTES: int = 256
#: The archive formats ``extract_source_archive`` reads.
SUPPORTED_ARCHIVE_FORMATS: Tuple[str, ...] = ("zip",)
#: What the link refusal calls the archives it refuses a link in, unless the caller
#: names its own: "symlinks are not allowed in source archives".
SOURCE_ARCHIVES = "source archives"

# A member's Unix mode is the high half of ``external_attr``: its file type is the
# S_IFMT bits (0xF000), and a symbolic link's type is S_IFLNK (0xA000).
_S_IFMT_SHIFTED = 0xF000 << 16
_S_IFLNK_SHIFTED = 0xA000 << 16

#: Bit 0 of a member's general purpose flags: its data is encrypted.
_ENCRYPTED_FLAG = 0x1
#: Bit 3 of a member's general purpose flags: its local header leaves its CRC-32 and
#: sizes out, and a data descriptor after its data gives them.
_DATA_DESCRIPTOR_FLAG = 0x8
#: Bit 11 of a member's general purpose flags: its name is UTF-8, not the legacy code
#: page, which is how a reader decodes the bytes it finds where the name is.
_UTF8_NAME_FLAG = 0x800
#: The compression methods a member may use (rule 8): stored, and deflated, the two
#: that Info-ZIP, git archive and zipfile write by default.
_ADMITTED_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
#: How much of a deflated member admission reads at a time, and the most that one
#: inflate call may produce (rule 9): memory stays at about twice this, whatever the
#: member declares or holds. The work is bounded by the sizes the members declare,
#: which rule 1 holds to ``ZipRules.max_extracted_bytes`` in all.
_INFLATE_STEP_BYTES = 64 * 1024
#: The methods a refusal names, by their numbers in PKWARE's APPNOTE (section 4.4.5): the
#: ones other tools write. Any other number is named as the number.
_METHOD_NAMES = {
    1: "Shrink",
    6: "Implode",
    9: "Deflate64",
    12: "bzip2",
    14: "LZMA",
    93: "Zstandard",
    95: "XZ",
    98: "PPMd",
}

# The records a zip is made of, as PKWARE's APPNOTE (section 4.3) lays them out and
# zipfile reads them (rule 6).
#: A member's local header: signature, version needed, flags, compression method, time,
#: date, CRC-32, compressed size, size, name length and extra field length.
_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
#: A central directory entry is 46 bytes before its name, and gives the lengths of its
#: name, extra field and comment at its 28th byte.
_CENTRAL_ENTRY_SIZE = 46
_CENTRAL_ENTRY_LENGTHS = struct.Struct("<3H")
_CENTRAL_ENTRY_LENGTHS_AT = 28
#: The end record: signature, two disk numbers, the entries on this disk and in all, the
#: central directory's size and offset, and the comment's length.
_END_RECORD = struct.Struct("<4s4H2LH")
_END_RECORD_SIGNATURE = b"PK\x05\x06"
#: How far from the end of the file zipfile looks for the end record: a comment of the
#: longest length and the record, counted as Python 3.11 counts it (later versions look
#: one byte less far, which finds the same record whenever they find one).
_END_RECORD_SEARCH = (1 << 16) + _END_RECORD.size
#: The zip64 end record locator, just before the end record: signature, disk, the zip64
#: end record's offset, disks.
_ZIP64_LOCATOR = struct.Struct("<4sLQL")
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
#: The zip64 end record: signature, its length after this field, two versions, two disk
#: numbers, the entries on this disk and in all, the central directory's size and
#: offset.
_ZIP64_END_RECORD = struct.Struct("<4sQ2H2L4Q")
_ZIP64_END_RECORD_SIGNATURE = b"PK\x06\x06"
#: A data descriptor: its signature, which a writer may leave out, then the CRC-32 and
#: the compressed size and size, in four bytes each or, for a zip64 member, in eight.
_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_DATA_DESCRIPTOR_BODIES = (struct.Struct("<3L"), struct.Struct("<L2Q"))
_LONGEST_DATA_DESCRIPTOR = len(_DATA_DESCRIPTOR_SIGNATURE) + max(
    body.size for body in _DATA_DESCRIPTOR_BODIES
)
#: An extra field is a run of blocks, each a header ID and a data length, then the data.
_EXTRA_BLOCK_HEAD = struct.Struct("<HH")
#: The extra field block that gives a member's zip64 sizes and offset.
_ZIP64_EXTRA = 0x0001
#: A size in a local header that its zip64 block gives instead.
_ZIP64_SIZE_MARKER = 0xFFFFFFFF
#: The Unicode path field (rule 3): a version byte and a CRC-32 before the name.
_UNICODE_PATH_EXTRA = 0x7075
_UNICODE_PATH_HEAD = 5
#: Where an extra field is, as a refusal names the place.
_CENTRAL_DIRECTORY_ENTRY = "the central directory entry"
_LOCAL_HEADER_ITSELF = "the local header"

#: Whether names are judged by what Windows can hold as well (rule 2).
_ON_WINDOWS = os.name == "nt"
#: The characters Windows reserves in a path component: the control characters and
#: these seven, as Python 3.13's ``ntpath.isreserved`` reads them.
_WINDOWS_RESERVED_CHARACTERS = frozenset(map(chr, range(32))) | frozenset('"*:<>?|')
#: The device names Windows reserves, with or without an extension.
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{digit}" for digit in "123456789\xb9\xb2\xb3"}
    | {f"LPT{digit}" for digit in "123456789\xb9\xb2\xb3"}
)

#: What the classification of zipfile's exceptions lets pass as they were raised.
#: Every other exception zipfile raises is about the archive. An OSError is the
#: destination's, since extraction writes there, the disk's where the archive is read
#: from one, or a damaged bzip2 stream's (see Limits); a MemoryError is the process's.
_NOT_THE_ARCHIVES: Tuple[Type[BaseException], ...] = (OSError, MemoryError)


class SourceArchiveRefusal(str, Enum):
    """The rule that refused an archive. The values reach users, so they are stable."""

    ARCHIVE_TOO_LARGE = "archive-too-large"
    TOO_MANY_MEMBERS = "too-many-members"
    EXTRACTED_TOO_LARGE = "extracted-too-large"
    EMPTY_NAME = "empty-name"
    BACKSLASH_IN_NAME = "backslash-in-name"
    ABSOLUTE_PATH = "absolute-path"
    PATH_TRAVERSAL = "path-traversal"
    DOT_COMPONENT = "dot-component"
    EMPTY_COMPONENT = "empty-component"
    NUL_IN_NAME = "nul-in-name"
    RESERVED_NAME = "reserved-name"
    UNICODE_PATH_MISMATCH = "unicode-path-mismatch"
    PATH_COLLISION = "path-collision"
    SYMLINK_MEMBER = "symlink-member"
    NOT_A_ZIP = "not-a-zip"
    # Only extract_source_archive refuses for these two: it opens the file itself.
    NOT_A_FILE = "not-a-file"
    UNREADABLE_ARCHIVE = "unreadable-archive"
    # Both entry points refuse for these three.
    ENCRYPTED_MEMBER = "encrypted-member"
    UNSUPPORTED_COMPRESSION = "unsupported-compression"
    UNREADABLE_MEMBER = "unreadable-member"


class SourceArchiveRefused(ValueError):
    """An archive a rule refused: ``kind`` names the rule, the text what it found."""

    def __init__(self, kind: SourceArchiveRefusal, message: str) -> None:
        super().__init__(message)
        self.kind = kind

    def __reduce__(
        self,
    ) -> Tuple[Type[SourceArchiveRefused], Tuple[SourceArchiveRefusal, str]]:
        # The default rebuilds an exception from its args, the message alone, which
        # this constructor does not take; a copy or a pickle would fail without this.
        return type(self), (self.kind, str(self))


class _BadZipFileRefused(SourceArchiveRefused, zipfile.BadZipFile):
    """The refusal of bytes that are not a zip (``not-a-zip``), a ``BadZipFile`` too.

    The MCP finalize raised ``zipfile.BadZipFile`` for them before it shared this
    module, and documents it, so a caller that catches that still does.
    """


def archive_too_large(size: int, limit: int) -> SourceArchiveRefused:
    """The refusal of an archive of ``size`` bytes, over ``limit``."""
    return SourceArchiveRefused(
        SourceArchiveRefusal.ARCHIVE_TOO_LARGE,
        f"zip too large: {size} > {limit} bytes",
    )


def is_symlink_member(info: zipfile.ZipInfo) -> bool:
    """Whether ``info`` is a symbolic link, by the Unix file type in ``external_attr``.

    A member with no type bits, as zip tools on Windows write, is not a link.
    """
    return (info.external_attr & _S_IFMT_SHIFTED) == _S_IFLNK_SHIFTED


def validate_member_name(name: str) -> None:
    """Refuse a member name, given as the archive spells it, that is not a plain path.

    Refused, in this order: an empty name; a backslash; an absolute name (a leading
    ``/``, or one this platform reads as absolute, such as a drive on Windows); a
    ``..`` component; a ``.`` component; an empty component (a directory's trailing
    ``/`` is not one); a NUL; and on Windows, a component Windows cannot hold as
    spelled (:func:`_reserved_on_windows`). A name that breaks more than one rule is
    refused for the first. A name whose dots are not a whole component
    (``..config``, ``notes..txt``) is a plain name.

    Raises:
        SourceArchiveRefused: naming the rule and the name.
    """
    if not name:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.EMPTY_NAME, "zip entry has empty name"
        )
    if "\\" in name:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.BACKSLASH_IN_NAME,
            f"backslash in zip entry name: {name!r}",
        )
    if os.path.isabs(name) or name.startswith("/"):
        raise SourceArchiveRefused(
            SourceArchiveRefusal.ABSOLUTE_PATH, f"absolute path in zip: {name!r}"
        )
    components = name.removesuffix("/").split("/")
    if ".." in components:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.PATH_TRAVERSAL, f"path traversal in zip: {name!r}"
        )
    if "." in components:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.DOT_COMPONENT,
            f"'.' component in zip entry name: {name!r}",
        )
    if "" in components:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.EMPTY_COMPONENT,
            f"empty component in zip entry name: {name!r}",
        )
    if "\x00" in name:
        # After the rules on the name's shape, so a name that also breaks one of
        # them keeps that rule's words.
        raise SourceArchiveRefused(
            SourceArchiveRefusal.NUL_IN_NAME, f"NUL in zip entry name: {name!r}"
        )
    if _ON_WINDOWS:
        for component in components:
            if _reserved_on_windows(component):
                raise SourceArchiveRefused(
                    SourceArchiveRefusal.RESERVED_NAME,
                    f"reserved name on Windows in zip entry name {name!r}: "
                    f"{component!r}",
                )


def _reserved_on_windows(component: str) -> bool:
    """Whether Windows cannot hold the path component ``component`` as spelled.

    The rules of Python 3.13's ``ntpath.isreserved``, which the supported 3.11 and
    3.12 lack: a trailing dot or space, a reserved character, or a device name with
    or without an extension (``nul.txt``, ``nul .txt``).
    """
    if component.endswith((".", " ")):
        return True
    if not _WINDOWS_RESERVED_CHARACTERS.isdisjoint(component):
        return True
    return component.partition(".")[0].rstrip(" ").upper() in _WINDOWS_DEVICE_NAMES


@dataclass(frozen=True)
class ZipRules:
    """The limits one extraction applies, and the check each member name passes.

    The defaults are the source-archive limits, read from this module's names when the
    rules are made, as ``MAX_ARCHIVE_BYTES`` is read when an archive is: a limit set
    on this module is the one applied. The MCP finalize builds its own each time it
    runs, from its module's names, for the same reason.
    """

    max_members: int = field(default_factory=lambda: MAX_MEMBERS)
    max_extracted_bytes: int = field(default_factory=lambda: MAX_EXTRACTED_BYTES)
    #: Given each member's name as the archive spells it, and then, for a member whose
    #: Unicode path field restates that name in other characters, the name the field
    #: gives, which zipfile from 3.12 extracts it under; raises to refuse.
    validate_name: Callable[[str], None] = validate_member_name
    symlink_excerpt_bytes: int = field(
        default_factory=lambda: SYMLINK_TARGET_EXCERPT_BYTES
    )
    #: The archives the link refusal names: "symlinks are not allowed in <archives>".
    archives: str = SOURCE_ARCHIVES


@dataclass(frozen=True)
class _LocalRecord:
    """What the walk of a member's local record finds that a later rule reads."""

    #: The extra field of its local header (rule 3).
    extra: bytes
    #: Where its data starts: after its local header, name and extra field (rule 9).
    data_at: int


def admit_zip_members(
    archive: zipfile.ZipFile, rules: Optional[ZipRules] = None
) -> List[zipfile.ZipInfo]:
    """Return every member of ``archive`` when ``rules`` admit them all.

    ``rules`` are, when none are given, ``ZipRules()``: the source-archive limits as
    this module's names hold them now.

    Writes nothing. Reads the file ``archive`` was opened on where its records are (the
    end records, the central directory, each member's local header and any data
    descriptor), for a link the first bytes of its target, and the compressed data of
    each deflated member, which it inflates under a bound and drops (rule 9); no other
    member data. The member count is checked first; then that no member is encrypted;
    then that none is compressed with a method other than stored or deflated, so that
    no data is ever handed to a decompressor that cannot be bounded; then that the file
    is one zip and nothing else; then, for each member in archive order, its name, its
    Unicode path fields and the name an admitted one gives, the uncompressed total so
    far, and whether it is a link; then that no two members are extracted to one path;
    last, that each member's data is the size it declares. The first rule that refuses
    ends the check.

    Raises:
        SourceArchiveRefused: naming the rule. What zipfile raises as the first bytes
            of a link's target are read is refused as unreadable, like anything else
            zipfile raises about the archive, but an ``OSError`` and a
            ``MemoryError``; so is a deflated stream zlib cannot read. Whatever
            ``rules.validate_name`` raises, and every exception of this module's own,
            is raised as it is.
        ValueError: ``archive`` is closed.
    """
    if rules is None:
        rules = ZipRules()
    members = archive.infolist()
    if len(members) > rules.max_members:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.TOO_MANY_MEMBERS,
            f"too many files in zip: {len(members)} > {rules.max_members}",
        )
    _refuse_encrypted_members(members)
    _refuse_unsupported_methods(members)
    spelled_names, records = _refuse_anything_but_one_zip(archive, members)
    total = 0
    for info, spelled, record in zip(members, spelled_names, records):
        rules.validate_name(info.orig_filename)
        restated = _refuse_a_second_name(info, spelled, record.extra)
        if restated is not None and restated != info.orig_filename:
            rules.validate_name(restated)
        total += info.file_size
        if total > rules.max_extracted_bytes:
            raise SourceArchiveRefused(
                SourceArchiveRefusal.EXTRACTED_TOO_LARGE,
                f"extracted size exceeds {rules.max_extracted_bytes} bytes "
                f"(at entry {info.filename!r})",
            )
        if is_symlink_member(info):
            raise _link_refused(archive, info, rules)
    _refuse_shared_paths(members)
    _refuse_data_that_is_not_its_size(_archive_file(archive), members, records)
    return members


def _archive_file(archive: zipfile.ZipFile) -> IO[bytes]:
    """The file ``archive`` reads, which the records and the data are read from."""
    handle = archive.fp
    if handle is None:
        raise ValueError("Attempt to use ZIP archive that was already closed")
    return handle


def _refuse_anything_but_one_zip(
    archive: zipfile.ZipFile, members: List[zipfile.ZipInfo]
) -> Tuple[List[bytes], List[_LocalRecord]]:
    """Refuse a file that holds anything besides one zip (rule 6).

    The end record has to end the file with its comment; the central directory has to
    be where the end record (or the zip64 end record) says, as many entries as it
    counts, none running past it; and the members' local records have to fill the file
    from byte 0 to the central directory, each local header agreeing with the entry
    that lists it (:func:`_local_records`). zipfile opened the archive, so the records
    it read are there to be found the way it found them.

    Returns each member's name in the bytes the central directory spells it with, and
    what its local record gives later rules (:class:`_LocalRecord`: the extra field of
    its local header for rule 3, where its data starts for rule 9), in archive order.
    """
    handle = _archive_file(archive)
    size = handle.seek(0, io.SEEK_END)
    end = _end_record_position(handle, size)
    # The entries on this disk and in all, the directory's size and offset, and the
    # comment's length: every field after the signature and the two disk numbers.
    on_this_disk, in_all, directory_size, directory_offset, comment_length = (
        _END_RECORD.unpack(_read_at(handle, end, _END_RECORD.size))[3:]
    )
    following = size - end - _END_RECORD.size
    if following > comment_length:
        raise _not_a_zip(
            f"{following - comment_length} bytes follow the archive's end record"
        )
    if following < comment_length:
        raise _not_a_zip(
            f"the archive's end record claims a {comment_length}-byte comment, and "
            f"{following} bytes follow it"
        )
    zip64 = _zip64_end_record(handle, end)
    if zip64 is not None:
        on_this_disk, in_all, directory_size, directory_offset = zip64[6:10]
    # zipfile puts the central directory where it lies, before the end records, and
    # takes any difference from where the end record says for bytes the zip was
    # appended to, which it adds to every member's offset.
    shift = archive.start_dir - directory_offset
    if shift > 0:
        raise _not_a_zip(f"{shift} bytes come before the archive")
    if shift < 0:
        raise _not_a_zip(
            "the archive's end record places its central directory "
            f"{-shift} bytes past where it lies"
        )
    held = len(members)
    counted = in_all if in_all != held else on_this_disk
    if counted != held:
        raise _not_a_zip(
            f"the archive's end record counts {counted} members, and its central "
            f"directory holds {held}"
        )
    spelled = _spelled_names(handle, archive.start_dir, directory_size, members)
    return spelled, _local_records(handle, archive.start_dir, members, spelled)


def _not_a_zip(message: str) -> SourceArchiveRefused:
    return _BadZipFileRefused(SourceArchiveRefusal.NOT_A_ZIP, message)


def _read_at(handle: IO[bytes], offset: int, length: int) -> bytes:
    """At most ``length`` bytes of ``handle`` from ``offset``; none before its start.

    The offsets and lengths come from the archive's own records, so one can be larger
    than any seek or read takes (an ``OverflowError``), or than the filesystem can
    hold (the ``OSError`` of a seek): nothing is there to read, as for an offset past
    the end of the file. A read that fails is the disk's, and is raised as it is.
    """
    if offset < 0 or length <= 0:
        return b""
    try:
        handle.seek(offset)
    except (OverflowError, OSError):
        return b""
    try:
        return handle.read(length)
    except OverflowError:
        return b""


def _end_record_position(handle: IO[bytes], size: int) -> int:
    """Where the end record zipfile read starts, found the way zipfile finds it.

    The last bytes, when they are an end record with no comment; otherwise the last end
    record signature in the stretch a comment of the longest length leaves room for.
    """
    if size >= _END_RECORD.size:
        last = _read_at(handle, size - _END_RECORD.size, _END_RECORD.size)
        if last.startswith(_END_RECORD_SIGNATURE) and last.endswith(b"\x00\x00"):
            return size - _END_RECORD.size
    start = max(size - _END_RECORD_SEARCH, 0)
    return start + _read_at(handle, start, size - start).rfind(_END_RECORD_SIGNATURE)


def _zip64_end_record(handle: IO[bytes], end: int) -> Optional[Tuple[int, ...]]:
    """The zip64 end record, when a locator sits just before the end record.

    The record has to be the 56 bytes just before the locator, and the locator has to
    place it there. Readers differ in where they look. zipfile before the releases that
    validate the locator reads the record just before it and takes no notice of the
    offset it holds. Later ones read at that offset first, look just before the locator
    when the record is not there, for bytes written before the archive, and refuse the
    archive as they open it when the record's own directory offset and size do not end
    at the offset the locator gives. Where the two are one place every reader finds the
    same record, which is where every writer puts it (bytes before the archive and zip64
    extensible data are refused by rule 6 in any case), so a locator that places the
    record anywhere else is refused as not a zip, whatever else the archive says. The
    record is read where it has to be, never at the offset the locator gives, which the
    archive chooses.

    The words of the refusal: "Zip64 end of central directory record not found" for a
    locator with no whole record before it, and "Corrupt zip64 end of central directory
    locator" for one that places the record past where it lies, as the releases that
    validate the locator say; "N bytes come before the archive" for one that places it
    before, where those releases say "Corrupt zip64 end of central directory record".
    ``open_zip`` asks before zipfile opens the archive
    (:func:`_refuse_a_misplaced_zip64_record`), so these are the words whichever
    zipfile reads it, and rule 6 asks again, for the record's fields.
    """
    locator_at = end - _ZIP64_LOCATOR.size
    if locator_at < 0:
        return None
    signature, _, record_at, _ = _ZIP64_LOCATOR.unpack(
        _read_at(handle, locator_at, _ZIP64_LOCATOR.size)
    )
    if signature != _ZIP64_LOCATOR_SIGNATURE:
        return None
    lies = locator_at - _ZIP64_END_RECORD.size
    record = _read_at(handle, lies, _ZIP64_END_RECORD.size)
    if not _is_zip64_end_record(record):
        raise _not_a_zip("Zip64 end of central directory record not found")
    if record_at > lies:
        raise _not_a_zip("Corrupt zip64 end of central directory locator")
    if record_at < lies:
        raise _not_a_zip(f"{lies - record_at} bytes come before the archive")
    return _ZIP64_END_RECORD.unpack(record)


def _is_zip64_end_record(record: bytes) -> bool:
    """Whether ``record`` holds a whole zip64 end record."""
    return len(record) == _ZIP64_END_RECORD.size and record.startswith(
        _ZIP64_END_RECORD_SIGNATURE
    )


def _refuse_a_misplaced_zip64_record(handle: IO[bytes]) -> None:
    """Refuse a zip64 end record that its locator does not place where it lies (rule 6).

    Decided from the file's bytes before zipfile opens it (:func:`open_zip`), so the
    verdict and its words are the rule's on every Python. The zipfile releases that
    check the zip64 end record as they open an archive refuse a locator that misplaces
    it themselves, in words of their own: for a locator that places the record before
    where it lies they say "Corrupt zip64 end of central directory record", and
    :func:`_zip64_end_record` says "N bytes come before the archive". The releases
    before them admit such an archive, and rule 6 refuses it with the same call.

    A file with no end record is not judged: zipfile refuses it, in its own words, and
    this reads no locator for it.
    """
    end = _end_record_position(handle, handle.seek(0, io.SEEK_END))
    record = _read_at(handle, end, _END_RECORD.size)
    if len(record) == _END_RECORD.size and record.startswith(_END_RECORD_SIGNATURE):
        _zip64_end_record(handle, end)


def _spelled_names(
    handle: IO[bytes], start: int, length: int, members: List[zipfile.ZipInfo]
) -> List[bytes]:
    """Each member's name in the bytes its central directory entry spells it with.

    zipfile reads the central directory's length of bytes and lets an entry's name,
    extra field or comment run past them, reading what is left. A reader of the file
    reads those fields from the end records after the directory instead, so an entry
    that runs past the directory is refused.
    """
    directory = _read_at(handle, start, length)
    names = []
    at = 0
    for info in members:
        name_length, extra_length, comment_length = _CENTRAL_ENTRY_LENGTHS.unpack_from(
            directory, at + _CENTRAL_ENTRY_LENGTHS_AT
        )
        name_at = at + _CENTRAL_ENTRY_SIZE
        at = name_at + name_length + extra_length + comment_length
        if at > len(directory):
            raise _not_a_zip(
                f"the central directory entry of zip entry {info.orig_filename!r} "
                "runs past the central directory"
            )
        names.append(directory[name_at : name_at + name_length])
    return names


def _local_records(
    handle: IO[bytes],
    directory_start: int,
    members: List[zipfile.ZipInfo],
    spelled: List[bytes],
) -> List[_LocalRecord]:
    """Refuse bytes before, between or after the members' local records.

    Taken in the order of their local headers, each record has to start where the one
    before it ends, the first at byte 0, and the last has to end where the central
    directory starts (:func:`_local_record_end` says where each ends, and what its
    local header has to agree on with the entry that lists it, ``spelled`` being that
    entry's name for each member). Returns what each member's record gives later rules,
    in archive order.
    """
    records = [_LocalRecord(b"", 0)] * len(members)
    order = sorted(range(len(members)), key=lambda at: members[at].header_offset)
    boundaries = [members[at].header_offset for at in order[1:]] + [directory_start]
    reached = 0
    previous: Optional[zipfile.ZipInfo] = None
    for position, boundary in zip(order, boundaries):
        info = members[position]
        if info.header_offset >= directory_start:
            raise _not_a_zip(
                f"the central directory places zip entry {info.orig_filename!r} at "
                f"byte {info.header_offset}, which is not before the central directory"
            )
        if info.header_offset != reached:
            raise _misplaced(previous, info, reached)
        reached, records[position] = _local_record_end(
            handle, info, boundary, spelled[position]
        )
        previous = info
    if reached != directory_start:
        if previous is None:
            raise _not_a_zip(
                f"{directory_start} bytes come before the archive's central directory"
            )
        if reached < directory_start:
            raise _not_a_zip(
                f"{directory_start - reached} bytes lie between zip entry "
                f"{previous.orig_filename!r} and the central directory"
            )
        raise _not_a_zip(
            f"zip entry {previous.orig_filename!r} runs into the central directory"
        )
    return records


def _misplaced(
    previous: Optional[zipfile.ZipInfo], info: zipfile.ZipInfo, reached: int
) -> SourceArchiveRefused:
    """The refusal of a local record that does not start at ``reached``."""
    if previous is None:
        return _not_a_zip(
            f"{info.header_offset} bytes come before the archive's first member"
        )
    if info.header_offset > reached:
        return _not_a_zip(
            f"{info.header_offset - reached} bytes lie between zip entries "
            f"{previous.orig_filename!r} and {info.orig_filename!r}"
        )
    return _not_a_zip(
        f"zip entries {previous.orig_filename!r} and {info.orig_filename!r} overlap"
    )


def _local_record_end(
    handle: IO[bytes], info: zipfile.ZipInfo, boundary: int, spelled: bytes
) -> Tuple[int, _LocalRecord]:
    """Where the local record of ``info`` ends, and what it gives later rules.

    The record is its header, name, extra field and data, as long as the central
    directory says; then, when the member has a data descriptor, the bytes up to
    ``boundary``, where the next record or the central directory starts, which have to
    be that descriptor. The local header has to agree with the central directory on
    what names the member, what places its data and says how to read it: the name, in
    the bytes ``spelled`` and with the flag that says how they are decoded, the method,
    the data descriptor flag and, without a descriptor, the CRC-32 and sizes. A reader
    that walks the local headers extracts each member under the name it finds there.
    """
    offset = info.header_offset
    header = _read_at(handle, offset, _LOCAL_HEADER.size)
    if len(header) < _LOCAL_HEADER.size or not header.startswith(
        _LOCAL_HEADER_SIGNATURE
    ):
        raise _not_a_zip(
            f"zip entry {info.orig_filename!r} has no local header at byte {offset}"
        )
    (_, _, flags, method, _, _, crc, compressed, size, name_length, extra_length) = (
        _LOCAL_HEADER.unpack(header)
    )
    name_at = offset + _LOCAL_HEADER.size
    extra_at = name_at + name_length
    extra = _read_at(handle, extra_at, extra_length)
    data_at = extra_at + extra_length
    data_end = data_at + info.compress_size
    record = _LocalRecord(extra, data_at)
    descriptor = bool(info.flag_bits & _DATA_DESCRIPTOR_FLAG)
    compared = [
        ("compression method", method, info.compress_type),
        ("data descriptor flag", bool(flags & _DATA_DESCRIPTOR_FLAG), descriptor),
        ("name", _read_at(handle, name_at, name_length), spelled),
        (
            "UTF-8 name flag",
            bool(flags & _UTF8_NAME_FLAG),
            bool(info.flag_bits & _UTF8_NAME_FLAG),
        ),
    ]
    if not descriptor:
        compressed, size = _local_zip64_sizes(info, extra, compressed, size)
        compared.append(("CRC-32", crc, info.CRC))
        compared.append(
            ("size", (compressed, size), (info.compress_size, info.file_size))
        )
    for what, local, central in compared:
        if local != central:
            raise _not_a_zip(
                f"the local header of zip entry {info.orig_filename!r} gives another "
                f"{what} than the central directory"
            )
    if not descriptor or data_end > boundary:
        return data_end, record
    between = boundary - data_end
    if between <= _LONGEST_DATA_DESCRIPTOR and _restates(
        _read_at(handle, data_end, between), info
    ):
        return boundary, record
    raise _not_a_zip(
        f"zip entry {info.orig_filename!r} is not followed by a data descriptor "
        "that restates its CRC-32 and sizes"
    )


def _local_zip64_sizes(
    info: zipfile.ZipInfo, extra: bytes, compressed: int, size: int
) -> Tuple[int, int]:
    """A local header's compressed size and size, from its zip64 block where marked.

    A local zip64 block gives the size and then the compressed size, eight bytes each,
    for those of the two the header marks; a marker the block does not resolve stays,
    and fails the comparison with the central directory.
    """
    if _ZIP64_SIZE_MARKER not in (compressed, size):
        return compressed, size
    for data in _extra_blocks(info, extra, _ZIP64_EXTRA, _LOCAL_HEADER_ITSELF):
        values = [
            value for (value,) in struct.iter_unpack("<Q", data[: len(data) // 8 * 8])
        ]
        if size == _ZIP64_SIZE_MARKER and values:
            size = values.pop(0)
        if compressed == _ZIP64_SIZE_MARKER and values:
            compressed = values.pop(0)
        break
    return compressed, size


def _restates(between: bytes, info: zipfile.ZipInfo) -> bool:
    """Whether ``between`` is a data descriptor restating the member's CRC-32 and sizes.

    With its signature or without, and in four-byte or eight-byte sizes: the bytes have
    to be one of those four whole, with nothing before or after.
    """
    expected = (info.CRC, info.compress_size, info.file_size)
    bodies = [between]
    if between.startswith(_DATA_DESCRIPTOR_SIGNATURE):
        bodies.append(between[len(_DATA_DESCRIPTOR_SIGNATURE) :])
    return any(
        len(body) == layout.size and layout.unpack(body) == expected
        for body in bodies
        for layout in _DATA_DESCRIPTOR_BODIES
    )


def _extra_blocks(
    info: zipfile.ZipInfo, extra: bytes, header_id: int, where: str
) -> Iterator[bytes]:
    """The data of each block of the extra field ``extra`` with ID ``header_id``.

    Fewer than four bytes left end the field, as zipfile reads it. A block that claims
    more data than is left is refused: zipfile refuses one in a central directory entry
    as it opens the archive, and reads no local header's extra field at all.
    """
    at = 0
    while len(extra) - at >= _EXTRA_BLOCK_HEAD.size:
        kind, length = _EXTRA_BLOCK_HEAD.unpack_from(extra, at)
        data_at = at + _EXTRA_BLOCK_HEAD.size
        if data_at + length > len(extra):
            raise _not_a_zip(
                f"{where} of zip entry {info.orig_filename!r} holds a corrupt extra "
                "field"
            )
        if kind == header_id:
            yield extra[data_at : data_at + length]
        at = data_at + length


def _refuse_a_second_name(
    info: zipfile.ZipInfo, spelled: bytes, local_extra: bytes
) -> Optional[str]:
    """Refuse ``info`` when a Unicode path field gives it a name that is not its own.

    ``spelled`` is the member's name in the bytes the archive spells it with, and
    ``local_extra`` its local header's extra field. Every Unicode path field in the
    central directory entry and in the local header is read, whatever its version and
    CRC-32 say, and has to restate the name: give the UTF-8 reading of ``spelled``,
    as Info-ZIP writes a name outside ASCII without the UTF-8 flag.

    Returns that reading when the member has a field, for rule 2 to judge as well, and
    None when it has none.
    """
    restated: Optional[str]
    try:
        restated = spelled.decode("utf-8")
    except UnicodeDecodeError:
        restated = None
    given = False
    for where, extra in (
        (_CENTRAL_DIRECTORY_ENTRY, info.extra),
        (_LOCAL_HEADER_ITSELF, local_extra),
    ):
        for named in _unicode_path_names(info, extra, where):
            given = True
            if named != restated:
                source = (
                    "its Unicode path field"
                    if where == _CENTRAL_DIRECTORY_ENTRY
                    else "the Unicode path field of its local header"
                )
                raise SourceArchiveRefused(
                    SourceArchiveRefusal.UNICODE_PATH_MISMATCH,
                    f"zip entry {info.orig_filename!r} is named {named!r} by {source}: "
                    "the field names another file",
                )
    return restated if given else None


def _unicode_path_names(
    info: zipfile.ZipInfo, extra: bytes, where: str
) -> Iterator[str]:
    """The names the Unicode path fields in the extra field ``extra`` give, in order.

    A field is a version byte, a CRC-32 and the name in UTF-8. One too short for the
    first two, or whose name is not UTF-8, is refused; in a central directory entry in
    the words zipfile from Python 3.12 refuses it with as it opens the archive, so that
    every Python gives one verdict for it.
    """
    for data in _extra_blocks(info, extra, _UNICODE_PATH_EXTRA, where):
        if len(data) < _UNICODE_PATH_HEAD:
            raise _corrupt_unicode_path(info, where, "")
        try:
            named = data[_UNICODE_PATH_HEAD:].decode("utf-8")
        except UnicodeDecodeError:
            raise _corrupt_unicode_path(info, where, ": invalid utf-8 bytes") from None
        yield named


def _corrupt_unicode_path(
    info: zipfile.ZipInfo, where: str, detail: str
) -> SourceArchiveRefused:
    if where == _CENTRAL_DIRECTORY_ENTRY:
        return _not_a_zip(f"Corrupt unicode path extra field (0x7075){detail}")
    return _not_a_zip(
        f"{where} of zip entry {info.orig_filename!r} holds a corrupt Unicode path "
        f"field (0x7075){detail}"
    )


#: What a path-collision refusal adds when its two names are one path only because the
#: platform folds names (rule 4): they are not spelled alike.
_FOLDED_NAMES_NOTE = (
    " (names that differ only in case or in Unicode normalization are one path "
    "on this platform)"
)


def _names_fold_together() -> bool:
    """Whether rule 4 compares paths by case and Unicode normalization, not as spelled.

    NTFS (Windows) keeps one file for names that differ only in case, and APFS (macOS,
    as it is set up by default) for names that differ in case or in Unicode
    normalization; the filesystems of Linux and the other Unix systems keep two. Both
    platforms get the same fold, since a source tree has no use for two names that
    differ in nothing else. Rule 4 asks here, and nowhere else, so that a test can say
    what another platform would.
    """
    return _ON_WINDOWS or sys.platform == "darwin"


def _path_key(name: str, folded: bool) -> str:
    """The key by which rule 4 sorts and compares the path of the member ``name``.

    The name less a directory's trailing ``/``, after NFC normalization and case
    folding when ``folded``, with each ``/`` read as the lowest character (an admitted
    name holds no NUL, and neither step makes one or a ``/``).
    """
    path = name.removesuffix("/")
    if folded:
        path = unicodedata.normalize("NFC", path).casefold()
    return path.replace("/", "\x00")


def _folded_note(holder: str, other: str, *, under: bool) -> str:
    """The note a collision needs when only folding makes ``other`` meet ``holder``.

    ``other`` meets ``holder`` as spelled when it is the same path, or, when ``under``,
    a path under it; then there is nothing to add.
    """
    exact_holder = _path_key(holder, folded=False)
    exact_other = _path_key(other, folded=False)
    if under:
        spelled_alike = exact_other.startswith(exact_holder + "\x00")
    else:
        spelled_alike = exact_other == exact_holder
    return "" if spelled_alike else _FOLDED_NAMES_NOTE


def _refuse_shared_paths(members: List[zipfile.ZipInfo]) -> None:
    """Refuse two members extracted to one path, and a member under a file.

    A member's path is the name zipfile extracts it under, less a directory's
    trailing ``/``; the name rules leave zipfile nothing else to rewrite in it. Where
    the platform's filesystems keep one file for names that differ only in case, or
    in Unicode normalization too (:func:`_names_fold_together`), paths are compared
    after NFC normalization and case folding, so ``app.py`` and ``APP.py`` are one
    path there and two on Linux.

    Sorted with each ``/`` read as the lowest character (an admitted name holds no
    NUL), a path is followed at once by its duplicates and then by the paths under
    it, so comparing each path with the next one finds every case in one pass; the key
    is a function of the path alone, so folding it changes nothing about that.
    """
    folded = _names_fold_together()
    order = sorted(
        (_path_key(info.filename, folded), position)
        for position, info in enumerate(members)
    )
    for (path, earlier), (following, later) in zip(order, order[1:]):
        holder = members[earlier].filename
        other = members[later].filename
        if following == path:
            raise SourceArchiveRefused(
                SourceArchiveRefusal.PATH_COLLISION,
                f"zip entries {holder!r} and {other!r} are extracted to one path"
                f"{_folded_note(holder, other, under=False)}",
            )
        if following.startswith(path + "\x00") and not holder.endswith("/"):
            raise SourceArchiveRefused(
                SourceArchiveRefusal.PATH_COLLISION,
                f"zip entry {other!r} is under {holder!r}, "
                "which the archive holds as a file"
                f"{_folded_note(holder, other, under=True)}",
            )


def _refuse_data_that_is_not_its_size(
    handle: IO[bytes], members: List[zipfile.ZipInfo], records: List[_LocalRecord]
) -> None:
    """Refuse a member whose data is not as long as the size it declares (rule 9).

    A stored member's data is its size. A deflated member is inflated here, and its
    stream has to end at its size and be the whole of its compressed data
    (:func:`_refuse_a_stream_off_its_size`); rule 8 left no other method. zipfile cuts
    a member at the size it declares and checks the CRC-32 of what it returned, so data
    past that size is invisible to it, while a reader that takes the member's whole
    data, as ``zipimport`` and ``python app.zip`` do, gets all of it.

    Last of the rules, so that every cheaper one decides first: the total of the sizes
    declared has been held to the limit by now, and that is all of the output this makes.
    """
    for info, record in zip(members, records):
        if info.compress_type == zipfile.ZIP_STORED:
            if info.compress_size != info.file_size:
                raise _not_a_zip(
                    f"zip entry {info.orig_filename!r} holds {info.compress_size} "
                    f"bytes of stored data and declares a size of {info.file_size} "
                    "bytes"
                )
        elif info.compress_size or info.file_size:
            _refuse_a_stream_off_its_size(handle, info, record.data_at)


def _refuse_a_stream_off_its_size(
    handle: IO[bytes], info: zipfile.ZipInfo, data_at: int
) -> None:
    """Refuse a deflated member whose stream does not end exactly at its size.

    Inflates the member's compressed data, ``info.compress_size`` bytes from
    ``data_at``, in steps: at most ``_INFLATE_STEP_BYTES`` of it are read at a time, and
    no call makes more than that of output, or more than one byte past the size the
    member declares, where it is refused. Memory stays at the step, and the work at the
    size declared, however far the stream could expand. What is made is counted and
    dropped.

    The stream has to end, at the size declared, and to be the whole of the compressed
    data: bytes after it are refused, since zipfile never reads them and a reader of
    the whole data would. A stream zlib cannot read is refused as an unreadable
    member, in the words extraction used for it.
    """
    name = info.orig_filename
    declared = info.file_size
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    produced = fed = 0
    pending = b""
    try:
        while not inflater.eof:
            if not pending and fed < info.compress_size:
                pending = _read_at(
                    handle,
                    data_at + fed,
                    min(_INFLATE_STEP_BYTES, info.compress_size - fed),
                )
                if not pending:
                    raise _stream_does_not_end(name, info.compress_size)
                fed += len(pending)
            offered = len(pending)
            # A call allowed no limit on its output (max_length 0) is the one thing
            # this bound must never make: the step is at least 1 whatever is left.
            made = inflater.decompress(
                pending, min(_INFLATE_STEP_BYTES, declared - produced + 1)
            )
            pending = inflater.unconsumed_tail
            produced += len(made)
            if produced > declared:
                raise _not_a_zip(
                    f"zip entry {name!r} inflates to more than the {declared} bytes "
                    "it declares"
                )
            if not made and len(pending) >= offered and not inflater.eof:
                # Nothing taken in and nothing made, with all of the data given: the
                # stream waits for bytes the member does not hold.
                raise _stream_does_not_end(name, info.compress_size)
    except zlib.error as error:
        raise _unreadable(f"zip entry {name!r}", error) from error
    if produced < declared:
        raise _not_a_zip(
            f"zip entry {name!r} inflates to {produced} bytes and declares {declared}"
        )
    left = info.compress_size - fed + len(inflater.unused_data)
    if left:
        raise _not_a_zip(
            f"zip entry {name!r} holds {left} bytes of compressed data after the end "
            "of its stream"
        )


def _stream_does_not_end(name: str, compress_size: int) -> SourceArchiveRefused:
    return _not_a_zip(
        f"zip entry {name!r} holds a compressed stream that does not end within its "
        f"{compress_size} bytes of data"
    )


def _link_refused(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, rules: ZipRules
) -> SourceArchiveRefused:
    """The refusal of link ``info``, quoting at most the first bytes of its target.

    A link member's content is whatever the archive says, up to the uncompressed
    total, and the refusal text is carried through every pass the error path makes
    over it, so only the head is read and shown. This is the one read of a member's
    data that admission makes: what zipfile raises for it is about the archive, and
    is refused as unreadable, as it is wherever else the archive is read.
    """
    with _zipfile_errors_refused("the archive"), archive.open(info) as member:
        head = member.read(rules.symlink_excerpt_bytes + 1)
    target = head[: rules.symlink_excerpt_bytes].decode("utf-8", errors="replace")
    if len(head) > rules.symlink_excerpt_bytes:
        target += "..."
    return SourceArchiveRefused(
        SourceArchiveRefusal.SYMLINK_MEMBER,
        f"symlink {info.filename!r} -> {target!r}: "
        f"symlinks are not allowed in {rules.archives}",
    )


def open_zip(handle: IO[bytes]) -> zipfile.ZipFile:
    """Open the zip that ``handle`` reads, or refuse it.

    What zipfile raises as it opens a file is about the archive, so both entry points
    refuse it here, in the same words. Bytes it does not open as a zip are refused as
    not a zip, in zipfile's own words; the refusal is a ``zipfile.BadZipFile`` as
    well. Anything else, such as a central directory entry that needs a newer reader
    than zipfile implements, is refused as unreadable ("the archive cannot be read:
    ..."). An ``OSError`` and a ``MemoryError`` are raised as they are.

    One rule is decided before zipfile reads the file: that a zip64 end record is where
    its locator places it (:func:`_refuse_a_misplaced_zip64_record`). Some zipfile
    releases refuse a locator that misplaces it as they open the archive, in words
    that are not the rule's, and others admit it, so the rule runs first and gives
    one verdict, in one set of words, whichever zipfile reads the file.

    Raises:
        SourceArchiveRefused: the archive was refused; ``kind`` names the rule.
    """
    try:
        _refuse_a_misplaced_zip64_record(handle)
        return zipfile.ZipFile(handle)
    except _NOT_THE_ARCHIVES:
        raise
    except SourceArchiveRefused:
        raise
    except (zipfile.BadZipFile, EOFError, ValueError) as error:
        raise _not_a_zip(str(error)) from error
    except Exception as error:
        # "zip file version 6.4": a central directory entry that needs a newer
        # reader than zipfile, which checks the version as it opens the archive.
        raise _unreadable("the archive", error) from error


def extract_zip_members(
    archive: zipfile.ZipFile,
    destination: Path,
    rules: Optional[ZipRules] = None,
) -> None:
    """Extract every member of an open ``archive`` into ``destination``, once admitted.

    For a caller that holds the archive open already, as the MCP finalize does: the
    members are admitted (:func:`admit_zip_members`, under ``rules``) and then
    extracted one at a time, so that a failure names its member.

    Raises:
        SourceArchiveRefused: a rule refused the archive, and nothing was written; or
            zipfile could not read a member, as extraction reached it, after the
            members before it were written. Every ``OSError`` and ``MemoryError`` is
            raised as it is: the caller decides what it means.
    """
    _extract_members(archive, destination, admit_zip_members(archive, rules))


def _extract_members(
    archive: zipfile.ZipFile, destination: Path, members: List[zipfile.ZipInfo]
) -> None:
    """Extract the admitted ``members`` one at a time, so a failure names its member."""
    for info in members:
        with _zipfile_errors_refused(f"zip entry {info.filename!r}"):
            archive.extractall(destination, [info])


def extract_source_archive(archive: Path, destination: Path) -> Path:
    """Extract the zip at ``archive`` into ``destination``, and return ``destination``.

    ``destination`` is made when it does not exist, and has to be an empty directory
    when it does. The archive is held to every rule of this module with its default
    limits, and ``archive`` has to be a regular file this function can read, since it
    opens the file itself.

    The file is read once, into memory, and zipfile reads that copy, so whatever
    zipfile raises while it reads is the archive's: a member it cannot read (damaged
    data, or a zip version it does not implement) is a ``SourceArchiveRefused``
    whatever exception zipfile raised for it, as it is for the MCP finalize.

    Every rule but the last is decided before anything is written, so a refused
    archive leaves ``destination`` as it was, not made if it did not exist. A member
    zipfile cannot read is refused when extraction reaches it, after the members
    before it were written, and an ``OSError`` can stop the extraction partway too.
    The caller owns ``destination`` and removes it on any failure.

    Raises:
        SourceArchiveRefused: the archive was refused; ``kind`` names the rule.
        OSError: ``destination`` exists and is not an empty directory, or cannot be
            made or written, or the archive could not be read from the disk.
    """
    destination = Path(destination)
    data = _read_archive(Path(archive))
    with open_zip(io.BytesIO(data)) as opened:
        members = admit_zip_members(opened)
        _make_empty_directory(destination)
        _extract_members(opened, destination, members)
    return destination


def _unreadable(what: str, error: Exception) -> SourceArchiveRefused:
    """The refusal of an archive zipfile could not read ``what`` of."""
    return SourceArchiveRefused(
        SourceArchiveRefusal.UNREADABLE_MEMBER,
        f"{what} cannot be read: {str(error) or type(error).__name__}",
    )


@contextlib.contextmanager
def _zipfile_errors_refused(what: str) -> Iterator[None]:
    """Refuse the archive for what zipfile raises in the block, which reads ``what``.

    The one classification of zipfile's exceptions that is not at its open. Every
    exception zipfile raises there is about the archive, but two: an ``OSError``,
    which is the destination's or the disk's, and a ``MemoryError``, which is the
    process's, pass as they were raised, as does a refusal already made.
    """
    try:
        yield
    except SourceArchiveRefused:
        raise
    except _NOT_THE_ARCHIVES:
        raise
    except Exception as error:
        raise _unreadable(what, error) from error


def _read_archive(archive: Path) -> bytes:
    """The bytes of the zip at ``archive``, refused past ``MAX_ARCHIVE_BYTES``.

    Measured before the read, so an archive over the limit is refused without being
    read, and read one byte past the limit, so a file that holds more than it
    measured (it grew in between, or it is a file the kernel reports as empty) is
    refused rather than read whole.
    """
    with _opened_regular_file(archive) as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > MAX_ARCHIVE_BYTES:
            raise archive_too_large(size, MAX_ARCHIVE_BYTES)
        data = handle.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            size = max(os.fstat(handle.fileno()).st_size, len(data))
            raise archive_too_large(size, MAX_ARCHIVE_BYTES)
    return data


def _open_without_waiting(path: str, _flags: int) -> int:
    """``open``'s opener: ``path`` as a read-only descriptor that waits for no writer.

    A FIFO opened for reading blocks until something opens it for writing. With
    O_NONBLOCK the open returns, and the check of the descriptor refuses what is not a
    regular file; a regular file is read the same with or without the flag. The flags
    ``open`` offers are not used: this is the read-only open, and ``os.open`` makes
    the descriptor non-inheritable.
    """
    return os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    )


@contextlib.contextmanager
def _opened_regular_file(archive: Path) -> Iterator[IO[bytes]]:
    """``archive`` opened for reading, refused unless it is a regular file.

    The path is checked before it is opened, so a FIFO is refused rather than waited
    on, and the open handle again, so the file read is the file checked. The open does
    not wait either (:func:`_open_without_waiting`): a FIFO put at the path after the
    first check is opened without blocking, and the second check refuses it.
    """
    shown = os.fspath(archive)
    try:
        found = os.stat(archive)
    except ValueError as error:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.UNREADABLE_ARCHIVE,
            f"{shown!r} is not a valid path: {error}",
        ) from error
    except OSError as error:
        raise _unreadable_path(shown, error) from error
    if not stat.S_ISREG(found.st_mode):
        raise _not_a_file(shown)
    try:
        handle = open(shown, "rb", opener=_open_without_waiting)
    except OSError as error:
        raise _unreadable_path(shown, error) from error
    with handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise _not_a_file(shown)
        yield handle


def _unreadable_path(shown: str, error: OSError) -> SourceArchiveRefused:
    return SourceArchiveRefused(
        SourceArchiveRefusal.UNREADABLE_ARCHIVE,
        f"{shown!r} cannot be read: {error.strerror or error}",
    )


def _not_a_file(shown: str) -> SourceArchiveRefused:
    return SourceArchiveRefused(
        SourceArchiveRefusal.NOT_A_FILE, f"{shown!r} is not a regular file"
    )


def _refuse_encrypted_members(members: List[zipfile.ZipInfo]) -> None:
    """Refuse an archive that holds an encrypted member (rule 7).

    Decided from the flags the central directory gives each member, so it reads no
    data, and a link is refused for it as any other member is.
    """
    for info in members:
        if info.flag_bits & _ENCRYPTED_FLAG:
            raise SourceArchiveRefused(
                SourceArchiveRefusal.ENCRYPTED_MEMBER,
                f"zip entry {info.filename!r} is encrypted: an encrypted member "
                "cannot be read",
            )


def _refuse_unsupported_methods(members: List[zipfile.ZipInfo]) -> None:
    """Refuse a member compressed with any method but stored or deflated (rule 8).

    Decided from the method the central directory gives each member, so it reads no
    data, and a link is refused for it as any other member is. Whatever size the
    member declares: zipfile hands a bzip2, LZMA or Zstandard member's data to a
    decompressor with no limit on its output, and cuts what it returns to the declared
    size only afterwards, so a few kilobytes can ask for gigabytes of memory.
    """
    for info in members:
        method = info.compress_type
        if method not in _ADMITTED_METHODS:
            named = _METHOD_NAMES.get(method)
            how = f"{named} (method {method})" if named else f"method {method}"
            raise SourceArchiveRefused(
                SourceArchiveRefusal.UNSUPPORTED_COMPRESSION,
                f"zip entry {info.orig_filename!r} is compressed with {how}: only "
                "stored and deflated members are read",
            )


def _make_empty_directory(destination: Path) -> None:
    """Make ``destination``, or check that the directory there is empty.

    A tree already there would be scanned with the archive's, as if the archive held
    it, so anything in it refuses the extraction.
    """
    destination.mkdir(exist_ok=True)
    with os.scandir(destination) as entries:
        if next(entries, None) is not None:
            raise OSError(
                errno.ENOTEMPTY,
                "the destination directory is not empty",
                os.fspath(destination),
            )
