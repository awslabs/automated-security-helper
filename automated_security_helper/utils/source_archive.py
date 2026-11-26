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
a Unicode path field that renames a member, and two members on one path (below).

What is refused
---------------
Every rule is decided from the archive's central directory before anything is
written, so a refused archive leaves the destination as it was.

1. Size. At most 100 MiB of archive, 500 MiB of members once uncompressed, and
   50,000 members, directories included. The uncompressed total is the sum of the
   sizes the members declare, which also bounds what extraction writes: zipfile
   stops reading a member at its declared size.
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
3. A second name. A member can carry a Unicode path field (extra field 0x7075), and
   zipfile, from Python 3.12, extracts the member under the name in it rather than
   the one the archive spells, while readers that ignore the field, ``zipimport``
   among them, keep the spelled one. The field is admitted only when it restates the
   name: the UTF-8 reading of the bytes the archive spells the name with, which is
   what Info-ZIP writes for a name outside ASCII. One that names another file is
   refused, so a member spelled ``app.py`` is not scanned as ``app.txt``, and the
   name an admitted field gives is judged by rule 2 too.
4. One path for each member. Two members extracted to one path are refused,
   whatever each is (two members of one name, a file and a directory), and so is a
   member under a path the archive holds as a file. zipfile writes the later of two
   members over the earlier, so the tree scanned would hold one of two files, while
   a reader that looks members up by name, as ``zipimport`` and ``python app.zip``
   do, can run the other.
5. Links. Every symbolic link is refused, wherever it points. Resolving a target
   before extraction races the extraction (an earlier member can make the directory
   a later link's path runs through), and a source tree needs none. The refusal
   quotes at most the first 256 bytes of the target.

A malformed member is refused, never repaired: an archive that has to be rewritten to
be safe is not the tree its sender meant to send.

Formats
-------
Zip only. A tar, a gzip file or anything else is refused as not a zip. Nothing
sniffs the content to decide what an archive holds, because the command names it:
``ash scan fs --archive`` reads source, and ``ash scan image --archive`` reads an
image tarball. A tar reader would need member rules of its own (hard links, devices,
sparse members) before it could be admitted here.

Entry points
------------
* ``extract_source_archive(archive, destination)`` reads the zip at a path, for
  ``ash scan fs --archive``. Besides the rules above it refuses a path that is not a
  regular file or cannot be read, an encrypted member, and a member zipfile cannot
  read back whole: damaged data, a compression method or zip version it does not
  implement, a method whose module this Python was built without. It reads the file
  once, into memory, and zipfile reads that copy, so nothing zipfile raises is about
  the disk. Every problem with the archive is a ``SourceArchiveRefused``; an
  ``OSError`` is a problem with the destination or the disk.
* ``extract_zip_members(archive, destination, rules)`` extracts an archive its caller
  holds open. The MCP finalize hashes an upload before extracting it, and has to
  extract the bytes it hashed, so it passes the handle it read, with its own limits
  (``ZipRules``). ``admit_zip_members`` is the checking half of it.

A refusal is a ``SourceArchiveRefused``, a ``ValueError`` whose ``kind``
(``SourceArchiveRefusal``) names the rule. Import this module where an archive is
read, not at the top of a CLI module, so ``ash --version`` and ``ash scan --help``
do not load it.

Limits
------
* Rule 4 compares names as the archive spells them. Names that differ only in case
  are one file on a filesystem that ignores case, and names that differ only in
  Unicode normalization are one on a filesystem that normalizes them. There zipfile
  writes the later of two files over the earlier, and a file and a directory end the
  extraction with the ``OSError`` the filesystem raises.
* A member whose data is damaged is found when extraction reaches it, after the
  members before it were written. The caller removes the destination on any failure.
* A damaged bzip2 stream reaches the caller as the ``OSError`` Python raises for it,
  which nothing tells apart from a disk error.
* A Unicode path field that restates its name from a legacy code page rather than
  from UTF-8 bytes (Info-ZIP under a locale that is not UTF-8, for a name outside
  ASCII) is refused as naming another file.
* zipfile before Python 3.12 ignores the Unicode path field and extracts every member
  under the name the archive spells, so rule 3 has nothing to refuse there.
"""

from __future__ import annotations

import contextlib
import errno
import io
import os
import stat
import zipfile
from dataclasses import dataclass
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
#: Bit 11 of a member's general purpose flags: its name is spelled in UTF-8.
_UTF8_NAME_FLAG = 0x800

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

#: What ``extract_source_archive`` lets pass from zipfile as it was raised. zipfile
#: reads the archive from memory there, so every other exception it raises is about
#: the archive. An OSError is the destination's, since extraction writes there, or a
#: damaged bzip2 stream's (see Limits); a MemoryError is the process's.
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
    # Only extract_source_archive refuses for these four: it opens the file and
    # reads every member's data itself.
    NOT_A_FILE = "not-a-file"
    UNREADABLE_ARCHIVE = "unreadable-archive"
    ENCRYPTED_MEMBER = "encrypted-member"
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

    The defaults are the source-archive limits. The MCP finalize builds its own each
    time it runs, from its module's names, so a limit set there is the one applied.
    """

    max_members: int = MAX_MEMBERS
    max_extracted_bytes: int = MAX_EXTRACTED_BYTES
    #: Given each member's name as the archive spells it, and then the name zipfile
    #: extracts it under when a Unicode path field gives another; raises to refuse.
    validate_name: Callable[[str], None] = validate_member_name
    symlink_excerpt_bytes: int = SYMLINK_TARGET_EXCERPT_BYTES
    #: The archives the link refusal names: "symlinks are not allowed in <archives>".
    archives: str = SOURCE_ARCHIVES


#: The rules ``extract_source_archive`` applies.
SOURCE_ARCHIVE_RULES = ZipRules()


def admit_zip_members(
    archive: zipfile.ZipFile, rules: ZipRules = SOURCE_ARCHIVE_RULES
) -> List[zipfile.ZipInfo]:
    """Return every member of ``archive`` when ``rules`` admit them all.

    Writes nothing. Reads the central directory and, for a link, the first bytes of
    its target. The member count is checked first; then, for each member in archive
    order, its name, the name zipfile extracts it under when a Unicode path field
    gives another, the uncompressed total so far, and whether it is a link; then that
    no two members are extracted to one path. The first rule that refuses ends the
    check.

    Raises:
        SourceArchiveRefused: naming the rule. Whatever ``rules.validate_name`` and
            zipfile raise is raised as it is.
    """
    members = archive.infolist()
    if len(members) > rules.max_members:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.TOO_MANY_MEMBERS,
            f"too many files in zip: {len(members)} > {rules.max_members}",
        )
    total = 0
    for info in members:
        rules.validate_name(info.orig_filename)
        if info.filename != info.orig_filename:
            _refuse_a_second_name(archive, info)
            rules.validate_name(info.filename)
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
    return members


def _refuse_a_second_name(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    """Refuse ``info`` when the name zipfile extracts it under is not its own.

    The name rules refuse a NUL and a backslash, the two things zipfile rewrites in a
    spelled name, so the names differ only by a Unicode path field. The field restates
    the name when it is the UTF-8 reading of the bytes the archive spells the name
    with, as Info-ZIP writes a name outside ASCII without the UTF-8 flag. zipfile
    decoded those bytes with the flag's encoding, or the archive's metadata encoding
    (cp437 unless the caller named one), so encoding the spelled name again gives
    them back.
    """
    if info.flag_bits & _UTF8_NAME_FLAG:
        encoding = "utf-8"
    else:
        # getattr: zipfile keeps the argument as this attribute, which the type
        # stubs know only as a constructor argument.
        encoding = getattr(archive, "metadata_encoding", None) or "cp437"
    restated: Optional[str]
    try:
        restated = info.orig_filename.encode(encoding).decode("utf-8")
    except UnicodeError:
        restated = None
    if info.filename != restated:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.UNICODE_PATH_MISMATCH,
            f"zip entry {info.orig_filename!r} is extracted as {info.filename!r}: "
            "its Unicode path field names another file",
        )


def _refuse_shared_paths(members: List[zipfile.ZipInfo]) -> None:
    """Refuse two members extracted to one path, and a member under a file.

    A member's path is the name zipfile extracts it under, less a directory's
    trailing ``/``; the name rules leave zipfile nothing else to rewrite in it.
    Sorted with each ``/`` read as the lowest character (an admitted name holds no
    NUL), a path is followed at once by its duplicates and then by the paths under
    it, so comparing each path with the next one finds every case in one pass.
    """
    order = sorted(
        (info.filename.removesuffix("/").replace("/", "\x00"), position)
        for position, info in enumerate(members)
    )
    for (path, earlier), (following, later) in zip(order, order[1:]):
        if following == path:
            raise SourceArchiveRefused(
                SourceArchiveRefusal.PATH_COLLISION,
                f"zip entries {members[earlier].filename!r} and "
                f"{members[later].filename!r} are extracted to one path",
            )
        holder = members[earlier].filename
        if following.startswith(path + "\x00") and not holder.endswith("/"):
            raise SourceArchiveRefused(
                SourceArchiveRefusal.PATH_COLLISION,
                f"zip entry {members[later].filename!r} is under {holder!r}, "
                "which the archive holds as a file",
            )


def _link_refused(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, rules: ZipRules
) -> SourceArchiveRefused:
    """The refusal of link ``info``, quoting at most the first bytes of its target.

    A link member's content is whatever the archive says, up to the uncompressed
    total, and the refusal text is carried through every pass the error path makes
    over it, so only the head is read and shown.
    """
    with archive.open(info) as member:
        head = member.read(rules.symlink_excerpt_bytes + 1)
    target = head[: rules.symlink_excerpt_bytes].decode("utf-8", errors="replace")
    if len(head) > rules.symlink_excerpt_bytes:
        target += "..."
    return SourceArchiveRefused(
        SourceArchiveRefusal.SYMLINK_MEMBER,
        f"symlink {info.filename!r} -> {target!r}: "
        f"symlinks are not allowed in {rules.archives}",
    )


def extract_zip_members(
    archive: zipfile.ZipFile,
    destination: Path,
    rules: ZipRules = SOURCE_ARCHIVE_RULES,
) -> None:
    """Extract every member of an open ``archive`` into ``destination``, once admitted.

    For a caller that holds the archive open already, as the MCP finalize does. What
    zipfile raises while it extracts (a damaged or encrypted member) and every
    ``OSError`` are raised as they are: the caller decides what they mean.

    Raises:
        SourceArchiveRefused: a rule refused the archive; nothing was written.
    """
    archive.extractall(destination, admit_zip_members(archive, rules))


def extract_source_archive(archive: Path, destination: Path) -> Path:
    """Extract the zip at ``archive`` into ``destination``, and return ``destination``.

    ``destination`` is made when it does not exist, and has to be an empty directory
    when it does. The archive is held to every rule of this module with its default
    limits, and to three more, since this function opens and extracts the file
    itself: ``archive`` must be a regular file it can read, no member may be
    encrypted, and zipfile must read every member's data back whole.

    The file is read once, into memory, and zipfile reads that copy, so whatever
    zipfile raises while it reads is the archive's: a member it cannot read (damaged
    data, a compression method or zip version it does not implement, a method whose
    module this Python lacks) is a ``SourceArchiveRefused`` whatever exception zipfile
    raised for it.

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
    try:
        opened = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError, ValueError) as error:
        raise SourceArchiveRefused(
            SourceArchiveRefusal.NOT_A_ZIP, str(error)
        ) from error
    except _NOT_THE_ARCHIVES:
        raise
    except Exception as error:
        # "zip file version 6.4": a central directory entry that needs a newer
        # reader than zipfile, which checks the version as it opens the archive.
        raise _unreadable("the archive", error) from error
    with opened:
        # Before the shared rules: the link rule reads a link's data, which an
        # encrypted member does not give up.
        _refuse_encrypted_members(opened)
        try:
            members = admit_zip_members(opened)
        except SourceArchiveRefused:
            raise
        except _NOT_THE_ARCHIVES:
            raise
        except Exception as error:
            raise _unreadable("the archive", error) from error
        _make_empty_directory(destination)
        for info in members:
            try:
                opened.extract(info, destination)
            except _NOT_THE_ARCHIVES:
                raise
            except Exception as error:
                raise _unreadable(f"zip entry {info.filename!r}", error) from error
    return destination


def _unreadable(what: str, error: Exception) -> SourceArchiveRefused:
    """The refusal of an archive zipfile could not read ``what`` of."""
    return SourceArchiveRefused(
        SourceArchiveRefusal.UNREADABLE_MEMBER,
        f"{what} cannot be read: {str(error) or type(error).__name__}",
    )


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


@contextlib.contextmanager
def _opened_regular_file(archive: Path) -> Iterator[IO[bytes]]:
    """``archive`` opened for reading, refused unless it is a regular file.

    The path is checked before it is opened, so a FIFO is refused rather than waited
    on, and the open handle again, so the file read is the file checked.
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
        handle = open(archive, "rb")
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


def _refuse_encrypted_members(archive: zipfile.ZipFile) -> None:
    for info in archive.infolist():
        if info.flag_bits & _ENCRYPTED_FLAG:
            raise SourceArchiveRefused(
                SourceArchiveRefusal.ENCRYPTED_MEMBER,
                f"zip entry {info.filename!r} is encrypted: an encrypted member "
                "cannot be read",
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
