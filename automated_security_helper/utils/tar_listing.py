# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tar's listing, read to the end of its bytes.

By default tarfile ends a tar's listing, with no error, at the zero blocks that end
a tar or at a header it cannot read after the first, though the bytes may go on: a
second tar after the first, or members past a damaged header. A reader that goes by
that listing, to extract the tar or to check its members against ignore paths,
misses the members past it. :func:`open_tar_listing` opens a tar so its listing
skips both (``ignore_zeros``) and reaches every header there is, and it records the
byte offset of each header it skipped that was not zeros: the member such a header
named is unknown.

Zero blocks hold nothing, so skipping them loses nothing; a header that cannot be
read is recorded. Every other header error is tarfile's own and is raised as it
raises it. The module uses the standard library only, so a plugin can carry a copy
of it byte for byte.

A tar whose bytes end partway through a block ends in a header tarfile reads as
truncated, and that is recorded too, even when the partial block is all zeros and
held nothing: a tar of 10240 bytes followed by 700 zero bytes records byte 10752.
Telling the two apart would mean reading the tail again, so the listing errs on the
side of calling the tar incomplete.

Reading past the end costs a block at a time, and a compressed tar can hold far
more blocks than its own size: a few hundred bytes of bz2 can decompress to tens of
mebibytes that no header reads. So only the first unreadable header is recorded,
and the listing stops once it has skipped SKIPPED_BYTES_LIMIT bytes of blocks,
zeros or not, and says where it stopped: what lies past that is not listed, which
a caller treats as a tar it has not read whole.

That limit is per listing, so a caller that lists many tars, such as one run's
archive converter, also gives them a shared SkippedBlocksBudget: past a tar's
ordinary end (ORDINARY_END_BYTES), each block a listing skips is charged to it,
and once it is spent a listing stops at the first block it is charged for. A
thousand tars of a few hundred bytes each then cost what a few do, and an
ordinary tar, whose end is no more than that padding, is charged nothing.
"""

from __future__ import annotations

import tarfile as _tarfile
from tarfile import HeaderError, TarFile, TarInfo
from tarfile import open as open_tar
from typing import IO, Any, List, Optional, Type, cast

#: tarfile's header errors for a block of zeros (EOFHeaderError) and for the end
#: of the bytes (EmptyHeaderError), which lose nothing. tarfile defines both, but
#: its type stubs do not declare them (they are not in tarfile.__all__), so they
#: are looked up by name; a tarfile without them fails here, at import, rather
#: than recording every zero block as unreadable.
_ZERO_BLOCK: Type[HeaderError] = vars(_tarfile)["EOFHeaderError"]
_END_OF_DATA: Type[HeaderError] = vars(_tarfile)["EmptyHeaderError"]

_BLOCK = 512

#: How many bytes of blocks a listing skips, zero blocks and unreadable headers
#: together, before it stops. Far more than the padding a tar writer adds at its
#: end, even with a large blocking factor, and small enough that the listing of
#: any file costs at most a few thousand skipped blocks.
SKIPPED_BYTES_LIMIT = 4 * 1024 * 1024

#: How many bytes of skipped blocks a tar's own end can take and still be
#: ordinary: the two zero blocks that end it and the padding to a whole record
#: (tarfile.RECORDSIZE, the 20 blocks tarfile and GNU tar write by default), with
#: a second record to spare. A listing's skipped blocks up to this many bytes are
#: not charged to a SkippedBlocksBudget.
ORDINARY_END_BYTES = 2 * _tarfile.RECORDSIZE

#: The most members tar_names lists.
MAX_LISTED_MEMBERS = 100_000


class SkippedBlocksBudget:
    """Bytes of skipped blocks that several listings share, past each one's
    ordinary end (ORDINARY_END_BYTES): ``used`` of ``limit``.

    SKIPPED_BYTES_LIMIT bounds one listing; this bounds them together. Once a
    listing has been charged past ``limit``, every listing sharing the budget
    stops at the first block it is charged for.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    @property
    def spent(self) -> bool:
        """Whether the listings have been charged past ``limit``."""
        return self.used > self.limit


class UnreadableTarHeader(ValueError):
    """A tar header that is not zeros could not be read; ``offset`` is its byte."""

    def __init__(self, offset: int) -> None:
        super().__init__(f"the tar header at byte {offset} could not be read")
        self.offset = offset


class TarListingStopped(ValueError):
    """The listing stopped at byte ``offset``, having skipped SKIPPED_BYTES_LIMIT
    bytes of blocks, so what follows is not listed."""

    def __init__(self, offset: int) -> None:
        super().__init__(
            f"the tar listing stopped at byte {offset}, past more than "
            f"{SKIPPED_BYTES_LIMIT} bytes of blocks it skipped"
        )
        self.offset = offset


class TarCutShort(ValueError):
    """The tar's bytes end at byte ``offset``, right after a member, with no
    end-of-archive zero block: it was cut at a block boundary, and what followed
    the last member listed is unknown."""

    def __init__(self, offset: int) -> None:
        super().__init__(
            f"the tar ends at byte {offset} with no end-of-archive block after its "
            "last member, so it was cut there and what followed is unknown"
        )
        self.offset = offset


class TooManyTarMembers(ValueError):
    """The tar holds more than ``limit`` members."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"it has more than {limit} members, more than are listed")
        self.limit = limit


def open_tar_listing(
    handle: IO[bytes],
    unreadable: List[int],
    stopped: Optional[List[int]] = None,
    budget: Optional[SkippedBlocksBudget] = None,
    mode: str = "r:*",
    ended: Optional[List[int]] = None,
    **options: Any,
) -> TarFile:
    """The tar in ``handle``, compressed or not, opened from its start so that its
    listing reads all of its bytes.

    The listing skips zero blocks and headers it cannot read, so it goes on to a
    second tar after the first and to the members past a damaged header. The first
    header it skips that is not zeros has its byte offset in the tar (in the
    decompressed stream, for a compressed tar) added to ``unreadable``, as the
    listing reaches it. Once it has skipped SKIPPED_BYTES_LIMIT bytes of blocks it
    stops, as at the end of the bytes, and the byte it stopped at is added to
    ``stopped``. With a ``budget`` shared with other listings, each block it skips
    past ORDINARY_END_BYTES is charged to the budget too, and it stops the same way
    at the block that takes the budget past its limit, or at the first one it is
    charged once the budget is spent. Read the whole listing (``getmembers``,
    ``getnames``, or to the end of an iteration) before looking at either list.
    ``options`` go to ``tarfile.open``, such as ``encoding``. ``mode`` is
    tarfile's open mode: the default ``"r:*"`` sniffs the compression by
    reading ahead, so a caller whose ``handle`` is already decompressed and
    read through a byte-budgeted stream passes ``"r:"``, which reads plain
    512-byte blocks and keeps the sniff's read-ahead off its budget.
    With ``ended``, a listing that read at least one member and reached the
    end of the bytes WITHOUT an end-of-archive zero block before it has that
    byte appended: a tar cut exactly at a block boundary presents no damaged
    header and no stop, and this is its one signal. An ordinary end (zero
    blocks before the end, a tar of end blocks only, a concatenated tar whose
    last blocks are zeros) appends nothing.

    Under ``"r:*"`` tarfile tries each compression in turn and reads the first
    header under each, so a listing can begin more than once. The counts, the
    lists and the budget charge belong to one reading of the bytes: each time
    the first header (byte 0) is read again, what the earlier attempt recorded
    is dropped and its budget charge given back, so an attempt tarfile
    abandoned leaves nothing in the result of the one it keeps.

    Raises:
        tarfile.TarError, OSError, EOFError: The tar could not be opened or read.
    """
    skipped = [0]
    charged = [0]
    # A handle that meters its header reads (the archive converter's bounded
    # stream) is credited each skipped block's bytes as the block is
    # classified, so skips are charged to this listing's own budgets and
    # never to the handle's header allowance.
    credit = getattr(handle, "allow_skipped_blocks", None)
    # Whether any member was read, and whether the LAST header event before
    # the current one was a zero block: at the end of the bytes these two
    # tell an ordinary end (zeros, then the end) from a tar cut at a block
    # boundary, which presents no damaged header and no stop. limit_stop is
    # set by the attempt that ended the listing at its limit, so the header
    # that contained that read (a pax or GNU long-name header reads the next
    # header inside its own) does not record the stop as the tar's end.
    read_any = [False]
    last_zero = [False]
    limit_stop = [False]

    def begin_attempt() -> None:
        """Drop what an earlier reading of these bytes recorded."""
        if budget is not None:
            budget.used -= charged[0]
        skipped[0] = 0
        charged[0] = 0
        read_any[0] = False
        last_zero[0] = False
        limit_stop[0] = False
        unreadable.clear()
        if stopped is not None:
            stopped.clear()
        if ended is not None:
            ended.clear()

    class _Recorded(TarInfo):
        @classmethod
        def fromtarfile(cls, tarfile: TarFile) -> _Recorded:
            # Where the header about to be read starts, in the (decompressed) tar.
            offset = tarfile.fileobj.tell()
            if offset == 0:
                begin_attempt()
            try:
                member = super().fromtarfile(tarfile)
            except _END_OF_DATA:
                # The bytes genuinely end here (a limit stop raises its own
                # _END_OF_DATA, flagged, from the read that hit the limit). An
                # end right after a member, with no end-of-archive zero block
                # between, means what followed is unknowable; the byte is
                # recorded for the caller's extracted-in-part row.
                if (
                    ended is not None
                    and not ended
                    and not limit_stop[0]
                    and read_any[0]
                    and not last_zero[0]
                ):
                    ended.append(offset)
                raise
            except HeaderError as error:
                if isinstance(error, _ZERO_BLOCK):
                    last_zero[0] = True
                else:
                    last_zero[0] = False
                    if not unreadable:
                        unreadable.append(offset)
                # The bytes tarfile read for this header before it raised: one
                # block for a plain header, more for a pax or GNU long-name
                # header whose extension it read first. Charged whole, rounded
                # up to blocks, so the limits bound what the listing read.
                consumed = max(_BLOCK, tarfile.fileobj.tell() - offset)
                consumed = -(-consumed // _BLOCK) * _BLOCK
                skipped[0] += consumed
                if credit is not None:
                    credit(consumed)
                over = skipped[0] > SKIPPED_BYTES_LIMIT
                if budget is not None and skipped[0] > ORDINARY_END_BYTES:
                    budget.used += consumed
                    charged[0] += consumed
                    over = over or budget.spent
                if not over:
                    raise
                # tarfile ends a listing at the end of the bytes after the first
                # header, so this ends it here.
                limit_stop[0] = True
                if stopped is not None and not stopped:
                    stopped.append(offset)
                raise _END_OF_DATA("the listing skipped its limit of blocks") from None
            else:
                read_any[0] = True
                last_zero[0] = False
                return member

    handle.seek(0)
    # tarfile.open is overloaded on Literal mode strings; ``mode`` is any mode
    # string the caller passes, so it is handed over untyped.
    return open_tar(
        fileobj=handle,
        mode=cast(Any, mode),
        ignore_zeros=True,
        tarinfo=_Recorded,
        **options,
    )


def tar_names(handle: IO[bytes]) -> List[str]:
    """The member names of the tar in ``handle``, compressed or not, from a listing
    that reads all of its bytes (:func:`open_tar_listing`), at most
    MAX_LISTED_MEMBERS of them.

    Raises:
        UnreadableTarHeader: A header that is not zeros could not be read, so the
            member it named is unknown. It names the first such header's byte.
        TarListingStopped: The listing stopped past SKIPPED_BYTES_LIMIT bytes of
            blocks it skipped, so what follows is unknown.
        TarCutShort: The bytes end right after a member with no end-of-archive
            block, so the tar was cut there and what followed is unknown.
        TooManyTarMembers: The tar holds more than MAX_LISTED_MEMBERS members;
            the listing stops there.
        tarfile.TarError, OSError, EOFError: The listing could not be read.
    """
    unreadable: List[int] = []
    stopped: List[int] = []
    ended: List[int] = []
    names: List[str] = []
    with open_tar_listing(handle, unreadable, stopped, ended=ended) as listing:
        for member in listing:
            if len(names) == MAX_LISTED_MEMBERS:
                raise TooManyTarMembers(MAX_LISTED_MEMBERS)
            names.append(member.name)
    if unreadable:
        raise UnreadableTarHeader(unreadable[0])
    if stopped:
        raise TarListingStopped(stopped[0])
    if ended:
        raise TarCutShort(ended[0])
    return names
