# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive converter extracts a tar to the end of its bytes.

By default tarfile ends a tar's listing, with no error, at a header it cannot read
after the first, or at the zero blocks that end a tar, though the bytes go on: past
a damaged header, or into a second tar after the first. Were the converter to
extract only what that listing held and record the archive as extracted
whole, the members past it would go unscanned and snyk-code would leave the
archive out of its copy too. So every member past zero blocks is extracted, and a header that
cannot be read makes the archive one extracted only in part: its results row names
the byte the header is at, a one-line warning names the archive, and the archive is
not recorded whole.
"""

from __future__ import annotations

import gzip
import io
import logging
import re
import tarfile
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)

pytestmark = pytest.mark.unit


def _tar_of(*members: Tuple[str, str]) -> bytes:
    """An uncompressed tar of ``(name, text)`` members, in order."""
    tarred = io.BytesIO()
    with tarfile.open(fileobj=tarred, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for name, text in members:
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
    return tarred.getvalue()


def _header_offset(tarred: bytes, name: str) -> int:
    with tarfile.open(fileobj=io.BytesIO(tarred)) as listing:
        (member,) = [m for m in listing.getmembers() if m.name == name]
    return member.offset


def _with_a_damaged_header(tarred: bytes, name: str) -> bytes:
    """``tarred`` with the checksum in member ``name``'s header broken, so tarfile
    reads that header as invalid."""
    offset = _header_offset(tarred, name)
    damaged = bytearray(tarred)
    damaged[offset + 148 : offset + 156] = b"0000000\0"
    return bytes(damaged)


def _stored(tarred: bytes, suffix: str) -> bytes:
    return gzip.compress(tarred) if suffix == "tar.gz" else tarred


def _convert(test_plugin_context, monkeypatch, name: str, content: bytes):
    source = Path(test_plugin_context.source_dir)
    (source / "lib").mkdir(parents=True, exist_ok=True)
    (source / "lib" / name).write_bytes(content)
    monkeypatch.setattr(
        f"{archive_converter.__name__}.scan_set",
        lambda **kwargs: [str(source / "lib" / name)],
    )
    converter = archive_converter.ArchiveConverter(
        context=test_plugin_context, config=archive_converter.ArchiveConverterConfig()
    )
    converter.convert()
    return converter


def _extracted(converter) -> List[str]:
    """The member files the converter wrote, relative to its archive's directory.

    The converter's own record of what it extracted (converted-sources.json, at the
    top of the results directory) is not a member and is left out.
    """
    results = Path(converter.results_dir)
    return sorted(
        p.relative_to(results).as_posix().split("/", 1)[1]
        for p in results.rglob("*")
        if p.is_file() and p != results / CONVERTED_SOURCES_FILE_NAME
    )


def _partly_warnings(caplog) -> List[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "extracted only in part" in r.getMessage()
    ]


SUFFIXES = ["tar", "tar.gz"]


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_a_damaged_middle_header_makes_the_archive_extracted_only_in_part(
    test_plugin_context, monkeypatch, caplog, suffix
):
    """mid.js's header cannot be read. The members around it are extracted, the
    archive is not recorded whole, and its results row and a warning name the byte
    the header is at."""
    whole = _tar_of(
        ("ok.js", "ok = 1\n"), ("mid.js", "mid = 1\n"), ("after.js", "a = 1\n")
    )
    offset = _header_offset(whole, "mid.js")
    tarred = _with_a_damaged_header(whole, "mid.js")
    name = f"b.{suffix}"

    with caplog.at_level(logging.WARNING):
        converter = _convert(
            test_plugin_context, monkeypatch, name, _stored(tarred, suffix)
        )

    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()
    assert _extracted(converter) == ["after.js", "ok.js"]
    # One record per archive, in the category the completeness gate reads.
    assert [r.path for r in converter.failed_inputs] == [f"lib/{name}"]
    assert converter.refused_inputs == []
    reason = converter.failed_inputs[0].reason
    assert "extracted only in part" in reason, reason
    assert f"byte {offset}" in reason, reason
    (warning,) = _partly_warnings(caplog)
    assert f"'lib/{name}'" in warning, warning
    assert f"byte {offset}" in warning, warning


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_a_second_tar_after_the_first_is_extracted_and_recorded_whole(
    test_plugin_context, monkeypatch, caplog, suffix
):
    """The zero blocks that end the first tar hold nothing: the second tar's
    members are extracted too, and with no header that cannot be read, the archive
    was extracted whole."""
    tarred = _tar_of(("ok.js", "ok = 1\n")) + _tar_of(("after.js", "a = 1\n"))
    name = f"b.{suffix}"

    with caplog.at_level(logging.WARNING):
        converter = _convert(
            test_plugin_context, monkeypatch, name, _stored(tarred, suffix)
        )

    assert _extracted(converter) == ["after.js", "ok.js"]
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {
        f"lib/{name}"
    }
    assert converter.refused_inputs == []
    assert _partly_warnings(caplog) == []


@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("padding", [0, 40], ids=["clean", "trailing-zero-blocks"])
def test_a_tar_that_ends_in_zero_blocks_is_extracted_whole(
    test_plugin_context, monkeypatch, caplog, suffix, padding
):
    """The controls: a clean tar, and one with zero blocks after its end, are
    extracted whole with nothing refused."""
    tarred = _tar_of(("ok.js", "ok = 1\n"), ("z.js", "z = 1\n")) + b"\0" * (
        512 * padding
    )
    name = f"b.{suffix}"

    with caplog.at_level(logging.WARNING):
        converter = _convert(
            test_plugin_context, monkeypatch, name, _stored(tarred, suffix)
        )

    assert _extracted(converter) == ["ok.js", "z.js"]
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {
        f"lib/{name}"
    }
    assert converter.refused_inputs == []
    assert _partly_warnings(caplog) == []


def test_the_warning_for_an_archive_extracted_in_part_is_one_line(
    test_plugin_context, monkeypatch, caplog
):
    """The archive's name comes from the scanned tree, so a newline in it is
    written as its escape: the warning stays one line."""
    tarred = _with_a_damaged_header(
        _tar_of(
            ("ok.js", "ok = 1\n"), ("mid.js", "mid = 1\n"), ("after.js", "a = 1\n")
        ),
        "mid.js",
    )

    with caplog.at_level(logging.WARNING):
        _convert(test_plugin_context, monkeypatch, "new\nline.tar", tarred)

    (warning,) = _partly_warnings(caplog)
    assert "\n" not in warning, warning
    assert "lib/new\\x0aline.tar" in warning, warning


def test_the_tar_listing_reads_past_zero_blocks_and_names_an_unreadable_header():
    """The shared listing (utils/tar_listing.py): a second tar's names are listed,
    and a header that cannot be read fails the listing with its byte."""
    from automated_security_helper.utils.tar_listing import (
        UnreadableTarHeader,
        tar_names,
    )

    two = _tar_of(("ok.js", "ok = 1\n")) + _tar_of(("after.js", "a = 1\n"))
    assert tar_names(io.BytesIO(two)) == ["ok.js", "after.js"]
    assert tar_names(io.BytesIO(gzip.compress(two))) == ["ok.js", "after.js"]

    damaged = _with_a_damaged_header(
        _tar_of(
            ("ok.js", "ok = 1\n"), ("mid.js", "mid = 1\n"), ("after.js", "a = 1\n")
        ),
        "mid.js",
    )
    with pytest.raises(UnreadableTarHeader) as raised:
        tar_names(io.BytesIO(damaged))
    assert raised.value.offset == 1024
    assert str(raised.value) == "the tar header at byte 1024 could not be read"


MIB = 1024 * 1024


def _ones_after(tarred: bytes, size: int) -> bytes:
    """``tarred`` followed by ``size`` bytes of 0x01, blocks no header reads, as a
    bz2 stream: a small file whose listing reads far past the tar's end."""
    import bz2

    return bz2.compress(tarred + b"\x01" * size)


def test_the_listing_keeps_only_the_first_unreadable_header():
    """Each block past the end that is not zeros is a header that cannot be read.
    Only the first is kept, not one offset per block."""
    from automated_security_helper.utils.tar_listing import open_tar_listing

    tarred = _tar_of(("ok.js", "ok = 1\n"))
    unreadable: List[int] = []
    with open_tar_listing(io.BytesIO(_ones_after(tarred, 10 * MIB)), unreadable) as t:
        names = t.getnames()

    assert names == ["ok.js"]
    assert unreadable == [len(tarred)]


def test_the_listing_stops_once_it_has_skipped_its_budget_of_blocks():
    """Past SKIPPED_BYTES_LIMIT of blocks skipped, zeros or not, the listing stops
    and says where: a second tar beyond that is not listed."""
    from automated_security_helper.utils import tar_listing

    first = _tar_of(("ok.js", "ok = 1\n"))
    gap = tar_listing.SKIPPED_BYTES_LIMIT + MIB
    tarred = first + b"\0" * gap + _tar_of(("after.js", "a = 1\n"))
    unreadable: List[int] = []
    stopped: List[int] = []

    with tar_listing.open_tar_listing(
        io.BytesIO(tarred), unreadable, stopped=stopped
    ) as listing:
        names = listing.getnames()

    assert names == ["ok.js"]
    assert unreadable == []
    assert len(stopped) == 1
    assert len(first) < stopped[0] <= len(first) + tar_listing.SKIPPED_BYTES_LIMIT + 512


def _member_only(tarred: bytes) -> bytes:
    """The first member of ``tarred``, its header and one block of data, with no
    zero blocks after it, so a listing skips only the blocks a test puts there.
    The member's data has to fit in one block."""
    return tarred[:1024]


@pytest.mark.parametrize(
    ("extra", "listed", "stops"),
    [
        pytest.param(0, ["ok.js", "after.js"], False, id="exactly-the-limit"),
        pytest.param(512, ["ok.js"], True, id="one-block-past-it"),
    ],
)
def test_the_listing_skips_exactly_its_limit_and_stops_one_block_past_it(
    extra, listed, stops
):
    """SKIPPED_BYTES_LIMIT bytes of blocks are skipped, and the listing goes on to
    the header after them. One block more, and it stops at that block."""
    from automated_security_helper.utils import tar_listing

    first = _member_only(_tar_of(("ok.js", "ok = 1\n")))
    gap = tar_listing.SKIPPED_BYTES_LIMIT + extra
    tarred = first + b"\0" * gap + _member_only(_tar_of(("after.js", "a = 1\n")))
    unreadable: List[int] = []
    stopped: List[int] = []

    with tar_listing.open_tar_listing(
        io.BytesIO(tarred), unreadable, stopped=stopped
    ) as listing:
        names = listing.getnames()

    assert names == listed
    assert unreadable == []
    assert stopped == ([len(first) + tar_listing.SKIPPED_BYTES_LIMIT] if stops else [])


def _gap_tar(gap: int) -> bytes:
    """ok.js, ``gap`` bytes of zero blocks, then after.js, and no other zeros."""
    return (
        _member_only(_tar_of(("ok.js", "ok = 1\n")))
        + b"\0" * gap
        + _member_only(_tar_of(("after.js", "a = 1\n")))
    )


def _listed(tarred: bytes, budget) -> Tuple[List[str], List[int]]:
    """The names a listing sharing ``budget`` reads, and where it stopped."""
    from automated_security_helper.utils import tar_listing

    unreadable: List[int] = []
    stopped: List[int] = []
    with tar_listing.open_tar_listing(
        io.BytesIO(tarred), unreadable, stopped=stopped, budget=budget
    ) as listing:
        names = listing.getnames()
    assert unreadable == []
    return names, stopped


def test_a_listing_that_spends_a_shared_budget_exactly_lists_on():
    """Past a tar's ordinary end (ORDINARY_END_BYTES), each block a listing skips
    is charged to the budget the listings share. A listing that spends it
    exactly reaches the next member."""
    from automated_security_helper.utils import tar_listing

    budget = tar_listing.SkippedBlocksBudget(4 * 512)
    names, stopped = _listed(_gap_tar(tar_listing.ORDINARY_END_BYTES + 4 * 512), budget)

    assert names == ["ok.js", "after.js"]
    assert stopped == []
    assert budget.used == 4 * 512
    assert not budget.spent


@pytest.mark.parametrize(
    ("past_the_end", "listed", "stops"),
    [
        pytest.param(0, ["ok.js", "after.js"], False, id="the-ordinary-end"),
        pytest.param(512, ["ok.js"], True, id="one-block-past-it"),
    ],
)
def test_a_listing_with_nothing_left_of_its_budget_stops_past_the_ordinary_end(
    past_the_end, listed, stops
):
    """With nothing left of the budget, a listing still skips a tar's ordinary
    end, and stops at the first block past it, at the byte that block starts
    at."""
    from automated_security_helper.utils import tar_listing

    budget = tar_listing.SkippedBlocksBudget(0)
    names, stopped = _listed(
        _gap_tar(tar_listing.ORDINARY_END_BYTES + past_the_end), budget
    )

    assert names == listed
    assert stopped == ([1024 + tar_listing.ORDINARY_END_BYTES] if stops else [])
    assert budget.spent is stops


def test_an_ordinary_tar_is_listed_whole_with_nothing_left_of_the_budget():
    """The control: a tar as tarfile writes it, its end padded to a whole
    record, is charged nothing and listed whole."""
    from automated_security_helper.utils import tar_listing

    budget = tar_listing.SkippedBlocksBudget(0)
    names, stopped = _listed(
        _tar_of(("ok.js", "ok = 1\n"), ("z.js", "z = 1\n")), budget
    )

    assert names == ["ok.js", "z.js"]
    assert stopped == []
    assert budget.used == 0


def _past_the_limit_in_bz2() -> bytes:
    """A bz2 tar of a few hundred bytes: one member, then more zero blocks than
    one listing skips (SKIPPED_BYTES_LIMIT and a MiB)."""
    import bz2

    from automated_security_helper.utils import tar_listing

    return bz2.compress(
        _member_only(_tar_of(("ok.js", "ok = 1\n")))
        + b"\0" * (tar_listing.SKIPPED_BYTES_LIMIT + MIB)
    )


def _convert_many(test_plugin_context, monkeypatch, content: bytes, count: int):
    """One conversion of ``count`` copies of the tar ``content``, in name order."""
    source = Path(test_plugin_context.source_dir)
    (source / "lib").mkdir(parents=True, exist_ok=True)
    paths = []
    for index in range(count):
        path = source / "lib" / f"a{index:03}.tar"
        path.write_bytes(content)
        paths.append(str(path))
    monkeypatch.setattr(
        f"{archive_converter.__name__}.scan_set", lambda **kwargs: paths
    )
    converter = archive_converter.ArchiveConverter(
        context=test_plugin_context, config=archive_converter.ArchiveConverterConfig()
    )
    converter.convert()
    return converter


def _stopped_at(reason: str) -> int:
    found = re.search(r"stopped at byte (\d+)", reason)
    assert found, reason
    return int(found.group(1))


def test_the_tars_of_one_conversion_share_a_budget_of_skipped_blocks(
    test_plugin_context, monkeypatch
):
    """200 small compressed tars, each with more zero blocks than one listing
    skips. Their listings share four times that limit, so once it is spent each
    later listing stops at its first block past a tar's ordinary end. Every
    archive is extracted only in part, and the blocks skipped in all are bounded
    by four archives' limit, not by the number of archives."""
    from automated_security_helper.utils import tar_listing

    count = 200
    converter = _convert_many(
        test_plugin_context, monkeypatch, _past_the_limit_in_bz2(), count
    )

    rows = converter.failed_inputs
    assert [row.path for row in rows] == [f"lib/a{i:03}.tar" for i in range(count)]
    assert all("extracted only in part" in row.reason for row in rows)
    # Each member's header and data are the archive's first 1024 bytes.
    skipped = sum(_stopped_at(row.reason) - 1024 for row in rows)
    bound = 4 * tar_listing.SKIPPED_BYTES_LIMIT + count * (2 * tarfile.RECORDSIZE + 512)
    assert skipped <= bound, (skipped, bound)
    assert sum("this run" in row.reason for row in rows) >= count - 4


def test_each_conversion_has_a_budget_of_its_own(test_plugin_context, monkeypatch):
    """Five such tars: four fit the conversion's budget and stop at one
    listing's limit, and the fifth stops on the budget, its row saying so. A
    second conversion starts with a budget of its own and does the same."""
    for _ in range(2):
        converter = _convert_many(
            test_plugin_context, monkeypatch, _past_the_limit_in_bz2(), 5
        )
        named_the_run = ["this run" in row.reason for row in converter.failed_inputs]
        assert named_the_run == [False, False, False, False, True]


def test_an_archive_whose_listing_stopped_is_extracted_only_in_part(
    test_plugin_context, monkeypatch, caplog
):
    """The converter records an archive whose listing stopped as extracted only in
    part: its results row and a warning say where, and it is not recorded whole."""
    from automated_security_helper.utils import tar_listing

    tarred = (
        _tar_of(("ok.js", "ok = 1\n"))
        + b"\0" * (tar_listing.SKIPPED_BYTES_LIMIT + MIB)
        + _tar_of(("after.js", "a = 1\n"))
    )

    with caplog.at_level(logging.WARNING):
        converter = _convert(test_plugin_context, monkeypatch, "b.tar", tarred)

    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()
    assert _extracted(converter) == ["ok.js"]
    (row,) = converter.failed_inputs
    assert converter.refused_inputs == []
    assert "extracted only in part" in row.reason, row.reason
    assert "stopped" in row.reason, row.reason
    (warning,) = _partly_warnings(caplog)
    assert "'lib/b.tar'" in warning, warning


def test_a_listing_of_names_stops_at_its_member_limit(monkeypatch):
    """tar_names lists at most MAX_LISTED_MEMBERS members, and refuses a tar that
    holds more; at the limit, it lists them all."""
    from automated_security_helper.utils import tar_listing

    monkeypatch.setattr(tar_listing, "MAX_LISTED_MEMBERS", 3)
    three = _tar_of(*[(f"m{index}.js", "m = 1\n") for index in range(3)])
    four = _tar_of(*[(f"m{index}.js", "m = 1\n") for index in range(4)])

    assert tar_listing.tar_names(io.BytesIO(three)) == ["m0.js", "m1.js", "m2.js"]
    with pytest.raises(tar_listing.TooManyTarMembers) as raised:
        tar_listing.tar_names(io.BytesIO(four))
    assert raised.value.limit == 3


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_a_tar_whose_first_header_cannot_be_read_has_a_results_row(
    test_plugin_context, monkeypatch, caplog, suffix
):
    """Nothing of it is read, so no scanner reads its members and snyk-code holds
    it back: its results row says so, where it was skipped with a debug line."""
    tarred = _with_a_damaged_header(
        _tar_of(("first.js", "f = 1\n"), ("ok.js", "ok = 1\n")), "first.js"
    )
    name = f"b.{suffix}"

    with caplog.at_level(logging.WARNING):
        converter = _convert(
            test_plugin_context, monkeypatch, name, _stored(tarred, suffix)
        )

    assert _extracted(converter) == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()
    # One FAILED record, the category the completeness gate reads.
    assert [row.path for row in converter.failed_inputs] == [f"lib/{name}"]
    assert converter.refused_inputs == []
    reason = converter.failed_inputs[0].reason
    assert "named as a tar but could not be read" in reason, reason
    assert any(f"lib/{name}" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize(
    "name, content",
    [
        pytest.param("b.zip", b"not an archive\n", id="zip-of-nothing"),
        pytest.param("b.ZIP", b"not an archive\n", id="zip-upper-case"),
        pytest.param("b.tar", b"not an archive\n", id="tar-of-nothing"),
        pytest.param("b.tar.gz", gzip.compress(b"not a tar\n"), id="tar-gz-of-text"),
    ],
)
def test_a_file_named_as_an_archive_it_cannot_be_read_as_has_a_results_row(
    test_plugin_context, monkeypatch, name, content
):
    """Every name the converter opens as an archive: one it cannot read as that
    kind is no archive anything extracts, so its results row says so."""
    converter = _convert(test_plugin_context, monkeypatch, name, content)

    assert _extracted(converter) == []
    assert [row.path for row in converter.failed_inputs] == [f"lib/{name}"]
    assert converter.refused_inputs == []
    assert "could not be read as" in converter.failed_inputs[0].reason


def test_a_gzip_of_one_file_has_no_results_row(test_plugin_context, monkeypatch):
    """The control: a .gz that holds one file, not a tar, is not an archive the
    converter extracts, and is no refusal."""
    converter = _convert(
        test_plugin_context, monkeypatch, "d.json.gz", gzip.compress(b"{}\n")
    )

    assert converter.refused_inputs == []
    assert converter.failed_inputs == []
