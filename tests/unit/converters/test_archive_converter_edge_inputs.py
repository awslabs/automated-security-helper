# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inputs at the edges of what the archive converter reads, each once lost whole.

- A zip64 archive's member pre-count walked the central directory from the end
  record's location less the directory's size. On the zipfile releases that leave
  the location at the plain end record (and take the zip64 record and locator off
  the start themselves), that is 76 bytes into the directory: no entry signature
  there, nothing counted, and the pre-count never refused a zip64 archive.
- A tar member's pax header of more than 1 KiB cost more than the 2048-byte
  per-member header allowance, so a tar of thousands of such members was refused
  as unreadable once the 4 MiB base was spent.
- An uncompressed tar whose first member is named ``BZh...`` was read as bzip2,
  failed to decompress, and was recorded as unreadable. The fix read a first block
  whose tar checksum held as a tar before any compressor's magic, which made a
  gzip whose header spelled a tar header read as that tar and never as the gzip
  a consumer unpacks: the magic decides first now, and the header only once the
  decompressor has refused the stream.
- A .tar.gz followed by bytes that are not another gzip member failed whole: the
  listing reads every byte there is, and GzipFile raises at the first byte after
  the last member that is not a member header.
- A member whose name holds a NUL raised ValueError out of the escape check and
  failed the whole archive; an encrypted zip member, or one in a compression
  method zipfile does not implement, raised out of extractall and lost every
  member already written.
- A zip member's path, as an ignore path names it, is the file zipfile writes; on
  Windows zipfile writes the host's forbidden characters as ``_`` and drops a
  part's trailing dots and spaces, which the path did not follow.
- An archive at a deep path was extracted into a directory named by its whole
  folded path, past the 255 bytes a file name may take, and was recorded as a
  failed input for the length of its own path.
- Both converters walked the tree without the workspace's output directory, so a
  walk fallback in a workspace scan could reach another project's output.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import struct
import sys
import tarfile
import types
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfigOptions,
    archive_kind,
)
from tests.utils.archive_builders import tar_bytes, zip_bytes

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


def _converter(context) -> ArchiveConverter:
    return ArchiveConverter(context=context, config=context.config.converters.archive)


def _convert_one(context, monkeypatch, name: str, data: bytes):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / name
    archive.write_bytes(data)
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = _converter(context)
    return converter, converter.convert()


# ---------------------------------------------------------------- zip64 pre-count


def zip64_declaring_one_entry_everywhere(count: int, monkeypatch) -> bytes:
    """A zip64 zip of ``count`` members whose records both declare one entry.

    The plain end record is saturated as a writer saturates it, and the zip64 end
    record's two counts are set to 1, so the declared-count check passes and only
    the directory walk can find the other members.
    """
    buffer = io.BytesIO()
    with monkeypatch.context() as patch:
        patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1, raising=True)
        with zipfile.ZipFile(buffer, "w") as archive:
            for i in range(count):
                archive.writestr(f"m{i}.py", f"x = {i}\n")
    raw = bytearray(buffer.getvalue())
    record = raw.rfind(b"PK\x06\x06")
    assert record >= 0, "zipfile wrote no zip64 end record"
    struct.pack_into("<QQ", raw, record + 24, 1, 1)
    end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, end + 8, 0xFFFF, 0xFFFF)
    return bytes(raw)


def end_record_as_the_older_zipfile_reads_it(monkeypatch) -> None:
    """Make the end record read as the zipfile releases before the _EndRecData64
    fix read it: the zip64 fields filled in, the location left at the plain end
    record, 76 bytes past the zip64 end record the current releases move it to.
    The location is moved only when this zipfile reports the current shape (the
    bytes at the location spell the zip64 end record's signature); on an
    interpreter that already reports the older shape, as the oldest Pythons ASH
    supports do, the record is left as read, since a location 76 bytes past the
    plain end record is one no zipfile release reports."""
    real = archive_converter._zip_end_record
    names = vars(zipfile)

    def older(handle):
        record = real(handle)
        if record and record[names["_ECD_SIGNATURE"]] == names["stringEndArchive64"]:
            handle.seek(record[names["_ECD_LOCATION"]])
            if handle.read(4) == names["stringEndArchive64"]:
                record = list(record)
                record[names["_ECD_LOCATION"]] += (
                    names["sizeEndCentDir64"] + names["sizeEndCentDir64Locator"]
                )
        return record

    monkeypatch.setattr(archive_converter, "_zip_end_record", older)


def test_a_zip64_directory_is_counted_whichever_location_zipfile_reports(monkeypatch):
    raw = zip64_declaring_one_entry_everywhere(20, monkeypatch)
    end_record_as_the_older_zipfile_reads_it(monkeypatch)

    assert archive_converter._zip_has_more_entries_than(io.BytesIO(raw), 10) is True
    # And the walk counts them, not the declared one: twenty is not more than twenty.
    assert archive_converter._zip_has_more_entries_than(io.BytesIO(raw), 20) is False


def test_a_zip64_directory_is_counted_as_this_zipfile_locates_it(monkeypatch):
    """The control: with the end record as this Python's zipfile reads it."""
    raw = zip64_declaring_one_entry_everywhere(20, monkeypatch)

    assert archive_converter._zip_has_more_entries_than(io.BytesIO(raw), 10) is True
    assert archive_converter._zip_has_more_entries_than(io.BytesIO(raw), 20) is False


def test_the_directory_start_is_read_from_the_record_the_location_names(monkeypatch):
    """The shape zipfile reported is told by the signature at the location it
    gave, never by trying both starts and taking the one whose bytes happen to
    spell an entry signature: a location that names neither end record answers
    None, and nothing is counted from a guessed start."""
    raw = zip64_declaring_one_entry_everywhere(3, monkeypatch)
    handle = io.BytesIO(raw)
    record = archive_converter._zip_end_record(handle)
    names = vars(zipfile)
    directory_bytes = record[names["_ECD_SIZE"]]

    start = archive_converter._zip_directory_start(handle, record, directory_bytes)
    assert start is not None
    handle.seek(start)
    assert handle.read(4) == b"PK\x01\x02"

    # The same record with its location pointed one byte off either signature.
    off = list(record)
    off[names["_ECD_LOCATION"]] += 1
    assert archive_converter._zip_directory_start(handle, off, directory_bytes) is None


# ---------------------------------------------------------------- pax allowance


def pax_tar(names) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 4
            tar.addfile(info, io.BytesIO(b"x=1\n"))
    return buffer.getvalue()


def test_a_pax_header_over_a_kibibyte_fits_the_per_member_allowance(monkeypatch):
    """With the base allowance taken away, each member stands on its per-member
    allowance alone: a pax header of three blocks (a path of about 1.2 KB, which
    tarfile writes as one pax record) plus the member's own header has to fit."""
    monkeypatch.setattr(f"{ARCHIVE_MODULE}._TAR_HEADER_BYTES_BASE", 0, raising=True)
    names = ["/".join(["component"] * 120) + f"/f{i}.py" for i in range(2)]
    raw = pax_tar(names)
    handle = io.BytesIO(raw)

    with contextlib.ExitStack() as stack:
        tar_ref, stream = ArchiveConverter._open_tar(handle, stack)
        budget = archive_converter._ExtractionBudget(
            ArchiveConverterConfigOptions(), len(raw)
        )
        members = archive_converter._tar_members_within(tar_ref, budget, stream)

    assert [member.name for member in members] == names


# ---------------------------------------------------------------- bzip2 sniff


def test_an_uncompressed_tar_whose_first_member_is_named_bzh_is_a_tar(
    test_plugin_context, monkeypatch
):
    raw = tar_bytes({"BZh9-notes.txt": "hello\n", "a.py": "x = 1\n"})

    assert archive_kind("src.tar", io.BytesIO(raw)) == "tar"

    converter, results = _convert_one(test_plugin_context, monkeypatch, "src.tar", raw)
    (extracted,) = results
    assert (extracted / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert converter.failed_inputs == []


def test_a_bzip2_stream_is_still_read_as_bzip2():
    """The control: a real bzip2 head passes the whole six-byte test."""
    compressed = bz2.compress(tar_bytes({"a.py": "x = 1\n"}))

    assert archive_converter._is_bzip2_head(compressed[:6]) is True
    assert archive_kind("src.tar", io.BytesIO(compressed)) == "tar"


def test_a_tar_whose_first_member_spells_the_whole_bzip2_head_is_a_tar(
    test_plugin_context, monkeypatch
):
    """A member name is free to spell bzip2's signature, block size and block
    magic; the tar header's checksum, not the first six bytes, says what it is."""
    raw = tar_bytes({"BZh91AY&SY-notes.txt": "hello\n", "a.py": "x = 1\n"})
    assert archive_converter._is_bzip2_head(raw[:6]) is True

    assert archive_kind("src.tar", io.BytesIO(raw)) == "tar"

    converter, results = _convert_one(test_plugin_context, monkeypatch, "src.tar", raw)
    (extracted,) = results
    assert (extracted / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert converter.failed_inputs == []


# ---------------------------------------------------------------- sniff order


def test_a_compressors_magic_is_read_before_the_tar_header(
    test_plugin_context, monkeypatch
):
    """The order pin: a stream whose first bytes carry a compressor's magic is
    read through that decompressor, and its first block is read as a tar header
    only once the decompressor has refused it. With the header test answering
    True for every block, a gzip-compressed tar is still opened as gzip and its
    member extracted. Read header-first, as it was, it was the tar its bytes
    spelled: not one at all, so the archive was not read."""
    monkeypatch.setattr(archive_converter, "_spells_a_tar_header", lambda block: True)
    raw = tar_bytes({"a.py": "x = 1\n"}, gz=True)
    plain = tar_bytes({"a.py": "x = 1\n"})

    with archive_converter._tar_stream(io.BytesIO(raw)) as stream:
        assert stream.read(tarfile.BLOCKSIZE) == plain[: tarfile.BLOCKSIZE]
    assert archive_kind("src.tar.gz", io.BytesIO(raw)) == "tar"

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "src.tar.gz", raw
    )
    (extracted,) = results
    assert (extracted / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert converter.failed_inputs == []


def test_a_tar_with_no_compressors_magic_is_read_as_a_tar(
    test_plugin_context, monkeypatch
):
    """The control: with no magic there is no decompressor to consult, so a bare
    tar is read as a tar whatever the header test says."""
    monkeypatch.setattr(archive_converter, "_spells_a_tar_header", lambda block: True)
    raw = tar_bytes({"a.py": "x = 1\n"})

    with archive_converter._tar_stream(io.BytesIO(raw)) as stream:
        assert stream.read(tarfile.BLOCKSIZE) == raw[: tarfile.BLOCKSIZE]
    assert archive_kind("src.tar", io.BytesIO(raw)) == "tar"

    converter, results = _convert_one(test_plugin_context, monkeypatch, "src.tar", raw)
    (extracted,) = results
    assert (extracted / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert converter.failed_inputs == []


@pytest.mark.parametrize(
    ("header_answer", "opened"),
    [
        pytest.param(False, 1, id="plain-gzip-bytes"),
        pytest.param(True, 2, id="bytes-that-also-spell-a-header"),
    ],
)
def test_the_decompressor_is_probed_only_where_the_block_also_spells_a_header(
    monkeypatch, header_answer, opened
):
    """A gzip whose first block spells no tar header is opened once, for the
    read. One whose first block does spell a header is opened twice: once to ask
    whether the decompressor reads it (it does, so the stream is gzip), then for
    the read. Read header-first, as it was, the second case opened no gzip at all."""
    opens = {"n": 0}
    real = archive_converter._GzipMembersStream

    class Counting(real):
        def __init__(self, raw):
            opens["n"] += 1
            super().__init__(raw)

    monkeypatch.setattr(archive_converter, "_GzipMembersStream", Counting)
    monkeypatch.setattr(
        archive_converter, "_spells_a_tar_header", lambda block: header_answer
    )
    raw = tar_bytes({"a.py": "x = 1\n"}, gz=True)
    plain = tar_bytes({"a.py": "x = 1\n"})

    with archive_converter._tar_stream(io.BytesIO(raw)) as stream:
        assert stream.read(tarfile.BLOCKSIZE) == plain[: tarfile.BLOCKSIZE]

    assert opens["n"] == opened


def test_a_compressed_stream_that_holds_no_tar_falls_back_to_the_raw_bytes(
    monkeypatch,
):
    """The fallback condition is tarfile's (``r:*``): where the first raw block
    spells a tar header, the decompressor is kept only when what it decompresses
    starts with a tar header too; otherwise the raw bytes are the tar a tarfile
    consumer reads. With the header test answering True, a gzip of a non-tar
    payload reads as its raw bytes, and a gzip of a tar as its payload (the
    control). Decompression alone used to keep the gzip, so the first case was
    read as a gzip holding no tar and the file recorded as unreadable."""
    monkeypatch.setattr(archive_converter, "_spells_a_tar_header", lambda block: True)
    gzip_of_text = gzip.compress(b"x = 1\n" * 100)
    gzip_of_tar = tar_bytes({"a.py": "x = 1\n"}, gz=True)
    plain = tar_bytes({"a.py": "x = 1\n"})

    with archive_converter._tar_stream(io.BytesIO(gzip_of_text)) as stream:
        assert stream.read(tarfile.BLOCKSIZE) == gzip_of_text[: tarfile.BLOCKSIZE]
    with archive_converter._tar_stream(io.BytesIO(gzip_of_tar)) as stream:
        assert stream.read(tarfile.BLOCKSIZE) == plain[: tarfile.BLOCKSIZE]

    probe = archive_converter._decompresses_to_a_tar_header
    assert (
        probe(archive_converter._GzipMembersStream, io.BytesIO(gzip_of_text)) is False
    )
    assert probe(archive_converter._GzipMembersStream, io.BytesIO(gzip_of_tar)) is True


def test_the_stream_says_when_it_read_raw_bytes_though_the_decompressor_read_fine(
    monkeypatch,
):
    """GNU tar skips a first block that is no header ("Skipping to next header")
    and node-tar skips an invalid entry (TAR_ENTRY_INVALID), then both extract
    what follows. Read as the raw tar its first block spells, a compressed stream
    whose decompressor read without error holds a tar this read never reaches.
    The stream says so (``compressed_payload_unread``). The controls: a gzip of a
    tar is read as the gzip, a gzip the decompressor refuses (cut short) is no such
    case since a consumer fails on it too, and a plain tar has no decompressor.
    The header test is forced, as the neighbors do, so no archive is hand-made."""
    monkeypatch.setattr(archive_converter, "_spells_a_tar_header", lambda block: True)
    gzip_of_text = gzip.compress(b"x = 1\n" * 100)
    gzip_of_tar = tar_bytes({"a.py": "x = 1\n"}, gz=True)
    cut_short = gzip_of_text[:12]

    with archive_converter._tar_stream(io.BytesIO(gzip_of_text)) as stream:
        assert stream.compressed_payload_unread is True
    with archive_converter._tar_stream(io.BytesIO(gzip_of_tar)) as stream:
        assert stream.compressed_payload_unread is False
    with archive_converter._tar_stream(io.BytesIO(cut_short)) as stream:
        assert stream.compressed_payload_unread is False
    with archive_converter._tar_stream(
        io.BytesIO(tar_bytes({"a.py": "x = 1\n"}))
    ) as stream:
        assert stream.compressed_payload_unread is False


def test_an_archive_whose_compressed_data_was_not_read_is_a_failed_input(
    test_plugin_context, monkeypatch
):
    """The tar the raw bytes spell is extracted, and the archive is recorded as a
    failed input of kind input (a reviewed suppression may accept it), so it is
    not counted as extracted whole and the completeness gate sees the loss. The
    stream's answer is set by a stand-in for the same reason as above."""
    real = archive_converter._tar_stream

    @contextlib.contextmanager
    def flagged(handle):
        with real(handle) as stream:
            stream.compressed_payload_unread = True
            yield stream

    monkeypatch.setattr(archive_converter, "_tar_stream", flagged)
    raw = tar_bytes({"a.py": "x = 1\n"})

    converter, results = _convert_one(test_plugin_context, monkeypatch, "src.tar", raw)

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == ["a.py"]
    (failed,) = converter.failed_inputs
    assert (failed.path, failed.kind, failed.accepted) == ("src.tar", "input", False)
    assert failed.reason.startswith("its compressed data was not read")
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


def test_a_plain_tar_is_recorded_whole_with_no_compressed_data_unread(
    test_plugin_context, monkeypatch
):
    """The control: no decompressor was set aside, so nothing is recorded."""
    raw = tar_bytes({"a.py": "x = 1\n"})

    converter, results = _convert_one(test_plugin_context, monkeypatch, "src.tar", raw)

    assert len(results) == 1
    assert converter.failed_inputs == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {
        "src.tar"
    }


# ---------------------------------------------------------------- gzip trailing bytes


def test_a_tar_gz_followed_by_other_bytes_is_extracted(
    test_plugin_context, monkeypatch
):
    """Every member is extracted, and the bytes after the gzip data, which nothing
    reads, are recorded by their count: a refusal without a limit, so the archive
    is not counted as extracted whole and the gate is not failed. They used to be
    dropped with nothing recorded, and the archive counted whole."""
    raw = tar_bytes({"a.py": "x = 1\n", "b.py": "y = 2\n"}, gz=True) + b"TRAILER\n"

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "src.tar.gz", raw
    )

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == ["a.py", "b.py"]
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member, refused.limit) == ("src.tar.gz", None, None)
    assert "8 bytes after the end of its gzip data" in refused.reason
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


def test_the_trailing_record_says_every_member_was_extracted(
    test_plugin_context, monkeypatch
):
    """The record is a refusal, which a reader takes as something the scan left
    out; here nothing of the archive's members was. The reason says so before
    it counts the tail, so the results row is not read as a partial extraction."""
    raw = tar_bytes({"a.py": "x = 1\n"}, gz=True) + b"TRAILER\n"

    converter, _ = _convert_one(test_plugin_context, monkeypatch, "src.tar.gz", raw)

    (refused,) = converter.refused_inputs
    assert refused.reason.startswith("every member of its gzip data was extracted")
    assert "the 8 bytes after the end of its gzip data" in refused.reason


def test_the_trailing_record_does_not_say_every_member_was_extracted_after_a_refusal(
    test_plugin_context, monkeypatch
):
    """Where a member of the archive was refused, the sentence that every member
    was extracted contradicts that refusal, in the same results row. The tail is
    still recorded by its count, and the reason says only that the gzip data was
    read to its end."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"x = 1\n"
        member = tarfile.TarInfo("a.py")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
        link = tarfile.TarInfo("link.py")
        link.type = tarfile.SYMTYPE
        link.linkname = "a.py"
        archive.addfile(link)
    raw = buffer.getvalue() + b"TRAILER\n"

    converter, _ = _convert_one(test_plugin_context, monkeypatch, "src.tar.gz", raw)

    (link_refusal,) = [r for r in converter.refused_inputs if r.member == "link.py"]
    assert "symbolic or hard link" in link_refusal.reason
    (tail,) = [r for r in converter.refused_inputs if r.member is None]
    assert "every member" not in tail.reason
    assert tail.reason.startswith("its gzip data was read to its end")
    assert "the 8 bytes after the end of its gzip data" in tail.reason
    assert tail.limit is None


def test_the_trailing_record_does_not_say_every_member_was_extracted_for_a_cut_tar(
    test_plugin_context, monkeypatch
):
    """A tar that ends at a member boundary, with no end-of-archive block, is
    recorded as extracted in part (its members past the cut may be missing), so
    the tail's record does not say every member was extracted either."""
    plain = tar_bytes({"a.py": "x = 1\n"})
    cut = plain[: 2 * tarfile.BLOCKSIZE]
    raw = gzip.compress(cut) + b"TRAILER\n"

    converter, _ = _convert_one(test_plugin_context, monkeypatch, "src.tar.gz", raw)

    assert converter.failed_inputs
    (tail,) = [r for r in converter.refused_inputs if r.member is None]
    assert "every member" not in tail.reason
    assert tail.reason.startswith("its gzip data was read to its end")


def test_the_trailing_record_names_whether_every_member_was_extracted(
    test_plugin_context,
):
    """The sentence follows the argument: every member where the archive was
    extracted whole (the default), only the read to the end where it was not."""
    converter = _converter(test_plugin_context)

    converter._record_trailing_bytes("whole.tar.gz", 8)
    converter._record_trailing_bytes("partial.tar.gz", 8, whole=False)

    whole, partial = converter.refused_inputs
    assert whole.reason.startswith("every member of its gzip data was extracted; the 8")
    assert partial.reason.startswith("its gzip data was read to its end; the 8")
    assert partial.reason.endswith("and were not read, so no scanner reads them")
    assert (whole.limit, partial.limit) == (None, None)


def test_the_bounded_tar_stream_reports_its_sources_trailing_bytes():
    """The count the converter records is read through the bounded stream's own
    method, not out of its wrapped source: 0 until the source has been read to
    its end, the source's count after, and 0 for a source that keeps none."""
    source = archive_converter._GzipMembersStream(
        io.BytesIO(gzip.compress(b"x" * 100) + b"TRAILER\n")
    )
    bounded = archive_converter._BoundedTarStream(source)

    assert bounded.trailing_bytes() == 0
    assert source.read() == b"x" * 100
    assert bounded.trailing_bytes() == 8

    plain = archive_converter._BoundedTarStream(io.BytesIO(b"\0" * 1024))
    assert plain.trailing_bytes() == 0


def test_the_trailing_count_survives_a_seek_back_to_the_start():
    """The listing reads the gzip stream to its end, where the count is taken;
    extraction then seeks back to each member's data, which starts the stream
    over. The count used to be reset with the rest of the stream's state, so the
    converter, reading it after extraction, found None for every .tar.gz with a
    member and recorded nothing. The file's tail does not change with the
    position, so the count is kept."""
    stream = archive_converter._GzipMembersStream(
        io.BytesIO(gzip.compress(b"x" * 100) + b"TRAILER\n")
    )

    assert stream.trailing is None
    assert stream.read() == b"x" * 100
    assert stream.trailing == 8

    stream.seek(0)

    assert stream.trailing == 8
    assert stream.read(10) == b"x" * 10
    assert stream.trailing == 8


def test_a_tar_gz_with_nothing_after_its_data_is_extracted_whole(
    test_plugin_context, monkeypatch
):
    """The control: a clean gzip ends with its last member and is recorded whole."""
    raw = tar_bytes({"a.py": "x = 1\n", "b.py": "y = 2\n"}, gz=True)

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "src.tar.gz", raw
    )

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == ["a.py", "b.py"]
    assert converter.refused_inputs == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {
        "src.tar.gz"
    }


def test_a_plain_gzip_followed_by_other_bytes_is_decompressed(
    test_plugin_context, monkeypatch
):
    """A .gz of one file took the GzipFile path, which failed the whole file on the
    bytes after its data (BadGzipFile) where the .tar.gz path read past them: the
    one stream serves both now, and the bytes are recorded the same way."""
    raw = gzip.compress(b'{"x": 1}\n') + b"TRAILER\n"

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "data.json.gz", raw
    )

    (extracted,) = results
    assert (extracted / "data.json").read_bytes() == b'{"x": 1}\n'
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert "8 bytes after the end of its gzip data" in refused.reason


def test_a_tar_gz_cut_short_still_fails(test_plugin_context, monkeypatch):
    """The control: a member cut short is a damaged archive, as before."""
    raw = tar_bytes({"a.py": "x = 1\n" * 200}, gz=True)

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "src.tar.gz", raw[: len(raw) // 2]
    )

    assert results == []
    assert [f.path for f in converter.failed_inputs] == ["src.tar.gz"]


# ---------------------------------------------------------------- member refusals


def test_a_member_whose_name_holds_a_nul_is_refused_alone(
    test_plugin_context, tmp_path
):
    converter = _converter(test_plugin_context)
    good = tarfile.TarInfo("ok.py")
    bad = tarfile.TarInfo("bad\x00name.py")

    kept = converter.inspect_members([good, bad], target_path=tmp_path, archive="a.tar")

    assert kept == [good]
    (refused,) = converter.refused_inputs
    assert refused.member == "bad\x00name.py"
    assert "NUL" in refused.reason


def test_an_encrypted_or_unsupported_zip_member_is_refused_alone(
    test_plugin_context, tmp_path
):
    converter = _converter(test_plugin_context)
    plain = zipfile.ZipInfo("a.py")
    plain.compress_type = zipfile.ZIP_DEFLATED
    encrypted = zipfile.ZipInfo("b.py")
    encrypted.flag_bits |= 0x1
    deflate64 = zipfile.ZipInfo("c.py")
    deflate64.compress_type = 9

    kept = converter.inspect_members(
        [plain, encrypted, deflate64], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [plain]
    reasons = {r.member: r.reason for r in converter.refused_inputs}
    assert "encrypted" in reasons["b.py"]
    assert "compression method (9)" in reasons["c.py"]


def test_a_patched_or_module_less_zip_member_is_refused_alone(
    test_plugin_context, tmp_path, monkeypatch
):
    """Two more members zipfile cannot read, which still raised out of extractall
    and so failed the whole archive: one whose data is marked as patched (flag bit
    5, NotImplementedError), and one compressed with bzip2 on a Python built
    without the bz2 module (RuntimeError, graded as the run's failure). The
    control first: with the module present the bzip2 member is admitted."""
    converter = _converter(test_plugin_context)
    plain = zipfile.ZipInfo("a.py")
    bzipped = zipfile.ZipInfo("b.py")
    bzipped.compress_type = zipfile.ZIP_BZIP2
    patched = zipfile.ZipInfo("c.py")
    patched.flag_bits |= 0x20

    admitted = converter.inspect_members(
        [bzipped], target_path=tmp_path, archive="a.zip"
    )
    assert admitted == [bzipped] and converter.refused_inputs == []

    monkeypatch.setattr(zipfile, "bz2", None, raising=True)
    kept = converter.inspect_members(
        [plain, bzipped, patched], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [plain]
    reasons = {r.member: r.reason for r in converter.refused_inputs}
    assert "needs a module this Python does not have" in reasons["b.py"]
    assert "patched data" in reasons["c.py"]


def test_a_strongly_encrypted_zip_member_is_refused_alone(
    test_plugin_context, tmp_path
):
    """Flag bit 6 (strong encryption) with bit 0 clear: zipfile's ``open`` raises
    NotImplementedError for it as for patched data, so one such member failed the
    whole archive past the bit-0 check. It is refused alone, the control admitted.
    The bit is set on a stdlib ZipInfo; no bytes are hand-assembled."""
    converter = _converter(test_plugin_context)
    plain = zipfile.ZipInfo("a.py")
    strong = zipfile.ZipInfo("d.py")
    strong.flag_bits |= 0x40
    assert not strong.flag_bits & 0x1

    kept = converter.inspect_members(
        [plain, strong], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [plain]
    (refused,) = converter.refused_inputs
    assert refused.member == "d.py"
    assert "strongly encrypted" in refused.reason
    assert "flag bit 6" in refused.reason


def test_a_member_whose_extraction_path_passes_the_host_limit_is_refused_alone(
    test_plugin_context, tmp_path, monkeypatch
):
    """On a host with a path length limit (Windows' MAX_PATH) the extractor's
    open of a longer path fails with ENOENT, which the failure grading reads as
    the run's fault, so one over-long member name failed the whole archive as a
    tool error. The member is refused alone by name, before extraction, and the
    control is admitted. The limit is set on the module: no real long path, so the
    test reads the same on every host."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(
        archive_converter, "_PATH_LENGTH_LIMIT", len(str(tmp_path)) + 1 + 10
    )
    short = zipfile.ZipInfo("ok.js")
    long = zipfile.ZipInfo("a_much_longer_name.js")

    kept = converter.inspect_members(
        [short, long], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [short]
    (refused,) = converter.refused_inputs
    assert refused.member == "a_much_longer_name.js"
    assert "path length limit" in refused.reason
    assert "a_much_longer_name" not in refused.reason


def test_a_host_without_a_path_length_limit_admits_a_long_member_name(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: with no limit set (the POSIX default) the same members are
    both admitted and nothing is refused."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(archive_converter, "_PATH_LENGTH_LIMIT", None)
    short = zipfile.ZipInfo("ok.js")
    long = zipfile.ZipInfo("a_much_longer_name.js")

    kept = converter.inspect_members(
        [short, long], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [short, long]
    assert converter.refused_inputs == []


def test_a_duplicate_whose_numbered_placement_passes_the_host_limit_is_refused_alone(
    test_plugin_context, tmp_path, monkeypatch
):
    """The length check reads the name as the archive holds it; a second member
    bound for a taken path is written in a numbered directory (``vendor/m~2/m.js``),
    four characters longer. A duplicate within those characters of the limit passed
    the check, and the extractor's open of its longer placement failed the whole
    archive. The placement is checked too: the duplicate is refused alone, by the
    same reason, and left under the name it was read with; the first is kept."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(
        archive_converter, "_PATH_LENGTH_LIMIT", len(str(tmp_path)) + 14
    )
    first = tarfile.TarInfo("vendor/m.js")
    second = tarfile.TarInfo("vendor/m.js")

    kept = converter.inspect_members(
        [first, second], target_path=tmp_path, archive="a.tar"
    )

    assert kept == [first]
    (refused,) = converter.refused_inputs
    assert refused.member == "vendor/m.js"
    assert "path length limit" in refused.reason
    assert second.name == "vendor/m.js"


def test_a_duplicate_whose_numbered_placement_fits_the_host_limit_is_still_renamed(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: with the limit one character past the placement's length the
    same pair is admitted, the second renamed, and nothing is refused."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(
        archive_converter, "_PATH_LENGTH_LIMIT", len(str(tmp_path)) + 17
    )
    first = tarfile.TarInfo("vendor/m.js")
    second = tarfile.TarInfo("vendor/m.js")

    kept = converter.inspect_members(
        [first, second], target_path=tmp_path, archive="a.tar"
    )

    assert kept == [first, second]
    assert converter.refused_inputs == []
    assert second.name == "vendor/m~2/m.js"


def _utf16_units(text: str) -> int:
    """The test's own count of what MAX_PATH counts."""
    return len(text.encode("utf-16-le")) // 2


def test_a_member_name_is_measured_in_utf16_units_against_the_host_limit(
    test_plugin_context, tmp_path, monkeypatch
):
    """MAX_PATH counts UTF-16 code units, so a name of characters past the basic
    plane is twice as long to the host as ``len`` says: counted in characters it
    passed a check it then failed at the open (ENOENT, the whole archive lost as a
    tool error). Four such characters and ``.js`` are 7 characters and 11 units;
    the limit sits between. The control, of 7 units, is admitted."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(
        archive_converter,
        "_PATH_LENGTH_LIMIT",
        _utf16_units(str(tmp_path)) + 1 + 10,
    )
    astral = zipfile.ZipInfo(chr(0x1D538) * 4 + ".js")
    plain = zipfile.ZipInfo("abcd.js")
    assert len(astral.filename) == len(plain.filename) == 7

    kept = converter.inspect_members(
        [astral, plain], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [plain]
    (refused,) = converter.refused_inputs
    assert refused.member == astral.filename


def test_a_members_directory_is_measured_against_the_hosts_directory_limit(
    test_plugin_context, tmp_path, monkeypatch
):
    """A host that makes a directory only up to MAX_PATH less 12 refuses to make
    one of 248 to 259 units though a file of that length would open, so a member
    whose whole path fits the file limit but whose directory does not failed the
    archive when its directory was made. It is refused alone. The controls: a
    shallow directory, and a member with no directory of its own, whose long file
    name fits the file limit, are admitted."""
    converter = _converter(test_plugin_context)
    head = _utf16_units(str(tmp_path)) + 1
    monkeypatch.setattr(archive_converter, "_PATH_LENGTH_LIMIT", head + 100)
    monkeypatch.setattr(archive_converter, "_DIRECTORY_LENGTH_LIMIT", head + 20)
    deep = zipfile.ZipInfo("d" * 25 + "/x.js")
    shallow = zipfile.ZipInfo("ddd/x.js")
    flat = zipfile.ZipInfo("f" * 30 + ".js")

    kept = converter.inspect_members(
        [deep, shallow, flat], target_path=tmp_path, archive="a.zip"
    )

    assert kept == [shallow, flat]
    (refused,) = converter.refused_inputs
    assert refused.member == deep.filename
    assert "path length limit" in refused.reason


def test_a_host_without_a_directory_limit_admits_a_deep_directory(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: with no directory limit (a host with long paths, or POSIX) the
    same deep member is admitted."""
    converter = _converter(test_plugin_context)
    head = _utf16_units(str(tmp_path)) + 1
    monkeypatch.setattr(archive_converter, "_PATH_LENGTH_LIMIT", head + 100)
    monkeypatch.setattr(archive_converter, "_DIRECTORY_LENGTH_LIMIT", None)
    deep = zipfile.ZipInfo("d" * 25 + "/x.js")

    kept = converter.inspect_members([deep], target_path=tmp_path, archive="a.zip")

    assert kept == [deep]
    assert converter.refused_inputs == []


def test_a_member_refused_for_its_path_length_is_also_a_failed_input_the_gate_counts(
    test_plugin_context, tmp_path, monkeypatch
):
    """The completeness gate reads failed inputs and ignores a refusal that names
    no limit, so an archive that gave a scannable file a path past the host's
    limit hid it from the scan, and the scan reported full coverage; before the
    length check such an archive failed as a gating tool error. The archive is
    recorded once as a failed input of kind input, which the gate counts and an
    ash-unconverted-input suppression may accept, with the members counted and
    none named; each member's own refusal stays."""
    converter = _converter(test_plugin_context)
    archive_file = str(Path(test_plugin_context.source_dir) / "a.zip")
    monkeypatch.setattr(
        archive_converter, "_PATH_LENGTH_LIMIT", len(str(tmp_path)) + 1 + 10
    )
    short = zipfile.ZipInfo("ok.js")
    long = zipfile.ZipInfo("a_much_longer_name.js")
    longer = zipfile.ZipInfo("another_long_name.js")

    kept = converter.inspect_members(
        [short, long, longer],
        target_path=tmp_path,
        archive="a.zip",
        archive_file=archive_file,
    )

    assert kept == [short]
    (failed,) = converter.failed_inputs
    assert (failed.path, failed.kind, failed.accepted) == ("a.zip", "input", False)
    assert failed.reason.startswith("2 members not extracted")
    assert "a_much_longer_name" not in failed.reason
    assert [r.member for r in converter.refused_inputs] == [
        "a_much_longer_name.js",
        "another_long_name.js",
    ]


def test_a_host_without_a_path_length_limit_records_no_failed_input_for_a_long_name(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: with no limit the same members are admitted and the archive
    is recorded as no failed input."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(archive_converter, "_PATH_LENGTH_LIMIT", None)
    members = [zipfile.ZipInfo("ok.js"), zipfile.ZipInfo("a_much_longer_name.js")]

    kept = converter.inspect_members(
        members, target_path=tmp_path, archive="a.zip", archive_file="a.zip"
    )

    assert kept == members
    assert converter.failed_inputs == []


def test_a_plain_gzip_whose_file_name_passes_the_host_limit_is_a_failed_input(
    test_plugin_context, tmp_path, monkeypatch
):
    """A ``.gz`` of one file is inspected as its one decompressed name, and the
    archive is dropped when that name is refused; the refusal alone left it out
    of the completeness gate."""
    converter = _converter(test_plugin_context)
    monkeypatch.setattr(
        archive_converter, "_PATH_LENGTH_LIMIT", len(str(tmp_path)) + 1 + 3
    )

    kept = converter.inspect_members(
        ["data.json"],
        target_path=tmp_path,
        archive="data.json.gz",
        archive_file=str(Path(test_plugin_context.source_dir) / "data.json.gz"),
    )

    assert kept == []
    (failed,) = converter.failed_inputs
    assert (failed.path, failed.kind) == ("data.json.gz", "input")


def test_an_archive_with_a_member_past_the_host_limit_is_not_recorded_whole(
    test_plugin_context, monkeypatch
):
    """End to end: the other member is extracted, the archive is a failed input of
    kind input, and it is left out of the archives recorded as extracted whole.
    The length arithmetic is the neighbors' subject, so the check is stood in for
    by a name."""
    monkeypatch.setattr(
        archive_converter,
        "_written_path_over_limit",
        lambda name, kind, target: (
            "9 characters with the extraction directory, limit 1"
            if name.startswith("toolong")
            else None
        ),
    )
    raw = zip_bytes({"ok.js": "ok = 1\n", "toolong.js": "x = 1\n"})

    converter, results = _convert_one(test_plugin_context, monkeypatch, "a.zip", raw)

    (extracted,) = results
    assert sorted(p.name for p in extracted.rglob("*") if p.is_file()) == ["ok.js"]
    (failed,) = converter.failed_inputs
    assert (failed.path, failed.kind) == ("a.zip", "input")
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


def _fake_registry(monkeypatch, value=None, error=None):
    """A ``winreg`` for the host the test runs on: ``LongPathsEnabled`` reads
    ``value``, or the open of the key raises ``error``."""

    def open_key(root, path):
        if error is not None:
            raise error
        return contextlib.nullcontext()

    fake = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE=0,
        OpenKey=open_key,
        QueryValueEx=lambda key, name: (value, 4),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(archive_converter, "_on_windows", lambda: True)


@pytest.mark.parametrize(
    ("value", "error", "expected"),
    [
        pytest.param(1, None, 32767, id="long-paths-enabled"),
        pytest.param(0, None, 260, id="long-paths-off"),
        pytest.param(None, None, 260, id="value-is-not-1"),
        pytest.param(None, FileNotFoundError("no key"), 260, id="key-absent"),
    ],
)
def test_a_windows_host_has_the_path_limit_its_long_path_setting_gives(
    monkeypatch, value, error, expected
):
    """MAX_PATH is the limit only where long paths are off: a host with
    ``LongPathsEnabled`` takes a path past it, and refusing a member there for 260
    lost a file the host could have written. A setting that cannot be read leaves
    MAX_PATH, the side that refuses a member by name."""
    _fake_registry(monkeypatch, value=value, error=error)

    assert archive_converter._host_path_length_limit() == expected


def test_a_host_that_is_not_windows_has_no_path_limit(monkeypatch):
    """The control: the registry is not asked off Windows."""
    monkeypatch.setattr(archive_converter, "_on_windows", lambda: False)

    assert archive_converter._host_path_length_limit() is None


def test_a_later_name_bound_for_a_taken_path_is_refused_when_members_are_names(
    test_plugin_context, tmp_path
):
    """A listing of bare names has no member object to rename, so the later of two
    names written to one path is refused, not admitted beside the first."""
    converter = _converter(test_plugin_context)

    kept = converter.inspect_members(
        ["pkg/a.py", "pkg/a.py"], target_path=tmp_path, archive="a.tar"
    )

    assert kept == ["pkg/a.py"]
    (refused,) = converter.refused_inputs
    assert refused.member == "pkg/a.py"
    assert "same path" in refused.reason


def test_a_later_member_object_bound_for_a_taken_path_is_still_renamed(
    test_plugin_context, tmp_path
):
    """The control: member objects keep the renaming shape, with no refusal. The
    later member is placed in a numbered directory beside the first, its file
    name kept, so a scanner that finds a file by its name still reads it."""
    converter = _converter(test_plugin_context)
    first = tarfile.TarInfo("pkg/a.py")
    second = tarfile.TarInfo("pkg/a.py")

    kept = converter.inspect_members(
        [first, second], target_path=tmp_path, archive="a.tar"
    )

    assert kept == [first, second]
    assert converter.refused_inputs == []
    assert first.name == "pkg/a.py"
    assert second.name == "pkg/a~2/a.py"


# ---------------------------------------------------------------- windows names


def test_a_zip_member_is_named_as_zipfile_writes_it_on_windows(monkeypatch):
    monkeypatch.setattr(archive_converter, "_on_windows", lambda: True)

    assert archive_converter._member_written_path("dir:x/name?.js ", "zip") == (
        "dir_x/name_.js"
    )
    assert archive_converter.member_source_path("lib.zip", "a*b.py", "zip") == (
        "lib.zip/a_b.py"
    )
    # A tar member is written by tarfile, which folds nothing.
    assert archive_converter._member_written_path("a*b.py", "tar") == "a*b.py"


def test_a_zip_member_keeps_its_name_elsewhere(monkeypatch):
    """The control: on a POSIX host the characters are part of the name."""
    monkeypatch.setattr(archive_converter, "_on_windows", lambda: False)

    assert archive_converter._member_written_path("dir:x/name?.js", "zip") == (
        "dir:x/name?.js"
    )


# ---------------------------------------------------------------- deep paths


def test_an_archive_at_a_deep_path_is_extracted_under_a_name_a_file_system_takes(
    test_plugin_context, monkeypatch
):
    tree = Path(test_plugin_context.source_dir)
    deep = tree.joinpath(*(["d" * 50] * 6))
    deep.mkdir(parents=True)
    archive = deep / "x.zip"
    archive.write_bytes(zip_bytes({"a.py": "x = 1\n"}))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = _converter(test_plugin_context)

    results = converter.convert()

    (extracted,) = results
    assert len(extracted.name.encode("utf-8")) <= 255
    assert (extracted / "a.py").is_file()
    assert converter.failed_inputs == []


def test_two_deep_archives_get_two_target_names():
    long_a = "/".join(["d" * 50] * 6) + "/a.zip"
    long_b = "/".join(["d" * 50] * 6) + "/b.zip"

    name_a = archive_converter._target_name(long_a, long_a)
    name_b = archive_converter._target_name(long_b, long_b)

    assert name_a != name_b
    assert len(name_a.encode("utf-8")) <= 255
    assert archive_converter._target_name("short.zip", "short.zip") == "short__zip"


def test_the_target_name_follows_the_archives_path_in_the_tree_not_the_working_directory():
    """The folded name was the archive's path relative to the process working
    directory: a run from outside the tree wrote the host's absolute path into
    the directory's name, and two runs named one archive two ways."""
    name = archive_converter._target_name(
        "/srv/checkout/lib/bundle.zip", "lib/bundle.zip"
    )

    assert name == "lib_sbundle__zip"


# ---------------------------------------------------------------- workspace output


def test_the_scan_set_leaves_out_the_workspace_output_directory(
    test_plugin_context, monkeypatch
):
    seen = {}

    def fake_scan_set(**kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", fake_scan_set)
    workspace_output = Path(test_plugin_context.output_dir).parent / "workspace-out"
    context = PluginContext(
        source_dir=test_plugin_context.source_dir,
        output_dir=test_plugin_context.output_dir,
        work_dir=test_plugin_context.work_dir,
        config=test_plugin_context.config,
        workspace_output_dir=workspace_output,
    )

    _converter(context).convert()

    assert seen["workspace_output_dir"] == str(context.workspace_output_dir)


def test_a_scan_outside_a_workspace_names_no_workspace_output(
    test_plugin_context, monkeypatch
):
    """The control: with no workspace, the argument is None, as the orchestrator's."""
    seen = {}

    def fake_scan_set(**kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", fake_scan_set)

    _converter(test_plugin_context).convert()

    assert seen["workspace_output_dir"] is None
