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
  failed to decompress, and was recorded as unreadable.
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
import io
import struct
import tarfile
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
    record, 76 bytes past the zip64 end record the current releases move it to."""
    real = archive_converter._zip_end_record
    names = vars(zipfile)

    def older(handle):
        record = real(handle)
        if record and record[names["_ECD_SIGNATURE"]] == names["stringEndArchive64"]:
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


# ---------------------------------------------------------------- gzip trailing bytes


def test_a_tar_gz_followed_by_other_bytes_is_extracted(
    test_plugin_context, monkeypatch
):
    raw = tar_bytes({"a.py": "x = 1\n", "b.py": "y = 2\n"}, gz=True) + b"TRAILER\n"

    converter, results = _convert_one(
        test_plugin_context, monkeypatch, "src.tar.gz", raw
    )

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == ["a.py", "b.py"]
    assert converter.failed_inputs == []
    assert converter.refused_inputs == []


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
    """The control: member objects keep the renaming shape, with no refusal."""
    converter = _converter(test_plugin_context)
    first = tarfile.TarInfo("pkg/a.py")
    second = tarfile.TarInfo("pkg/a.py")

    kept = converter.inspect_members(
        [first, second], target_path=tmp_path, archive="a.tar"
    )

    assert kept == [first, second]
    assert converter.refused_inputs == []
    assert first.name == "pkg/a.py"
    assert second.name != "pkg/a.py"


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
