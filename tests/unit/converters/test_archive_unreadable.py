# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive the converter cannot read is a failed input, cleaned up, and fails the gate.

A `.zip`, `.tar` or `.gz` that zipfile and tarfile cannot read (a bad CRC, a
truncated stream, a damaged gzip file, an empty file) used
to leave only a log line, and a zip that failed part way left the members already
written on disk, where the scanners read them as if the archive had been
extracted. Each is now one failed input (``converter_results.archive.failed_inputs``,
the record a notebook that could not be converted gets), nothing it wrote is left
behind, and the completeness gate counts it.

tarfile ends its member list without an error when a header after the first is
damaged, or the archive stops at a member boundary or inside a header, so those
tars extracted their first members and recorded nothing. A tar whose members do
not end at an end-of-archive block is now unreadable too.

An archive whose members collide (a file where an earlier member made a directory,
or the reverse) is no longer unreadable: the admission check refuses the later
member alone before anything is written, and the rest is extracted (REFUSED_MEMBER
below). The extraction-time fallback for a pair the check misses is tested in
test_archive_failures_are_input_errors.py.
"""

from __future__ import annotations

import gzip
import io
import logging
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.utils.scan_output_dirs import CONVERTED_SOURCES_FILE_NAME
from tests.utils.archive_builders import tar_bytes

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def bad_crc_zip() -> bytes:
    """A stored zip whose second member's CRC is wrong: the first extracts first."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("ok.py", "print(1)\n")
        archive.writestr("bad.py", "print(2)\n")
    raw = bytearray(buffer.getvalue())
    second = raw.rfind(b"PK\x01\x02")
    struct.pack_into("<I", raw, second + 16, 0xDEADBEEF)
    return bytes(raw)


def truncated_tar() -> bytes:
    data = b"print(2)\n" * 200
    return tar_bytes({"v.py": data})[:700]


THREE_MEMBERS = {"a.py": b"a = 1\n", "b.py": b"b = 2\n", "c.py": b"c = 3\n"}
#: Each member of THREE_MEMBERS is one header block and one data block, so the
#: second header starts here.
SECOND_HEADER = 2 * tarfile.BLOCKSIZE


def three_member_tar() -> bytearray:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in THREE_MEMBERS.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    raw = bytearray(buffer.getvalue())
    assert raw[SECOND_HEADER : SECOND_HEADER + 4] == b"b.py"
    return raw


def tar_with_damaged_second_header() -> bytes:
    raw = three_member_tar()
    raw[SECOND_HEADER + 148 : SECOND_HEADER + 156] = b"0000000\x00"
    return bytes(raw)


def tar_cut_at_a_member_boundary() -> bytes:
    return bytes(three_member_tar()[:SECOND_HEADER])


def tar_cut_inside_a_header() -> bytes:
    return bytes(three_member_tar()[: SECOND_HEADER + 100])


def tar_with_noise_for_a_header() -> bytes:
    raw = three_member_tar()
    raw[SECOND_HEADER : SECOND_HEADER + tarfile.BLOCKSIZE] = bytes(
        (i * 37 + 11) % 251 for i in range(tarfile.BLOCKSIZE)
    )
    return bytes(raw)


#: A file member named like the directory an earlier member made, and the reverse:
#: the second member of each cannot be written where the first put something else.
FILE_OVER_DIRECTORY = [
    ("d.py/a.py", b"a = 1\n"),
    ("d.py", b"d = 2\n"),
    ("z.py", b"z = 3\n"),
]
DIRECTORY_OVER_FILE = [
    ("d.py", b"d = 2\n"),
    ("d.py/a.py", b"a = 1\n"),
    ("z.py", b"z = 3\n"),
]


def zip_of(members) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def tar_of(members) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def empty_valid_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    return buffer.getvalue()


UNREADABLE = [
    pytest.param("crc.zip", bad_crc_zip(), id="bad-crc-zip"),
    pytest.param("cut.tar", truncated_tar(), id="truncated-tar"),
    pytest.param(
        "data.json.gz",
        gzip.compress(b'{"a": 1}\n' * 200)[:-30],
        id="damaged-plain-gzip",
    ),
    pytest.param(
        "crc.json.gz",
        gzip.compress(b'{"a": 1}\n' * 200)[:-8] + b"\x00" * 4 + struct.pack("<I", 1800),
        id="plain-gzip-bad-crc",
    ),
    pytest.param("empty.zip", b"", id="empty-file"),
    pytest.param("noise.tar.gz", b"\x1f\x8b" + b"\x00" * 64, id="damaged-gzip"),
]

#: Archives whose members collide (a file where an earlier member made a directory,
#: or a member under a path an earlier member made a file). These used to fail the
#: whole archive at extraction; the admission check now refuses the later member
#: alone, before anything is written, and the rest of the archive is extracted and
#: scanned. (refused member, the files extracted) beside each.
REFUSED_MEMBER = [
    pytest.param(
        "clash.zip",
        zip_of(FILE_OVER_DIRECTORY),
        "d.py",
        ["a.py", "z.py"],
        id="zip-file-over-a-directory",
    ),
    pytest.param(
        "clash.tar",
        tar_of(FILE_OVER_DIRECTORY),
        "d.py",
        ["a.py", "z.py"],
        id="tar-file-over-a-directory",
    ),
    pytest.param(
        "clash.zip",
        zip_of(DIRECTORY_OVER_FILE),
        "d.py/a.py",
        ["d.py", "z.py"],
        id="zip-directory-over-a-file",
    ),
    pytest.param(
        "clash.tar",
        tar_of(DIRECTORY_OVER_FILE),
        "d.py/a.py",
        ["d.py", "z.py"],
        id="tar-directory-over-a-file",
    ),
]


#: Tars whose damage sits PAST a readable member: the skip-tolerant listing
#: extracts the members it can read and records the remainder as one FAILED
#: input ("extracted only in part"), which the completeness gate reads, and
#: archives_extracted_whole holds the archive back from whole-archive
#: consumers. The all-or-nothing posture for these shapes is superseded.
EXTRACTED_IN_PART = [
    pytest.param(
        "header.tar", tar_with_damaged_second_header(), id="tar-damaged-second-header"
    ),
    pytest.param(
        "header.tar.gz",
        gzip.compress(tar_with_damaged_second_header()),
        id="tar-gz-damaged-second-header",
    ),
    pytest.param(
        "boundary.tar", tar_cut_at_a_member_boundary(), id="tar-cut-at-member-boundary"
    ),
    pytest.param(
        "boundary.tar.gz",
        gzip.compress(tar_cut_at_a_member_boundary()),
        id="tar-gz-cut-at-member-boundary",
    ),
    pytest.param("inside.tar", tar_cut_inside_a_header(), id="tar-cut-inside-header"),
    pytest.param(
        "noise.tar", tar_with_noise_for_a_header(), id="tar-noise-for-a-header"
    ),
]


def convert(context, monkeypatch, name: str, data: bytes):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / name
    archive.write_bytes(data)
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def files_under(converter) -> List[str]:
    """Every file the converter extracted; its record of the sources is not one."""
    root = Path(converter.results_dir)
    if not root.exists():
        return []
    return sorted(
        p.name
        for p in root.rglob("*")
        if p.is_file() and p != root / CONVERTED_SOURCES_FILE_NAME
    )


@pytest.mark.parametrize("name, data", UNREADABLE)
def test_an_unreadable_archive_is_one_failed_input_and_leaves_nothing(
    name, data, test_plugin_context, monkeypatch, ash_warnings
):
    converter, results = convert(test_plugin_context, monkeypatch, name, data)

    assert results == []
    assert files_under(converter) == [], "a member of the unreadable archive is left"
    assert [r.path for r in converter.failed_inputs] == [name]
    assert converter.failed_inputs[0].reason
    assert converter.refused_inputs == []
    assert [w.getMessage() for w in ash_warnings if f"'{name}'" in w.getMessage()] != []


@pytest.mark.parametrize("name, data", UNREADABLE)
def test_an_unreadable_archive_fails_the_completeness_gate(
    name, data, test_plugin_context, monkeypatch
):
    converter, _ = convert(test_plugin_context, monkeypatch, name, data)
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], failed_inputs=list(converter.failed_inputs)
    )

    listed = incomplete_converters(model)

    assert [row.name for row in listed] == ["archive"]
    assert name in listed[0].reason


@pytest.mark.parametrize("name, data", EXTRACTED_IN_PART)
def test_a_damaged_tar_is_extracted_in_part_with_the_loss_recorded(
    name, data, test_plugin_context, monkeypatch, ash_warnings
):
    """The readable members are extracted; the remainder is ONE failed input."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        archives_extracted_whole,
    )

    converter, results = convert(test_plugin_context, monkeypatch, name, data)

    (extracted,) = results
    assert files_under(converter) != [], "the readable members are extracted"
    assert [r.path for r in converter.failed_inputs] == [name]
    assert "extracted only in part" in converter.failed_inputs[0].reason
    assert converter.refused_inputs == [], "one record per archive, failed category"
    assert archives_extracted_whole(test_plugin_context) == set(), (
        "a partially-extracted archive is held back from whole-archive consumers"
    )


@pytest.mark.parametrize("name, data", EXTRACTED_IN_PART)
def test_a_tar_extracted_in_part_fails_the_completeness_gate(
    name, data, test_plugin_context, monkeypatch
):
    converter, _ = convert(test_plugin_context, monkeypatch, name, data)
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], failed_inputs=list(converter.failed_inputs)
    )

    listed = incomplete_converters(model)

    assert [row.name for row in listed] == ["archive"]
    assert name in listed[0][1]


def test_a_valid_empty_zip_is_not_refused(test_plugin_context, monkeypatch):
    converter, results = convert(
        test_plugin_context, monkeypatch, "none.zip", empty_valid_zip()
    )

    assert len(results) == 1
    assert converter.refused_inputs == []
    assert converter.failed_inputs == []


@pytest.mark.parametrize("name, data, refused_member, extracted", REFUSED_MEMBER)
def test_a_colliding_member_is_refused_alone_and_the_rest_is_extracted(
    name, data, refused_member, extracted, test_plugin_context, monkeypatch
):
    """The later member of a colliding pair is refused by name before anything is
    written; the archive is not a failed input, its other members are scanned, and
    it is not recorded as extracted whole. Before, the extractor raised on the
    pair and the whole archive was one failed input with nothing left behind."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        archives_extracted_whole,
    )

    converter, results = convert(test_plugin_context, monkeypatch, name, data)

    assert len(results) == 1
    assert files_under(converter) == extracted
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member) == (name, refused_member)
    assert archives_extracted_whole(test_plugin_context) == set()


@pytest.mark.parametrize("name, data, refused_member, extracted", REFUSED_MEMBER)
def test_a_refused_member_leaves_the_completeness_gate_alone(
    name, data, refused_member, extracted, test_plugin_context, monkeypatch
):
    """A refusal without a limit is not lost coverage the gate counts: the member
    the extractor could not have written is named in the results, and the archive's
    other members were scanned."""
    converter, _ = convert(test_plugin_context, monkeypatch, name, data)
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], failed_inputs=list(converter.failed_inputs)
    )

    assert incomplete_converters(model) == []


@pytest.mark.parametrize("name, data, refused_member, extracted", REFUSED_MEMBER)
def test_a_collision_is_reported_by_member_not_by_work_directory_path(
    name, data, refused_member, extracted, test_plugin_context, monkeypatch
):
    """The refusal names the member by its name in the archive, and its reason
    carries no path of the work directory (the earlier shape quoted the OS
    error's path, which was the work directory's, so the member's path was
    substituted; the refusal is built from the names alone)."""
    converter, _ = convert(test_plugin_context, monkeypatch, name, data)

    (refused,) = converter.refused_inputs
    assert refused.member == refused_member
    assert str(Path(converter.results_dir)) not in refused.reason, refused.reason
    assert str(Path(test_plugin_context.work_dir)) not in refused.reason, refused.reason
    assert "/" not in refused.reason.replace("d.py/a.py", ""), refused.reason


def test_a_readable_archive_is_extracted_as_before(test_plugin_context, monkeypatch):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        payload = b"print('ok')\n"
        info = tarfile.TarInfo("ok.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    converter, results = convert(
        test_plugin_context, monkeypatch, "ok.tar.gz", data.getvalue()
    )

    (extracted,) = results
    assert (extracted / "ok.py").read_bytes() == b"print('ok')\n"
    assert converter.refused_inputs == []


@pytest.mark.parametrize("gz", [False, True], ids=["tar", "tar-gz"])
def test_an_intact_tar_extracts_every_member(gz, test_plugin_context, monkeypatch):
    raw = bytes(three_member_tar())
    name = "whole.tar.gz" if gz else "whole.tar"
    converter, results = convert(
        test_plugin_context, monkeypatch, name, gzip.compress(raw) if gz else raw
    )

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == sorted(THREE_MEMBERS)
    assert converter.failed_inputs == []


def test_a_tar_ending_in_one_end_block_is_extracted(test_plugin_context, monkeypatch):
    """tarfile itself stops at the first end-of-archive block, so one is enough."""
    raw = bytes(three_member_tar()[: 6 * tarfile.BLOCKSIZE]) + tarfile.NUL * 512
    converter, results = convert(test_plugin_context, monkeypatch, "one.tar", raw)

    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == sorted(THREE_MEMBERS)
    assert converter.failed_inputs == []


def test_a_tar_of_end_blocks_only_is_an_empty_archive(test_plugin_context, monkeypatch):
    converter, results = convert(
        test_plugin_context, monkeypatch, "none.tar", tarfile.NUL * 1024
    )

    assert len(results) == 1
    assert converter.failed_inputs == []
    assert converter.refused_inputs == []


def empty_tar_bytes() -> bytes:
    """What ``tar -cf empty.tar -T /dev/null`` writes: end blocks only, a record long."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w"):
        pass
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("name", "data"),
    [
        pytest.param("empty.tar", empty_tar_bytes(), id="tar"),
        pytest.param("empty.tar.gz", gzip.compress(empty_tar_bytes()), id="tar-gz"),
    ],
)
def test_a_real_empty_tar_is_an_empty_archive_recorded_whole(
    name, data, test_plugin_context, monkeypatch
):
    """A valid archive with no members: tarfile.open opens it, so the converter
    extracts it to nothing, records no failure and counts it as extracted whole;
    reading its first block of zeros as "not a tar" made it fail the completeness
    gate with a false reason."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        archives_extracted_whole,
    )

    converter, results = convert(test_plugin_context, monkeypatch, name, data)

    assert len(results) == 1
    assert files_under(converter) == []
    assert converter.failed_inputs == []
    assert converter.refused_inputs == []
    assert archives_extracted_whole(test_plugin_context) == {name}
