# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A zip's members are counted against max_members before zipfile reads them all.

``zipfile.ZipFile()`` builds a ZipInfo for every central-directory entry when it
opens the archive, about 560 bytes of memory per entry, and the entries were
admitted against ``max_members`` only after that. A zip holding only a central
directory spends 47 bytes on disk per entry, so the memory followed the entry
count, not the limit. The entries are now counted first, by walking their fixed
headers, and an archive with more than ``max_members`` is refused before zipfile
opens it. The walk does not trust the count the end record declares.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)
LIMIT = 10


def zip_of(count: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for i in range(count):
            archive.writestr(f"m{i}.py", f"x = {i}\n")
    return buffer.getvalue()


def with_declared_count(raw: bytes, count: int) -> bytes:
    """``raw`` with both entry counts in its end record set to ``count``."""
    data = bytearray(raw)
    at = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, at + 8, count, count)
    return bytes(data)


def zip64_of(count: int, monkeypatch) -> bytes:
    """A zip that zipfile writes with a zip64 end record and locator.

    The end record's counts are then set to 0xFFFF, as a writer does when the count
    does not fit, so a reader must take them from the zip64 record.
    """
    with monkeypatch.context() as patch:
        patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1, raising=True)
        raw = zip_of(count)
    assert b"PK\x06\x06" in raw and b"PK\x06\x07" in raw
    return with_declared_count(raw, 0xFFFF)


def zip64_declaring_one_entry(count: int, monkeypatch) -> bytes:
    """A zip64 zip whose end record is not saturated and declares one entry.

    zipfile reads the zip64 end record whenever its locator is there, saturated
    or not, so it reads every entry the zip64 record declares.
    """
    with monkeypatch.context() as patch:
        patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1, raising=True)
        raw = zip_of(count)
    return with_declared_count(raw, 1)


def zip64_with_extensible_data(count: int, monkeypatch, extra: int = 16) -> bytes:
    """A zip64 zip with ``extra`` bytes of extensible data in its zip64 end record.

    The record's size field grows by ``extra`` and the bytes sit between the record
    and its locator, which zipfile accounts for when it finds the record from the
    locator's offset.
    """
    with monkeypatch.context() as patch:
        patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1, raising=True)
        raw = bytearray(zip_of(count))
    record = raw.rfind(b"PK\x06\x06")
    locator = raw.rfind(b"PK\x06\x07")
    assert locator == record + 56
    (size,) = struct.unpack_from("<Q", raw, record + 4)
    struct.pack_into("<Q", raw, record + 4, size + extra)
    raw[locator:locator] = bytes(extra)
    return with_declared_count(bytes(raw), 0xFFFF)


def with_a_trailing_byte(raw: bytes) -> bytes:
    """zipfile finds the end record by searching back, so a byte after it is read past."""
    return raw + b"\x00"


def zipfile_allows_for_extensible_data() -> bool:
    """Whether this Python's zipfile opens ``zip64_with_extensible_data``.

    Releases before the fix to ``_EndRecData64`` assume the zip64 end record sits
    right before its locator. Given extensible data they read the saturated counts
    of the plain end record (65535 entries) and locate the central directory from
    that record, so they cannot open the zip and ASH has no directory to count.
    ASH reads the end record with zipfile's own ``_EndRecData``, so the probe asks it
    for the count as well as opening the zip.
    """
    with pytest.MonkeyPatch.context() as patch:
        raw = zip64_with_extensible_data(LIMIT, patch)
    try:
        end_record = vars(zipfile)["_EndRecData"](io.BytesIO(raw))
        if not end_record or end_record[vars(zipfile)["_ECD_ENTRIES_TOTAL"]] != LIMIT:
            return False
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return len(archive.namelist()) == LIMIT
    except (zipfile.BadZipFile, OSError, ValueError, KeyError, struct.error):
        return False


@pytest.fixture
def limited(test_plugin_context, monkeypatch):
    options = test_plugin_context.config.converters.archive.options
    monkeypatch.setattr(options, "max_members", LIMIT, raising=True)
    return test_plugin_context


def convert(context, monkeypatch, data: bytes, forbid_zipfile: bool):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / "many.zip"
    archive.write_bytes(data)
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    opened = []
    if forbid_zipfile:
        real = zipfile.ZipFile

        def spy(*args, **kwargs):
            opened.append(args)
            return real(*args, **kwargs)

        monkeypatch.setattr(f"{ARCHIVE_MODULE}.zipfile.ZipFile", spy, raising=True)
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert(), opened


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda mp: zip_of(200), id="declared-count"),
        pytest.param(
            lambda mp: with_declared_count(zip_of(200), 1), id="count-declared-low"
        ),
        pytest.param(lambda mp: zip64_of(200, mp), id="zip64-count"),
        pytest.param(lambda mp: with_a_trailing_byte(zip_of(200)), id="trailing-byte"),
        pytest.param(
            lambda mp: with_a_trailing_byte(with_declared_count(zip_of(200), 1)),
            id="trailing-byte-count-declared-low",
        ),
        pytest.param(
            lambda mp: zip64_declaring_one_entry(200, mp), id="zip64-not-saturated"
        ),
        pytest.param(
            lambda mp: zip64_with_extensible_data(200, mp), id="zip64-extensible-data"
        ),
    ],
)
def test_a_zip_over_max_members_is_refused_before_zipfile_opens_it(
    build, limited, monkeypatch
):
    data = build(monkeypatch)

    converter, results, opened = convert(limited, monkeypatch, data, True)

    assert results == []
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("many.zip", "max_members")
    ]
    assert opened == [], "zipfile read the central directory before the count"
    assert converter.failed_inputs == []


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda mp: zip_of(LIMIT), id="at-the-limit"),
        pytest.param(lambda mp: zip64_of(LIMIT, mp), id="zip64-at-the-limit"),
        pytest.param(
            lambda mp: with_a_trailing_byte(zip_of(LIMIT)),
            id="trailing-byte-at-the-limit",
        ),
        pytest.param(
            lambda mp: zip64_with_extensible_data(LIMIT, mp),
            id="zip64-extensible-data-at-the-limit",
            marks=pytest.mark.skipif(
                not zipfile_allows_for_extensible_data(),
                reason=(
                    "this zipfile cannot open a zip64 zip with extensible data, so "
                    "ASH refuses it for max_members as a zip it cannot count; "
                    "newer releases of zipfile allow for the data"
                ),
            ),
        ),
    ],
)
def test_a_zip_at_max_members_is_extracted(build, limited, monkeypatch):
    converter, results, _ = convert(limited, monkeypatch, build(monkeypatch), False)

    (extracted,) = results
    assert len(list(extracted.iterdir())) == LIMIT
    assert converter.refused_inputs == []
    assert converter.failed_inputs == []
