# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive the converter cannot read is refused, cleaned up, and fails the gate.

A `.zip`, `.tar` or `.gz` that zipfile and tarfile cannot read (a bad CRC, a
truncated stream, a gzip-compressed file that is not a tarball, an empty file) used
to leave only a log line, and a zip that failed part way left the members already
written on disk, where the scanners read them as if the archive had been
extracted. Each is now one refused input with ``scan_incomplete`` set, nothing it
wrote is left behind, and the completeness gate counts it as it counts an archive
over an extraction limit.
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
from tests.utils.archive_builders import tar_bytes

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


def empty_valid_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    return buffer.getvalue()


UNREADABLE = [
    pytest.param("crc.zip", bad_crc_zip(), id="bad-crc-zip"),
    pytest.param("cut.tar", truncated_tar(), id="truncated-tar"),
    pytest.param("data.json.gz", gzip.compress(b'{"a": 1}\n'), id="plain-gzip"),
    pytest.param("empty.zip", b"", id="empty-file"),
    pytest.param("noise.tar.gz", b"\x1f\x8b" + b"\x00" * 64, id="damaged-gzip"),
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
    root = Path(converter.results_dir)
    if not root.exists():
        return []
    return sorted(p.name for p in root.rglob("*") if p.is_file())


@pytest.mark.parametrize("name, data", UNREADABLE)
def test_an_unreadable_archive_is_refused_once_and_leaves_nothing(
    name, data, test_plugin_context, monkeypatch, ash_warnings
):
    converter, results = convert(test_plugin_context, monkeypatch, name, data)

    assert results == []
    assert files_under(converter) == [], "a member of the unreadable archive is left"
    assert [
        (r.path, r.member, r.limit, r.scan_incomplete) for r in converter.refused_inputs
    ] == [(name, None, None, True)]
    assert converter.refused_inputs[0].reason
    assert [w.getMessage() for w in ash_warnings if f"'{name}'" in w.getMessage()] != []


@pytest.mark.parametrize("name, data", UNREADABLE)
def test_an_unreadable_archive_fails_the_completeness_gate(
    name, data, test_plugin_context, monkeypatch
):
    converter, _ = convert(test_plugin_context, monkeypatch, name, data)
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], refused_inputs=list(converter.refused_inputs)
    )

    listed = incomplete_converters(model)

    assert [n for n, _ in listed] == ["archive"]
    assert name in listed[0][1]


def test_a_valid_empty_zip_is_not_refused(test_plugin_context, monkeypatch):
    converter, results = convert(
        test_plugin_context, monkeypatch, "none.zip", empty_valid_zip()
    )

    assert len(results) == 1
    assert converter.refused_inputs == []


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
