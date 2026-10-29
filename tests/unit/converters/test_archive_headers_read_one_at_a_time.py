# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tar is read one header at a time, and reading stops at the header over a limit.

Reading every header first (``TarFile.getmembers``) decompresses the whole stream,
member data included, before any limit is checked. Here the stream is unreadable
right after the header that takes the archive over ``max_members``: an archive read
one header at a time is refused for ``max_members`` before reaching the damage,
while one read whole fails on the damage instead.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zlib
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from tests.utils.archive_builders import GENEROUS_LIMITS, incompressible

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)
LIMIT = 3


def damaged_after_the_fourth_header() -> bytes:
    """A tar.gz of four members whose gzip stream is damaged inside the fourth's data."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for index in range(LIMIT):
            data = f"n = {index}\n".encode()
            info = tarfile.TarInfo(f"m{index}.py")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        data = incompressible(512 * 1024, seed=7)
        info = tarfile.TarInfo("big.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    compressed = bytearray(gzip.compress(raw.getvalue(), mtime=0))
    # The fourth member's data is incompressible, so it fills most of the stream;
    # overwrite a stretch in its middle.
    middle = len(compressed) // 2
    compressed[middle : middle + 4096] = b"\xff" * 4096
    return bytes(compressed)


def test_the_stream_after_the_over_limit_header_is_never_read(
    test_plugin_context, monkeypatch
):
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    archive = tree / "damaged.tar.gz"
    archive.write_bytes(damaged_after_the_fourth_header())
    with tarfile.open(archive, mode="r:gz") as whole:
        try:
            whole.getmembers()
        except (tarfile.TarError, OSError, EOFError, zlib.error):
            pass
        else:
            raise AssertionError("the damage must stop a reader of the whole stream")
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    config = ArchiveConverterConfig(
        options=ArchiveConverterConfigOptions(
            **{**GENEROUS_LIMITS, "max_members": LIMIT}
        )
    )
    test_plugin_context.config.converters.archive = config
    converter = ArchiveConverter(context=test_plugin_context, config=config)

    assert converter.convert() == []

    assert [(r.path, r.member, r.limit) for r in converter.refused_inputs] == [
        ("damaged.tar.gz", None, "max_members")
    ]
