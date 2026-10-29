# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converter's found-member line names the member by its name.

``inspect_members`` logs each member it keeps. The line held the member object
itself, whose str is the object's repr: ``<TarInfo 'name' at 0x...>`` for tar,
``<ZipInfo filename='name' ...>`` for zip. The repr spells the name its own way
(tar's quotes it like Python source, with a memory address beside it), so the
log named the same member differently per archive kind, and not as any other
line in the run names it. The line now carries the member's name, through
shown_on_one_line like the rest of the function's lines, so a control character
in the name is written as its escape.
"""

from __future__ import annotations

import logging
import tarfile
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)

#: A member name with a control character, as an archive author may write it.
NAME = "pkg/app\x1b[2J.py"


@pytest.fixture
def ash_records():
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=1)
    logger = logging.getLogger("ash")
    level = logger.level
    logger.setLevel(1)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


def _converter(tmp_path: Path) -> archive_converter.ArchiveConverter:
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    return archive_converter.ArchiveConverter(
        context=context, config=archive_converter.ArchiveConverterConfig()
    )


def _member(kind: str):
    if kind == "tar":
        info = tarfile.TarInfo(NAME)
        info.size = 1
        return info
    return zipfile.ZipInfo(NAME)


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_the_found_member_line_names_the_member_as_shown(tmp_path, ash_records, kind):
    converter = _converter(tmp_path)

    kept = converter.inspect_members([_member(kind)], target_path=tmp_path / "out")

    assert len(kept) == 1
    found = [
        record.getMessage()
        for record in ash_records
        if "Found .py file" in record.getMessage()
    ]
    assert len(found) == 1, [record.getMessage() for record in ash_records]
    (line,) = found
    assert "pkg/app\\x1b[2J.py" in line, ascii(line)
    assert "\x1b" not in line, ascii(line)
    assert "TarInfo" not in line and "ZipInfo" not in line, ascii(line)
    assert " at 0x" not in line, ascii(line)
