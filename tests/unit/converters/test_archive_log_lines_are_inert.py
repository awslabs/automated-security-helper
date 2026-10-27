# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converter's log lines show archive and member names as inert data.

``record_refused_input`` and ``record_failed_input`` log each refusal and failure
during the scan, to the console and to ``ash.log``. The names in them come from
the scanned tree: an escape sequence reached the reader's terminal raw, and rich
markup in a name was rendered, or raised MarkupError inside the archive's
``except``, which turned the archive into a failed input and failed the gate. Each
name is passed through ``inert_text`` and each record is logged with markup off.
The reports had tests for this; the log lines had none.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from tests.utils.host_file_names import skip_unless_the_host_can_name

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

ARCHIVE_NAME = "\x1b[32mgreen.zip"
MEMBERS = ["\x1b[31mred\x1b[0m.zip", "[/b]closing.zip", "[bold]styled[/bold].zip"]


def zip_of(members: Dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture
def ash_records():
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


def convert(context, monkeypatch, files: Dict[str, bytes]):
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, data in files.items():
        (tree / name).write_bytes(data)
        paths.append(str(tree / name))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: list(paths))
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def assert_inert(record: logging.LogRecord) -> None:
    message = record.getMessage()
    assert "\x1b" not in message, repr(message)
    assert getattr(record, "markup", None) is False, message


def test_refused_member_lines_escape_names_and_turn_markup_off(
    test_plugin_context, monkeypatch, ash_records
):
    skip_unless_the_host_can_name(ARCHIVE_NAME)
    data = zip_of({"keep.py": "x = 1\n", **dict.fromkeys(MEMBERS, "nested")})

    converter, results = convert(test_plugin_context, monkeypatch, {ARCHIVE_NAME: data})

    assert len(results) == 1, "a member name changed the archive's outcome"
    assert converter.failed_inputs == []
    lines = [r for r in ash_records if "Skipped member" in r.getMessage()]
    assert len(lines) == len(MEMBERS), [r.getMessage() for r in ash_records]
    for record in lines:
        assert_inert(record)
        assert "'\\x1b[32mgreen.zip'" in record.getMessage()
    messages = "\n".join(r.getMessage() for r in lines)
    assert "\\x1b[31mred\\x1b[0m.zip" in messages
    assert "[/b]closing.zip" in messages
    assert "[bold]styled[/bold].zip" in messages


def test_a_failed_input_line_escapes_the_name_and_turns_markup_off(
    test_plugin_context, monkeypatch, ash_records
):
    failing_name = "\x1b[33m[bold]bad.zip"
    skip_unless_the_host_can_name(failing_name)
    converter, _ = convert(
        test_plugin_context, monkeypatch, {failing_name: b"PK not a zip"}
    )

    assert len(converter.failed_inputs) == 1
    (record,) = [r for r in ash_records if "Could not convert" in r.getMessage()]
    assert_inert(record)
    assert "\\x1b[33m[bold]bad.zip" in record.getMessage()
