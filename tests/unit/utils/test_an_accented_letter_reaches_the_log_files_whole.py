# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""WindowsSafeFilter's rewrite is for the console: the log files keep the text.

The filter puts a record in the console's terms (ASCII, or the code page the
console writes), and keeps the record's text as logged so the UTF-8 files write
it whole (``_UNFILTERED_ATTR``). The unit tests of the filter read the record
the filter rewrote; these read the two files the real handlers write through
``get_logger``, so a rewrite that reached them, or a character dropped on the
way, fails here whichever rule the console gets.
"""

from __future__ import annotations

import json
import logging

import pytest

from automated_security_helper.utils.log import WindowsSafeFilter, get_logger

pytestmark = pytest.mark.unit

MESSAGE = "the-accent-mark caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{SNOWMAN} end"


@pytest.fixture
def logger_and_files(tmp_path):
    name = "ash_test_log_accent"
    logger = get_logger(
        name=name,
        level="DEBUG",
        output_dir=tmp_path,
        log_format="BOTH",
        show_progress=False,
        use_color=False,
        file_log_level="DEBUG",
        truncate_log=True,
        use_stderr=True,
    )

    def read() -> tuple[str, list[dict]]:
        for handler in logger.handlers:
            handler.flush()
        tabular = (tmp_path / f"{name}.log").read_text(encoding="utf-8")
        lines = (tmp_path / f"{name}.log.jsonl").read_text(encoding="utf-8")
        return tabular, [json.loads(line) for line in lines.splitlines()]

    yield logger, read

    plain = logging.getLogger(name)
    for handler in list(plain.handlers):
        handler.close()
        plain.removeHandler(handler)
    plain.filters = []


@pytest.mark.parametrize(
    "writes",
    [None, lambda character: character == "\N{LATIN SMALL LETTER E WITH ACUTE}"],
    ids=["a console known to write only ASCII", "a code page that writes the e acute"],
)
def test_the_files_hold_the_text_as_logged(logger_and_files, monkeypatch, writes):
    logger, read = logger_and_files
    filters = [f for f in logger.filters if isinstance(f, WindowsSafeFilter)]
    assert filters, "the logger carries no WindowsSafeFilter"
    for windows in filters:
        monkeypatch.setattr(windows, "_active", True)
        monkeypatch.setattr(windows, "_writes", writes)

    logger.info(MESSAGE)

    tabular, records = read()
    assert MESSAGE in tabular, tabular
    mine = [
        record
        for record in records
        if any(MESSAGE in str(value) for value in record.values())
    ]
    assert mine, records
