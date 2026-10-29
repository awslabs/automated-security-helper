# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ash.log.jsonl holds no "##name[" a CI runner would read as a command.

Why this exists
---------------
A CI step may print ASH's JSONL log, and a record quotes text the scanned tree
chose: a file name, a tool's output. JSON escapes a line break, so no "::" can
start a line, but "##vso[" (and "##[", "##teamcity[") is read anywhere in a line
and JSON leaves it as it is. The formatter writes the first "#" of each with
JSON's own escape, so the line still parses to the same record.
"""

from __future__ import annotations

import json
import logging
import re

import pytest

from automated_security_helper.utils.log import get_logger

pytestmark = pytest.mark.unit

#: A record quoting a file name that holds each runner's named-command form.
MESSAGE = "scanned x##vso[task.setvariable variable=x]1 ##[warning]y ##teamcity[z]"


def test_a_jsonl_line_holds_no_named_command_and_reads_back(tmp_path):
    logger = get_logger(
        level=logging.INFO,
        output_dir=tmp_path,
        log_format="JSONL",
        show_progress=False,
        use_color=False,
    )
    logger.warning(MESSAGE)
    for handler in logger.handlers:
        handler.flush()

    (log,) = sorted(tmp_path.rglob("*.jsonl"))
    lines = [
        line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    records = [json.loads(line) for line in lines]
    # The control: the record was written, and reads back as it was logged.
    assert any(record.get("message") == MESSAGE for record in records), records
    assert not [line for line in lines if re.search(r"##[A-Za-z]*\[", line)], lines
