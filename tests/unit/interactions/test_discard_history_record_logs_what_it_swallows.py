# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The history-record discard never raises, and says at debug what it swallowed.

Why these tests exist
---------------------
``discard_history_record`` runs while a cancel is propagating, so it must not
raise; its except arm was a bare ``pass``, so a failed unlink left the stale
record with no trace of why. The arm now logs the swallowed failure at debug,
which is the trace a reader follows when a cancelled run still shows in
``ash trend``. The helper is public: the MCP runner's settle discards from its
restore path too (cli/mcp_tools.py).

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

RECORD_ID = "ASH-20260101120000-abcdefabcdef"


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_a_failed_discard_leaves_a_debug_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Red at the base: the name was private and its except arm was a bare pass,
    # so no record of the swallowed failure was emitted.
    from automated_security_helper.interactions.run_ash_scan import (
        discard_history_record,
    )
    from automated_security_helper.utils import scan_history
    from automated_security_helper.utils.log import ASH_LOGGER

    def refused(*_args: Any, **_kwargs: Any) -> bool:
        raise RuntimeError("unlink refused for the test")

    monkeypatch.setattr(scan_history, "discard_run_record", refused)

    handler = _Records()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        # Must not raise: the cancel is what the caller must see.
        discard_history_record({"metadata": {"report_id": RECORD_ID}}, tmp_path)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    swallowed = [
        record
        for record in handler.records
        if record.levelno == logging.DEBUG
        and "unlink refused for the test" in record.getMessage()
    ]
    assert swallowed, [record.getMessage() for record in handler.records]


def test_results_that_name_no_record_discard_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a results value with no report id removes nothing, quietly."""
    from automated_security_helper.interactions.run_ash_scan import (
        discard_history_record,
    )

    history = tmp_path / "history"
    history.mkdir()
    record = history / f"{RECORD_ID}.json"
    record.write_text("{}", encoding="utf-8")

    discard_history_record({"metadata": {}}, tmp_path)
    discard_history_record(None, tmp_path)

    assert record.exists()
