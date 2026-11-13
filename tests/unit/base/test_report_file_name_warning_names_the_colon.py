# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused report file name's warning names every character the rule refuses.

``is_report_file_name`` refuses a colon (on NTFS ``report.json:stream`` is a
stream of another reporter's file), and the validator replaced such a value with
the default while its warning named only ``/``, ``\\`` and NUL. An operator whose
value held a colon was told it was not a file name, and not why. The warning
names the colon too.
"""

from __future__ import annotations

import logging
from typing import Annotated, Iterator, List

import pytest
from pydantic import BaseModel

from automated_security_helper.base.options import (
    report_file_name,
    reset_refused_tool_version_warnings,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

KEY = "reporters.probe.options.output_file"


class _Options(BaseModel):
    output_file: Annotated[str, report_file_name(KEY)] = "summary.md"


@pytest.fixture
def warnings_logged() -> Iterator[List[str]]:
    """ASH_LOGGER's warnings; it does not propagate, so caplog would see none."""
    records: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    reset_refused_tool_version_warnings()
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        reset_refused_tool_version_warnings()


def test_the_warning_for_a_name_with_a_colon_names_the_colon(warnings_logged):
    _Options(output_file="ash.sarif:stream")

    (message,) = [text for text in warnings_logged if KEY in text]
    assert "':'" in message, message
