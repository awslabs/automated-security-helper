# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The "found no files to convert" line names only converters that had no input.

When some converter produced paths, the phase logs which converters found nothing
to convert. A converter whose every input failed returned no paths too, and listing
it there would tell the reader it had nothing to do, when it is the one that left
inputs unscanned.
"""

from __future__ import annotations

import logging
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from tests.unit.core.test_convert_phase_failure_recording import (
    _EmptyConverter,
    _FailingInputsConverter,
    _ProductiveConverter,
    _run,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-no-files-line"),
    )


@pytest.fixture
def info_lines():
    lines: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield lines
    finally:
        logger.removeHandler(handler)


def test_a_converter_whose_inputs_all_failed_is_not_listed_as_finding_none(
    context, info_lines
):
    _run(context, [_ProductiveConverter, _EmptyConverter, _FailingInputsConverter])

    (line,) = [m for m in info_lines if "found no files to convert" in m]
    assert "empty-converter" in line
    assert "failing-inputs-converter" not in line
