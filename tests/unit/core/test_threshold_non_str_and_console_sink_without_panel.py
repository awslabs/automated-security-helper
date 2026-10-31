# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two edges of earlier fixes, pinned.

* ``_restrict_severity_threshold`` skipped a scanner threshold of None and
  read a blank string as "take the restricted global"; a threshold that is
  neither None nor a string (``False``, ``0``) reached ``stricter_of``, which
  ranks strings. Such a value is left alone with a warning for the scanner's
  own validation to refuse.
* ``_replace_panel_handler_with_console`` copied the panel handler's level
  with no guard for a display whose handler was already taken off; the
  panel's default level stands in.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest
from rich.console import Console

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return source, output


@pytest.fixture
def restore_handlers():
    original = list(ASH_LOGGER.handlers)
    yield
    ASH_LOGGER.handlers = original


class TestANonStringScannerThresholdIsLeftAlone:
    @pytest.mark.parametrize("own", [False, 0, ["HIGH"]])
    def test_the_value_is_not_ranked_and_stays(self, tmp_path, own):
        source, output = _dirs(tmp_path)
        config = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": own}}}
        )
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        # Red at the previous tip: the value reached stricter_of. LOW is
        # stricter than the default global MEDIUM, so a string threshold here
        # would be tightened (the control below); this one is left alone.
        orchestrator._restrict_severity_threshold(config, "LOW")

        options = (config.scanners.model_extra or {})["custom-scanner"]["options"]
        assert options["severity_threshold"] == own

    def test_a_string_threshold_is_still_tightened(self, tmp_path):
        """The control: a looser ladder value is tightened to the request.

        On the ladder a LOWER threshold gates MORE findings, so LOW is the
        stricter request and HIGH the looser configured value.
        """
        source, output = _dirs(tmp_path)
        config = AshConfig(
            scanners={"custom-scanner": {"options": {"severity_threshold": "HIGH"}}}
        )
        orchestrator = ASHScanOrchestrator(source_dir=source, output_dir=output)

        orchestrator._restrict_severity_threshold(config, "LOW")

        options = (config.scanners.model_extra or {})["custom-scanner"]["options"]
        assert options["severity_threshold"] == "LOW"


def test_the_console_sink_is_made_when_no_panel_handler_is_left(restore_handlers):
    display = LiveProgressDisplay(show_progress=True)
    display.console = Console(file=io.StringIO(), width=120)
    ASH_LOGGER.removeHandler(display.log_handler)
    display.log_handler = None

    # Red at the previous tip: AttributeError on None.level.
    display._replace_panel_handler_with_console()

    assert isinstance(display.log_handler, logging.StreamHandler)
    assert display.log_handler in ASH_LOGGER.handlers
    assert display.log_handler.level == 15
    ASH_LOGGER.removeHandler(display.log_handler)
