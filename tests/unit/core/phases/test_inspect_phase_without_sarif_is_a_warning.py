# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An inspection that finds no SARIF is a warning, not an error with no cause.

``analyze_sarif_fields`` ends a command-line run with ``typer.Exit(code=1)`` when
it finds no SARIF file. ``typer.Exit`` is a ``RuntimeError``, so the phase's broad
``except Exception`` caught it and logged ``Error during inspection phase: `` with
nothing after the colon, because an Exit carries no message.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

from automated_security_helper.core.phases.inspect_phase import InspectPhase
from automated_security_helper.utils import log as ash_log

pytestmark = pytest.mark.unit


@pytest.fixture
def logger(monkeypatch):
    recorder = MagicMock()
    monkeypatch.setattr(ash_log, "ASH_LOGGER", recorder)
    # The phase module bound the name at import, so it is replaced there too.
    from automated_security_helper.core.phases import inspect_phase

    monkeypatch.setattr(inspect_phase, "ASH_LOGGER", recorder)
    return recorder


def _run(output_dir: Path) -> AshAggregatedResults:
    context = MagicMock()
    context.output_dir = output_dir
    phase = InspectPhase(plugin_context=context)
    return phase._execute_phase(aggregated_results=AshAggregatedResults())


def test_no_sarif_files_is_a_warning_and_not_an_error(tmp_path, logger):
    output_dir = tmp_path / "empty-out"
    output_dir.mkdir()

    result = _run(output_dir)

    # Red at the base: error("Error during inspection phase: ") with no cause.
    logger.error.assert_not_called()
    logger.warning.assert_called_once()
    message = logger.warning.call_args.args[0]
    assert "exit code 1" in message
    assert str(output_dir) in message
    assert isinstance(result, AshAggregatedResults)


def test_a_real_failure_is_still_an_error_with_its_cause(tmp_path, logger, monkeypatch):
    from automated_security_helper.utils import sarif_field_analysis

    def broken(**_kwargs):
        raise ValueError("the analysis could not be written")

    monkeypatch.setattr(sarif_field_analysis, "analyze_sarif_fields", broken)
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    _run(output_dir)

    logger.error.assert_called_once()
    assert "the analysis could not be written" in logger.error.call_args.args[0]
    logger.warning.assert_not_called()
