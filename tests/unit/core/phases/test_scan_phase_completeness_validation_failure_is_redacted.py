# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A completeness validation that raised reports its error without environment values.

Why these tests exist
---------------------
``ScanPhase._validate_result_completeness`` swallows an exception from the
completeness pass so the scan can continue, and reports it in the log and as an
error event. The text of that exception can quote a value the configuration read
from the environment (a token in a path, a URL with a credential). The log line
and the event carried it as the exception printed it, where every other place
that shows an error it did not raise redacts it with the configuration's
environment values.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

ENV_VALUE = "env-read-token-9d41c"


def _phase(tmp_path, validation_manager) -> tuple[ScanPhase, AshAggregatedResults]:
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    config = get_default_config()
    config._environment_values = [ENV_VALUE]
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = validation_manager
    return phase, aggregated


def test_the_logged_and_notified_error_carries_no_environment_value(
    tmp_path, caplog, monkeypatch
):
    manager = MagicMock()
    manager.ensure_complete_results.side_effect = RuntimeError(
        f"could not read {ENV_VALUE}"
    )
    phase, aggregated = _phase(tmp_path, manager)
    notify = MagicMock()
    monkeypatch.setattr(phase, "notify_event", notify)

    with caplog.at_level(logging.ERROR):
        phase._validate_result_completeness(aggregated)

    # Red at the base: the log line and the event's message and exception both
    # carried the value as the exception printed it.
    assert "could not read" in caplog.text
    assert ENV_VALUE not in caplog.text
    sent = repr(notify.call_args_list)
    assert "could not read" in sent
    assert ENV_VALUE not in sent
