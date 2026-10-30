# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin dropped because its own check raised leaves a visible, redacted trace.

``EnginePhase.filter_enabled_plugins`` swallows an exception from a plugin's
enabled, ``is_python_only`` or dependency check so one plugin cannot take down
the phase. It logged the exception's repr at DEBUG, which neither the console
nor ``ash.log`` keeps by default, so the plugin vanished from a default run
(and the report phase then told the operator its dependencies were not
satisfied). The line is now a warning, and its text goes through ``error_text``
with the values the config read from the environment, as the text it records for
the caller does.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import automated_security_helper.base.engine_phase as engine_phase_module
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext

pytestmark = pytest.mark.unit

SECRET = "tok-secretvalue-from-the-environment"


class _Phase(EnginePhase):
    @property
    def phase_name(self) -> str:
        return "report"

    def _execute_phase(self, aggregated_results, **kwargs):
        return aggregated_results


def _raising_reporter(message: str) -> MagicMock:
    instance = MagicMock()
    instance.config.enabled = True
    instance.validate_plugin_dependencies.side_effect = RuntimeError(message)
    return instance


def _filter(instance, context, failures=None):
    phase = _Phase(plugin_context=MagicMock(spec=PluginContext))
    return phase.filter_enabled_plugins(
        plugin_instances=[instance],
        plugin_context=context,
        failures=failures,
    )


def test_the_exclusion_is_a_warning_naming_the_plugin_and_the_error(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(engine_phase_module, "ASH_LOGGER", logger)

    survivors = _filter(
        _raising_reporter("cannot reach the service"), SimpleNamespace()
    )

    assert survivors == []
    # Red at the base: the line went to logger.debug, below the default level.
    logger.warning.assert_called_once()
    line = logger.warning.call_args.args[0]
    assert "MagicMock" in line
    assert "report phase" in line
    assert "RuntimeError: cannot reach the service" in line
    logger.debug.assert_not_called()


def test_the_environment_values_are_hidden_in_the_line_and_in_the_record(
    monkeypatch,
):
    logger = MagicMock()
    monkeypatch.setattr(engine_phase_module, "ASH_LOGGER", logger)
    context = SimpleNamespace(
        config=SimpleNamespace(_environment_values=[SECRET]),
    )
    failures: dict = {}
    instance = _raising_reporter(f"the service refused {SECRET}")

    _filter(instance, context, failures)

    # Red at the base: the repr was logged as raised, secret included.
    line = logger.warning.call_args.args[0]
    assert SECRET not in line
    assert SECRET not in failures[id(instance)]
    assert "RuntimeError" in line


def test_a_plugin_that_passes_its_checks_logs_nothing(monkeypatch):
    """The control: only a raising check is reported."""
    logger = MagicMock()
    monkeypatch.setattr(engine_phase_module, "ASH_LOGGER", logger)
    instance = MagicMock()
    instance.config.enabled = True
    instance.validate_plugin_dependencies.return_value = True

    survivors = _filter(instance, SimpleNamespace())

    assert survivors == [instance]
    logger.warning.assert_not_called()
