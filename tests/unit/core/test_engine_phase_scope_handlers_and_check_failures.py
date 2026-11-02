# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""EnginePhase reaches the handlers it was handed, survives a raising one, and
tells a raising check from an exclusion.

Three defects of ``EnginePhase``, each pinned by a test red on the tree that
carried it:

* The engine hands a phase the scan's handler filter at construction and then
  sets ``plugin_scope`` (the run's plugin set) on it; ``notify_event`` passed the
  scope alone, so a handler the embedding program subscribed from outside the
  plugin namespace never received a phase event (SCAN_START, SCAN_COMPLETE,
  CONVERT_*, REPORT_*, *_PHASE_*), although the handed filter admits it.
* ``execute`` notified the *_PHASE_START and *_PHASE_COMPLETE events with no
  guard, so one raising handler aborted the scan, and at COMPLETE discarded a
  finished phase's results.
* ``filter_enabled_plugins`` dropped a plugin whose own check raised exactly as
  it dropped an excluded one, so a caller could not record the first as a
  failure.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType

pytestmark = pytest.mark.unit


class _FakePhase(EnginePhase):
    @property
    def phase_name(self) -> str:
        return "scan"

    def _execute_phase(self, aggregated_results, **kwargs):
        return aggregated_results


def _context() -> MagicMock:
    return MagicMock(spec=PluginContext)


class TestPhaseEventsReachTheHandedFilter:
    def test_a_handler_the_handed_filter_admits_is_notified(self, monkeypatch):
        import automated_security_helper.base.engine_phase as engine_phase_module

        def program_handler(**_kwargs):
            return None

        def scope(callback):  # the run's plugins: never the program's handler
            return callback is not program_handler

        def handed(callback):  # the scan's handler filter: admits the program's
            return True

        seen = {}

        def notify(event_type, handler_filter=None, **_data):
            seen["admits_program_handler"] = handler_filter is None or handler_filter(
                program_handler
            )
            return []

        monkeypatch.setattr(engine_phase_module.ash_plugin_manager, "notify", notify)
        phase = _FakePhase(plugin_context=_context(), plugin_filter=handed)
        # What the engine does after building a phase.
        phase.plugin_scope = scope

        phase.notify_event(AshEventType.SCAN_START)

        # Red at the base: the scope alone was passed, and it refuses the
        # program's handler.
        assert seen["admits_program_handler"] is True

    def test_a_handler_neither_admits_is_still_refused(self, monkeypatch):
        """The control: the union does not open the scope to every handler."""
        import automated_security_helper.base.engine_phase as engine_phase_module

        def foreign_handler(**_kwargs):
            return None

        seen = {}

        def notify(event_type, handler_filter=None, **_data):
            seen["admits_foreign"] = handler_filter is None or handler_filter(
                foreign_handler
            )
            return []

        monkeypatch.setattr(engine_phase_module.ash_plugin_manager, "notify", notify)
        phase = _FakePhase(plugin_context=_context(), plugin_filter=lambda cb: False)
        phase.plugin_scope = lambda cb: False

        phase.notify_event(AshEventType.SCAN_START)

        assert seen["admits_foreign"] is False


class TestARaisingPhaseEventHandlerDoesNotAbortThePhase:
    def test_the_results_survive_a_raising_complete_handler(self):
        phase = _FakePhase(plugin_context=_context())
        calls = []

        def raising_at_complete(event_type, **kwargs):
            calls.append(event_type)
            if event_type == AshEventType.SCAN_PHASE_COMPLETE:
                raise RuntimeError("a subscriber crashed")

        phase.notify_event = raising_at_complete  # type: ignore[method-assign]
        agg = AshAggregatedResults()

        # Red at the base: the RuntimeError escaped execute() and the finished
        # phase's results were discarded with it.
        results = phase.execute(aggregated_results=agg)

        assert results is agg
        assert AshEventType.SCAN_PHASE_START in calls
        assert AshEventType.SCAN_PHASE_COMPLETE in calls

    def test_a_raising_start_handler_still_ends_the_run_as_itself(self):
        """The contract the engine's real-run test pins: a START handler's error
        propagates as itself, before any of the phase's work has run."""
        phase = _FakePhase(plugin_context=_context())
        failure = RuntimeError("a start subscriber crashed")

        def raising_at_start(event_type, **kwargs):
            if event_type == AshEventType.SCAN_PHASE_START:
                raise failure

        phase.notify_event = raising_at_start  # type: ignore[method-assign]

        # Red at the previous tip: the guard swallowed the START handler's error
        # too, and the phase ran on.
        with pytest.raises(RuntimeError) as ended:
            phase.execute(aggregated_results=AshAggregatedResults())
        assert ended.value is failure

    def test_a_complete_handlers_failure_is_logged_redacted(self, caplog):
        """The logged text carries no value the run's config read from the
        environment, which a plugin's exception can quote."""
        secret = "zz-quoted-env-value-4411"
        context = _context()
        context.config = SimpleNamespace(_environment_values=[secret])
        phase = _FakePhase(plugin_context=context)

        def raising_at_complete(event_type, **kwargs):
            if event_type == AshEventType.SCAN_PHASE_COMPLETE:
                raise RuntimeError(f"complete handler cannot use {secret}")

        phase.notify_event = raising_at_complete  # type: ignore[method-assign]

        with caplog.at_level(logging.ERROR):
            phase.execute(aggregated_results=AshAggregatedResults())

        logged = [m for m in caplog.messages if "Failed to notify" in m]
        assert logged, caplog.messages
        assert all("complete handler cannot use" in m for m in logged)
        # Red at the previous tip: the line carried the value as the handler
        # quoted it.
        assert all(secret not in m for m in logged), logged


class TestARaisingCheckIsReportedApartFromAnExclusion:
    def test_the_failures_dict_names_the_instance_whose_check_raised(self):
        phase = _FakePhase(plugin_context=_context())
        raising = MagicMock()
        raising.config.enabled = True
        raising.is_python_only.side_effect = RuntimeError("cannot tell")
        excluded = MagicMock()
        excluded.config.enabled = True
        excluded.is_python_only.return_value = False

        failures: dict = {}
        survivors = phase.filter_enabled_plugins(
            plugin_instances=[raising, excluded],
            plugin_context=phase.plugin_context,
            python_only=True,
            check_dependencies=False,
            failures=failures,
        )

        assert survivors == []
        # Red at the base: the parameter did not exist, and both were dropped
        # the same way.
        assert set(failures) == {id(raising)}
        assert "RuntimeError" in failures[id(raising)]

    def test_the_failure_text_hides_the_plugins_own_environment_values(self):
        """The text reaches the scan phase's ERROR row, ash.log and the reports;
        it is redacted with the run's configuration values and with the values
        the plugin itself read from the environment, as the phases' other
        plugin-sourced lines are."""
        run_secret = "zz-run-env-value-7731"
        own_secret = "zz-plugin-env-value-7732"
        context = _context()
        context.config = SimpleNamespace(_environment_values=[run_secret])
        phase = _FakePhase(plugin_context=context)
        raising = MagicMock()
        raising.config.enabled = True
        raising._environment_values.return_value = [own_secret]
        raising.is_python_only.side_effect = RuntimeError(
            f"cannot tell with {run_secret} or {own_secret}"
        )

        failures: dict = {}
        phase.filter_enabled_plugins(
            plugin_instances=[raising],
            plugin_context=phase.plugin_context,
            python_only=True,
            check_dependencies=False,
            failures=failures,
        )

        text = failures[id(raising)]
        assert "RuntimeError" in text
        assert run_secret not in text, text
        # Red at the previous tip: only the run's values were redacted.
        assert own_secret not in text, text
