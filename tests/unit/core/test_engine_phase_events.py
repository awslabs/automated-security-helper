"""Regression test: EnginePhase uses AshEventType enum, not strings (M3)."""

from unittest.mock import MagicMock

from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.events import AshEventType


class FakePhase(EnginePhase):
    @property
    def phase_name(self) -> str:
        return "scan"

    def _execute_phase(self, aggregated_results, **kwargs):
        return aggregated_results


def test_execute_notifies_with_enum_not_string():
    ctx = MagicMock(spec=PluginContext)
    phase = FakePhase(plugin_context=ctx)

    captured_events = []

    def spy_notify(event_type, **kwargs):
        captured_events.append(event_type)
        return []

    phase.notify_event = spy_notify

    agg = AshAggregatedResults()
    phase.execute(aggregated_results=agg)

    assert len(captured_events) >= 2
    for evt in captured_events:
        assert isinstance(evt, AshEventType), (
            f"Expected AshEventType enum, got {type(evt).__name__}: {evt!r}"
        )
