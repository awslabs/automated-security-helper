# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the plugin system."""

import pytest
from pathlib import Path

from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.base.plugin_context import PluginContext

# Ensure models are rebuilt after all imports
PluginContext.model_rebuild()


@pytest.fixture(autouse=True)
def _own_plugin_registry(monkeypatch):
    """Each test clears and registers into a copy of the global registry, which
    every later test in the worker shares: the built-in event handlers stay
    subscribed and a converter registered here is not left behind
    (test_plugin_system_leaves_the_registry.py)."""
    library = ash_plugin_manager.plugin_library
    monkeypatch.setattr(
        library,
        "event_handlers",
        {event: list(callbacks) for event, callbacks in library.event_handlers.items()},
    )
    monkeypatch.setattr(library, "converters", dict(library.converters))


def registry_changes_left_behind() -> list[str]:
    """What this file's tests changed in the shared registry and did not undo.

    Not a test. test_plugin_system_leaves_the_registry.py runs this file in a
    pytest process of its own and calls this after it, so the registry is read
    here, in the file whose tests change it. Empty when the built-in event
    handlers are all still subscribed and the converter test_plugin_registration
    registers is gone.
    """
    from automated_security_helper.plugin_modules.ash_builtin import (
        ASH_EVENT_HANDLERS,
    )

    library = ash_plugin_manager.plugin_library
    left = [
        f"built-in handler no longer subscribed: {callback.__name__}"
        for event, callbacks in ASH_EVENT_HANDLERS.items()
        for callback in callbacks
        if not any(
            callback is present for present in library.event_handlers.get(event, [])
        )
    ]
    if "test-plugin" in library.converters:
        left.append("a converter registered by a test is still registered")
    return left


def test_event_subscription():
    """Test that events can be subscribed to and triggered."""
    # Clear any existing subscribers
    ash_plugin_manager.plugin_library.event_handlers.clear()

    results = []

    def test_handler(data, **kwargs):
        results.append(data)
        return data

    # Subscribe to an event
    ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, test_handler)

    # Notify the event
    test_data = "test_data"
    notification_results = ash_plugin_manager.notify(
        AshEventType.SCAN_COMPLETE, test_data
    )

    # Check that the handler was called
    assert len(results) == 1
    assert results[0] == test_data
    assert notification_results[0] == test_data


@pytest.fixture
def mock_plugin_context():
    """Create a mock plugin context for testing."""
    # Create a minimal context with required attributes
    context = PluginContext(
        source_dir=Path("/test/source"), output_dir=Path("/test/output")
    )
    return context


def test_plugin_registration():
    """Test that plugins can be registered and retrieved."""
    # Register a test plugin
    ash_plugin_manager.register_plugin_module(
        "converter", "test-plugin", "test.plugin.module", plugin_module_enabled=True
    )

    # Check that the plugin was registered
    assert "test-plugin" in ash_plugin_manager.plugin_library.converters


def test_convert_phase_events(mock_plugin_context):
    """Test that convert phase events are properly triggered."""
    # Clear any existing subscribers
    ash_plugin_manager.plugin_library.event_handlers.clear()

    # Create tracking variables for event handlers
    start_called = False
    progress_called = False
    complete_called = False
    complete_args = None

    # Define event handlers
    def on_start(**kwargs):
        nonlocal start_called
        start_called = True

    def on_progress(**kwargs):
        nonlocal progress_called
        progress_called = True

    def on_complete(results, **kwargs):
        nonlocal complete_called, complete_args
        complete_called = True
        complete_args = {"results": results, **kwargs}

    # Subscribe to events
    ash_plugin_manager.subscribe(AshEventType.CONVERT_START, on_start)
    ash_plugin_manager.subscribe(AshEventType.CONVERT_PHASE_PROGRESS, on_progress)
    ash_plugin_manager.subscribe(AshEventType.CONVERT_COMPLETE, on_complete)

    # Simulate a convert phase execution
    ash_plugin_manager.notify(
        AshEventType.CONVERT_START, plugin_context=mock_plugin_context
    )
    ash_plugin_manager.notify(
        AshEventType.CONVERT_PHASE_PROGRESS,
        completed=50,
        plugin_context=mock_plugin_context,
    )
    ash_plugin_manager.notify(
        AshEventType.CONVERT_COMPLETE,
        results=["converted_file.py"],
        plugin_context=mock_plugin_context,
    )

    # Check that all handlers were called
    assert start_called
    assert progress_called
    assert complete_called

    # Check that the complete handler was called with the correct arguments
    assert complete_args["results"] == ["converted_file.py"]
    assert complete_args["plugin_context"] == mock_plugin_context


def test_scan_phase_events(mock_plugin_context):
    """Test that scan phase events are properly triggered."""
    # Clear any existing subscribers
    ash_plugin_manager.plugin_library.event_handlers.clear()

    # Create tracking variables for event handlers
    start_called = False
    progress_called = False
    complete_called = False
    complete_args = None

    # Define event handlers
    def on_start(**kwargs):
        nonlocal start_called
        start_called = True

    def on_progress(**kwargs):
        nonlocal progress_called
        progress_called = True

    def on_complete(results, **kwargs):
        nonlocal complete_called, complete_args
        complete_called = True
        complete_args = {"results": results, **kwargs}

    # Subscribe to events
    ash_plugin_manager.subscribe(AshEventType.SCAN_START, on_start)
    ash_plugin_manager.subscribe(AshEventType.SCAN_PHASE_PROGRESS, on_progress)
    ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, on_complete)

    # Simulate a scan phase execution
    ash_plugin_manager.notify(
        AshEventType.SCAN_START, plugin_context=mock_plugin_context
    )
    ash_plugin_manager.notify(
        AshEventType.SCAN_PHASE_PROGRESS,
        completed=50,
        plugin_context=mock_plugin_context,
    )
    ash_plugin_manager.notify(
        AshEventType.SCAN_COMPLETE,
        results=[{"findings": []}],
        plugin_context=mock_plugin_context,
    )

    # Check that all handlers were called
    assert start_called
    assert progress_called
    assert complete_called

    # Check that the complete handler was called with the correct arguments
    assert complete_args["results"] == [{"findings": []}]
    assert complete_args["plugin_context"] == mock_plugin_context


def test_report_phase_events(mock_plugin_context):
    """Test that report phase events are properly triggered."""
    # Clear any existing subscribers
    ash_plugin_manager.plugin_library.event_handlers.clear()

    # Create tracking variables for event handlers
    start_called = False
    progress_called = False
    complete_called = False
    complete_args = None

    # Define event handlers
    def on_start(**kwargs):
        nonlocal start_called
        start_called = True

    def on_progress(**kwargs):
        nonlocal progress_called
        progress_called = True

    def on_complete(results, **kwargs):
        nonlocal complete_called, complete_args
        complete_called = True
        complete_args = {"results": results, **kwargs}

    # Subscribe to events
    ash_plugin_manager.subscribe(AshEventType.REPORT_START, on_start)
    ash_plugin_manager.subscribe(AshEventType.REPORT_PHASE_PROGRESS, on_progress)
    ash_plugin_manager.subscribe(AshEventType.REPORT_COMPLETE, on_complete)

    # Simulate a report phase execution
    ash_plugin_manager.notify(
        AshEventType.REPORT_START, plugin_context=mock_plugin_context
    )
    ash_plugin_manager.notify(
        AshEventType.REPORT_PHASE_PROGRESS,
        completed=50,
        plugin_context=mock_plugin_context,
    )
    ash_plugin_manager.notify(
        AshEventType.REPORT_COMPLETE,
        results=["report.txt"],
        plugin_context=mock_plugin_context,
    )

    # Check that all handlers were called
    assert start_called
    assert progress_called
    assert complete_called

    # Check that the complete handler was called with the correct arguments
    assert complete_args["results"] == ["report.txt"]
    assert complete_args["plugin_context"] == mock_plugin_context
