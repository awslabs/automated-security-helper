# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``builtin_plugin_registry`` (the ``_builtin_plugins_only`` fixture) loses nothing.

The fixture swaps the plugin registry for a copy holding only ASH's built-ins. A plugin
module imported for the first time inside a snapshot test registers into that copy, and
because the module then stays in ``sys.modules`` its registration code never runs again.
If the copy were simply discarded, every later test in the worker would see a registry
without that plugin, which no real process could produce. These tests drive the context
manager directly, inside the test's own (already swapped) registry, and clean up what
they add so nothing leaks into the rest of the suite.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from automated_security_helper.plugins import ash_plugin_manager
from tests.snapshot.conftest import builtin_plugin_registry

_MODULE = "snapshot_registry_probe_plugin"
_REPORTER = "SnapshotRegistryProbeReporter"
_EVENT = "snapshot-registry-probe-event"


@pytest.fixture
def probe_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """An importable module that registers a reporter and an event handler on import."""
    (tmp_path / f"{_MODULE}.py").write_text(
        "from automated_security_helper.plugins import ash_plugin_manager\n"
        f"ash_plugin_manager.register_plugin_module('reporter', {_REPORTER!r}, __name__)\n"
        "def on_event(*args, **kwargs):\n"
        "    return None\n"
        f"ash_plugin_manager.subscribe({_EVENT!r}, on_event)\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    yield
    # Undo everything the import did, so the outer fixture's merge finds nothing.
    sys.modules.pop(_MODULE, None)
    library = ash_plugin_manager.plugin_library
    library.reporters.pop(_REPORTER, None)
    handlers = library.event_handlers.get(_EVENT)
    if handlers is not None:
        handlers[:] = [h for h in handlers if h.__module__ != _MODULE]
        if not handlers:
            del library.event_handlers[_EVENT]


def _handler_modules() -> list[str]:
    handlers = ash_plugin_manager.plugin_library.event_handlers.get(_EVENT, [])
    return [h.__module__ for h in handlers]


@pytest.mark.usefixtures("probe_module")
def test_a_plugin_first_imported_inside_is_kept_afterwards():
    library = ash_plugin_manager.plugin_library
    assert _REPORTER not in library.reporters
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            importlib.import_module(_MODULE)
            assert _REPORTER in library.reporters
            assert _handler_modules() == [_MODULE]
        # monkeypatch has not restored the real dicts yet; the copy is still installed.
    # Now it has. The module is cached, so importing it again would register nothing;
    # the registration must have been carried over.
    assert _MODULE in sys.modules
    assert library.reporters[_REPORTER].plugin_module_path == _MODULE
    assert _handler_modules() == [_MODULE]


def test_a_registration_from_an_already_imported_module_is_not_kept():
    """A test that registers a fake by hand gets it undone, as before."""
    library = ash_plugin_manager.plugin_library
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            ash_plugin_manager.register_plugin_module(
                "reporter", "SnapshotRegistryHandMade", __name__
            )
            assert "SnapshotRegistryHandMade" in library.reporters
    assert "SnapshotRegistryHandMade" not in library.reporters


def test_an_existing_registration_is_not_overwritten(monkeypatch):
    """A key the real registry already holds keeps the real registry's entry."""
    library = ash_plugin_manager.plugin_library
    name, original = next(iter(library.reporters.items()))
    with pytest.MonkeyPatch.context() as mp:
        with builtin_plugin_registry(mp):
            replacement = original.model_copy(
                update={"plugin_module_path": "snapshot_registry_new_module"}
            )
            library.reporters[name] = replacement
            # Pretend the module was imported during the block.
            monkeypatch.setitem(sys.modules, "snapshot_registry_new_module", sys)
    assert library.reporters[name] is original
