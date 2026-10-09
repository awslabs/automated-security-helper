"""The per-test restore of process-wide tool state in tests/conftest.py.

``get_uv_tool_runner()`` is one object per process and memoizes whether uv runs.
A test that patched the standard library's ``subprocess.run`` before building a
converter made that memo False, and an unrelated test later on the same xdist
worker failed with "UV is not available". These tests poison each piece of state
the way a test can, check that the poison took (the control), and check that
leaving ``_ProcessWideToolState`` puts back what was there.
"""

import importlib
import subprocess
import sys
from unittest.mock import patch

import automated_security_helper.plugins as plugins_module
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.events import AshEventType
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from tests.conftest import (
    _PLUGINS_MODULE,
    _PROCESS_WIDE_PROBE_MEMOS,
    _UV_TOOL_RUNNER_MODULE,
    _ProcessWideToolState,
)


def test_every_name_the_restore_looks_up_exists():
    """The restore finds each module with ``sys.modules.get`` and skips a missing one.

    That is right for a module the run never imported, and it would also make a
    misspelled or renamed module silently stop being restored. So each name is
    resolved here, where a mismatch fails.
    """
    for module_name, attribute in _PROCESS_WIDE_PROBE_MEMOS:
        memo = getattr(importlib.import_module(module_name), attribute)
        assert isinstance(memo, (dict, list)), (module_name, attribute)
    runner_module = importlib.import_module(_UV_TOOL_RUNNER_MODULE)
    assert runner_module is uv_tool_runner
    assert runner_module._uv_tool_runner is uv_tool_runner.get_uv_tool_runner()
    assert importlib.import_module(_PLUGINS_MODULE) is plugins_module
    assert plugins_module.ash_plugin_manager is ash_plugin_manager


def test_a_memoized_uv_is_not_available_is_rolled_back():
    runner = uv_tool_runner.get_uv_tool_runner()
    attributes = dict(vars(runner))

    with _ProcessWideToolState():
        uv_tool_runner.reset_uv_tool_runner()
        # What the converter tests did: the stand-in cannot answer `uv --version`.
        with patch.object(subprocess, "run", side_effect=IndexError("cmd[6]")):
            assert uv_tool_runner.get_uv_tool_runner().is_uv_available() is False
        assert uv_tool_runner.get_uv_tool_runner()._uv_available_cache is False

    assert uv_tool_runner.get_uv_tool_runner() is runner
    assert vars(runner) == attributes


def test_the_original_runner_gets_its_own_attributes_back():
    runner = uv_tool_runner.get_uv_tool_runner()
    attributes = dict(vars(runner))

    with _ProcessWideToolState():
        runner._uv_available_cache = False
        runner.uv_executable = "/nonexistent/uv"

    assert vars(runner) == attributes


def test_a_memoized_failure_is_rolled_back_and_a_success_is_kept():
    versions = uv_tool_runner._uv_tool_version_cache
    before = dict(versions)

    with _ProcessWideToolState():
        versions["conftest-probe-failed::"] = None
        versions["conftest-probe-succeeded::"] = "conftest-probe 1.0"

    try:
        assert "conftest-probe-failed::" not in versions
        assert versions.pop("conftest-probe-succeeded::") == "conftest-probe 1.0"
        assert versions == before
    finally:
        versions.pop("conftest-probe-succeeded::", None)


def test_an_answer_that_was_already_memoized_is_put_back():
    versions = uv_tool_runner._uv_tool_version_cache
    versions["conftest-probe::"] = "conftest-probe 1.0"
    try:
        with _ProcessWideToolState():
            versions["conftest-probe::"] = None
        assert versions["conftest-probe::"] == "conftest-probe 1.0"
    finally:
        versions.pop("conftest-probe::", None)


def test_a_rebound_memo_is_replaced_by_the_original_and_none_of_it_is_kept():
    command_memo = uv_tool_runner._uv_command_cache
    commands = dict(command_memo)

    with _ProcessWideToolState():
        uv_tool_runner._uv_command_cache = {"bandit::bandit": ["made", "up"]}

    assert uv_tool_runner._uv_command_cache is command_memo
    assert command_memo == commands


def test_the_cheap_probe_memos_are_rolled_back_in_full():
    executables = dict(subprocess_utils._find_executable_cache)

    with _ProcessWideToolState():
        subprocess_utils._find_executable_cache["test_cmd"] = "/nonexistent/test_cmd"
        subprocess_utils._find_executable_cache["opengrep"] = None

    assert subprocess_utils._find_executable_cache == executables


def test_a_rebound_plugin_manager_is_put_back():
    with _ProcessWideToolState():
        plugins_module.ash_plugin_manager = object()

    assert plugins_module.ash_plugin_manager is ash_plugin_manager


def test_a_registration_and_handlers_a_test_made_are_rolled_back():
    library = ash_plugin_manager.plugin_library
    handlers = {event: list(found) for event, found in library.event_handlers.items()}
    converters = dict(library.converters)

    def handler_declared_in_the_test(**kwargs):
        return None

    with _ProcessWideToolState():
        ash_plugin_manager.register_plugin_module(
            "converter", "test-plugin", "test.plugin.module", plugin_module_enabled=True
        )
        library.event_handlers.clear()
        ash_plugin_manager.subscribe(
            AshEventType.SCAN_COMPLETE, handler_declared_in_the_test
        )
        assert "test-plugin" in library.converters

    assert library.converters == converters
    assert {
        event: list(found) for event, found in library.event_handlers.items()
    } == handlers


def test_what_importing_a_plugin_module_registered_is_kept(tmp_path, monkeypatch):
    """The import that registered it will not run again, so dropping it loses it."""
    module_name = "ash_conftest_isolation_probe_plugin"
    (tmp_path / f"{module_name}.py").write_text(
        "from automated_security_helper.plugins import ash_plugin_manager\n"
        "from automated_security_helper.plugins.decorators import ash_converter_plugin\n"
        "from automated_security_helper.plugins.events import AshEventType\n"
        "\n"
        "@ash_converter_plugin\n"
        "class ConftestIsolationProbeConverter:\n"
        "    pass\n"
        "\n"
        "def on_scan_complete(**kwargs):\n"
        "    return None\n"
        "\n"
        "ash_plugin_manager.subscribe(AshEventType.SCAN_COMPLETE, on_scan_complete)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    library = ash_plugin_manager.plugin_library
    try:
        with _ProcessWideToolState():
            module = __import__(module_name)
            assert "ConftestIsolationProbeConverter" in library.converters

        registration = library.converters["ConftestIsolationProbeConverter"]
        assert registration.plugin_module_path == module_name
        assert module.on_scan_complete in library.event_handlers.get(
            AshEventType.SCAN_COMPLETE, []
        )
    finally:
        library.converters.pop("ConftestIsolationProbeConverter", None)
        module = sys.modules.pop(module_name, None)
        if module is not None:
            callbacks = library.event_handlers.get(AshEventType.SCAN_COMPLETE, [])
            if module.on_scan_complete in callbacks:
                callbacks.remove(module.on_scan_complete)
