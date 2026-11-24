# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's version-reading opt-ins reach the runner as one bundle.

``_get_uv_tool_version`` (the scan's version read) and
``_get_tool_installation_info`` (the dependency check's) both ask the runner for
a tool's version. The plugin's declared capabilities for that read (the
interpreter request, the package-metadata read) used to be threaded into each
call by hand, so the two call sites drifted: one passed the interpreter request
and neither the other. ``UVToolMixin._uv_runner_version_kwargs`` is the single
source; these tests pin that

* the bundle holds exactly the declared opt-ins, and is empty for a plugin that
  declares none (the runner is then called with the arguments it always was);
* both mixin call sites spread the bundle, and the installation-info read reaches
  the version probe with the same interpreter request the scan runs under;
* no call to the runner's version-reading methods in the mixin module is made
  without the bundle, so a third call site cannot drop an opt-in.
"""

from __future__ import annotations

import ast
import inspect
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base import uv_tool_mixin
from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

_GET_RUNNER = "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
_VERSION_READERS = {"get_tool_version", "get_tool_installation_info"}


class _Plugin(UVToolMixin):
    """The attributes the mixin reads from PluginBase, and nothing else."""

    def __init__(self, python_request=None, from_metadata=False):
        self.command = "bandit"
        self.use_uv_tool = True
        self.uv_tool_package_name = None
        self.uv_tool_install_commands = []
        self.exit_code = 0
        self.output = ""
        self.errors: list = []
        self.tool_version = None
        self._python_request = python_request
        self._from_metadata = from_metadata
        self._log_messages = []

    def _plugin_log(self, *args, **kwargs):
        self._log_messages.append(args)

    def _get_tool_package_extras(self):
        return None

    def _get_tool_version_constraint(self):
        return None

    def _get_tool_with_dependencies(self):
        return None

    def _get_tool_python_request(self):
        return self._python_request

    def _tool_version_from_metadata(self):
        return self._from_metadata

    def _is_offline_mode(self):
        return False


class TestTheBundle:
    def test_a_plugin_that_declares_nothing_has_an_empty_bundle(self):
        assert _Plugin()._uv_runner_version_kwargs() == {}

    def test_the_bundle_holds_every_declared_opt_in(self):
        plugin = _Plugin(python_request=">=3.10,<3.14", from_metadata=True)
        assert plugin._uv_runner_version_kwargs() == {
            "python_request": ">=3.10,<3.14",
            "from_metadata": True,
        }

    def test_the_bundle_is_built_from_the_two_declared_hooks(self):
        plugin = _Plugin(python_request=">=3.10,<3.14", from_metadata=True)
        assert plugin._uv_runner_version_kwargs() == {
            **plugin._uv_python_kwargs(),
            **plugin._uv_metadata_kwargs(),
        }


class TestTheCallSites:
    def _info_runner(self):
        runner = MagicMock()
        runner.get_tool_installation_info.return_value = {
            "is_uv_installed": True,
            "is_pre_installed": False,
            "preferred_source": "uv",
            "available": True,
        }
        return runner

    def test_the_installation_info_read_carries_the_scans_interpreter(self):
        plugin = _Plugin(python_request=">=3.10,<3.14")
        runner = self._info_runner()
        with patch(_GET_RUNNER, return_value=runner):
            plugin._get_tool_installation_info()
        kwargs = runner.get_tool_installation_info.call_args.kwargs
        assert kwargs["python_request"] == ">=3.10,<3.14"
        assert "from_metadata" not in kwargs

    def test_the_installation_info_read_carries_the_metadata_opt_in(self):
        plugin = _Plugin(from_metadata=True)
        runner = self._info_runner()
        with patch(_GET_RUNNER, return_value=runner):
            plugin._get_tool_installation_info()
        kwargs = runner.get_tool_installation_info.call_args.kwargs
        assert kwargs["from_metadata"] is True
        assert "python_request" not in kwargs

    def test_a_plugin_that_declares_nothing_calls_the_runner_as_before(self):
        plugin = _Plugin()
        runner = self._info_runner()
        with patch(_GET_RUNNER, return_value=runner):
            plugin._get_tool_installation_info()
        assert set(runner.get_tool_installation_info.call_args.kwargs) == {
            "offline",
            "package",
        }

    def test_the_scans_version_read_and_the_dependency_check_agree(self):
        plugin = _Plugin(python_request=">=3.10,<3.14", from_metadata=True)
        runner = self._info_runner()
        runner.get_tool_version.return_value = "1.7.0"
        runner.uv_availability.return_value = (True, None)
        with patch(_GET_RUNNER, return_value=runner):
            plugin._get_uv_tool_version("bandit")
            plugin._get_tool_installation_info()
        version = runner.get_tool_version.call_args.kwargs
        info = runner.get_tool_installation_info.call_args.kwargs
        bundle = plugin._uv_runner_version_kwargs()
        for key, value in bundle.items():
            assert version[key] == value
            assert info[key] == value


class TestTheRunnerHonorsTheBundle:
    @pytest.fixture(autouse=True)
    def _isolate(self):
        _reset_uv_tool_runner_caches()
        yield
        _reset_uv_tool_runner_caches()

    def test_the_installation_info_probe_runs_under_the_request_and_the_opt_in(self):
        runner = UVToolRunner(uv_executable="uv")
        runner._uv_available_cache = True
        with (
            patch.object(runner, "is_tool_installed", return_value=True),
            patch.object(runner, "get_tool_version", return_value="1.0") as probe,
        ):
            info = runner.get_tool_installation_info(
                "guarddog",
                "guarddog",
                offline=False,
                package="guarddog",
                python_request=">=3.10,<3.14",
                from_metadata=True,
            )
        assert info["uv_version"] == "1.0"
        kwargs = probe.call_args.kwargs
        assert kwargs["python_request"] == ">=3.10,<3.14"
        assert kwargs["from_metadata"] is True

    def test_the_defaults_probe_as_they_always_did(self):
        runner = UVToolRunner(uv_executable="uv")
        runner._uv_available_cache = True
        with (
            patch.object(runner, "is_tool_installed", return_value=True),
            patch.object(runner, "get_tool_version", return_value="1.0") as probe,
        ):
            runner.get_tool_installation_info("bandit", "bandit")
        kwargs = probe.call_args.kwargs
        assert kwargs["python_request"] is None
        assert kwargs["from_metadata"] is False


class TestTheBundleIsTheOnlySource:
    @staticmethod
    def _version_reading_calls():
        tree = ast.parse(inspect.getsource(uv_tool_mixin))
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _VERSION_READERS
        ]

    @staticmethod
    def _spreads(call, helper):
        return any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Call)
            and isinstance(keyword.value.func, ast.Attribute)
            and keyword.value.func.attr == helper
            for keyword in call.keywords
        )

    def test_the_sweep_finds_both_call_sites(self):
        # A planted positive: a sweep that matched nothing would pass the test
        # below on an empty list.
        attrs = sorted(c.func.attr for c in self._version_reading_calls())
        assert attrs == ["get_tool_installation_info", "get_tool_version"]

    def test_every_version_reading_call_spreads_the_bundle(self):
        for call in self._version_reading_calls():
            assert self._spreads(call, "_uv_runner_version_kwargs"), (
                f"line {call.lineno}: {call.func.attr} is called without "
                "**self._uv_runner_version_kwargs()"
            )

    def test_no_version_reading_call_threads_a_single_opt_in_by_hand(self):
        for call in self._version_reading_calls():
            assert not self._spreads(call, "_uv_python_kwargs"), call.lineno
            assert not self._spreads(call, "_uv_metadata_kwargs"), call.lineno
