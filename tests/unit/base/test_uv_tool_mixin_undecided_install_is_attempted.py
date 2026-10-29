# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv mixin installs a tool when the runner cannot say whether to.

``_should_install_tool`` answers True when the runner's own answer cannot be
read. Its caller asks only once the tool was found unavailable, and a False there
read as "already installed": no install was attempted, and the scan went on to
start a tool that was not there.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin

pytestmark = pytest.mark.unit


class FakePlugin(UVToolMixin):
    """The attributes the mixin reads from PluginBase, and nothing else."""

    def __init__(self, command="bandit"):
        self.command = command
        self.use_uv_tool = True
        self.uv_tool_package_name = None
        self.uv_tool_install_commands = []
        self.logged: list[tuple[str, int]] = []

    def _plugin_log(self, message, level=logging.INFO, **kwargs):
        self.logged.append((message, level))

    def _get_tool_package_extras(self):
        return None

    def _get_tool_version_constraint(self):
        return None

    def _get_tool_with_dependencies(self):
        return None


class TestAnUndecidedInstallIsAttempted:
    def test_a_runner_that_cannot_answer_means_install(self):
        """Fails at the base: the error was logged and False returned, which the
        caller read as "already installed"."""
        plugin = FakePlugin()
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=RuntimeError("the tool listing broke"),
        ):
            assert plugin._should_install_tool() is True

        ((message, level),) = plugin.logged
        assert level == logging.WARNING
        assert "the tool listing broke" in message
        assert "attempting the installation" in message

    def test_the_runners_own_no_is_still_believed(self):
        """The control: a runner that answers False is not overruled."""
        plugin = FakePlugin()
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as get_runner:
            get_runner.return_value.should_install_tool.return_value = False
            assert plugin._should_install_tool() is False
