# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``python_request``: a uv-backed plugin can ask for a compatible interpreter.

Why this exists: GuardDog 3.2.0 depends on pygit2 and yara-python, which publish
no CPython 3.14 wheels. uv picks the newest interpreter it can find, so on a host
where that is 3.14 ``uv tool install guarddog==3.2.0`` builds both from source and
fails without libgit2 headers. ``UVToolMixin._get_tool_python_request`` lets the
plugin pass ``--python '>=3.10,<3.14'`` to install, run and the version probe.

The other half of the contract matters as much: a plugin that does not override
the hook must call the runner exactly as before, with no new argument at all.
"""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)


@pytest.fixture(autouse=True)
def _isolate_module_caches():
    _reset_uv_tool_runner_caches()
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable="uv")
    r._uv_available_cache = True
    return r


def _install(runner, **kwargs):
    with (
        patch("subprocess.run") as mock_run,
        patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ),
        patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ),
    ):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=""),  # uv tool list: not installed
            MagicMock(returncode=0),  # uv tool install
        ]
        assert runner.install_tool_with_version("guarddog", "==3.2.0", **kwargs)
        return mock_run.call_args_list[-1][0][0]


def test_install_passes_python_before_the_requirement(runner):
    cmd = _install(runner, python_request=">=3.10,<3.14")
    assert cmd[:3] == ["uv", "tool", "install"]
    index = cmd.index("--python")
    assert cmd[index + 1] == ">=3.10,<3.14"
    assert index < cmd.index("guarddog==3.2.0")


def test_install_without_a_request_is_unchanged(runner):
    assert _install(runner) == ["uv", "tool", "install", "guarddog==3.2.0"]


def test_run_tool_passes_python(runner, tmp_path):
    with patch(
        "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
        return_value={"returncode": 0, "stdout": "", "stderr": ""},
    ) as run:
        runner.run_tool(
            "guarddog",
            args=["--version"],
            version_constraint="==3.2.0",
            results_dir=tmp_path,
            python_request=">=3.10,<3.14",
        )
        cmd = run.call_args.kwargs["command"]
    assert cmd[:5] == ["uv", "tool", "run", "--python", ">=3.10,<3.14"]
    assert cmd[cmd.index("--from") + 1] == "guarddog==3.2.0"


def test_run_tool_without_a_request_is_unchanged(runner, tmp_path):
    with patch(
        "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
        return_value={"returncode": 0, "stdout": "", "stderr": ""},
    ) as run:
        runner.run_tool("bandit", args=["-h"], results_dir=tmp_path)
        cmd = run.call_args.kwargs["command"]
    assert "--python" not in cmd


def test_version_probe_passes_python_and_keys_its_memo_on_it(runner):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="3.2.0\n")
        assert (
            runner.get_tool_version(
                "guarddog", "guarddog==3.2.0", python_request=">=3.10,<3.14"
            )
            == "3.2.0"
        )
        cmd = mock_run.call_args[0][0]
        assert cmd[:5] == ["uv", "tool", "run", "--python", ">=3.10,<3.14"]
        # A probe without the request is a different environment: probed again.
        runner.get_tool_version("guarddog", "guarddog==3.2.0")
        assert mock_run.call_count == 2
        assert "--python" not in mock_run.call_args[0][0]


class _Plugin(UVToolMixin):
    command = "guarddog"
    use_uv_tool = True
    uv_tool_package_name = None
    uv_tool_install_commands: list = []

    def __init__(self, request):
        self._request = request

    def _plugin_log(self, *args, **kwargs):
        pass

    def _get_tool_version_constraint(self):
        return "==3.2.0"

    def _get_tool_python_request(self):
        return self._request


def test_mixin_install_command_and_kwargs_follow_the_hook():
    plugin = _Plugin(">=3.10,<3.14")
    plugin._setup_uv_tool_install_commands()
    assert plugin.uv_tool_install_commands == [
        "uv tool install --python >=3.10,<3.14 guarddog==3.2.0"
    ]
    assert plugin._uv_python_kwargs() == {"python_request": ">=3.10,<3.14"}


def test_mixin_without_the_hook_adds_nothing():
    plugin = _Plugin(None)
    plugin._setup_uv_tool_install_commands()
    assert plugin.uv_tool_install_commands == ["uv tool install guarddog==3.2.0"]
    assert plugin._uv_python_kwargs() == {}
    assert UVToolMixin._get_tool_python_request(plugin) is None
