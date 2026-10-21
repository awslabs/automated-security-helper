"""Extended tests for utils/uv_tool_runner.py — covers run_tool, get_tool_installation_info, caching, and validation."""

import os
import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    _reset_uv_tool_runner_caches,
    get_uv_tool_runner,
    reset_uv_tool_runner,
)
from automated_security_helper.utils.process_env import DISPLAY_VARIABLES
from tests.utils.env_assertions import differing_names


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    """Hand names that resolve nowhere to the mocked spawn on every platform.

    These tests replace the process boundary and pass it programs that are not
    installed. On Windows ASH refuses such a name before spawning it
    (subprocess_utils._refuse_unresolved_on_windows); these tests are about what
    happens after the spawn, so that decision is set aside here.
    """
    from automated_security_helper.utils import subprocess_utils as _subprocess_utils

    monkeypatch.setattr(_subprocess_utils, "_refuse_unresolved_on_windows", False)


@pytest.fixture(autouse=True)
def _isolate_module_caches():
    """Clear the module-level memo caches around every test in this file.

    ``get_tool_version`` memoizes per ``tool::package``, so without this the
    version one test mocks would be served to the next -- and a test asserting
    a *failed* probe would instead see the previous test's success.
    """
    _reset_uv_tool_runner_caches()
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable="uv")
    r._uv_available_cache = True
    return r


class TestRunTool:
    """Tests for run_tool method."""

    def test_raises_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        with pytest.raises(UVToolRunnerError, match="not available"):
            runner.run_tool("bandit")

    def test_basic_run_without_results_dir(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["uv", "tool", "run", "bandit"],
                returncode=0,
                stdout="output",
                stderr="",
            )
            result = runner.run_tool("bandit", args=["-r", "src/"], cwd=Path("/tmp"))  # nosec B108
            assert result.returncode == 0
            assert result.stdout == "output"

    def test_with_package_extras(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=[], package_extras=["sarif", "toml"])
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            # Should contain bandit[sarif,toml]
            from_idx = cmd.index("--from")
            assert "bandit[sarif,toml]" in cmd[from_idx + 1]

    def test_with_version_constraint(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=[], version_constraint=">=1.7.0")
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            from_idx = cmd.index("--from")
            assert ">=1.7.0" in cmd[from_idx + 1]

    def test_quiet_passes_uvs_quiet_flag_before_the_tool(self, runner):
        """``--quiet`` is uv's own flag, so it goes ahead of the tool name:
        uv's resolver and installer lines stay off stderr while its error
        diagnostics still print, for callers that read stderr to tell uv's
        failures from the tool's."""
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("jupyter-nbconvert", args=[], quiet=True)
            cmd = mock_run.call_args[0][0]
            assert "--quiet" in cmd
            assert cmd.index("--quiet") < cmd.index("jupyter-nbconvert")

    def test_a_run_not_asked_to_be_quiet_passes_no_quiet_flag(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=[])
            assert "--quiet" not in mock_run.call_args[0][0]

    @staticmethod
    def _timeout_with_child(still_running: bool) -> subprocess.TimeoutExpired:
        """A TimeoutExpired carrying spawn_run's record of the child it started."""

        class _Child:
            def poll(self):
                return None if still_running else -9

        class _Record:
            process = _Child()

        error = subprocess.TimeoutExpired(cmd=["uv"], timeout=5)
        setattr(error, "_ash_started_child", _Record())
        return error

    def test_a_timeout_whose_stop_left_the_child_running_has_no_exit_code(self, runner):
        """TimedOutProcess's returncode is None for a child the stop did not
        end, by its own contract: the record spawn_run attaches to the
        TimeoutExpired says whether the child still runs, and the error says
        so rather than reading as an ordinary timeout."""
        with patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=self._timeout_with_child(still_running=True),
        ):
            result = runner.run_tool("bandit", args=[])

        assert getattr(result, "timed_out", False) is True
        assert result.returncode is None
        assert "did not end" in result.error, result.error

    def test_a_timeout_whose_child_was_ended_keeps_the_timeout_code(self, runner):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=self._timeout_with_child(still_running=False),
        ):
            result = runner.run_tool("bandit", args=[])

        assert getattr(result, "timed_out", False) is True
        assert result.returncode == 124
        assert "did not end" not in result.error, result.error

    def test_with_results_dir(self, runner, tmp_path):
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 0,
                "stdout": "result output",
                "stderr": "",
            }
            result = runner.run_tool(
                "bandit",
                args=["-r", "src/"],
                results_dir=results_dir,
            )
            assert result.returncode == 0
            assert result.stdout == "result output"

    def test_raises_on_subprocess_error(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "uv")
            with pytest.raises(UVToolRunnerError):
                runner.run_tool("bandit", check=True)

    def test_offline_mode_adds_flag(self, runner):
        with (
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
            patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=True,
            ),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=[])
            cmd = mock_run.call_args[0][0]
            assert "--offline" in cmd

    def test_with_custom_env(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            env = {"MY_VAR": "value"}
            runner.run_tool("bandit", args=[], env=env)
            call_kwargs = mock_run.call_args[1]
            # By names: a failure would print a merged environment's values.
            assert differing_names(call_kwargs.get("env") or {}, env) == []

    def test_none_args_defaults_to_empty_list(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=None)
            cmd = mock_run.call_args[0][0]
            # Tool name should be last element
            assert cmd[-1] == "bandit"

    def test_with_package_name(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", package_name="bandit-pkg")
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            assert "bandit-pkg" in cmd


class TestGetToolInstallationInfo:
    """Tests for get_tool_installation_info."""

    def test_uv_installed_tool(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            # list returns the tool
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="bandit 1.7.0\n"),  # list
                MagicMock(returncode=0, stdout="1.7.0\n"),  # version
            ]
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                info = runner.get_tool_installation_info("bandit")
                assert info["is_uv_installed"] is True
                assert info["preferred_source"] == "uv"
                assert info["available"] is True

    def test_pre_installed_tool(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")  # list empty
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value="/usr/bin/bandit",
            ):
                info = runner.get_tool_installation_info("bandit")
                assert info["is_pre_installed"] is True
                assert info["preferred_source"] == "pre_installed"
                assert info["available"] is True

    def test_no_tool_available(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                info = runner.get_tool_installation_info("missing-tool")
                assert info["available"] is False
                assert info["preferred_source"] == "none"


class TestShouldInstallTool:
    """Tests for should_install_tool."""

    def test_returns_false_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        assert runner.should_install_tool("bandit") is False

    def test_returns_false_when_already_uv_installed(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.0\n")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                assert runner.should_install_tool("bandit") is False

    def test_returns_false_when_pre_installed_and_prefer_cached(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value="/usr/bin/bandit",
            ):
                assert runner.should_install_tool("bandit", prefer_cached=True) is False

    def test_returns_true_when_not_installed(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                assert runner.should_install_tool("bandit") is True


class TestGetCacheInfo:
    """Tests for get_cache_info."""

    def test_cache_available(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="/home/user/.cache/uv\n"
            )
            info = runner.get_cache_info()
            assert info["cache_available"] is True

    def test_cache_not_available(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            info = runner.get_cache_info()
            assert info["cache_available"] is False

    def test_cache_exception(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=RuntimeError("boom"),
        ):
            info = runner.get_cache_info()
            assert info["cache_available"] is False


class TestValidateCachedTool:
    """Tests for validate_cached_tool."""

    def test_functional_tool(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.7.0\n")
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is True
            assert result["version"] is not None

    def test_non_functional_tool(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is False

    def test_exception_handling(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=RuntimeError("boom"),
        ):
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is False
            assert result["error"] is not None


class TestResetUvToolRunner:
    """Tests for reset_uv_tool_runner."""

    def test_resets_global_instance(self):
        runner1 = get_uv_tool_runner()
        reset_uv_tool_runner()
        runner2 = get_uv_tool_runner()
        # Identity, not just type. reset_uv_tool_runner() rebinds the module
        # global to `UVToolRunner()` unconditionally, so a new instance is the
        # contract rather than a possibility -- the earlier "potentially
        # different instance" wording undersold it. Asserting only isinstance
        # here passed even if reset_uv_tool_runner() did nothing at all, which
        # is the one thing this test exists to rule out.
        assert runner2 is not runner1
        assert isinstance(runner2, UVToolRunner)


class TestGetToolVersionOffline:
    """The version probe honors ASH_OFFLINE the way run_tool does.

    It once was the only uv call that did not. Under ``ash scan --mode nix`` it
    resolved and downloaded the newest semgrep from PyPI and was killed at its
    15s timeout when the download was slow, leaving uv's cache with the index
    entry but not the wheel. The scan's ``uv tool run --offline`` then failed with
    "the requested data wasn't found in the cache" (nix arm64 CI, 2026-10-06).
    """

    def _probe(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="1.172.0\n", stderr=""
            )
            version = runner.get_tool_version("semgrep", "semgrep>=1.125.0,<2.0.0")
        assert mock_run.call_count == 1
        return version, mock_run.call_args

    def test_offline_probe_passes_offline_to_uv(self, runner, monkeypatch):
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        monkeypatch.delenv("UV_OFFLINE", raising=False)
        version, call = self._probe(runner)
        command = call.args[0]
        # uv by the absolute path ASH resolved for it, never by name.
        assert Path(command[0]).stem == "uv" and Path(command[0]).is_absolute()
        assert command[1:4] == ["tool", "run", "--offline"]
        assert command[-2:] == ["semgrep", "--version"]
        assert call.kwargs["env"]["UV_OFFLINE"] == "1"
        assert version == "1.172.0"

    def test_online_probe_is_unchanged(self, runner, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        _, call = self._probe(runner)
        assert "--offline" not in call.args[0]
        # An explicit copy of the environment, never None: see utils/process_env.py.
        # Compared by names, so a failure prints no value. Its output is read, so
        # it runs without the caller's display variables and with NO_COLOR set
        # (environ_for_parsed_output).
        env = call.kwargs["env"]
        assert env is not None
        changed = set(differing_names(env, os.environ))
        assert changed <= {*DISPLAY_VARIABLES, "NO_COLOR"}, sorted(changed)
        no_color = env.get("NO_COLOR")
        assert no_color == "1"
