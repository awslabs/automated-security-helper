"""Extended tests for utils/uv_tool_runner.py — covers run_tool, get_tool_installation_info, caching, and validation."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    get_uv_tool_runner,
    reset_uv_tool_runner,
)


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
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["uv", "tool", "run", "bandit"],
                returncode=0,
                stdout="output",
                stderr="",
            )
            result = runner.run_tool("bandit", args=["-r", "src/"], cwd=Path("/tmp"))
            assert result.returncode == 0
            assert result.stdout == "output"

    def test_with_package_extras(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool(
                "bandit", args=[], package_extras=["sarif", "toml"]
            )
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            # Should contain bandit[sarif,toml]
            from_idx = cmd.index("--from")
            assert "bandit[sarif,toml]" in cmd[from_idx + 1]

    def test_with_version_constraint(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool(
                "bandit", args=[], version_constraint=">=1.7.0"
            )
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            from_idx = cmd.index("--from")
            assert ">=1.7.0" in cmd[from_idx + 1]

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
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "uv")
            with pytest.raises(UVToolRunnerError):
                runner.run_tool("bandit", check=True)

    def test_offline_mode_adds_flag(self, runner):
        with patch("subprocess.run") as mock_run, patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=True,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=[])
            cmd = mock_run.call_args[0][0]
            assert "--offline" in cmd

    def test_with_custom_env(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            env = {"MY_VAR": "value"}
            runner.run_tool("bandit", args=[], env=env)
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get("env") == env

    def test_none_args_defaults_to_empty_list(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            runner.run_tool("bandit", args=None)
            cmd = mock_run.call_args[0][0]
            # Tool name should be last element
            assert cmd[-1] == "bandit"

    def test_with_package_name(self, runner):
        with patch("subprocess.run") as mock_run:
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
        with patch("subprocess.run") as mock_run:
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
        with patch("subprocess.run") as mock_run:
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
        with patch("subprocess.run") as mock_run:
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
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.0\n")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                assert runner.should_install_tool("bandit") is False

    def test_returns_false_when_pre_installed_and_prefer_cached(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value="/usr/bin/bandit",
            ):
                assert runner.should_install_tool("bandit", prefer_cached=True) is False

    def test_returns_true_when_not_installed(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ):
                assert runner.should_install_tool("bandit") is True


class TestGetCacheInfo:
    """Tests for get_cache_info."""

    def test_cache_available(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="/home/user/.cache/uv\n"
            )
            info = runner.get_cache_info()
            assert info["cache_available"] is True

    def test_cache_not_available(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="error"
            )
            info = runner.get_cache_info()
            assert info["cache_available"] is False

    def test_cache_exception(self, runner):
        with patch("subprocess.run", side_effect=RuntimeError("boom")):
            info = runner.get_cache_info()
            assert info["cache_available"] is False


class TestCleanCache:
    """Tests for clean_cache."""

    def test_clean_succeeds(self, runner):
        with patch("subprocess.run"):
            assert runner.clean_cache() is True

    def test_clean_fails(self, runner):
        with patch("subprocess.run", side_effect=RuntimeError("fail")):
            assert runner.clean_cache() is False


class TestValidateCachedTool:
    """Tests for validate_cached_tool."""

    def test_functional_tool(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.7.0\n")
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is True
            assert result["version"] is not None

    def test_non_functional_tool(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is False

    def test_exception_handling(self, runner):
        with patch("subprocess.run", side_effect=RuntimeError("boom")):
            result = runner.validate_cached_tool("bandit")
            assert result["is_functional"] is False
            assert result["error"] is not None


class TestResetUvToolRunner:
    """Tests for reset_uv_tool_runner."""

    def test_resets_global_instance(self):
        runner1 = get_uv_tool_runner()
        reset_uv_tool_runner()
        runner2 = get_uv_tool_runner()
        # After reset, should still be a valid UVToolRunner but potentially different instance
        assert isinstance(runner2, UVToolRunner)
