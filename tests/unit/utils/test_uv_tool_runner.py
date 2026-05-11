"""Tests for utils/uv_tool_runner.py — covers UVToolRunner class methods."""

import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    UVToolRetryConfig,
    _reset_uv_tool_runner_caches,
    find_executable,
    find_uv_or_none,
    get_uv_tool_command,
    get_uv_tool_runner,
)


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable="uv")
    r._uv_available_cache = None
    return r


class TestUVToolRetryConfig:
    """Tests for UVToolRetryConfig dataclass."""

    def test_defaults(self):
        config = UVToolRetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0
        assert config.jitter is True
        assert config.network_check_timeout == 5.0

    def test_custom_values(self):
        config = UVToolRetryConfig(max_retries=5, base_delay=2.0)
        assert config.max_retries == 5
        assert config.base_delay == 2.0


class TestIsUvAvailable:
    """Tests for is_uv_available."""

    def test_available_when_command_succeeds(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert runner.is_uv_available() is True

    def test_unavailable_when_command_fails(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert runner.is_uv_available() is False

    def test_unavailable_on_exception(self, runner):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            assert runner.is_uv_available() is False

    def test_caches_result(self, runner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            runner.is_uv_available()
            runner.is_uv_available()
            assert mock_run.call_count == 1


class TestListAvailableTools:
    """Tests for list_available_tools."""

    def test_returns_tool_names(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.0\ncheckov 3.0.0\n"
            )
            tools = runner.list_available_tools()
            assert "bandit" in tools
            assert "checkov" in tools

    def test_raises_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        with pytest.raises(UVToolRunnerError):
            runner.list_available_tools()

    def test_raises_on_subprocess_error(self, runner):
        runner._uv_available_cache = True
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "uv"),
        ):
            with pytest.raises(UVToolRunnerError):
                runner.list_available_tools()

    def test_handles_sub_command_lines(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.0\n- bandit-baseline\n"
            )
            tools = runner.list_available_tools()
            assert "bandit" in tools


class TestIsToolInstalled:
    """Tests for is_tool_installed."""

    def test_returns_true_when_in_list(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.0\n"
            )
            assert runner.is_tool_installed("bandit") is True

    def test_returns_false_when_not_in_list(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="checkov 3.0.0\n"
            )
            assert runner.is_tool_installed("bandit") is False

    def test_returns_false_on_error(self, runner):
        runner._uv_available_cache = True
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "uv"),
        ):
            assert runner.is_tool_installed("bandit") is False


class TestGetToolVersion:
    """Tests for get_tool_version."""

    def test_returns_version_string(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.8\n"
            )
            version = runner.get_tool_version("bandit")
            assert version == "bandit 1.7.8"

    def test_returns_none_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        assert runner.get_tool_version("bandit") is None

    def test_returns_none_on_failure(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("bandit") is None

    def test_uses_package_name_in_from_param(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="1.7.8\n"
            )
            runner.get_tool_version("bandit", package_name="bandit[sarif]")
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            assert "bandit[sarif]" in cmd

    def test_returns_none_on_exception(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run", side_effect=RuntimeError("boom")):
            assert runner.get_tool_version("bandit") is None


class TestInstallToolWithVersion:
    """Tests for install_tool_with_version."""

    def test_skips_already_installed(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            # list_available_tools response
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.0\n"
            )
            result = runner.install_tool_with_version("bandit")
            assert result is True

    def test_returns_false_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        assert runner.install_tool_with_version("bandit") is False

    def test_successful_install(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            # First call: list_available_tools (tool not installed)
            # Second call: install command
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="checkov 3.0.0\n"),
                MagicMock(returncode=0),  # install succeeds
            ]
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ), patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ):
                result = runner.install_tool_with_version("bandit")
                assert result is True

    def test_raises_on_timeout(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list (tool not present)
                subprocess.TimeoutExpired("uv", 300),
            ]
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ), patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ):
                with pytest.raises(UVToolRunnerError, match="timed out"):
                    runner.install_tool_with_version("bandit", timeout=300)

    def test_returns_false_in_offline_mode(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ), patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=True,
            ):
                result = runner.install_tool_with_version("bandit")
                assert result is False

    def test_with_version_constraint(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list
                MagicMock(returncode=0),  # install
            ]
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ), patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ):
                runner.install_tool_with_version(
                    "bandit", version_constraint=">=1.7.0"
                )
                install_cmd = mock_run.call_args_list[-1][0][0]
                assert "bandit>=1.7.0" in install_cmd

    def test_with_package_extras(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list
                MagicMock(returncode=0),  # install
            ]
            with patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ), patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ):
                runner.install_tool_with_version(
                    "bandit", package_extras=["sarif", "toml"]
                )
                install_cmd = mock_run.call_args_list[-1][0][0]
                assert "bandit[sarif,toml]" in install_cmd


class TestGetUvToolRunner:
    """Tests for the singleton get_uv_tool_runner."""

    def test_returns_runner_instance(self):
        runner = get_uv_tool_runner()
        assert isinstance(runner, UVToolRunner)

    def test_returns_same_instance(self):
        runner1 = get_uv_tool_runner()
        runner2 = get_uv_tool_runner()
        assert runner1 is runner2


class TestGetInstalledToolVersion:
    """Tests for get_installed_tool_version."""

    def test_returns_none_when_not_installed(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="checkov 3.0\n")
            assert runner.get_installed_tool_version("bandit") is None

    def test_returns_version_when_installed(self, runner):
        runner._uv_available_cache = True
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="bandit 1.7.0\n"),  # list
                MagicMock(returncode=0, stdout="1.7.0\n"),  # version
            ]
            result = runner.get_installed_tool_version("bandit")
            assert result == "1.7.0"


# ---------------------------------------------------------------------------
# Module-level fallback helpers: find_uv_or_none / find_executable /
# get_uv_tool_command.
# ---------------------------------------------------------------------------


@pytest.fixture
def reset_module_caches():
    _reset_uv_tool_runner_caches()
    yield
    _reset_uv_tool_runner_caches()


class TestFindUvOrNone:
    """Tests for find_uv_or_none."""

    def test_returns_none_when_uv_not_on_path(self, monkeypatch, reset_module_caches):
        monkeypatch.setenv("PATH", "")
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ):
            assert find_uv_or_none() is None

    def test_returns_path_when_uv_present(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/opt/uv/bin/uv",
        ):
            assert find_uv_or_none() == "/opt/uv/bin/uv"

    def test_memoizes_result(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/opt/uv/bin/uv",
        ) as mock_find:
            find_uv_or_none()
            find_uv_or_none()
            assert mock_find.call_count == 1


class TestFindExecutable:
    """Tests for the module-level find_executable wrapper."""

    def test_returns_path_when_found(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/local/bin/bandit",
        ):
            assert find_executable("bandit") == "/usr/local/bin/bandit"

    def test_returns_none_when_missing(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ):
            assert find_executable("nope") is None

    def test_memoizes_result(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/local/bin/bandit",
        ) as mock_find:
            find_executable("bandit")
            find_executable("bandit")
            assert mock_find.call_count == 1


class TestGetUvToolCommand:
    """Tests for get_uv_tool_command."""

    def test_returns_uv_form_when_probe_succeeds(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="bandit 1.7\n", stderr=""
            )
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["uv", "tool", "run", "bandit"]
            assert mock_run.call_count == 1

    def test_falls_back_to_direct_binary_when_uv_probe_fails(
        self, reset_module_caches
    ):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run, patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            return_value="/usr/local/bin/bandit",
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="not found"
            )
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]

    def test_falls_back_to_direct_binary_when_uv_missing(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value=None,
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            return_value="/usr/local/bin/bandit",
        ):
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]

    def test_returns_none_when_neither_works(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value=None,
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            return_value=None,
        ):
            assert get_uv_tool_command("bandit") is None

    def test_handles_uv_probe_subprocess_error(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=30),
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            return_value="/usr/local/bin/bandit",
        ):
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]

    def test_uses_fallback_binary_override(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value=None,
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
        ) as mock_find:
            mock_find.return_value = "/usr/local/bin/detect-secrets"
            cmd = get_uv_tool_command(
                "detect-secrets", fallback_binary="detect-secrets"
            )
            assert cmd == ["/usr/local/bin/detect-secrets"]
            mock_find.assert_called_once_with("detect-secrets")

    def test_memoizes_result_no_re_probe(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok\n", stderr=""
            )
            first = get_uv_tool_command("bandit")
            second = get_uv_tool_command("bandit")
            assert first == second == ["uv", "tool", "run", "bandit"]
            assert mock_run.call_count == 1

    def test_memoizes_negative_result(self, reset_module_caches):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value=None,
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            return_value=None,
        ) as mock_find:
            assert get_uv_tool_command("bandit") is None
            assert get_uv_tool_command("bandit") is None
            assert mock_find.call_count == 1
