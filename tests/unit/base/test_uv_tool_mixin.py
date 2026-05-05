"""Tests for base/uv_tool_mixin.py — covers version detection, execution, validation, and installation."""

from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path
import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin


class FakePlugin(UVToolMixin):
    """Minimal stub that satisfies the attributes UVToolMixin reads from PluginBase."""

    def __init__(self, **kwargs):
        self.command = kwargs.get("command", "bandit")
        self.use_uv_tool = kwargs.get("use_uv_tool", True)
        self.uv_tool_package_name = kwargs.get("uv_tool_package_name", None)
        self.uv_tool_install_commands = kwargs.get("uv_tool_install_commands", [])
        self.exit_code = 0
        self.output = ""
        self.errors = ""
        self._log_messages = []

    def _plugin_log(self, *args, **kwargs):
        self._log_messages.append(args)

    def _process_command_response(self, response):
        self.exit_code = response.get("returncode", 0)
        self.output = response.get("stdout", "")
        self.errors = response.get("stderr", "")

    def _get_tool_package_extras(self):
        return None

    def _get_tool_version_constraint(self):
        return None

    def _get_tool_with_dependencies(self):
        return None


class TestGetUvToolVersion:
    """Tests for _get_uv_tool_version."""

    def test_returns_none_when_use_uv_tool_disabled(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._get_uv_tool_version("bandit") is None

    def test_returns_version_string(self):
        """Direct test of the method logic with mocked runner."""
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version == "1.7.0"

    def test_returns_none_when_uv_not_available(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version is None

    def test_returns_none_on_import_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            # ImportError is caught inside the method
            version = plugin._get_uv_tool_version("bandit")
            assert version is None

    def test_returns_none_on_runner_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_runner = MagicMock()
            mock_runner.is_uv_available.side_effect = UVToolRunnerError("broken")
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version is None

    def test_returns_none_on_unexpected_exception(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.side_effect = RuntimeError("unexpected")
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version is None


class TestTryUvToolExecution:
    """Tests for _try_uv_tool_execution."""

    def test_successful_execution(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_result = MagicMock()
            mock_result.stdout = "output text"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_runner.run_tool.return_value = mock_result
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),
            )

            assert result is not None
            assert result["stdout"] == "output text"
            assert result["returncode"] == 0

    def test_returns_none_when_uv_unavailable(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),
            )
            assert result is None

    def test_returns_none_on_runner_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = UVToolRunnerError("fail")
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),
            )
            assert result is None

    def test_returns_none_on_import_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),
            )
            assert result is None

    def test_returns_none_on_unexpected_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = RuntimeError("unexpected")
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),
            )
            assert result is None

    def test_passes_env_to_runner(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_runner.run_tool.return_value = mock_result
            mock_get_runner.return_value = mock_runner

            env = {"MY_VAR": "value"}
            plugin._try_uv_tool_execution(
                command=["bandit"],
                working_dir=Path("/tmp"),
                env=env,
            )

            call_kwargs = mock_runner.run_tool.call_args[1]
            assert call_kwargs.get("env") == env


class TestValidateUvToolAvailability:
    """Tests for _validate_uv_tool_availability."""

    def test_returns_true_when_uv_not_required(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._validate_uv_tool_availability() is True

    def test_returns_true_when_uv_available(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_get_runner.return_value = mock_runner

            assert plugin._validate_uv_tool_availability() is True

    def test_returns_false_when_uv_unavailable(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._validate_uv_tool_availability() is False

    def test_returns_false_on_runner_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_get_runner.side_effect = UVToolRunnerError("broken")

            assert plugin._validate_uv_tool_availability() is False

    def test_returns_false_on_import_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            assert plugin._validate_uv_tool_availability() is False


class TestValidateToolAvailabilityWithPreInstalled:
    """Tests for _validate_tool_availability_with_pre_installed."""

    def test_no_command_returns_unavailable(self):
        plugin = FakePlugin(command="")
        result = plugin._validate_tool_availability_with_pre_installed()
        assert result["available"] is False
        assert "No command specified" in result["errors"][0]

    def test_returns_available_when_tool_found(self):
        plugin = FakePlugin(command="bandit")

        with patch.object(
            plugin,
            "_get_tool_installation_info",
            return_value={
                "available": True,
                "preferred_source": "uv",
                "uv_version": "1.7.0",
                "is_uv_installed": True,
                "is_pre_installed": False,
            },
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is True
            assert result["validation_method"] == "uv"

    def test_returns_available_with_pre_installed(self):
        plugin = FakePlugin(command="bandit")

        with patch.object(
            plugin,
            "_get_tool_installation_info",
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_version": "1.6.0",
                "pre_installed_path": "/usr/bin/bandit",
                "is_uv_installed": False,
                "is_pre_installed": True,
            },
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is True
            assert result["validation_method"] == "pre_installed"
            assert len(result["warnings"]) > 0

    def test_attempts_install_when_not_available(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(
            plugin,
            "_get_tool_installation_info",
            side_effect=[
                {
                    "available": False,
                    "preferred_source": "none",
                    "is_uv_installed": False,
                    "is_pre_installed": False,
                },
                {
                    "available": True,
                    "preferred_source": "uv",
                    "uv_version": "1.7.0",
                    "is_uv_installed": True,
                    "is_pre_installed": False,
                },
            ],
        ), patch.object(plugin, "_should_install_tool", return_value=True), patch.object(
            plugin, "_install_uv_tool", return_value=True
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is True
            assert result["validation_method"] == "uv_installed"

    def test_fails_when_install_not_possible(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=False)

        with patch.object(
            plugin,
            "_get_tool_installation_info",
            return_value={
                "available": False,
                "preferred_source": "none",
                "is_uv_installed": False,
                "is_pre_installed": False,
            },
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is False


class TestInstallUvTool:
    """Tests for _install_uv_tool."""

    def test_returns_false_when_uv_not_required(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._install_uv_tool() is False

    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._install_uv_tool() is False

    def test_returns_false_in_offline_mode(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=True):
            assert plugin._install_uv_tool() is False

    def test_returns_false_when_uv_unavailable(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is False

    def test_returns_true_when_already_installed_and_functional(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": True}
            mock_runner.is_tool_installed.return_value = True
            mock_runner.validate_cached_tool.return_value = {
                "is_functional": True,
                "version": "1.7.0",
            }
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True

    def test_successful_installation(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner, patch(
            "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
        ):
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": False}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = True
            mock_runner.get_installed_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True

    def test_failed_installation(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": False}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is False

    def test_returns_false_on_runner_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_get_runner.side_effect = UVToolRunnerError("broken")

            assert plugin._install_uv_tool() is False

    def test_returns_false_on_import_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            assert plugin._install_uv_tool() is False

    def test_returns_false_on_unexpected_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_get_runner.side_effect = RuntimeError("boom")

            assert plugin._install_uv_tool() is False

    def test_with_custom_retry_config(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False), patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner, patch(
            "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
        ):
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": True}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = True
            mock_runner.get_installed_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            result = plugin._install_uv_tool(
                timeout=60,
                retry_config={"max_retries": 2, "base_delay": 0.5, "max_delay": 10.0},
            )
            assert result is True


class TestIsUvToolInstalled:
    """Tests for _is_uv_tool_installed."""

    def test_returns_false_when_uv_not_used(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._is_uv_tool_installed() is False

    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._is_uv_tool_installed() is False

    def test_returns_true_when_tool_in_list(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.return_value = ["bandit", "checkov"]
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is True

    def test_returns_false_when_tool_not_in_list(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.return_value = ["checkov"]
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is False

    def test_falls_back_to_version_check_on_list_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_runner = MagicMock()
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.side_effect = UVToolRunnerError("fail")
            mock_runner.get_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is True


class TestGetToolInstallationInfo:
    """Tests for _get_tool_installation_info."""

    def test_no_command_returns_empty_info(self):
        plugin = FakePlugin(command="")
        info = plugin._get_tool_installation_info()
        assert info["tool_name"] is None
        assert info["available"] is False

    def test_returns_runner_info(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.get_tool_installation_info.return_value = {
                "is_uv_installed": True,
                "is_pre_installed": False,
                "uv_version": "1.7.0",
                "pre_installed_version": None,
                "pre_installed_path": None,
                "preferred_source": "uv",
                "available": True,
            }
            mock_get_runner.return_value = mock_runner

            info = plugin._get_tool_installation_info()
            assert info["tool_name"] == "bandit"
            assert info["available"] is True

    def test_returns_error_info_on_exception(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=RuntimeError("broken"),
        ):
            info = plugin._get_tool_installation_info()
            assert info["available"] is False
            assert "error" in info


class TestShouldInstallTool:
    """Tests for _should_install_tool."""

    def test_returns_false_when_uv_not_used(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._should_install_tool() is False

    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._should_install_tool() is False

    def test_delegates_to_runner(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.should_install_tool.return_value = True
            mock_get_runner.return_value = mock_runner

            assert plugin._should_install_tool() is True

    def test_returns_false_on_exception(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=RuntimeError("broken"),
        ):
            assert plugin._should_install_tool() is False


class TestSetupUvToolInstallCommands:
    """Tests for _setup_uv_tool_install_commands."""

    def test_does_nothing_when_uv_disabled(self):
        plugin = FakePlugin(use_uv_tool=False)
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == []

    def test_does_nothing_when_no_command(self):
        plugin = FakePlugin(command="", use_uv_tool=True)
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == []

    def test_basic_install_command(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert len(plugin.uv_tool_install_commands) == 1
        assert "uv tool install bandit" in plugin.uv_tool_install_commands[0]

    def test_install_with_package_name(self):
        plugin = FakePlugin(
            command="bandit", use_uv_tool=True, uv_tool_package_name="bandit-pkg"
        )

        with patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert "bandit-pkg" in plugin.uv_tool_install_commands[0]

    def test_install_with_version_constraint(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(
            plugin, "_get_tool_version_constraint", return_value=">=1.7.0"
        ), patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert ">=1.7.0" in plugin.uv_tool_install_commands[0]

    def test_install_with_extras(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(
            plugin, "_get_tool_package_extras", return_value=["sarif", "toml"]
        ), patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert "bandit[sarif,toml]" in plugin.uv_tool_install_commands[0]


class TestExtensionPoints:
    """Tests for extension point default implementations."""

    def test_get_tool_version_constraint_returns_none(self):
        plugin = FakePlugin()
        # The base implementation should return None (passthrough)
        assert UVToolMixin._get_tool_version_constraint(plugin) is None

    def test_get_tool_package_extras_returns_none(self):
        plugin = FakePlugin()
        assert UVToolMixin._get_tool_package_extras(plugin) is None

    def test_get_tool_with_dependencies_returns_none(self):
        plugin = FakePlugin()
        assert UVToolMixin._get_tool_with_dependencies(plugin) is None


class TestIsOfflineMode:
    """Tests for _is_offline_mode."""

    def test_delegates_to_constants(self):
        plugin = FakePlugin()

        with patch(
            "automated_security_helper.core.constants.is_offline_mode", return_value=True
        ):
            assert plugin._is_offline_mode() is True

        with patch(
            "automated_security_helper.core.constants.is_offline_mode", return_value=False
        ):
            assert plugin._is_offline_mode() is False
