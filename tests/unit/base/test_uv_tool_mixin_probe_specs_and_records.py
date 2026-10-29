# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv mixin probes, installs and records the environment the scan runs in.

Each test pins one fix in ``base/uv_tool_mixin.py``:

* the ``--from`` spec, the pre-installed verification and the version probes
  are built on the package that provides the tool (``uv_tool_package_name``),
  not on the executable's name;
* a failed response still grades the scan (``exit_code``), and the handler's
  own DEBUG line cannot raise out of it;
* the offline explainer reads only a stderr log this run wrote;
* a scanner switched to a verified PATH copy reports that copy's version;
* the stored install command carries the plugin's ``--with`` dependencies;
* a successful install is not reported as failed by its best-effort version read;
* an installed-but-broken tool is reinstalled, and the plugin's own offline mode
  reaches uv;
* the import-failure arm of the uv run names the component that failed to
  import, and still answers when the runner's own import is what raised;
* the mixin's private-attribute annotations are plain annotations, and the one
  public name it types stays out of every plugin model's fields.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.utils.pre_installed_tool import (
    PreInstalledToolVerdict,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

pytestmark = pytest.mark.unit


class FakePlugin(UVToolMixin):
    """The attributes the mixin reads from PluginBase, and nothing else."""

    def __init__(self, **kwargs):
        self.command = kwargs.get("command", "bandit")
        self.use_uv_tool = kwargs.get("use_uv_tool", True)
        self.uv_tool_package_name = kwargs.get("uv_tool_package_name", None)
        self.uv_tool_install_commands = []
        self.exit_code = 0
        self.output = ""
        self.errors: list = []
        self.tool_version = kwargs.get("tool_version", None)
        self.extras = kwargs.get("extras", None)
        self.constraint = kwargs.get("constraint", None)
        self.with_dependencies = kwargs.get("with_dependencies", None)
        self.offline = kwargs.get("offline", False)
        self._log_messages = []

    def _plugin_log(self, *args, **kwargs):
        self._log_messages.append(args)

    def _process_command_response(self, response):
        self.exit_code = response.get("returncode", 0)
        self.output = response.get("stdout", "")

    def _get_tool_package_extras(self):
        return self.extras

    def _get_tool_version_constraint(self):
        return self.constraint

    def _get_tool_with_dependencies(self):
        return self.with_dependencies

    def _get_tool_python_request(self):
        return None

    def _is_offline_mode(self):
        return self.offline


class _BrokenResult:
    """A run result whose stdout cannot be read, with the tool's own exit code."""

    returncode = 1
    stderr = ""

    @property
    def stdout(self):
        raise RuntimeError("read broke")


class TestTheFromSpecNamesThePackage:
    def test_a_package_named_apart_from_the_command_is_the_from_spec(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert", uv_tool_package_name="nbconvert"
        )
        assert plugin._uv_from_spec() == "nbconvert"

    def test_extras_and_the_constraint_ride_the_package_name(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert",
            uv_tool_package_name="nbconvert",
            extras=["webpdf"],
            constraint=">=7",
        )
        assert plugin._uv_from_spec() == "nbconvert[webpdf]>=7"

    def test_a_tool_whose_package_is_its_command_passes_no_from_spec(self):
        """The control: the pre-existing shape is unchanged."""
        assert FakePlugin(command="bandit")._uv_from_spec() is None
        assert FakePlugin(command="bandit", extras=["sarif"])._uv_from_spec() == (
            "bandit[sarif]"
        )

    def test_the_run_passes_the_package_name_to_the_runner(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert", uv_tool_package_name="nbconvert"
        )
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as get_runner:
            runner = MagicMock()
            runner.uv_availability.return_value = (True, None)
            runner.run_tool.return_value = SimpleNamespace(
                stdout="", stderr="", returncode=0
            )
            get_runner.return_value = runner
            plugin._try_uv_tool_execution(
                command=["jupyter-nbconvert", "x.ipynb"],
                working_dir=Path("/tmp"),  # nosec B108
            )
        assert runner.run_tool.call_args.kwargs["package_name"] == "nbconvert"

    def test_the_installation_info_probes_the_scans_spec(self):
        plugin = FakePlugin(command="bandit", extras=["sarif"])
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as get_runner:
            runner = MagicMock()
            runner.get_tool_installation_info.return_value = {
                "is_uv_installed": True,
                "is_pre_installed": False,
                "preferred_source": "uv",
                "available": True,
            }
            get_runner.return_value = runner
            plugin._get_tool_installation_info()
        runner.get_tool_installation_info.assert_called_once_with(
            "bandit", "bandit[sarif]"
        )

    def test_the_pre_installed_copy_is_verified_against_the_package(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert", uv_tool_package_name="nbconvert"
        )
        verdict = PreInstalledToolVerdict("satisfied", "/opt/bin/x", "nbconvert", "")
        with (
            patch(
                "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool",
                return_value=verdict,
            ) as verify,
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value="/opt/uv",
            ),
        ):
            plugin._select_tool_execution(
                {
                    "preferred_source": "pre_installed",
                    "pre_installed_path": "/opt/bin/x",
                }
            )
        assert verify.call_args.args[1] == "nbconvert"


class TestAFailedResponseStillGradesTheScan:
    def test_the_tools_exit_code_is_folded_when_the_response_build_raised(self):
        plugin = FakePlugin(command="bandit")
        response = plugin._uv_response(_BrokenResult(), None)
        assert response["returncode"] == 1
        assert plugin.exit_code == 1

    def test_a_raising_values_hook_does_not_escape_the_handler(self, caplog):
        plugin = FakePlugin(command="bandit")

        def _raises():
            raise RuntimeError("the values hook broke")

        plugin._values_to_redact = _raises  # type: ignore[method-assign]
        with caplog.at_level(logging.DEBUG, logger="ash"):
            response = plugin._uv_response(_BrokenResult(), None)
        assert response.get("post_run_error") is True
        assert "read broke" in response["error"]


class TestTheOfflineExplainerReadsOnlyThisRunsLog:
    RESOLVER_TEXT = "error: No solution found when resolving tool dependencies\n"

    def _run(self, plugin, results_dir, write_log):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as get_runner:
            runner = MagicMock()
            runner.uv_availability.return_value = (True, None)

            def _run_tool(**kwargs):
                if write_log:
                    (results_dir / "FakePlugin.stderr.log").write_text(
                        self.RESOLVER_TEXT * 40, encoding="utf-8"
                    )
                return SimpleNamespace(stdout="", stderr="", returncode=1)

            runner.run_tool.side_effect = _run_tool
            get_runner.return_value = runner
            return plugin._try_uv_tool_execution(
                command=["bandit"], working_dir=results_dir, results_dir=results_dir
            )

    def test_a_leftover_log_from_an_earlier_run_is_not_this_runs_failure(
        self, tmp_path
    ):
        plugin = FakePlugin(command="bandit", offline=True)
        (tmp_path / "FakePlugin.stderr.log").write_text(
            self.RESOLVER_TEXT, encoding="utf-8"
        )
        response = self._run(plugin, tmp_path, write_log=False)
        assert response is not None and response["returncode"] == 1
        assert plugin.errors == [], plugin.errors

    def test_a_log_this_run_wrote_is_explained(self, tmp_path):
        """The control: the explainer still names the cause for this run's log."""
        plugin = FakePlugin(command="bandit", offline=True)
        (tmp_path / "FakePlugin.stderr.log").write_text("older\n", encoding="utf-8")
        self._run(plugin, tmp_path, write_log=True)
        assert len(plugin.errors) == 1, plugin.errors
        assert "could not resolve" in plugin.errors[0]


class TestAVerifiedPathCopyReportsItsOwnVersion:
    def test_the_verdicts_version_replaces_the_probed_one(self):
        plugin = FakePlugin(command="bandit", tool_version="1.9.0")
        verdict = PreInstalledToolVerdict(
            "satisfied", "/opt/bin/bandit", "bandit", "", version="1.7.9"
        )
        with (
            patch(
                "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool",
                return_value=verdict,
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value="/opt/uv",
            ),
        ):
            assert (
                plugin._select_tool_execution(
                    {
                        "preferred_source": "pre_installed",
                        "pre_installed_path": "/opt/bin/bandit",
                    }
                )
                is True
            )
        assert plugin.use_uv_tool is False
        assert plugin.tool_version == "1.7.9"


class TestTheStoredInstallCommand:
    def test_it_carries_the_with_dependencies(self):
        plugin = FakePlugin(command="bandit", with_dependencies=["sarif-om>=1.0"])
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == [
            "uv tool install --with sarif-om>=1.0 bandit"
        ]


def _install_runner(**overrides):
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.get_cache_info.return_value = {"cache_available": False}
    runner.is_tool_installed.return_value = False
    runner.install_tool_with_version.return_value = True
    runner.get_installed_tool_version.return_value = "1.7.0"
    for name, value in overrides.items():
        setattr(runner, name, value)
    return runner


class TestInstall:
    def test_a_successful_install_survives_a_failed_version_read(self):
        plugin = FakePlugin(command="bandit")
        runner = _install_runner()
        runner.get_installed_tool_version.side_effect = UVToolRunnerError("listing")
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=runner,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            assert plugin._install_uv_tool() is True

    def test_an_installed_but_broken_tool_is_reinstalled(self):
        plugin = FakePlugin(command="bandit")
        runner = _install_runner()
        runner.is_tool_installed.return_value = True
        runner.validate_cached_tool.return_value = {
            "is_functional": False,
            "version": None,
            "error": "Could not determine tool version",
        }
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=runner,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            assert plugin._install_uv_tool() is True
        kwargs = runner.install_tool_with_version.call_args.kwargs
        assert kwargs["reinstall"] is True
        assert kwargs["offline"] is False


class TestADeferredVersionProbeStaysOwedUntilItAnswers:
    def test_a_transient_runner_failure_does_not_lose_the_probe(self):
        """The probe deferred at construction is cleared before it runs, so one
        timeout or spawn error left tool_version None for the instance's life.
        A runner that raises once and then answers gives the version on the
        second resolve."""
        plugin = FakePlugin(command="bandit")
        plugin._deferred_tool_version_probe = ("bandit", None)
        runner = MagicMock()
        runner.is_uv_available.return_value = True
        runner.get_tool_version.side_effect = [
            UVToolRunnerError("the probe timed out"),
            "1.7.9",
        ]
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=runner,
        ):
            plugin.resolve_deferred_tool_version()
            assert plugin.tool_version is None
            plugin.resolve_deferred_tool_version()
        assert plugin.tool_version == "1.7.9"
        assert plugin._deferred_tool_version_probe is None
        assert runner.get_tool_version.call_count == 2


class TestTheImportFailureArmNamesTheComponent:
    RUNNER_WORDING = "the uv tool runner could not be imported"

    def _available_runner(self):
        runner = MagicMock()
        runner.uv_availability.return_value = (True, None)
        return runner

    def test_another_modules_import_error_is_not_blamed_on_the_runner(self):
        class Plugin(FakePlugin):
            def _uv_run_inputs_for_records(self):
                raise ImportError("No module named 'yaml'", name="yaml")

        plugin = Plugin(command="bandit")
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=self._available_runner(),
        ):
            result = plugin._try_uv_tool_execution(
                command=["bandit"],
                working_dir=Path("/tmp"),  # nosec B108
            )
        assert result is None
        assert plugin._uv_run_failure is not None
        assert not plugin._uv_run_failure.startswith(self.RUNNER_WORDING)
        assert "yaml" in plugin._uv_run_failure, plugin._uv_run_failure

    def test_the_runners_own_import_failure_is_still_answered(self, monkeypatch):
        """The control, and the unbound-name hazard: the except arm names the
        runner's error class, which the failing import used to bind locally."""
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.delattr(uv_tool_runner, "get_uv_tool_runner")
        plugin = FakePlugin(command="bandit")
        result = plugin._try_uv_tool_execution(
            command=["bandit"],
            working_dir=Path("/tmp"),  # nosec B108
        )
        assert result is None
        assert plugin._uv_run_failure is not None
        assert plugin._uv_run_failure.startswith(self.RUNNER_WORDING), (
            plugin._uv_run_failure
        )


class TestTheMixinsAnnotations:
    def test_the_private_attributes_are_annotated_at_runtime(self):
        """An underscore-named annotation is no pydantic field, so neither needs
        the TYPE_CHECKING fence; the deferred probe's used to sit behind it."""
        annotations = UVToolMixin.__annotations__
        assert "_uv_run_failure" in annotations
        assert "_deferred_tool_version_probe" in annotations

    def test_the_public_name_is_no_field_of_a_plugin_model(self):
        """The control: the fenced annotation stays out of the model fields."""
        from automated_security_helper.base.plugin_base import PluginBase

        assert "dependency_unavailable_reason" not in UVToolMixin.__annotations__
        assert "dependency_unavailable_reason" not in PluginBase.model_fields
        assert "_deferred_tool_version_probe" not in PluginBase.model_fields


class TestThePluginsOwnOfflineMode:
    def test_a_scanner_offline_by_its_options_is_offline_to_uv(self, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)

        class Scanner(UVToolMixin):
            def _scanner_offline(self):
                return True

        assert Scanner()._is_offline_mode() is True

    def test_without_a_scanner_mode_ash_decides(self, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        assert UVToolMixin()._is_offline_mode() is False
        monkeypatch.setenv("ASH_OFFLINE", "1")
        assert UVToolMixin()._is_offline_mode() is True
