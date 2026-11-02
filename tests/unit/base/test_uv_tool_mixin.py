"""Tests for base/uv_tool_mixin.py — covers version detection, execution, validation, and installation."""

from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from tests.utils.env_assertions import differing_names


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
        # The DOCUMENTED one-argument extension signature, deliberately: a
        # third-party override looks exactly like this, so every cell that
        # drives _uv_response through FakePlugin also proves the seam stays
        # compatible (the uv inputs are computed from the plugin's own
        # hooks, never passed as a parameter or carried on an attribute).
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

    @pytest.mark.unit
    def test_returns_none_when_use_uv_tool_disabled(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._get_uv_tool_version("bandit") is None

    @pytest.mark.unit
    def test_returns_version_string(self):
        """Direct test of the method logic with mocked runner."""
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version == "1.7.0"

    @pytest.mark.unit
    def test_returns_none_when_uv_not_available(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (False, None)
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            version = plugin._get_uv_tool_version("bandit")
            assert version is None

    @pytest.mark.unit
    def test_a_refused_check_is_logged_as_the_sandbox_refusing_uv(self):
        """Not as uv being absent, which sends the operator to install uv."""
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )
        from automated_security_helper.utils.uv_tool_runner import UVToolRunner

        plugin = FakePlugin(use_uv_tool=True)
        runner = UVToolRunner()
        # The unit guard stubs every runner's ``uv_availability`` to
        # (False, None) for this module (tests/utils/tool_guard.py; only the
        # runner's own module is a probe subject), so the probe whose refusal
        # arm would record the scope's refusal never runs here, and the stub
        # stands: a probe that spawns is what the guard keeps out of the unit
        # tier. What the arm records is seeded in its place -- the refusal's
        # text on this thread's check state -- and the stubbed answer stays
        # "not available", the state the product reads: unavailable_reason
        # names the recorded refusal, and the mixin words it over the bare
        # answer.
        runner._check_state().refusal = "firejail is not installed"
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=runner,
            ),
            sandbox_scope(RefusingScope("jupyter", "firejail is not installed")),  # type: ignore[arg-type]
        ):
            assert plugin._get_uv_tool_version("jupyter-nbconvert") is None

        (message,) = [args[0] for args in plugin._log_messages]
        assert "scanner sandbox refused to run uv" in message
        assert "firejail is not installed" in message
        assert "jupyter-nbconvert version detection" in message
        assert "UV is not available" not in message

    @pytest.mark.unit
    def test_returns_none_on_import_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            # ImportError is caught inside the method
            version = plugin._get_uv_tool_version("bandit")
            assert version is None

    @pytest.mark.unit
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

    @pytest.mark.unit
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

    @pytest.mark.parametrize(
        "arm,marker",
        [
            pytest.param(
                "import-error",
                "UV tool runner module not available for",
                id="import-error",
            ),
            pytest.param(
                "unexpected", "Unexpected error getting UV tool", id="unexpected"
            ),
        ],
    )
    @pytest.mark.unit
    def test_the_version_error_arms_logs_hide_the_plugins_values(self, arm, marker):
        """The version probe's ImportError and catch-all arms log the error
        text, which can quote a path with an env-read value in it: they pass
        through the redaction of the plugin's own values, as the
        UVToolRunnerError arm beside them does."""
        from types import SimpleNamespace

        canary = "ENVCANARY-uvver-55555"
        plugin = FakePlugin(use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        if arm == "import-error":
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=ImportError(f"no module under /opt/{canary}/lib"),
            )
        else:
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            )
        with patcher as mock_get_runner:
            if arm == "unexpected":
                mock_runner = MagicMock()
                mock_runner.is_uv_available.side_effect = RuntimeError(
                    f"probe broke on /opt/{canary}/bin"
                )
                mock_get_runner.return_value = mock_runner
            assert plugin._get_uv_tool_version("bandit") is None

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        # The control: the arm's line was emitted.
        assert any(marker in line for line in logged), logged
        assert not any(canary in line for line in logged), logged


class TestTryUvToolExecution:
    """Tests for _try_uv_tool_execution."""

    @pytest.mark.unit
    def test_successful_execution(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_result = MagicMock()
            mock_result.stdout = "output text"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_runner.run_tool.return_value = mock_result
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

            assert result is not None
            assert result["stdout"] == "output text"
            assert result["returncode"] == 0

    @pytest.mark.unit
    def test_a_raising_inputs_hook_does_not_drop_the_dispatch(self):
        """The pre-dispatch record computes the run's inputs from overridable
        hooks, and a record must never replace the run itself: a hook that
        raises used to abort the dispatch as a runner error. The record falls
        back to the plain value layer and the run proceeds."""

        def _raises():
            raise TypeError("signature drift")

        plugin = FakePlugin(command="bandit")
        plugin._uv_from_spec = _raises  # the hook _uv_run_inputs reads first

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_result = MagicMock()
            mock_result.stdout = "output text"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_runner.run_tool.return_value = mock_result
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

        assert result is not None, "the raising hook dropped the dispatch"
        assert result["returncode"] == 0, result

    @pytest.mark.unit
    def test_returns_none_when_uv_unavailable(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (False, None)
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )
            assert result is None

    @staticmethod
    def _unavailable_runner(probe_failure):
        from types import SimpleNamespace

        return SimpleNamespace(
            uv_availability=lambda: (False, probe_failure),
        )

    @pytest.mark.unit
    def test_an_unavailable_uvs_reason_names_the_probes_failure(self):
        """When the runner remembers WHY its probe failed, the scan's reason
        and the log line carry it: "uv is not available" alone reads as "uv
        is not installed" while the probe may have timed out or been refused
        by the sandbox, and the operator fixes those differently."""
        plugin = FakePlugin(command="bandit")
        failure = "the probe timed out after 10 seconds"

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=self._unavailable_runner(failure),
        ):
            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

        assert result is None
        assert plugin._uv_run_failure == f"uv is not available ({failure})", (
            plugin._uv_run_failure
        )
        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        assert any(failure in line for line in logged), logged

    @pytest.mark.unit
    def test_an_absent_uvs_reason_stays_the_plain_sentence(self):
        """The control: with no remembered probe failure (uv absent), the
        plain sentence is the whole truth and gains no empty parenthesis."""
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=self._unavailable_runner(None),
        ):
            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

        assert result is None
        assert plugin._uv_run_failure == "uv is not available", plugin._uv_run_failure

    @pytest.mark.unit
    def test_returns_none_on_runner_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = UVToolRunnerError("fail")
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )
            assert result is None

    @pytest.mark.unit
    def test_the_dispatch_log_hides_the_plugins_values(self):
        """The pre-dispatch DEBUG line logs the tool's args, and an argument
        can carry a value the plugin's config read from the environment (a
        path, a token in a flag). The runner's own command-line log is already
        redacted; this line printed the args raw, so the value reached
        ash.log. It passes through the redaction of the plugin's own values,
        as the mixin's other lines do."""
        from types import SimpleNamespace

        canary = "ENVCANARY-uvdispatch-55555"
        plugin = FakePlugin(command="bandit")
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import (
                UVToolRunnerError,
            )

            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = UVToolRunnerError("not dispatched")
            mock_get_runner.return_value = mock_runner

            plugin._try_uv_tool_execution(
                command=["bandit", "--target", f"/opt/{canary}/src"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        dispatch = [line for line in logged if "via UV tool run" in line]
        # The control: the dispatch line was emitted.
        assert dispatch, logged
        assert not any(canary in line for line in logged), logged

    @pytest.mark.unit
    def test_the_dispatch_log_hides_a_spec_that_pins_an_env_read_value(self):
        """The pre-dispatch record quotes the command line, and a plugin-built
        spec can PIN a short env-read value ("1.8"), which sits below the
        value layer's whole-word band: a record carrying only the value layer
        would print "bandit==1.8" in clear. The record gets the run's inputs,
        so the pinning spec is hidden by origin."""
        from types import SimpleNamespace

        pin = "1.8"
        spec = f"bandit=={pin}"
        plugin = FakePlugin(command="bandit")
        plugin._uv_run_inputs = lambda: (spec,)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[pin])
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import (
                UVToolRunnerError,
            )

            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = UVToolRunnerError("not dispatched")
            mock_get_runner.return_value = mock_runner

            plugin._try_uv_tool_execution(
                command=["bandit", "--require", spec],
                working_dir=Path("/tmp/work"),  # nosec B108
            )

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        dispatch = [line for line in logged if "via UV tool run" in line]
        # The control: the dispatch line was emitted.
        assert dispatch, logged
        assert not any(spec in line for line in dispatch), dispatch

    @pytest.mark.parametrize(
        "raising_method,drive,marker",
        [
            pytest.param(
                "run_tool",
                lambda plugin: plugin._try_uv_tool_execution(
                    command=["bandit", "--target", "a.py"],
                    working_dir=Path("/tmp/work"),  # nosec B108
                ),
                "UV tool runner error for",
                id="run",
            ),
            pytest.param(
                "get_tool_version",
                lambda plugin: plugin._get_uv_tool_version("bandit"),
                "UV tool runner error getting",
                id="version",
            ),
            pytest.param(
                "is_uv_available",
                lambda plugin: plugin._validate_uv_tool_availability(),
                "UV tool runner error during validation",
                id="validation",
            ),
            pytest.param(
                "is_tool_installed",
                lambda plugin: plugin._install_uv_tool(),
                "INSTALLATION_ERROR",
                id="installation",
            ),
        ],
    )
    @pytest.mark.unit
    def test_the_runner_error_log_hides_the_plugins_values(
        self, raising_method, drive, marker, monkeypatch
    ):
        """The runner's refusal text can embed the full argv (its spawn and
        timeout messages quote the command), and an argument can carry a value
        the plugin's config read from the environment. The WARNING that logs
        the error printed it raw, so the value reached ash.log; it passes
        through the redaction of the plugin's own values, as the mixin's
        other lines do - on all FOUR UVToolRunnerError arms (run, version,
        validation, installation), each driven through its own entry point."""
        # Cleared as the install cells clear it: under an operator's
        # ASH_OFFLINE=true, _install_uv_tool logs its offline skip and returns
        # before it asks the runner anything, so the installation arm's
        # control would find no runner error to read.
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        from types import SimpleNamespace

        canary = "ENVCANARY-uvrun-77777"
        plugin = FakePlugin(command="bandit")
        plugin.use_uv_tool = True
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import (
                UVToolRunnerError,
            )

            mock_runner = MagicMock()
            error = UVToolRunnerError(
                "Command '['uv', 'tool', 'run', 'bandit', '--target', "
                f"'/opt/{canary}/src']' failed to start"
            )
            if raising_method != "is_uv_available":
                mock_runner.uv_availability.return_value = (True, None)
                mock_runner.is_uv_available.return_value = True
            getattr(mock_runner, raising_method).side_effect = error
            mock_get_runner.return_value = mock_runner

            drive(plugin)

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        warning = [line for line in logged if marker in line]
        # The control: the arm's WARNING was emitted.
        assert warning, logged
        assert not any(canary in line for line in logged), logged

    @pytest.mark.parametrize(
        "raised,marker",
        [
            # An ImportError raised with no module name is not the runner's
            # own import failing, so the arm words it as an import that failed
            # while preparing the run (the runner wording is reserved for an
            # ImportError whose name is the runner module).
            pytest.param(
                ImportError,
                "Import failed while preparing the uv run",
                id="import-error",
            ),
            pytest.param(
                RuntimeError,
                "Unexpected error during UV tool execution",
                id="unexpected",
            ),
        ],
    )
    @pytest.mark.unit
    def test_the_other_error_arms_logs_hide_the_plugins_values(
        self, raised, marker, caplog
    ):
        """The ImportError and catch-all arms log the error too, and a raise
        from the runner can quote the full argv with an env-read value in it.
        Their WARNING and DEBUG lines pass through the redaction of the
        plugin's own values, as the UVToolRunnerError arm's line does."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "ENVCANARY-uvarms-33333"
        plugin = FakePlugin(command="bandit")
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = raised(
                f"Command '['uv', 'tool', 'run', 'bandit', '--target', "
                f"'/opt/{canary}/src']' broke"
            )
            mock_get_runner.return_value = mock_runner

            with caplog.at_level(logging_module.DEBUG, logger="ash"):
                plugin._try_uv_tool_execution(
                    command=["bandit", "--target", f"/opt/{canary}/src"],
                    working_dir=Path("/tmp/work"),  # nosec B108
                )

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        # The control: the arm's WARNING was emitted.
        assert any(marker in line for line in logged), logged
        assert not any(canary in line for line in logged), logged
        assert canary not in caplog.text, caplog.text

    @pytest.mark.integration
    def test_the_after_start_debug_hides_the_plugins_values(self, caplog):
        """The failure-after-the-start DEBUG line logs the error that ended the
        wait, which can quote the argv: it passes through the same redaction."""
        import logging as logging_module
        import subprocess  # nosec B404 -- the cell spawns this Python
        import sys
        from types import SimpleNamespace

        from automated_security_helper.utils.subprocess_utils import (
            StartWatch,
            spawn_run,
            watched_launch,
        )

        canary = "ENVCANARY-uvafter-44444"
        plugin = FakePlugin(command="bandit")
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        watch = StartWatch()
        with watch.watching(), watched_launch():
            try:
                spawn_run([sys.executable, "-c", "import sys; sys.exit(7)"], check=True)
            except subprocess.CalledProcessError:
                pass
        assert watch.started is not None, "the launch was not watched"

        with caplog.at_level(logging_module.DEBUG, logger="ash"):
            # The caller's ONE guarded read of the values hook, taken as a
            # required parameter (never a defaulted empty set), so two reads
            # cannot disagree and no caller can silently pass nothing.
            after = plugin._uv_failure_after_the_start(
                watch,
                RuntimeError(f"wait broke on '/opt/{canary}/src'"),
                record_values=(canary,),
            )

        # The control: the failure was attributed after the start and logged.
        assert after is not None, after
        assert "failed after its child started" in caplog.text, caplog.text
        assert canary not in caplog.text, caplog.text

    @pytest.mark.unit
    def test_the_response_error_debug_hides_the_plugins_values(self, caplog):
        """When handling a returned run's response raises, the DEBUG line logs
        the error that broke it, which can quote a path with an env-read value
        in it: its message and the traceback it carries pass through the same
        redaction as the mixin's other lines."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "ENVCANARY-uvresp-66666"
        plugin = FakePlugin(command="bandit")
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        class _BrokenResult:
            returncode = 0
            stderr = ""

            @property
            def stdout(self):
                raise RuntimeError(f"read broke on '/opt/{canary}/out'")

        with caplog.at_level(logging_module.DEBUG, logger="ash"):
            response = plugin._uv_response(_BrokenResult(), None)

        # The control: the error was handled and its DEBUG line emitted.
        assert response is not None
        assert "UV tool response error details" in caplog.text, caplog.text
        assert canary not in caplog.text, caplog.text

    @pytest.mark.unit
    def test_returns_none_on_import_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )
            assert result is None

    @pytest.mark.unit
    def test_returns_none_on_unexpected_error(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.run_tool.side_effect = RuntimeError("unexpected")
            mock_get_runner.return_value = mock_runner

            result = plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src/"],
                working_dir=Path("/tmp/work"),  # nosec B108
            )
            assert result is None

    @pytest.mark.unit
    def test_passes_env_to_runner(self):
        plugin = FakePlugin(command="bandit")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
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
                working_dir=Path("/tmp"),  # nosec B108
                env=env,
            )

            call_kwargs = mock_runner.run_tool.call_args[1]
            # By names: a failure would print a merged environment's values.
            assert differing_names(call_kwargs.get("env") or {}, env) == []


class TestValidateUvToolAvailability:
    """Tests for _validate_uv_tool_availability."""

    @pytest.mark.unit
    def test_returns_true_when_uv_not_required(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._validate_uv_tool_availability() is True

    @pytest.mark.unit
    def test_returns_true_when_uv_available(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_get_runner.return_value = mock_runner

            assert plugin._validate_uv_tool_availability() is True

    @pytest.mark.unit
    def test_returns_false_when_uv_unavailable(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (False, None)
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._validate_uv_tool_availability() is False

    @pytest.mark.unit
    def test_returns_false_on_runner_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_get_runner.side_effect = UVToolRunnerError("broken")

            assert plugin._validate_uv_tool_availability() is False

    @pytest.mark.unit
    def test_returns_false_on_import_error(self):
        plugin = FakePlugin(use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no module"),
        ):
            assert plugin._validate_uv_tool_availability() is False

    @pytest.mark.parametrize(
        "arm,marker",
        [
            pytest.param(
                "import-error",
                "UV tool runner module not available during validation",
                id="import-error",
            ),
            pytest.param(
                "unexpected",
                "Unexpected error during UV tool validation",
                id="unexpected",
            ),
        ],
    )
    @pytest.mark.unit
    def test_the_validation_error_arms_logs_hide_the_plugins_values(self, arm, marker):
        """The validation's ImportError and catch-all arms log the error text,
        which can quote a path with an env-read value in it: they pass through
        the redaction of the plugin's own values, as the UVToolRunnerError arm
        beside them does."""
        from types import SimpleNamespace

        canary = "ENVCANARY-uvval-77777"
        plugin = FakePlugin(use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        if arm == "import-error":
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=ImportError(f"no module under /opt/{canary}/lib"),
            )
        else:
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            )
        with patcher as mock_get_runner:
            if arm == "unexpected":
                mock_runner = MagicMock()
                mock_runner.is_uv_available.side_effect = RuntimeError(
                    f"probe broke on /opt/{canary}/bin"
                )
                mock_get_runner.return_value = mock_runner
            assert plugin._validate_uv_tool_availability() is False

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        # The control: the arm's line was emitted.
        assert any(marker in line for line in logged), logged
        assert not any(canary in line for line in logged), logged


class TestValidateToolAvailabilityWithPreInstalled:
    """Tests for _validate_tool_availability_with_pre_installed."""

    @pytest.mark.unit
    def test_no_command_returns_unavailable(self):
        plugin = FakePlugin(command="")
        result = plugin._validate_tool_availability_with_pre_installed()
        assert result["available"] is False
        assert "No command specified" in result["errors"][0]

    @pytest.mark.unit
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

    @pytest.mark.unit
    def test_returns_available_with_pre_installed(self):
        plugin = FakePlugin(command="bandit")

        # The decision how the copy runs is _select_tool_execution's (it
        # verifies the copy against the requirement); here it keeps uv, so the
        # unverified copy is reported with a warning.
        with (
            patch.object(
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
            ),
            patch.object(plugin, "_select_tool_execution", return_value=True),
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is True
            assert result["validation_method"] == "pre_installed"
            assert len(result["warnings"]) > 0

    @pytest.mark.unit
    def test_attempts_install_when_not_available(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(
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
            ),
            patch.object(plugin, "_should_install_tool", return_value=True),
            patch.object(plugin, "_install_uv_tool", return_value=True),
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
            assert result["available"] is True
            assert result["validation_method"] == "uv_installed"

    @pytest.mark.unit
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

    @pytest.mark.unit
    def test_returns_false_when_uv_not_required(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_in_offline_mode(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=True):
            assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_when_uv_unavailable(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (False, None)
            mock_runner.is_uv_available.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_true_when_already_installed_and_functional(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": True}
            mock_runner.is_tool_installed.return_value = True
            mock_runner.validate_cached_tool.return_value = {
                "is_functional": True,
                "version": "1.7.0",
            }
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True

    @pytest.mark.unit
    def test_successful_installation(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": False}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = True
            mock_runner.get_installed_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True

    @pytest.mark.unit
    def test_the_install_record_passes_the_public_anchor_and_hides_a_short_pin(
        self,
    ):
        """The installation-attempt record and the runner's stderr debug line
        pass the SAME public anchor to the shower -- uv_tool_package_name or
        command, the install's own tool name. With self.command there
        instead, a scanner whose config command differs from its package name
        had the package-name token of a hidden spec replaced in this record
        and kept in the runner's line, numbering the placeholders apart. And
        a version constraint that pins an env-read value below the value
        layer's whole-word band ("9.9") is hidden on the record lines by the
        input-origin arm."""
        plugin = FakePlugin(
            command="cmdqz", use_uv_tool=True, uv_tool_package_name="pkgqz"
        )
        from automated_security_helper.utils import uv_tool_runner as runner_module

        real_shown = runner_module.shown_uv_output
        anchors: list = []

        def _recording_shown(text, values, **kwargs):
            anchors.append(kwargs.get("tool_name"))
            return real_shown(text, values, **kwargs)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(plugin, "_values_to_redact", return_value=("9.9",)),
            patch.object(plugin, "_get_tool_version_constraint", return_value="==9.9"),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
            patch(
                "automated_security_helper.utils.uv_tool_runner.shown_uv_output",
                _recording_shown,
            ),
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": True}
            mock_runner.is_tool_installed.return_value = True
            mock_runner.validate_cached_tool.return_value = {
                "is_functional": True,
                "version": "1.7.0",
            }
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True

        assert anchors, "the installation record never reached the shower"
        assert set(anchors) == {"pkgqz"}, anchors
        logged = "\n".join(
            " ".join(str(part) for part in msg) for msg in plugin._log_messages
        )
        assert "pkgqz==9.9" not in logged, logged
        assert "==9.9" not in logged, logged

    @pytest.mark.unit
    def test_the_setup_debug_line_hides_the_spec_through_the_install_inputs(self):
        """One builder serves the install's spec and every record about it.
        _setup_uv_tool_install_commands still built its spec by hand and
        logged it through the plain value layer, so a short pin below the
        whole-word band ("9.9") and a value glued into an extra printed in
        the DEBUG line while the installation-attempt record hid them."""
        plugin = FakePlugin(
            command="cmdqz", use_uv_tool=True, uv_tool_package_name="pkgqz"
        )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(plugin, "_values_to_redact", return_value=("9.9", "qz4b")),
            patch.object(plugin, "_get_tool_version_constraint", return_value="==9.9"),
            patch.object(
                plugin, "_get_tool_package_extras", return_value=["sarifqz4b"]
            ),
        ):
            plugin._setup_uv_tool_install_commands()

        assert plugin.uv_tool_install_commands == [
            "uv tool install pkgqz[sarifqz4b]==9.9"
        ], plugin.uv_tool_install_commands
        logged = "\n".join(
            " ".join(str(part) for part in msg) for msg in plugin._log_messages
        )
        assert "Set up UV tool install command: uv tool install" in logged, logged
        assert "==9.9" not in logged, logged
        assert "sarifqz4b" not in logged, logged

    @pytest.mark.unit
    def test_the_install_records_extras_and_retry_lines_hide_glued_values(
        self,
    ):
        """[INSTALLATION_ATTEMPT]'s "Package extras:" line and
        [INSTALLATION_START]'s "retry_config=" line sat beside the two
        redacted record lines UNREDACTED: an extra is plugin-built like the
        spec it rides in, and a third-party plugin can glue an env-read
        value into either. The extra is hidden whole by origin; the retry
        dict's values are hidden by the value layer."""
        plugin = FakePlugin(command="stub-tool", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(plugin, "_values_to_redact", return_value=("qz4b", "77.25")),
            patch.object(
                plugin, "_get_tool_package_extras", return_value=["sarifqz4b"]
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": True}
            mock_runner.is_tool_installed.return_value = True
            mock_runner.validate_cached_tool.return_value = {
                "is_functional": True,
                "version": "1.7.0",
            }
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool(retry_config={"max_delay": 77.25}) is True

        logged = "\n".join(
            " ".join(str(part) for part in msg) for msg in plugin._log_messages
        )
        assert "sarifqz4b" not in logged, logged
        assert "qz4b" not in logged, logged
        assert "77.25" not in logged, logged
        extras_lines = [
            line for line in logged.splitlines() if "Package extras:" in line
        ]
        assert extras_lines, logged

    @pytest.mark.unit
    def test_the_pre_installed_verify_carries_the_plugins_values(self, monkeypatch):
        """_select_tool_execution's verify call wires _values_to_redact into
        verify_pre_installed_tool: the verdict's detail embeds the probe's
        redacted excerpt, so a call with values=() prints the excerpt
        unredacted while every other cell stays green (the MO3 wiring
        mutant)."""
        plugin = FakePlugin(command="faketool", use_uv_tool=True)
        seen: list = []

        def _recording_verify(executable, package, extras, constraint, **kwargs):
            seen.append(tuple(kwargs.get("values", ())))
            from types import SimpleNamespace

            return SimpleNamespace(
                status="unverifiable",
                executable=executable,
                requirement="faketool",
                detail="",
                summary="",
                version=None,
                from_nix=False,
            )

        monkeypatch.setattr(plugin, "_is_offline_mode", lambda: False)
        monkeypatch.setattr(plugin, "_values_to_redact", lambda: ("qz4b",))
        monkeypatch.setattr(
            "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool",
            _recording_verify,
        )
        monkeypatch.setattr(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            lambda: None,
        )
        monkeypatch.setattr(
            "automated_security_helper.utils.uv_tool_runner.find_executable",
            lambda name: "/usr/bin/true",
        )

        plugin._select_tool_execution(
            {"preferred_source": "pre_installed", "pre_installed_path": "/usr/bin/true"}
        )

        assert seen == [("qz4b",)], seen

    @pytest.mark.unit
    def test_the_install_call_carries_the_plugins_redaction_values(self):
        """install_tool_with_version redacts uv's stderr for its debug log
        with the caller's values, and the mixin is the caller that holds them:
        the install call passes _values_to_redact() through, or the runner has
        nothing to redact an env-read constraint with however uv respells it.
        The runner reads that set as the run's COMPLETE env-read set (the same
        one redact_values is given): with any value present, a plugin-built
        input no value covers prints at DEBUG, so this handoff carrying the
        whole set is what makes that contract sound."""
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(
                plugin, "_values_to_redact", create=True, return_value=("VAL-5912",)
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": False}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = True
            mock_runner.get_installed_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is True
            kwargs = mock_runner.install_tool_with_version.call_args.kwargs
        assert tuple(kwargs.get("values", ())) == ("VAL-5912",), kwargs

    @pytest.mark.unit
    def test_failed_installation(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_cache_info.return_value = {"cache_available": False}
            mock_runner.is_tool_installed.return_value = False
            mock_runner.install_tool_with_version.return_value = False
            mock_get_runner.return_value = mock_runner

            assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_on_runner_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_get_runner.side_effect = UVToolRunnerError("broken")

            assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_on_import_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=ImportError("no module"),
            ),
        ):
            assert plugin._install_uv_tool() is False

    @pytest.mark.unit
    def test_returns_false_on_unexpected_error(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
        ):
            mock_get_runner.side_effect = RuntimeError("boom")

            assert plugin._install_uv_tool() is False

    @pytest.mark.parametrize(
        "arm,marker",
        [
            pytest.param(
                "import-error",
                "[INSTALLATION_ERROR] UV tool runner module not available",
                id="import-error",
            ),
            pytest.param(
                "unexpected",
                "[INSTALLATION_ERROR] Unexpected error during UV tool installation",
                id="unexpected",
            ),
        ],
    )
    @pytest.mark.unit
    def test_the_installation_error_arms_logs_hide_the_plugins_values(
        self, arm, marker, caplog
    ):
        """The installation's ImportError and catch-all arms log the error
        text, which can quote a path with an env-read value in it: their Error
        lines pass through the redaction of the plugin's own values, as the
        UVToolRunnerError arm beside them does, and the catch-all's DEBUG
        traceback is redacted too."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "ENVCANARY-uvinst-88888"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        if arm == "import-error":
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=ImportError(f"no module under /opt/{canary}/lib"),
            )
        else:
            patcher = patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=RuntimeError(f"install broke on /opt/{canary}/bin"),
            )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patcher,
            caplog.at_level(logging_module.DEBUG, logger="ash"),
        ):
            assert plugin._install_uv_tool() is False

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        # The control: the arm's line was emitted.
        assert any(marker in line for line in logged), logged
        assert not any(canary in line for line in logged), logged
        if arm == "unexpected":
            # The DEBUG traceback carries the exception's own text.
            assert "UV tool installation error details" in caplog.text, caplog.text
        assert canary not in caplog.text, caplog.text

    @pytest.mark.unit
    def test_with_custom_retry_config(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
            ) as mock_get_runner,
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
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

    @pytest.mark.unit
    def test_returns_false_when_uv_not_used(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._is_uv_tool_installed() is False

    @pytest.mark.unit
    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._is_uv_tool_installed() is False

    @pytest.mark.unit
    def test_returns_true_when_tool_in_list(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.return_value = ["bandit", "checkov"]
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is True

    @pytest.mark.unit
    def test_returns_false_when_tool_not_in_list(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.return_value = ["checkov"]
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is False

    @pytest.mark.unit
    def test_a_list_error_answers_not_installed_without_running_the_tool(self):
        """The listing is the question; a `uv tool run --version` fallback
        succeeded for a tool uv could resolve on the spot, so an uninstalled
        tool read as installed whenever the listing failed."""
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.list_available_tools.side_effect = UVToolRunnerError("fail")
            mock_runner.get_tool_version.return_value = "1.7.0"
            mock_get_runner.return_value = mock_runner

            assert plugin._is_uv_tool_installed() is False
            assert mock_runner.get_tool_version.call_count == 0


class TestGetToolInstallationInfo:
    """Tests for _get_tool_installation_info."""

    @pytest.mark.unit
    def test_no_command_returns_empty_info(self):
        plugin = FakePlugin(command="")
        info = plugin._get_tool_installation_info()
        assert info["tool_name"] is None
        assert info["available"] is False

    @pytest.mark.unit
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

    @pytest.mark.unit
    def test_returns_error_info_on_exception(self):
        plugin = FakePlugin(command="bandit")

        # The uv side raised; the PATH side is read on its own, so the test
        # pins what PATH answers rather than reading the host's.
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                side_effect=RuntimeError("broken"),
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            info = plugin._get_tool_installation_info()
            assert info["available"] is False
            assert "error" in info


class TestShouldInstallTool:
    """Tests for _should_install_tool."""

    @pytest.mark.unit
    def test_returns_false_when_uv_not_used(self):
        plugin = FakePlugin(use_uv_tool=False)
        assert plugin._should_install_tool() is False

    @pytest.mark.unit
    def test_returns_false_when_no_command(self):
        plugin = FakePlugin(command="")
        assert plugin._should_install_tool() is False

    @pytest.mark.unit
    def test_delegates_to_runner(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.should_install_tool.return_value = True
            mock_get_runner.return_value = mock_runner

            assert plugin._should_install_tool() is True

    @pytest.mark.unit
    def test_an_answer_that_cannot_be_read_means_install(self):
        """The caller asks only once the tool was found unavailable, so a False
        here read as "already installed" and no install was tried."""
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=RuntimeError("broken"),
        ):
            assert plugin._should_install_tool() is True


class TestSetupUvToolInstallCommands:
    """Tests for _setup_uv_tool_install_commands."""

    @pytest.mark.unit
    def test_does_nothing_when_uv_disabled(self):
        plugin = FakePlugin(use_uv_tool=False)
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == []

    @pytest.mark.unit
    def test_does_nothing_when_no_command(self):
        plugin = FakePlugin(command="", use_uv_tool=True)
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == []

    @pytest.mark.unit
    def test_basic_install_command(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert len(plugin.uv_tool_install_commands) == 1
        assert "uv tool install bandit" in plugin.uv_tool_install_commands[0]

    @pytest.mark.unit
    def test_install_with_package_name(self):
        plugin = FakePlugin(
            command="bandit", use_uv_tool=True, uv_tool_package_name="bandit-pkg"
        )

        with patch.object(plugin, "_is_offline_mode", return_value=False):
            plugin._setup_uv_tool_install_commands()

        assert "bandit-pkg" in plugin.uv_tool_install_commands[0]

    @pytest.mark.unit
    def test_install_with_version_constraint(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(
                plugin, "_get_tool_version_constraint", return_value=">=1.7.0"
            ),
            patch.object(plugin, "_is_offline_mode", return_value=False),
        ):
            plugin._setup_uv_tool_install_commands()

        assert ">=1.7.0" in plugin.uv_tool_install_commands[0]

    @pytest.mark.unit
    def test_install_with_extras(self):
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(
                plugin, "_get_tool_package_extras", return_value=["sarif", "toml"]
            ),
            patch.object(plugin, "_is_offline_mode", return_value=False),
        ):
            plugin._setup_uv_tool_install_commands()

        assert "bandit[sarif,toml]" in plugin.uv_tool_install_commands[0]

    @pytest.mark.unit
    def test_a_refused_constraint_read_from_the_environment_is_not_logged(self):
        """A constraint the requirement check refuses is logged as refused, and
        the refusal names the tool, never the constraint's text. When the
        constraint is a value the scan's config read from the environment, no
        logged line may carry it: the config sets such a value aside at load
        when it is not a version specifier, so this covers a plugin that
        builds its constraint some other way. The redaction of the plugin's
        own values stays as a second guard on the same line."""
        from types import SimpleNamespace

        canary = "~~9.9.9rc777"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        with patch.object(plugin, "_get_tool_version_constraint", return_value=canary):
            plugin._setup_uv_tool_install_commands()

        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        # The control: the refusal ran, in its own words, and named the tool.
        assert plugin.uv_tool_install_commands == []
        refusals = [line for line in logged if "Refusing to pass" in line]
        assert len(refusals) == 1, logged
        assert "bandit" in refusals[0], refusals
        assert not any("9.9.9rc777" in line for line in logged), logged

    @pytest.mark.unit
    def test_a_raising_values_hook_does_not_crash_the_setup(self):
        """The values hook is overridable, and this method runs at plugin
        construction: a hook that raises must cost the two log lines their
        content, never the scanner itself. The method read the hook bare for
        its DEBUG line, so a raising hook crashed construction for the sake
        of a log line. The stored command is unaffected; the line that would
        have carried the spec is replaced by a note naming the failure."""
        plugin = FakePlugin(
            command="cmdqz", use_uv_tool=True, uv_tool_package_name="pkgqz"
        )

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(plugin, "_values_to_redact", side_effect=RuntimeError("boom")),
            patch.object(plugin, "_get_tool_version_constraint", return_value="==9.9"),
        ):
            plugin._setup_uv_tool_install_commands()

        assert plugin.uv_tool_install_commands == ["uv tool install pkgqz==9.9"], (
            plugin.uv_tool_install_commands
        )
        logged = "\n".join(
            " ".join(str(part) for part in msg) for msg in plugin._log_messages
        )
        assert "values hook raised RuntimeError" in logged, logged
        assert "==9.9" not in logged, logged

    @pytest.mark.unit
    def test_a_raising_values_hook_does_not_crash_the_spec_refusal(self):
        """The refusal arm reads the same hook for its WARNING line, so a
        raising hook crashed the refusal too. The refusal still stands (no
        command is stored), and the logged line is the hook-failure note."""
        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_values_to_redact", side_effect=RuntimeError("boom")),
            patch.object(
                plugin, "_get_tool_version_constraint", return_value="~~9.9.9rc777"
            ),
        ):
            plugin._setup_uv_tool_install_commands()

        assert plugin.uv_tool_install_commands == []
        logged = "\n".join(
            " ".join(str(part) for part in msg) for msg in plugin._log_messages
        )
        assert "values hook raised RuntimeError" in logged, logged
        assert "9.9.9rc777" not in logged, logged

    @pytest.mark.unit
    def test_the_setup_builds_its_inputs_with_the_tools_dependencies(self):
        """The install-input builder accepts the tool's extra dependencies,
        and the install path passes them; this setup did not, so the two
        records numbered their hidden arguments from different input sets
        ("<argument N not shown>" drift across records of one install)."""
        import automated_security_helper.utils.uv_tool_runner as uv_tool_runner

        real_inputs = uv_tool_runner.uv_install_inputs
        seen: dict = {}

        def _recording_inputs(tool_name, **kwargs):
            seen.update(kwargs)
            return real_inputs(tool_name, **kwargs)

        plugin = FakePlugin(command="bandit", use_uv_tool=True)

        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(plugin, "_get_tool_with_dependencies", return_value=["depqz"]),
            patch(
                "automated_security_helper.utils.uv_tool_runner.uv_install_inputs",
                _recording_inputs,
            ),
        ):
            plugin._setup_uv_tool_install_commands()

        assert seen.get("with_dependencies") == ["depqz"], seen

    @pytest.mark.unit
    def test_an_install_with_a_refused_constraint_logs_no_constraint_text(
        self, monkeypatch
    ):
        """Through _install_uv_tool with the real runner: a plugin-built
        constraint the requirement check refuses makes the install answer
        False, and no logged line, the runner's refusal included, carries the
        constraint's text. The mixin's lines pass through the redaction of the
        plugin's own values; the runner, which holds no values, must not quote
        the spec at all. ASH_OFFLINE is cleared as the runner tests clear it:
        the runner's own offline check returns before the requirement check,
        so under an operator's ASH_OFFLINE=1 this cell would measure the
        offline early-out, not the refusal."""
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        import logging as logging_module
        from types import SimpleNamespace
        from unittest.mock import patch as mock_patch

        from automated_security_helper.utils.log import ASH_LOGGER
        from automated_security_helper.utils.uv_tool_runner import UVToolRunner

        class _Lines(logging_module.Handler):
            def __init__(self):
                super().__init__(level=logging_module.DEBUG)
                self.lines: list = []

            def emit(self, record):
                self.lines.append(record.getMessage())

        canary = "~~9.9.9rc777"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )
        runner = UVToolRunner(uv_executable="/nonexistent-ash-test/uv")
        handler = _Lines()
        level = ASH_LOGGER.level
        ASH_LOGGER.addHandler(handler)
        ASH_LOGGER.setLevel(logging_module.DEBUG)
        try:
            with (
                mock_patch.object(
                    plugin, "_get_tool_version_constraint", return_value=canary
                ),
                # As the neighbors pin it: an ASH_OFFLINE=1 environment takes
                # the offline path before the requirement check, and this cell
                # is about the check.
                mock_patch.object(plugin, "_is_offline_mode", return_value=False),
                mock_patch.object(runner, "uv_availability", return_value=(True, None)),
                mock_patch.object(runner, "is_tool_installed", return_value=False),
                mock_patch(
                    "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                    return_value=runner,
                ),
            ):
                assert plugin._install_uv_tool(timeout=1) is False
        finally:
            ASH_LOGGER.removeHandler(handler)
            ASH_LOGGER.setLevel(level)

        logged = [
            " ".join(str(part) for part in args) for args in plugin._log_messages
        ] + handler.lines
        joined = "\n".join(logged)
        # The controls: the runner's refusal ran and the tool is named.
        assert "Refusing to pass" in joined, joined
        assert "bandit" in joined, joined
        assert "9.9.9rc777" not in joined, joined


class TestExtensionPoints:
    """Tests for extension point default implementations."""

    @pytest.mark.unit
    def test_get_tool_version_constraint_returns_none(self):
        plugin = FakePlugin()
        # The base implementation should return None (passthrough)
        assert UVToolMixin._get_tool_version_constraint(plugin) is None

    @pytest.mark.unit
    def test_get_tool_package_extras_returns_none(self):
        plugin = FakePlugin()
        assert UVToolMixin._get_tool_package_extras(plugin) is None

    @pytest.mark.unit
    def test_get_tool_with_dependencies_returns_none(self):
        plugin = FakePlugin()
        assert UVToolMixin._get_tool_with_dependencies(plugin) is None


class TestIsOfflineMode:
    """Tests for _is_offline_mode."""

    @pytest.mark.unit
    def test_delegates_to_constants(self):
        plugin = FakePlugin()

        with patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=True,
        ):
            assert plugin._is_offline_mode() is True

        with patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ):
            assert plugin._is_offline_mode() is False


class SpecPlugin(FakePlugin):
    """A plugin whose scan runs under extras and a version constraint."""

    def _get_tool_package_extras(self):
        return ["sarif", "toml"]

    def _get_tool_version_constraint(self):
        return ">=1.7.0,<2.0.0"


class TestProbeSharesTheScansEnvironment:
    """The probe must run under the same ``--from`` spec as the scan.

    ``uv tool run bandit`` and
    ``uv tool run --from 'bandit[sarif,toml]>=1.7.0,<2.0.0' bandit`` resolve to
    different environments. stevedore's entry-point cache is keyed on
    ``sys.executable`` and ``sys.prefix``, so those warm two different cache
    files -- and a probe that warms the wrong one leaves the scan's file cold for
    N concurrent scanners to race. Serializing the probe then removes nothing.
    Measured directly: one workspace scan produced five distinct bandit
    environments.
    """

    @pytest.mark.unit
    def test_the_spec_matches_what_run_tool_builds(self):
        """Same string the scan path passes as --from, or the guarantee is void."""
        plugin = SpecPlugin(command="bandit")
        assert plugin._uv_from_spec() == "bandit[sarif,toml]>=1.7.0,<2.0.0"

    @pytest.mark.unit
    def test_no_extras_and_no_constraint_means_no_from(self):
        """The scan passes no --from either, so the probe must not invent one."""
        assert FakePlugin(command="bandit")._uv_from_spec() is None

    @pytest.mark.unit
    def test_the_probe_is_given_the_scans_spec_by_default(self):
        plugin = SpecPlugin(command="bandit")
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_tool_version.return_value = "bandit 1.9.4"
            mock_get_runner.return_value = mock_runner

            plugin._get_uv_tool_version("bandit")

            # The spec is the positional pair; the plugin's offline mode and
            # package ride as keywords beside the values (checked apart).
            args, kwargs = mock_runner.get_tool_version.call_args
            assert args == ("bandit", "bandit[sarif,toml]>=1.7.0,<2.0.0")
            assert kwargs["values"] == ()

    @pytest.mark.unit
    def test_an_explicit_package_name_still_wins(self):
        """An explicit package_name is the caller's own spec, handed on as
        given: the default fills in only where the caller named none."""
        plugin = SpecPlugin(command="jupyter-nbconvert")
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as mock_get_runner:
            mock_runner = MagicMock()
            mock_runner.uv_availability.return_value = (True, None)
            mock_runner.is_uv_available.return_value = True
            mock_runner.get_tool_version.return_value = "7.16.0"
            mock_get_runner.return_value = mock_runner

            plugin._get_uv_tool_version("jupyter-nbconvert", "nbconvert")

            args, kwargs = mock_runner.get_tool_version.call_args
            assert args == ("jupyter-nbconvert", "nbconvert")
            assert kwargs["values"] == ()


class TestOfflineResolveMessageIsRedacted:
    """_explain_offline_resolve_failure quotes the --from spec and uv's stderr.

    Both can hold a value the plugin's config read from the environment -- the
    spec is plugin-built, and uv's resolver text quotes the requirement back --
    and the message goes to ``errors`` (reports) and an ERROR log. It is
    redacted with the plugin's own values, the way the install's debug line
    redacts the same stderr."""

    @pytest.mark.unit
    def test_the_offline_resolve_message_holds_no_value(self):
        import types

        logged: list = []
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit==9.9.9rc777",
            _uv_run_inputs_for_records=lambda: ("bandit==9.9.9rc777",),
            _values_to_redact=lambda: ("9.9.9rc777",),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: logged.append(msg),
        )
        response = {
            "returncode": 1,
            "stderr": (
                "  x No solution found when resolving dependencies:\n"
                "  `-> Because there is no version of bandit==9.9.9rc777 and "
                "you require bandit==9.9.9rc777, we can conclude that your "
                "requirements are unsatisfiable."
            ),
        }
        UVToolMixin._explain_offline_resolve_failure(fake, response, None)
        assert fake.errors, "the cell shows nothing: no message was built"
        assert "No solution found" in fake.errors[0], fake.errors[0]
        assert "9.9.9rc777" not in fake.errors[0], fake.errors[0]
        assert all(
            "9.9.9rc777" not in " ".join(str(part) for part in msg) for msg in logged
        ), logged

    @pytest.mark.unit
    def test_a_non_color_code_inside_the_phrase_does_not_defeat_the_cause_match(
        self,
    ):
        """A terminal-aware uv can write non-color CSI codes (an erase-line
        \\x1b[K) into its progress text, and one inside "No solution found
        when resolving" is not whitespace, so .split() keeps it glued to a
        word. The pre-match strip takes the full CSI set -- the SAME codes
        the shown layers strip -- so the cause-first message is still
        written."""
        import types

        logged: list = []
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit==9.9.9rc777",
            _uv_run_inputs_for_records=lambda: ("bandit==9.9.9rc777",),
            _values_to_redact=lambda: ("9.9.9rc777",),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: logged.append(msg),
        )
        response = {
            "returncode": 1,
            "stderr": (
                "  x No \x1b[Ksolution found when resolving dependencies:\n"
                "  `-> Because there is no version of bandit==9.9.9rc777, we "
                "can conclude that your requirements are unsatisfiable."
            ),
        }
        UVToolMixin._explain_offline_resolve_failure(fake, response, None)
        assert fake.errors, "the cell shows nothing: no message was built"
        assert "No solution found" in fake.errors[0], fake.errors[0]
        assert "9.9.9rc777" not in fake.errors[0], fake.errors[0]

    @pytest.mark.unit
    def test_an_overflowing_log_read_keeps_no_fake_tail(self, tmp_path):
        """Under the write preference the message's text is a bounded log
        read; when the log is larger than the read, the text's last bytes are
        the READ's cut, not uv's closing hints. A tail-keep there presented a
        mid-file fragment as the conclusion -- and the cut can split a value,
        leaving a fragment no whole-spelling match catches. On an overflowing
        read the message keeps the head only and names the log."""
        import types

        value = "VALSECRET9281777"
        limit = 800 * 32
        prefix = "x No solution found when resolving dependencies: "
        # The value straddles the read bound: the read keeps its first nine
        # characters as the text's very last bytes.
        pad = "p" * (limit - len(prefix) - 9)
        log = tmp_path / "SimpleNamespace.stderr.log"
        log.write_text(
            f"{prefix}{pad}{value} closing hints that are never read",
            encoding="utf-8",
        )
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit",
            _uv_run_inputs_for_records=lambda: ("bandit",),
            _values_to_redact=lambda: (value,),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: None,
        )

        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": ""}, tmp_path
        )

        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert "VALSECRET" not in shown, shown[-400:]
        assert "the log continues beyond this excerpt" in shown, shown[-400:]
        assert "closing hints" not in shown, shown[-400:]

    @pytest.mark.unit
    def test_the_named_log_path_hides_an_env_read_value(self, tmp_path):
        """The composed message is redacted WHOLE: the clause naming the log
        on an overflowing read, and the command interpolations, are added
        after the piecewise redaction, so a results directory under an
        env-read path printed in clear in ``errors`` and the ERROR log."""
        import types

        value = "secretdir-8841"
        results_dir = tmp_path / value
        results_dir.mkdir()
        limit = 800 * 32
        log = results_dir / "SimpleNamespace.stderr.log"
        log.write_text(
            "x No solution found when resolving dependencies: " + "p" * limit,
            encoding="utf-8",
        )
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit",
            _uv_run_inputs_for_records=lambda: ("bandit",),
            _values_to_redact=lambda: (value,),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: None,
        )

        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": ""}, results_dir
        )

        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert "the log continues beyond this excerpt" in shown, shown[-400:]
        assert value not in shown, shown[-400:]

    @pytest.mark.unit
    def test_a_code_heavy_log_keeps_the_read_edge_out_of_the_head(self, tmp_path):
        """The read's cut can land inside a value, and a log that is mostly
        escape codes strips to under the 500 kept characters -- so the
        head-keep, written to drop the edge, put the edge's live piece
        INSIDE the kept head. The bounded read trims its edge before any
        strip or cut, like every other log read."""
        import types

        value = "VALSECRET9281777"
        limit = 800 * 32
        prefix = "x No solution found when resolving dependencies: Because "
        kept = 6 + ((limit - len(prefix) - 6) % 4)
        filler = "\x1b[0m" * ((limit - len(prefix) - kept) // 4)
        log = tmp_path / "SimpleNamespace.stderr.log"
        log.write_text(
            f"{prefix}{filler}{value} closing hints that are never read",
            encoding="utf-8",
        )
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit",
            _uv_run_inputs_for_records=lambda: ("bandit",),
            _values_to_redact=lambda: (value,),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: None,
        )

        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": ""}, tmp_path
        )

        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert value[:kept] not in shown, shown[-400:]
        assert "the log continues beyond this excerpt" in shown, shown[-400:]

    @pytest.mark.unit
    def test_a_with_dependency_pinning_a_value_is_hidden_in_the_message(self):
        """The message gets the run's WHOLE input set, not just the --from
        spec: a --with dependency that PINS a short env-read value ("1.8",
        below the value layer's whole-word band) is quoted back by uv's
        resolver text, and a smaller input set printed it here in clear while
        the report lines beside it hid it."""
        import types

        logged: list = []
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "semgrep",
            _uv_run_inputs_for_records=lambda: ("semgrep", "bandit==1.8"),
            _values_to_redact=lambda: ("1.8",),
            command="semgrep",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: logged.append(msg),
        )
        response = {
            "returncode": 1,
            "stderr": (
                "  x No solution found when resolving dependencies:\n"
                "  `-> Because you require bandit==1.8, we can conclude that "
                "your requirements are unsatisfiable."
            ),
        }
        UVToolMixin._explain_offline_resolve_failure(fake, response, None)
        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert "No solution found" in shown, shown
        assert "bandit==1.8" not in shown, shown
        assert all(
            "bandit==1.8" not in " ".join(str(part) for part in msg) for msg in logged
        ), logged

    @pytest.mark.unit
    def test_a_cut_at_the_excerpt_boundary_cannot_leave_a_value_fragment(self):
        """The quoted stderr used to be sliced BEFORE the redaction, so a cut
        inside the quoted requirement left a live value fragment
        ("bandit==9.9.9rc") at a cut edge with no marker -- a piece the
        redaction's own rules show. The stderr is redacted first and the
        redacted text sliced, so no cut can create a fragment; the value here
        straddles the head cut's edge, the shape the swapped order leaks."""
        import types

        value = "VALSECRET9281777"
        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: f"bandit=={value}",
            _uv_run_inputs_for_records=lambda: (f"bandit=={value}",),
            _values_to_redact=lambda: (value,),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: None,
        )
        prefix = "x No solution found when resolving dependencies: "
        # Padded so a 500-character head cut of the UNREDACTED text would keep
        # exactly nine characters of the value ("VALSECRET"), the fragment
        # shape the band rules show when it sits at a cut edge with no
        # marker; the tail filler makes the excerpt long enough to be cut.
        pad = "p" * (500 - len(prefix) - len("bandit==") - 9)
        stderr = f"{prefix}{pad}bandit=={value} {'and more resolver text ' * 20}"
        assert len(stderr) > 800, "the cell shows nothing: no cut would happen"
        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": stderr}, None
        )
        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert "No solution found" in shown, shown
        assert "VALSECRET" not in shown, shown

    @pytest.mark.unit
    def test_a_long_resolver_text_keeps_both_ends_and_marks_the_cut(self):
        """The message's head is the actionable part ("Offline mode: ...
        Install ... or put a ... on PATH"), uv's own error line leads its
        stderr, and its closing "hint:" lines are often the most specific
        thing it says: a long resolver text must cost none of them. The
        redacted stderr keeps its first 500 and last 300 characters around a
        marker counting exactly what was dropped, and the composed message is
        never tail-cut by the shared helper's bound."""
        import types

        fake = types.SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "bandit==1.7.5",
            _uv_run_inputs_for_records=lambda: ("bandit==1.7.5",),
            _values_to_redact=lambda: (),
            command="bandit",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: None,
        )
        stderr = (
            "x No solution found when resolving dependencies: "
            + "because of this and that " * 120
            + "hint: the tail text."
        )
        assert len(stderr) > 2600, "the cell shows nothing: the stderr is short"
        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": stderr}, None
        )
        assert fake.errors, "the cell shows nothing: no message was built"
        shown = fake.errors[0]
        assert shown.startswith("Offline mode: uv could not resolve"), shown[:120]
        assert "No solution found" in shown, shown[:400]
        # values=() and no color codes, so the excerpt is the stripped stderr
        # itself: the exact bound is checkable, not just "some marker".
        said = stderr.strip()
        assert said[:500] in shown, shown[:700]
        assert said[-300:] in shown, shown[-400:]
        assert "hint: the tail text." in shown, shown[-200:]
        marker = f"... ({len(said) - 800} more characters not shown) ..."
        assert marker in shown, (marker, shown[400:700])
        assert len(shown) < 1600, len(shown)

    @pytest.mark.unit
    def test_a_responses_stderr_enters_errors_redacted(self):
        """_uv_response hands the response to _process_command_response, which
        puts the tool's stderr lines into ``errors`` (reports) BEFORE the
        offline explainer runs: the resolver text that quotes an env-read
        requirement back must be redacted there too, or the redacted offline
        message sits beside the same text in clear. The stream log keeps the
        tool's text verbatim; only the report lines are redacted."""
        from types import SimpleNamespace

        from automated_security_helper.base.plugin_base import PluginBase

        canary = "ENVCANARY-stderr-77421"
        plugin = FakePlugin(command="bandit")
        # The REAL accumulator, not FakePlugin's raw stub: the seam under test
        # is PluginBase._process_command_response reached through _uv_response.
        plugin.errors = []
        plugin.output = []
        plugin._process_command_response = PluginBase._process_command_response.__get__(
            plugin
        )
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )
        result = SimpleNamespace(
            stdout="",
            stderr=(
                f"error: you require bandit=={canary}\n"
                f"second line also quoting {canary}"
            ),
            returncode=1,
        )
        response = plugin._uv_response(result, None)
        assert response is not None
        assert plugin.errors, "the cell shows nothing: no stderr line reached errors"
        assert any("you require" in line for line in plugin.errors), plugin.errors
        assert all(canary not in line for line in plugin.errors), plugin.errors

    @pytest.mark.unit
    def test_a_responses_stderr_hides_respelled_and_colored_values(self):
        """uv RESPELLS what it quotes back -- "9.9.9-RC777" prints as
        "9.9.9rc777" (PEP 440 canonical) -- and colors it, so a raw-value
        redaction leaves uv's respelled line in the reports in clear beside
        the redacted offline message, and an SGR code inside the value splits
        the match. The report lines go through the same value layer as the
        debug record: every printable spelling, color codes removed first."""
        from types import SimpleNamespace

        from automated_security_helper.base.plugin_base import PluginBase

        canary = "9.9.9-RC" + "777"
        respelled = "9.9.9rc" + "777"
        plugin = FakePlugin(command="bandit")
        plugin.errors = []
        plugin.output = []
        plugin._process_command_response = PluginBase._process_command_response.__get__(
            plugin
        )
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )
        result = SimpleNamespace(
            stdout="",
            stderr=(
                f"error: no version of bandit=={respelled} matches\n"
                "and in color \x1b[31m9.9.9-RC\x1b[0m" + "777 too"
            ),
            returncode=1,
        )
        response = plugin._uv_response(result, None)
        assert response is not None
        assert plugin.errors, "the cell shows nothing: no stderr line reached errors"
        assert any("no version of" in line for line in plugin.errors), plugin.errors
        assert all(respelled not in line for line in plugin.errors), plugin.errors
        assert all(canary not in line for line in plugin.errors), plugin.errors
        assert all("\x1b[" not in line for line in plugin.errors), plugin.errors

    @pytest.mark.unit
    def test_a_glued_value_in_the_spec_is_hidden_in_the_report_lines(self):
        """The report lines get the SAME hiding arms as the install debug
        record: _process_command_response computes the run's plugin-built
        inputs from the plugin's own hooks, so a spec that holds a glued
        env-read value ("qz4b" inside "pkgqz4b==1.0") is hidden in
        ``errors`` too. Without the inputs, errors carried the spec in clear
        while the debug line and the offline message hid it -- the reports
        had WEAKER redaction than the log."""
        from types import SimpleNamespace

        from automated_security_helper.base.plugin_base import PluginBase

        value = "qz4b"
        spec = "pkg" + value + "==1.0"
        plugin = FakePlugin(command="bandit")
        plugin.errors = []
        plugin.output = []
        plugin._process_command_response = PluginBase._process_command_response.__get__(
            plugin
        )
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[value])
        )
        with patch.object(plugin, "_uv_from_spec", create=True, return_value=spec):
            result = SimpleNamespace(
                stdout="",
                stderr=f"error: there is no version of {spec}, so resolution failed.",
                returncode=1,
            )
            response = plugin._uv_response(result, None)
        assert response is not None
        assert plugin.errors, "the cell shows nothing: no stderr line reached errors"
        assert any("resolution failed" in line for line in plugin.errors), plugin.errors
        assert all(spec not in line for line in plugin.errors), plugin.errors
        assert all(value not in line for line in plugin.errors), plugin.errors

    @pytest.mark.unit
    def test_a_resolver_error_past_the_excerpts_read_still_gets_the_cause(
        self, tmp_path
    ):
        """The offline explainer matched its cause phrase only on the shown
        excerpt's bounded read: a resolver error after that much earlier
        output (warnings, a wrapper's lines) was silently skipped and the
        downstream symptom came back as the only word. The cause match now
        consults the log itself through a reader that returns a verdict and
        never text; the message still quotes the bounded excerpt and names
        the log for the rest."""
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.errors = []
        log = tmp_path / "FakePlugin.stderr.log"
        log.write_text(
            ("an unrelated warning line of output\n" * 2000)
            + "No solution found when resolving your requirements\n",
            encoding="utf-8",
        )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=True),
            patch.object(plugin, "_values_to_redact", return_value=()),
        ):
            plugin._explain_offline_resolve_failure(
                {"returncode": 1, "stderr": ""}, tmp_path
            )

        assert plugin.errors, "the cause-first message was skipped"
        assert plugin.errors[0].startswith("Offline mode: uv could not resolve")
        assert log.as_posix() in plugin.errors[0], plugin.errors[0]

        # Control: a log of the same size with no resolver error stays quiet.
        control = FakePlugin(command="bandit", use_uv_tool=True)
        control.errors = []
        log.write_text("an unrelated warning line of output\n" * 2001, encoding="utf-8")
        with (
            patch.object(control, "_is_offline_mode", return_value=True),
            patch.object(control, "_values_to_redact", return_value=()),
        ):
            control._explain_offline_resolve_failure(
                {"returncode": 1, "stderr": ""}, tmp_path
            )
        assert control.errors == [], control.errors

    @pytest.mark.unit
    def test_an_offline_unsatisfied_reason_hides_the_plugins_values(self, caplog):
        """_select_tool_execution's offline-unsatisfied branch writes the
        requirement and the verdict's detail into dependency_unavailable_reason
        and an ERROR log. Both are built from the plugin's constraint, which
        can hold an env-read value, and the verdict quotes the requirement
        back: the reason and the log line are redacted like the offline
        resolver message."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "9.9.9rc777"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )

        verdict = SimpleNamespace(
            status="unsatisfied",
            detail=f"found bandit 1.7.5, which does not satisfy bandit=={canary}",
            from_nix=False,
        )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=True),
            patch.object(
                plugin, "_get_tool_package_extras", create=True, return_value=[]
            ),
            patch.object(
                plugin,
                "_get_tool_version_constraint",
                create=True,
                return_value=f"=={canary}",
            ),
            patch(
                "automated_security_helper.utils.pre_installed_tool."
                "verify_pre_installed_tool",
                return_value=verdict,
            ),
            caplog.at_level(logging_module.ERROR, logger="ash"),
        ):
            satisfied = plugin._select_tool_execution(
                {
                    "preferred_source": "pre_installed",
                    "pre_installed_path": "/usr/bin/bandit",
                }
            )

        assert satisfied is False, "the cell shows nothing: the branch never ran"
        reason = plugin.dependency_unavailable_reason
        assert reason, "the cell shows nothing: no reason was recorded"
        assert "cannot be used" in reason, reason
        assert canary not in reason, reason
        assert canary not in caplog.text, caplog.text

    @pytest.mark.unit
    def test_an_old_signature_override_still_handles_a_uv_response(self):
        """_process_command_response is PluginBase's documented extension
        seam: a subclass overriding it with the one-argument signature must
        keep working on the uv path. Were the uv inputs passed as a new
        parameter, that override would TypeError, the mixin's handler would
        catch it, and EVERY uv run of such a plugin would grade
        post_run_error with only a debug trace -- so this cell drives the
        real _uv_response and asserts the override ran and the response kept
        the run's own verdict."""
        from types import SimpleNamespace

        seen: list = []

        class _OldSignaturePlugin(FakePlugin):
            def _process_command_response(self, response):
                seen.append(dict(response))
                self.exit_code = response.get("returncode", 0)

        plugin = _OldSignaturePlugin(command="bandit")
        plugin.context = SimpleNamespace(config=SimpleNamespace(_environment_values=[]))
        result = SimpleNamespace(stdout="", stderr="one finding", returncode=1)
        response = plugin._uv_response(result, None)
        assert seen, "the cell shows nothing: the override never ran"
        assert response is not None
        assert response.get("returncode") == 1, response
        assert response.get("post_run_error") is None, response

    @pytest.mark.unit
    def test_the_satisfied_verdict_line_hides_the_plugins_values(self, caplog):
        """_select_tool_execution's satisfied branch logs the requirement
        back ("it satisfies {requirement!r}"), and the requirement is built
        from the plugin's constraint, which can hold an env-read value: the
        INFO line is redacted like the unsatisfied reason. Each verdict line
        is pinned on its own, so unwrapping one site cannot hide behind a
        cell that only reads another."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "9.9.9rc777"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )
        verdict = SimpleNamespace(
            status="satisfied",
            detail=f"found bandit {canary}",
            from_nix=False,
        )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(
                plugin, "_get_tool_package_extras", create=True, return_value=[]
            ),
            patch.object(
                plugin,
                "_get_tool_version_constraint",
                create=True,
                return_value=f"=={canary}",
            ),
            patch(
                "automated_security_helper.utils.pre_installed_tool."
                "verify_pre_installed_tool",
                return_value=verdict,
            ),
            caplog.at_level(logging_module.INFO, logger="ash"),
        ):
            satisfied = plugin._select_tool_execution(
                {
                    "preferred_source": "pre_installed",
                    "pre_installed_path": "/usr/bin/bandit",
                }
            )

        assert satisfied is True, "the cell shows nothing: the branch never ran"
        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        assert any("Using pre-installed" in line for line in logged), logged
        assert all(canary not in line for line in logged), logged

    @pytest.mark.unit
    def test_the_through_uv_verdict_line_hides_the_plugins_values(self, caplog):
        """_select_tool_execution's not-directly branch logs the verdict's
        detail ("through uv, not directly: ..."), which quotes the
        requirement back: the WARNING line is redacted like the other verdict
        lines, and pinned on its own for the same reason."""
        import logging as logging_module
        from types import SimpleNamespace

        canary = "9.9.9rc777"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[canary])
        )
        verdict = SimpleNamespace(
            status="unsatisfied",
            detail=f"found bandit 1.7.5, which does not satisfy bandit=={canary}",
            from_nix=False,
        )
        with (
            patch.object(plugin, "_is_offline_mode", return_value=False),
            patch.object(
                plugin, "_get_tool_package_extras", create=True, return_value=[]
            ),
            patch.object(
                plugin,
                "_get_tool_version_constraint",
                create=True,
                return_value=f"=={canary}",
            ),
            patch(
                "automated_security_helper.utils.pre_installed_tool."
                "verify_pre_installed_tool",
                return_value=verdict,
            ),
            caplog.at_level(logging_module.INFO, logger="ash"),
        ):
            satisfied = plugin._select_tool_execution(
                {
                    "preferred_source": "pre_installed",
                    "pre_installed_path": "/usr/bin/bandit",
                }
            )

        assert satisfied is True, "the cell shows nothing: the branch never ran"
        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        assert any("through uv, not directly" in line for line in logged), logged
        assert all(canary not in line for line in logged), logged


class TestWrappedUvTextIsRedactedOnEveryRoute:
    """uv wraps a long clause at a space with an indented continuation, so an
    env-read value can reach these routes with one of its spaces respelled as
    a line break plus indent, which no whole-spelling match sees. The
    normalization that restores each value's own spelling lives in the shared
    uv layer (``shown_uv_output``), so the cause extraction, the install
    explainer, and the verdict lines all hide the wrapped value, not only the
    one route that unwraps."""

    @staticmethod
    def _explain(stderr, values):
        from types import SimpleNamespace

        logged: list = []
        fake = SimpleNamespace(
            _is_offline_mode=lambda: True,
            _uv_from_spec=lambda: "faketool==1.0",
            _uv_run_inputs_for_records=lambda: ("faketool==1.0",),
            _values_to_redact=lambda: values,
            command="faketool",
            errors=[],
            _plugin_log=lambda *msg, **_kwargs: logged.append(
                " ".join(str(part) for part in msg)
            ),
        )
        UVToolMixin._explain_offline_resolve_failure(
            fake, {"returncode": 1, "stderr": stderr}, None
        )
        return fake.errors, logged

    @pytest.mark.unit
    def test_the_explainer_hides_an_unwrapped_value(self):
        """Control: the unwrapped spelling was already hidden."""
        stderr = (
            "  x No solution found when resolving dependencies:\n"
            "  `-> Because faketool depends on Zq7Kx9Lm Pw4Nv2Rt and you "
            "require faketool, we can conclude that your requirements are "
            "unsatisfiable.\n"
        )
        errors, logged = self._explain(stderr, ("Zq7Kx9Lm Pw4Nv2Rt",))
        assert errors and "No solution found" in errors[0], errors
        assert "Zq7Kx9Lm" not in errors[0], errors[0]
        assert "Pw4Nv2Rt" not in errors[0], errors[0]

    @pytest.mark.unit
    def test_the_explainer_hides_a_value_uv_wrapped_at_a_space(self):
        """The install explainer quotes uv's stderr through the shared uv
        layer with no unwrap step of its own, so a value wrapped at one of
        its spaces printed its halves in ``errors`` (reports) and the ERROR
        log until the layer itself normalized the respelling."""
        stderr = (
            "  x No solution found when resolving dependencies:\n"
            "  `-> Because faketool depends on Zq7Kx9Lm\n"
            "      Pw4Nv2Rt and you require faketool, we can conclude that "
            "your requirements are unsatisfiable.\n"
        )
        errors, logged = self._explain(stderr, ("Zq7Kx9Lm Pw4Nv2Rt",))
        assert errors and "No solution found" in errors[0], errors
        assert "Zq7Kx9Lm" not in errors[0], errors[0]
        assert "Pw4Nv2Rt" not in errors[0], errors[0]
        assert all(
            "Zq7Kx9Lm" not in line and "Pw4Nv2Rt" not in line for line in logged
        ), logged

    @pytest.mark.unit
    def test_the_through_uv_line_hides_a_wrapped_detail(self):
        """The not-directly WARNING/INFO line prints the verdict's detail. A
        detail that still carries uv's wrap (the unverifiable arm returns
        uv's own text) must not print the value's halves: the line's
        redaction normalizes the respelling before it matches."""
        from types import SimpleNamespace
        from unittest.mock import patch as patch_

        value = "Zq7Kx9Lm Pw4Nv2Rt"
        plugin = FakePlugin(command="bandit", use_uv_tool=True)
        plugin.context = SimpleNamespace(
            config=SimpleNamespace(_environment_values=[value])
        )
        verdict = SimpleNamespace(
            status="unverifiable",
            detail=(
                "error: failed to inspect the environment near Zq7Kx9Lm\n"
                "      Pw4Nv2Rt while reading metadata"
            ),
            from_nix=False,
        )
        with (
            patch_.object(plugin, "_is_offline_mode", return_value=False),
            patch_.object(
                plugin, "_get_tool_package_extras", create=True, return_value=[]
            ),
            patch_.object(
                plugin,
                "_get_tool_version_constraint",
                create=True,
                return_value=None,
            ),
            patch_(
                "automated_security_helper.utils.pre_installed_tool."
                "verify_pre_installed_tool",
                return_value=verdict,
            ),
        ):
            satisfied = plugin._select_tool_execution(
                {
                    "preferred_source": "pre_installed",
                    "pre_installed_path": "/usr/bin/bandit",
                }
            )

        assert satisfied is True, "the cell shows nothing: the branch never ran"
        logged = [" ".join(str(part) for part in args) for args in plugin._log_messages]
        through = [line for line in logged if "through uv, not directly" in line]
        assert through, logged
        assert all(
            "Zq7Kx9Lm" not in line and "Pw4Nv2Rt" not in line for line in through
        ), through
