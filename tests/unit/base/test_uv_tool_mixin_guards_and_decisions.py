# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv mixin's guards hold at every seam, and it decides what it reports.

Each test pins one change in ``base/uv_tool_mixin.py``:

* ``guarded_values_read`` treats bytes, a mapping and an iterable with
  non-string entries as unusable answers, never as "no values";
* every uv gate reads the two-valued availability answer and names the probe's
  own failure, and the runner's error class is the module import, so a failing
  runner import is answered instead of raising an unbound name;
* the error arms of the version probe, the validation, the installed check, the
  installation info and the install decision redact with one guarded read, or
  withhold the text;
* the run passes the plugin's ``--with`` dependencies and redacts its error
  lines through the uv layer;
* the response handler keeps every field it can read when a flag read raises,
  redacts the handling error's text, and a raising explainer does not grade the
  run as a post-run error;
* the offline explainer records its message once and matches the cause on a
  stripped copy only;
* the pre-installed decision survives an unusable values hook, puts the
  verdict's summary in the recorded reason, and is made by the default
  validation path too;
* the stored install command is checked against the package and holds no
  whitespace; the probe sites refuse a spec that names another package;
* the install reads an empty retry config as the caller's choice, passes the
  caller's values to the cached-tool check, records the installed version as the
  plugin's, and says what a False install means;
* the installed check never answers by running the tool; the installation info
  reads PATH when uv cannot answer; a pre-installed copy's unknown version is
  printed as unknown.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.uv_tool_mixin import (
    UVToolMixin,
    guarded_values_read,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunnerError

pytestmark = pytest.mark.unit

SECRET = "ENVCANARY-uvlow-31337"
RUNNER = "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"


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
        self.values = kwargs.get("values", ())
        self._log_messages: list = []

    def _plugin_log(self, *args, **kwargs):
        self._log_messages.append((args, kwargs.get("level")))

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

    def _values_to_redact(self):
        return self.values

    def logged(self) -> list[str]:
        return [" ".join(str(part) for part in args) for args, _ in self._log_messages]


class RecordingPlugin(FakePlugin):
    """A plugin whose ERROR log appends to errors, as PluginBase's does."""

    def _plugin_log(self, *args, **kwargs):
        super()._plugin_log(*args, **kwargs)
        if kwargs.get("level") == logging.ERROR:
            self.errors.append("(fake) " + "\n".join(str(a) for a in args))


def _raising_hook():
    raise RuntimeError("the values hook broke")


def _runner(**overrides):
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.get_cache_info.return_value = {"cache_available": False}
    runner.is_tool_installed.return_value = False
    runner.install_tool_with_version.return_value = True
    runner.get_installed_tool_version.return_value = "1.7.0"
    runner.run_tool.return_value = SimpleNamespace(stdout="", stderr="", returncode=0)
    for name, value in overrides.items():
        setattr(runner, name, value)
    return runner


class TestTheGuardedReadRefusesWhatIsNotAValueSet:
    @pytest.mark.parametrize(
        "answer",
        [
            pytest.param(b"secret", id="bytes"),
            pytest.param({"k": "v"}, id="mapping"),
            pytest.param(["ok", 7], id="non-string-entry"),
            pytest.param(bytearray(b"x"), id="bytearray"),
        ],
    )
    def test_an_unusable_answer_is_none(self, answer):
        plugin = FakePlugin(values=answer)
        read = guarded_values_read(plugin)
        assert read.values is None
        assert "unusable" in read.failure()

    def test_strings_are_the_values(self):
        """The control."""
        plugin = FakePlugin(values=["a", "b"])
        assert guarded_values_read(plugin).values == ("a", "b")

    def test_a_none_entry_is_an_unset_value_not_a_broken_hook(self):
        """An override such as ``(*super()._values_to_redact(), self._token)``
        with the token unset answers a None ENTRY. Dropping it hides nothing, so
        the other values stand and no run is refused for it; a whole answer of
        None and entries of other types stay unusable (the cases above)."""
        plugin = FakePlugin(values=["a", None, "b"])
        assert guarded_values_read(plugin).values == ("a", "b")


class TestEveryGateNamesTheProbesFailure:
    FAILURE = "the probe timed out after 10 seconds"

    def _failed_runner(self):
        return _runner(
            uv_availability=MagicMock(return_value=(False, self.FAILURE)),
            is_uv_available=MagicMock(return_value=False),
        )

    def test_the_version_probe(self):
        plugin = FakePlugin()
        with patch(RUNNER, return_value=self._failed_runner()):
            assert plugin._get_uv_tool_version("bandit") is None
        assert any(self.FAILURE in line for line in plugin.logged()), plugin.logged()

    def test_the_validation(self):
        plugin = FakePlugin()
        with patch(RUNNER, return_value=self._failed_runner()):
            assert plugin._validate_uv_tool_availability() is False
        assert any(self.FAILURE in line for line in plugin.logged()), plugin.logged()

    def test_the_install(self):
        plugin = FakePlugin()
        with patch(RUNNER, return_value=self._failed_runner()):
            assert plugin._install_uv_tool() is False
        assert any(self.FAILURE in line for line in plugin.logged()), plugin.logged()

    def test_the_installed_check(self):
        plugin = FakePlugin()
        with patch(RUNNER, return_value=self._failed_runner()):
            assert plugin._is_uv_tool_installed() is False
        assert any(self.FAILURE in line for line in plugin.logged()), plugin.logged()

    def test_an_absent_uv_keeps_the_plain_words(self):
        """The control."""
        plugin = FakePlugin()
        runner = _runner(
            uv_availability=MagicMock(return_value=(False, None)),
            is_uv_available=MagicMock(return_value=False),
        )
        with patch(RUNNER, return_value=runner):
            assert plugin._get_uv_tool_version("bandit") is None
        assert any("UV is not available" in line for line in plugin.logged())


class TestTheRunnersOwnImportFailureIsAnswered:
    """The except arms name the runner's error class, which a local import
    bound inside the try: when that import raised, evaluating the arm raised
    UnboundLocalError instead of answering."""

    @pytest.fixture
    def no_runner(self, monkeypatch):
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.delattr(uv_tool_runner, "get_uv_tool_runner")

    def test_the_version_probe(self, no_runner):
        plugin = FakePlugin()
        assert plugin._get_uv_tool_version("bandit") is None
        assert any("module not available" in line for line in plugin.logged())

    def test_the_validation(self, no_runner):
        assert FakePlugin()._validate_uv_tool_availability() is False

    def test_the_install(self, no_runner):
        plugin = FakePlugin()
        assert plugin._install_uv_tool() is False
        assert any("INSTALLATION_ERROR" in line for line in plugin.logged())

    def test_the_installed_check(self, no_runner):
        assert FakePlugin()._is_uv_tool_installed() is False


class TestTheErrorArmsRedactWithOneGuardedRead:
    def _broken(self, method, error):
        return _runner(**{method: MagicMock(side_effect=error)})

    def test_the_version_probe_reads_the_hook_once(self):
        """The except arm used to read the hook a second time, bare: a hook that
        answered once and then raised escaped the arm as its own error."""
        answers = iter([(SECRET,)])

        def _once():
            try:
                return next(answers)
            except StopIteration:
                raise RuntimeError("the values hook broke on its second read") from None

        plugin = FakePlugin()
        plugin._values_to_redact = _once  # type: ignore[method-assign]
        runner = self._broken(
            "get_tool_version", UVToolRunnerError(f"argv held /opt/{SECRET}/bin")
        )
        with patch(RUNNER, return_value=runner):
            assert plugin._get_uv_tool_version("bandit") is None
        logged = plugin.logged()
        assert any("UV tool runner error getting" in line for line in logged), logged
        assert not any(SECRET in line for line in logged), logged

    def test_the_validation_with_a_raising_hook_withholds_the_text(self):
        plugin = FakePlugin()
        plugin._values_to_redact = _raising_hook  # type: ignore[method-assign]
        runner = self._broken(
            "uv_availability", UVToolRunnerError(f"argv held /opt/{SECRET}/bin")
        )
        with patch(RUNNER, return_value=runner):
            assert plugin._validate_uv_tool_availability() is False
        logged = plugin.logged()
        assert any("values hook raised RuntimeError" in line for line in logged), logged
        assert not any(SECRET in line for line in logged), logged

    def test_the_installed_check_redacts_the_listing_error(self):
        plugin = FakePlugin(values=(SECRET,))
        runner = self._broken(
            "list_available_tools", UVToolRunnerError(f"listing broke at {SECRET}")
        )
        with patch(RUNNER, return_value=runner):
            assert plugin._is_uv_tool_installed() is False
        logged = plugin.logged()
        assert any("treated as not installed" in line for line in logged), logged
        assert not any(SECRET in line for line in logged), logged

    def test_the_installed_check_redacts_an_unexpected_error(self):
        plugin = FakePlugin(values=(SECRET,))
        runner = self._broken("list_available_tools", RuntimeError(f"at {SECRET}"))
        with patch(RUNNER, return_value=runner):
            assert plugin._is_uv_tool_installed() is False
        assert not any(SECRET in line for line in plugin.logged()), plugin.logged()

    def test_the_installation_info_redacts_its_error(self):
        plugin = FakePlugin(values=(SECRET,))
        with (
            patch(RUNNER, side_effect=RuntimeError(f"broken at {SECRET}")),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            info = plugin._get_tool_installation_info()
        assert info["available"] is False
        assert SECRET not in info["error"]
        assert not any(SECRET in line for line in plugin.logged()), plugin.logged()

    def test_the_install_decision_redacts_its_error(self):
        """An answer that cannot be read means install (the chain's shape); the
        line that says so is redacted."""
        plugin = FakePlugin(values=(SECRET,))
        with patch(RUNNER, side_effect=RuntimeError(f"broken at {SECRET}")):
            assert plugin._should_install_tool() is True
        logged = plugin.logged()
        assert any("attempting the installation" in line for line in logged), logged
        assert not any(SECRET in line for line in logged), logged


class TestTheRun:
    def _run(self, plugin, runner):
        with patch(RUNNER, return_value=runner):
            return plugin._try_uv_tool_execution(
                command=["bandit", "-r", "src"],
                working_dir=Path("/tmp"),  # nosec B108
            )

    def test_the_with_dependencies_ride_the_run(self):
        plugin = FakePlugin(
            command="jupyter-nbconvert",
            uv_tool_package_name="nbconvert",
            with_dependencies=["jupyter"],
        )
        runner = _runner()
        self._run(plugin, runner)
        assert runner.run_tool.call_args.kwargs["with_dependencies"] == ["jupyter"]

    def test_the_runner_error_line_goes_through_the_uv_layer(self):
        """The plain value layer hides a value whole; the uv layer, which every
        other record of the run uses, also hides the plugin-built input that
        holds it in the spelling uv prints. The arm's text reaches that layer."""
        import automated_security_helper.utils.uv_tool_runner as runner_module

        shown: list = []
        original = runner_module.shown_uv_output

        def _spy(text, *args, **kwargs):
            shown.append(text)
            return original(text, *args, **kwargs)

        plugin = FakePlugin(values=(SECRET,))
        runner = _runner(
            run_tool=MagicMock(
                side_effect=UVToolRunnerError(f"spawn failed: --from bandit=={SECRET}")
            )
        )
        with patch.object(runner_module, "shown_uv_output", _spy):
            assert self._run(plugin, runner) is None
        assert any(
            text.startswith("UV tool runner error for bandit") for text in shown
        ), shown
        logged = plugin.logged()
        assert any("UV tool runner error for bandit" in line for line in logged)
        assert not any(SECRET in line for line in logged), logged


class TestTheResponseHandler:
    def test_a_raising_explainer_does_not_grade_the_run(self):
        plugin = FakePlugin(offline=True)

        def _broken_explainer(*args, **kwargs):
            raise RuntimeError("the explainer broke")

        plugin._explain_offline_resolve_failure = _broken_explainer  # type: ignore[method-assign]
        result = SimpleNamespace(stdout="", stderr="resolver text", returncode=1)
        response = plugin._uv_response(result, None)
        assert response["returncode"] == 1
        assert response.get("post_run_error") is None, response

    def test_a_flag_read_that_raises_keeps_the_later_fields(self):
        class _Result:
            stdout = ""
            stderr = ""
            returncode = None
            timed_out = True
            could_not_stop = True
            could_not_stop_pid = 4242
            error = "the runner's reason"

            @property
            def cancelled(self):
                raise RuntimeError("flag read broke")

        response = FakePlugin()._uv_response(_Result(), None)
        assert response["timed_out"] is True
        assert response["could_not_stop"] is True
        assert response["could_not_stop_pid"] == 4242
        assert "the runner's reason" in response["error"]
        assert response.get("post_run_error") is None, response

    def test_the_handling_errors_text_is_redacted(self):
        class _Result:
            returncode = 0
            stderr = ""

            @property
            def stdout(self):
                raise RuntimeError(f"read broke on /opt/{SECRET}/out")

        response = FakePlugin(values=(SECRET,))._uv_response(_Result(), None)
        assert response["post_run_error"] is True
        assert "read broke" in response["error"]
        assert SECRET not in response["error"], response["error"]

    def test_the_handling_errors_text_is_withheld_without_values(self):
        class _Result:
            returncode = 0
            stderr = ""

            @property
            def stdout(self):
                raise RuntimeError(f"read broke on /opt/{SECRET}/out")

        plugin = FakePlugin()
        plugin._values_to_redact = _raising_hook  # type: ignore[method-assign]
        response = plugin._uv_response(_Result(), None)
        assert response["post_run_error"] is True
        assert "RuntimeError" in response["error"]
        assert SECRET not in response["error"], response["error"]


class TestTheOfflineExplainer:
    RESOLVER = "error: No solution found when resolving tool dependencies\n"

    def test_the_message_is_recorded_once(self):
        plugin = RecordingPlugin(offline=True)
        plugin._explain_offline_resolve_failure(
            {"returncode": 1, "stderr": self.RESOLVER}, None
        )
        assert len(plugin.errors) == 1, plugin.errors
        assert "could not resolve" in plugin.errors[0]

    def test_a_stand_in_that_records_nothing_still_gets_the_message(self):
        """The control."""
        plugin = FakePlugin(offline=True)
        plugin._explain_offline_resolve_failure(
            {"returncode": 1, "stderr": self.RESOLVER}, None
        )
        assert len(plugin.errors) == 1, plugin.errors

    def test_the_quoted_text_reaches_the_shower_as_written(self):
        """Only the cause match reads a stripped copy; the shower redacts the
        values against the text as written and strips the codes itself."""
        import automated_security_helper.utils.uv_tool_runner as runner_module

        plugin = FakePlugin(offline=True)
        shown: list = []
        original = runner_module.shown_uv_output

        def _spy(text, *args, **kwargs):
            shown.append(text)
            return original(text, *args, **kwargs)

        with patch.object(runner_module, "shown_uv_output", _spy):
            plugin._explain_offline_resolve_failure(
                {
                    "returncode": 1,
                    "stderr": "error: No solution\x1b[K found when resolving",
                },
                None,
            )
        assert plugin.errors, "the cause was not matched through the escape code"
        assert any("\x1b[K" in text for text in shown), shown
        assert "\x1b" not in plugin.errors[0]


class TestThePreInstalledDecision:
    INFO = {
        "preferred_source": "pre_installed",
        "pre_installed_path": "/opt/bin/bandit",
    }

    def test_an_unusable_values_hook_keeps_uv(self):
        plugin = FakePlugin()
        plugin._values_to_redact = _raising_hook  # type: ignore[method-assign]
        with patch(
            "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool"
        ) as verify:
            assert plugin._select_tool_execution(dict(self.INFO)) is True
        assert verify.call_count == 0
        assert plugin.use_uv_tool is True
        assert plugin.dependencies_satisfied is True
        assert any("was not verified" in line for line in plugin.logged())

    def test_the_recorded_reason_carries_the_summary_not_the_path(self):
        plugin = FakePlugin(offline=True)
        verdict = SimpleNamespace(
            status="unsatisfied",
            detail="found bandit 1.7.5 at /opt/bin/bandit, which does not satisfy bandit>=1.8",
            summary="the installed version does not satisfy the requirement",
            from_nix=False,
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
            assert plugin._select_tool_execution(dict(self.INFO)) is False
        reason = plugin.dependency_unavailable_reason
        assert "the installed version does not satisfy" in reason, reason
        assert "/opt/bin/bandit" not in reason, reason
        assert any("/opt/bin/bandit" in line for line in plugin.logged())

    def test_a_verdict_without_a_summary_keeps_its_detail(self):
        """The control: a stand-in verdict carrying only a detail."""
        plugin = FakePlugin(offline=True)
        verdict = SimpleNamespace(
            status="unsatisfied", detail="found bandit 1.7.5", from_nix=False
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
            assert plugin._select_tool_execution(dict(self.INFO)) is False
        assert "found bandit 1.7.5" in plugin.dependency_unavailable_reason


class TestTheDefaultValidationDecides:
    INFO = {
        "available": True,
        "preferred_source": "pre_installed",
        "pre_installed_version": None,
        "pre_installed_path": "/opt/bin/bandit",
        "is_uv_installed": False,
        "is_pre_installed": True,
    }

    def test_a_refused_copy_is_not_available(self):
        plugin = FakePlugin()
        plugin.dependency_unavailable_reason = None

        def _refuse(info):
            plugin.dependency_unavailable_reason = "Offline mode: bandit cannot be used"
            return False

        with (
            patch.object(
                plugin, "_get_tool_installation_info", return_value=dict(self.INFO)
            ),
            patch.object(plugin, "_select_tool_execution", side_effect=_refuse),
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
        assert result["available"] is False
        assert result["errors"] == ["Offline mode: bandit cannot be used"]

    def test_a_verified_copy_runs_directly_with_no_warning(self):
        plugin = FakePlugin()

        def _switch(info):
            plugin.use_uv_tool = False
            return True

        with (
            patch.object(
                plugin, "_get_tool_installation_info", return_value=dict(self.INFO)
            ),
            patch.object(plugin, "_select_tool_execution", side_effect=_switch),
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
        assert result["available"] is True
        assert result["warnings"] == []

    def test_an_unverified_copy_keeps_uv_and_warns(self):
        """The control, and the "unknown" version word."""
        plugin = FakePlugin()
        with (
            patch.object(
                plugin, "_get_tool_installation_info", return_value=dict(self.INFO)
            ),
            patch.object(plugin, "_select_tool_execution", return_value=True),
        ):
            result = plugin._validate_tool_availability_with_pre_installed()
        assert result["available"] is True
        assert len(result["warnings"]) == 1
        assert any("version: unknown" in line for line in plugin.logged())
        assert not any("version: None" in line for line in plugin.logged())


class TestTheStoredInstallCommand:
    def test_whitespace_in_a_constraint_is_normalized_away(self):
        plugin = FakePlugin(
            constraint=">= 1.0, < 2", with_dependencies=["sarif-om >= 1.0"]
        )
        plugin._setup_uv_tool_install_commands()
        (command,) = plugin.uv_tool_install_commands
        assert command == "uv tool install --with sarif-om>=1.0 bandit<2,>=1.0"
        assert command.split() == [
            "uv",
            "tool",
            "install",
            "--with",
            "sarif-om>=1.0",
            "bandit<2,>=1.0",
        ]

    def test_a_spec_that_names_another_package_is_refused(self):
        plugin = FakePlugin(constraint="2")
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == []
        # The logged line is the runner's own refusal, which opens "Refusing
        # to pass the tool spec to uv"; the word "refused" appears only on the
        # withheld-text branch (a values hook that raised), which this plugin
        # does not take.
        assert any(
            "Refusing to pass the tool spec to uv" in line for line in plugin.logged()
        ), plugin.logged()

    def test_the_plain_command_is_unchanged(self):
        """The control."""
        plugin = FakePlugin(constraint=">=1.7", extras=["sarif"])
        plugin._setup_uv_tool_install_commands()
        assert plugin.uv_tool_install_commands == ["uv tool install bandit[sarif]>=1.7"]

    def test_the_with_dependencies_hook_is_read_once(self):
        """One read serves the checks, the spec builder and the stored command.

        The hook is overridable, so two reads can disagree: a hook that answers
        differently on each call would have its first answer checked, its
        second built into the spec's record and its third stored as the
        ``--with`` arguments. The stored command carries the ONE answer that was
        checked.
        """
        answers = iter([["first>=1"], ["second>=2"], ["third>=3"]])
        reads: list = []

        class ShiftingPlugin(FakePlugin):
            def _get_tool_with_dependencies(self):
                answer = next(answers)
                reads.append(answer)
                return answer

        plugin = ShiftingPlugin(constraint=">=1.7")
        plugin._setup_uv_tool_install_commands()
        (command,) = plugin.uv_tool_install_commands
        assert command == "uv tool install --with first>=1 bandit>=1.7"
        assert len(reads) == 1, reads


class TestTheProbeSitesRefuseAnotherPackagesSpec:
    def test_the_installation_info(self):
        plugin = FakePlugin(constraint="2")
        runner = _runner()
        with (
            patch(RUNNER, return_value=runner),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            info = plugin._get_tool_installation_info()
        assert runner.get_tool_installation_info.call_count == 0
        assert info["available"] is False
        assert info["error"] == "UVToolRunnerError"

    def test_the_version_probe(self):
        plugin = FakePlugin(constraint="2")
        runner = _runner()
        with patch(RUNNER, return_value=runner):
            assert plugin._get_uv_tool_version("bandit") is None
        assert runner.get_tool_version.call_count == 0

    def test_a_spec_naming_the_package_is_probed(self):
        """The control."""
        plugin = FakePlugin(constraint=">=2")
        runner = _runner(get_tool_version=MagicMock(return_value="2.1"))
        with patch(RUNNER, return_value=runner):
            assert plugin._get_uv_tool_version("bandit") == "2.1"
        assert runner.get_tool_version.call_args.args[1] == "bandit>=2"


class TestTheInstall:
    def _install(self, plugin, runner, **kwargs):
        with (
            patch(RUNNER, return_value=runner),
            patch(
                "automated_security_helper.utils.subprocess_utils.clear_find_executable_cache"
            ),
        ):
            return plugin._install_uv_tool(**kwargs)

    def test_an_empty_retry_config_is_the_callers_choice(self):
        plugin = FakePlugin()
        assert self._install(plugin, _runner(), retry_config={}) is True
        assert any("custom retry configuration" in line for line in plugin.logged())

    def test_the_cached_tool_check_gets_the_callers_values(self):
        plugin = FakePlugin(values=(SECRET,))
        runner = _runner(is_tool_installed=MagicMock(return_value=True))
        runner.validate_cached_tool.return_value = {
            "is_functional": True,
            "version": "1",
        }
        assert self._install(plugin, runner) is True
        assert runner.validate_cached_tool.call_args.kwargs["values"] == (SECRET,)

    def test_the_installed_version_becomes_the_plugins(self):
        plugin = FakePlugin()
        assert self._install(plugin, _runner()) is True
        assert plugin.tool_version == "1.7.0"

    def test_a_false_install_says_nothing_was_installed(self):
        plugin = FakePlugin()
        runner = _runner(install_tool_with_version=MagicMock(return_value=False))
        assert self._install(plugin, runner) is False
        failed = [line for line in plugin.logged() if "INSTALLATION_FAILED" in line]
        assert failed and "was not installed" in failed[0], plugin.logged()
        assert "after all retry attempts" not in failed[0]


class TestTheInstalledCheckNeverRunsTheTool:
    def test_a_failed_listing_answers_not_installed(self):
        plugin = FakePlugin()
        runner = _runner(
            list_available_tools=MagicMock(side_effect=UVToolRunnerError("no listing")),
            get_tool_version=MagicMock(return_value="1.7.0"),
        )
        with patch(RUNNER, return_value=runner):
            assert plugin._is_uv_tool_installed() is False
        assert runner.get_tool_version.call_count == 0

    def test_a_listed_tool_is_installed(self):
        """The control."""
        plugin = FakePlugin()
        runner = _runner(list_available_tools=MagicMock(return_value=["bandit"]))
        with patch(RUNNER, return_value=runner):
            assert plugin._is_uv_tool_installed() is True


class TestTheInstallationInfoReadsPathWhenUvCannotAnswer:
    def test_a_copy_on_path_is_reported(self):
        plugin = FakePlugin()
        with (
            patch(RUNNER, side_effect=RuntimeError("broken")),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value="/opt/bin/bandit",
            ),
        ):
            info = plugin._get_tool_installation_info()
        assert info["available"] is True
        assert info["preferred_source"] == "pre_installed"
        assert info["pre_installed_path"] == "/opt/bin/bandit"
        assert info["is_uv_installed"] is False
        assert info["error"] == "RuntimeError"

    def test_nothing_on_path_stays_unavailable(self):
        """The control."""
        plugin = FakePlugin()
        with (
            patch(RUNNER, side_effect=RuntimeError("broken")),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            info = plugin._get_tool_installation_info()
        assert info["available"] is False
        assert info["preferred_source"] == "none"
