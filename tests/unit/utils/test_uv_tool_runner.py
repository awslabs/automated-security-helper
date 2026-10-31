"""Tests for utils/uv_tool_runner.py — covers UVToolRunner class methods."""

import ast
import os
import re
import subprocess  # nosec B404
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

import automated_security_helper
from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    UVToolRetryConfig,
    _install_retry_delay,
    _reset_uv_tool_runner_caches,
    find_executable,
    find_uv_or_none,
    get_uv_tool_command,
    get_uv_tool_runner,
    invalidate_tool_version_cache,
)
from tests.utils.env_assertions import differing_names
from tests.utils.fake_tool_paths import fake_tool_path

pytestmark = pytest.mark.unit

#: The uv the probe tests find. The probe spawns this path with the process boundary
#: mocked, and ASH starts a program given by path only when the host anchors it: on
#: Windows a bare ``/opt/uv/bin/uv`` has no drive, is refused before the mocked runner
#: is reached, and the probe is never seen. Nothing is created at this path.
UV_PATH = fake_tool_path("/opt/uv/bin/uv")

#: Where the mocked uv lives. ASH refuses to spawn a program whose path is not
#: anchored (a drive letter is needed on Windows), so /opt/uv/bin/uv gets one there.
UV_PATH = os.path.abspath("/opt/uv/bin/uv")


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

    ``get_tool_version`` memoizes per ``tool::package``, so without this a
    version cached by one test would be served to the next and the second test
    would assert against a value its own mock never produced.
    """
    _reset_uv_tool_runner_caches()
    yield
    _reset_uv_tool_runner_caches()


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


class TestExitDescription:
    """_exit_description's branches, each built from the code alone. It reads
    a result object's response flags before the exit code, since a flagged
    result's code is ASH's fixed one, never the tool's own: "exited 124"
    would misread a timeout as the command's own exit."""

    @staticmethod
    def _result(**fields):
        from types import SimpleNamespace

        return SimpleNamespace(**fields)

    def test_the_timed_out_flag_wins_over_an_exit_code(self):
        from automated_security_helper.utils.uv_tool_runner import _exit_description

        result = self._result(returncode=124, timed_out=True)
        assert _exit_description(result) == "the command timed out"

    def test_each_flag_hides_the_code_it_rode_in_with(self):
        from automated_security_helper.utils.uv_tool_runner import _exit_description

        flagged = {
            "cancelled": "the run was cancelled",
            "result_rejected": "ASH rejected the tool's result",
            "spawn_failed": "the command never started",
        }
        for flag, text in flagged.items():
            result = self._result(returncode=1, **{flag: True})
            assert _exit_description(result) == text, flag

    def test_a_child_the_stop_did_not_end_has_no_exit(self):
        from automated_security_helper.utils.uv_tool_runner import _exit_description

        assert _exit_description(self._result(returncode=None)) == (
            "the command did not exit"
        )

    def test_a_negative_code_is_a_signal_death(self):
        from automated_security_helper.utils.uv_tool_runner import _exit_description

        assert _exit_description(self._result(returncode=-15)) == (
            "the command was ended by signal 15"
        )

    def test_a_plain_code_reads_as_the_exit(self):
        from automated_security_helper.utils.uv_tool_runner import _exit_description

        assert _exit_description(self._result(returncode=2)) == "the command exited 2"

    def test_where_signals_do_not_exist_a_negative_code_is_the_exit(self, monkeypatch):
        # signal_death answers None on Windows, where a negative code is just
        # a large exit value; the helper then reports the code as written.
        # Pinned by stubbing signal_death rather than faking os.name, so the
        # cell measures this helper's fall-through, not the platform gate.
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.setattr(uv_tool_runner, "signal_death", lambda rc, cmd: None)
        result = self._result(returncode=-1073741819)
        assert uv_tool_runner._exit_description(result) == (
            "the command exited -1073741819"
        )


class TestIsUvAvailable:
    """Tests for is_uv_available."""

    def test_available_when_command_succeeds(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert runner.is_uv_available() is True
            mock_run.assert_called_once()

    def test_unavailable_when_command_fails(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert runner.is_uv_available() is False

    def test_unavailable_on_exception(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=FileNotFoundError(),
        ):
            assert runner.is_uv_available() is False

    def test_caches_result(self, runner):
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            runner.is_uv_available()
            runner.is_uv_available()
            assert mock_run.call_count == 1

    def test_a_sandbox_refusal_is_not_remembered(self, runner):
        """A check refused by a probe's sandbox scope says nothing about uv itself.

        The runner is shared by the whole process, so caching that answer made uv
        read as missing for every later spawn, sandboxed or not.
        """
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        with sandbox_scope(RefusingScope("jupyter", "no bwrap here")):  # type: ignore[arg-type]
            assert runner.is_uv_available() is False
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert runner.is_uv_available() is True

    def test_a_sandbox_refusal_is_named_as_the_reason(self, runner):
        """Not "UV is not available": uv may be installed; the sandbox refused it."""
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        with sandbox_scope(RefusingScope("jupyter", "no bwrap here")):  # type: ignore[arg-type]
            assert runner.is_uv_available() is False
            reason = runner.unavailable_reason()

        assert "scanner sandbox refused to run uv" in reason
        assert "no bwrap here" in reason
        assert "UV is not available" not in reason

    def test_an_absent_uv_is_named_as_before(self, runner):
        """Control, and a later check clears an earlier refusal's reason."""
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        with sandbox_scope(RefusingScope("jupyter", "no bwrap here")):  # type: ignore[arg-type]
            runner.is_uv_available()
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert runner.is_uv_available() is False

        assert runner.unavailable_reason() == "UV is not available"


class TestListAvailableTools:
    """Tests for list_available_tools."""

    def test_returns_tool_names(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
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
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=subprocess.CalledProcessError(1, "uv"),
        ):
            with pytest.raises(UVToolRunnerError):
                runner.list_available_tools()

    def test_handles_sub_command_lines(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.7.0\n- bandit-baseline\n"
            )
            tools = runner.list_available_tools()
            assert "bandit" in tools


class TestIsToolInstalled:
    """Tests for is_tool_installed."""

    def test_returns_true_when_in_list(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.0\n")
            assert runner.is_tool_installed("bandit") is True

    def test_returns_false_when_not_in_list(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="checkov 3.0.0\n")
            assert runner.is_tool_installed("bandit") is False

    def test_returns_false_on_error(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=subprocess.CalledProcessError(1, "uv"),
        ):
            assert runner.is_tool_installed("bandit") is False


class TestGetToolVersion:
    """Tests for get_tool_version."""

    def test_returns_version_string(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.8\n")
            version = runner.get_tool_version("bandit")
            assert version == "bandit 1.7.8"

    def test_returns_none_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        assert runner.get_tool_version("bandit") is None

    def test_returns_none_on_failure(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("bandit") is None

    def test_uses_package_name_in_from_param(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.7.8\n")
            runner.get_tool_version("bandit", package_name="bandit[sarif]")
            cmd = mock_run.call_args[0][0]
            assert "--from" in cmd
            assert "bandit[sarif]" in cmd

    def test_returns_none_on_exception(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=RuntimeError("boom"),
        ):
            assert runner.get_tool_version("bandit") is None

    def test_a_sandbox_refusal_is_not_remembered(self, runner):
        """A probe its sandbox scope refused did not run, so it measured nothing."""
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        runner._uv_available_cache = True
        with sandbox_scope(RefusingScope("bandit", "no bwrap here")):  # type: ignore[arg-type]
            assert runner.get_tool_version("bandit") is None
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.8\n")
            assert runner.get_tool_version("bandit") == "bandit 1.7.8"


class TestInstallToolWithVersion:
    """Tests for install_tool_with_version."""

    def test_skips_already_installed(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            # list_available_tools response
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.0\n")
            result = runner.install_tool_with_version("bandit")
            assert result is True

    def test_returns_false_when_uv_unavailable(self, runner):
        runner._uv_available_cache = False
        assert runner.install_tool_with_version("bandit") is False

    def test_successful_install(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            # First call: list_available_tools (tool not installed)
            # Second call: install command
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="checkov 3.0.0\n"),
                MagicMock(returncode=0),  # install succeeds
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                result = runner.install_tool_with_version("bandit")
                assert result is True

    def test_raises_on_timeout(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list (tool not present)
                subprocess.TimeoutExpired("uv", 300),
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                with pytest.raises(UVToolRunnerError, match="timed out"):
                    runner.install_tool_with_version("bandit", timeout=300)

    def test_a_timed_out_install_drops_the_memoized_version(self, runner):
        """ASH stops a timed-out install without knowing how far uv got:
        the tool can be fully installed by the time the stop lands. A
        version answer memoized before the install (None for a tool that
        was not installed yet) then no longer describes the environment,
        so the timeout drops this tool's cache entry exactly as a
        completed install does, and the next probe asks uv again. Before
        this, the memoized pre-install None outlived the timed-out
        install for the rest of the process."""
        runner._uv_available_cache = True
        # What a pre-install probe of a missing tool leaves behind.
        with uv_tool_runner._uv_tool_runner_cache_lock:
            uv_tool_runner._uv_tool_version_cache["bandit::"] = None
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list (tool not present)
                subprocess.TimeoutExpired("uv", 300),
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                with pytest.raises(UVToolRunnerError, match="timed out"):
                    runner.install_tool_with_version("bandit", timeout=300)
        with uv_tool_runner._uv_tool_runner_cache_lock:
            assert "bandit::" not in uv_tool_runner._uv_tool_version_cache, (
                "the memoized pre-install answer survived the timed-out install"
            )

    def test_a_timeouts_error_names_no_part_of_the_spec(self, runner):
        """The timeout's message names the operation and the tool, never the
        assembled spec: a plugin-built constraint or --with dependency can
        hold a value its config read from the environment, and neither this
        function nor the runner holds the values to redact it with --
        checked_requirement's rule, and the run path's own timeout shape
        ("uv tool run <tool>"), applied to the install timeout too."""
        constraint = "==9.9.9rc777"
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list (tool not present)
                subprocess.TimeoutExpired("uv", 300),
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                with pytest.raises(UVToolRunnerError) as raised:
                    runner.install_tool_with_version(
                        "bandit",
                        version_constraint=constraint,
                        with_dependencies=["left-pad==1.0.1rc9"],
                        timeout=300,
                    )
        text = str(raised.value)
        # The control: the operation and the tool are named.
        assert "timed out" in text, text
        assert "uv tool install bandit" in text, text
        assert constraint not in text, text
        assert "left-pad" not in text, text

    def test_returns_false_in_offline_mode(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=True,
                ),
            ):
                result = runner.install_tool_with_version("bandit")
                assert result is False

    def test_with_version_constraint(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list
                MagicMock(returncode=0),  # install
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                runner.install_tool_with_version("bandit", version_constraint=">=1.7.0")
                install_cmd = mock_run.call_args_list[-1][0][0]
                assert "bandit>=1.7.0" in install_cmd

    def test_with_package_extras(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # list
                MagicMock(returncode=0),  # install
            ]
            with (
                patch(
                    "automated_security_helper.utils.subprocess_utils.find_executable",
                    return_value=None,
                ),
                patch(
                    "automated_security_helper.core.constants.is_offline_mode",
                    return_value=False,
                ),
            ):
                runner.install_tool_with_version(
                    "bandit", package_extras=["sarif", "toml"]
                )
                install_cmd = mock_run.call_args_list[-1][0][0]
                assert "bandit[sarif,toml]" in install_cmd


def _always_fails_with_reset(attempt_number):
    """Every attempt dies the way a flaky index does: non-zero exit, no output."""
    return subprocess.CalledProcessError(
        1, ["uv", "tool", "install"], "", "Connection reset by peer"
    )


@contextmanager
def _install_harness(runner, outcome_for_attempt):
    """Reduce ``install_tool_with_version`` to just its own install subprocess.

    ``is_tool_installed`` is stubbed out rather than driven through ASH's plain
    runner deliberately: these tests read a *count*, and a count that
    silently also included the ``uv tool list`` probe could not be read.

    ``outcome_for_attempt(n)`` is called with the 1-based attempt number and
    returns either a ``CompletedProcess``-alike to return or an exception
    instance to raise.
    """
    installs: list = []
    sleeps: list = []

    def _run(cmd, *args, **kwargs):
        installs.append(cmd)
        outcome = outcome_for_attempt(len(installs))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    runner._uv_available_cache = True
    with (
        patch.object(runner, "is_tool_installed", return_value=False),
        patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ),
        patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=_run,
        ),
        # The backoff is handed whole to the wait helper, which splits it into
        # cancel-polling chunks; recording the helper's argument reads the
        # schedule the retry chose, not the chunking.
        patch(
            "automated_security_helper.utils.uv_tool_runner._sleep_between_attempts",
            side_effect=sleeps.append,
        ),
    ):
        yield installs, sleeps


class TestInstallRetriesActuallyHappen:
    """Regression tests for ``retry_config`` being honoured at all.

    ``install_tool_with_version`` used to accept ``retry_config`` and ignore it.
    There was no retry loop in the function, so a caller asking for
    ``max_retries=3`` got exactly one attempt -- and BanditScanner asks for
    exactly that on every cold install.

    Why it survived review is the part worth pinning. Every observable anyone
    checked sits *upstream* of the missing code:
    ``UVToolMixin._install_uv_tool`` logs "[INSTALLATION_CONFIG] Using custom
    retry configuration / max_retries=3, base_delay=1.0s" before it calls in;
    ``test_bandit_scanner_behavior`` asserts the config dict was passed with the
    installer stubbed out; ``test_uv_tool_mixin.test_with_custom_retry_config``
    mocks the runner wholesale; and ``TestUVToolRetryConfig`` above reads the
    dataclass's own fields back to itself. All four still pass with the retry
    entirely absent. They were not vacuous -- they just watched something the
    defect does not move.

    So these assert the two things it does move: how many installs are attempted,
    and what the backoff wait is handed between them. Jitter is off wherever an
    exact interval is asserted, so the schedule is arithmetic rather than a
    range. Nothing here measures wall clock, which would flake low on a fast
    machine and high on a loaded one.
    """

    def test_an_exhausted_installs_error_has_no_resolver_text_or_argv(
        self, runner, monkeypatch
    ):
        """uv's resolver errors quote the requirement they could not satisfy,
        and the spec and ``--with`` dependencies are plugin-built and can hold
        a value their config read from the environment -- the rule the timeout
        arm already states, and nothing here holds the values to redact with.
        An exhausted install's error keeps the exit code, the one retriable
        fact that carries no argv, and names the command by its fixed shape."""
        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv", "tool", "install", "bandit==REQ-SECRET-9174"],
                stderr=(
                    "error: Because there is no version of bandit==REQ-SECRET-9174\n"
                ),
            )

        with (
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError) as caught,
        ):
            runner.install_tool_with_version("bandit")

        assert len(installs) == 1
        text = str(caught.value)
        assert "REQ-SECRET-9174" not in text, text
        assert "exit code 1" in text, text
        assert "(uv tool install bandit; arguments not shown)" in text, text
        assert "Command:" not in text, text

    def test_the_install_timeouts_label_names_no_arguments(self, runner, monkeypatch):
        """The timeout's message labels the command by its fixed shape, never
        as a ``Command:`` line: the assembled argv is exactly what it leaves
        out, so the label must not read as a command that can be rerun as
        written -- copied, it would reinstall the latest unconstrained tool
        without its --with dependencies."""
        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def times_out(_attempt):
            return subprocess.TimeoutExpired(cmd=["uv"], timeout=300)

        with (
            _install_harness(runner, times_out) as (installs, _),
            pytest.raises(UVToolRunnerError) as caught,
        ):
            runner.install_tool_with_version("bandit", timeout=300)

        assert len(installs) == 1
        text = str(caught.value)
        assert "(uv tool install bandit; arguments not shown)" in text, text
        assert "Command:" not in text, text

    def test_a_failed_installs_stderr_reaches_the_debug_log_without_values(
        self, runner, monkeypatch, caplog
    ):
        """uv's stderr is the only clue to a 5xx, a DNS failure or a resolver
        conflict, and the retry path exists for exactly those: it reaches the
        debug log with each plugin-built argument replaced by a placeholder,
        so a failed install stays diagnosable without the raised text or any
        log quoting the spec or a --with dependency."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = "==9.9.9rc777"
        dep = "left-pad==1.0.1rc9"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: Because there is no version of bandit{constraint} "
                    f"and you require {dep},\nresolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                with_dependencies=[dep],
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "9.9.9rc777" not in shown, shown
        assert "left-pad" not in shown, shown
        assert "not shown>" in shown, shown
        assert "there is no version of" in shown, shown
        # One record, one console line, like every sibling that logs
        # tool-written text: a raw newline splits the record at the handler.
        assert "\n" not in shown, shown

    def test_the_debug_logs_redaction_survives_an_extras_stripped_respelling(
        self, runner, monkeypatch, caplog
    ):
        """uv names a requirement without the extras the spec carried
        (``bandit[sarif]==X`` comes back as ``bandit==X``), so a whole-spec
        replace finds nothing: the bare constraint is replaced too, longest
        token first, and the version never reaches the debug log."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = "==9.9.9rc777"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: Because there is no version of bandit{constraint}, "
                    f"resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                package_extras=["sarif"],
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "9.9.9rc777" not in shown, shown
        assert "sarif" not in shown, shown

    def test_the_debug_logs_redaction_survives_a_respaced_specifier(
        self, runner, monkeypatch, caplog
    ):
        """uv respells a constraint's spacing and order (">= 1.7, < 2" can
        come back ">=1.7,<2"), and packaging's own normalization REORDERS
        ("<2,>=1.7"), so no whole-string token in either form matches: each
        individual specifier, spaces stripped, is a token too, and the pieces
        match whatever order and spacing the whole came back in."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr="error: no version of bandit satisfies >=1.7,<2 today.",
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=">= 1.7, < 2",
                package_extras=["sarif"],
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG and "today" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "1.7" not in shown, shown
        assert "<2" not in shown, shown
        assert "no version of bandit satisfies" in shown, shown

    def test_the_debug_log_keeps_a_builtin_constraint_diagnosable(
        self, runner, monkeypatch, caplog
    ):
        """With the caller's values in hand, text_without_values is the guard
        for environment-read material in any spelling: the token layer then
        hides only tokens that carry one of those values. A builtin constraint
        is the very thing a resolver conflict is about, and hiding every
        occurrence of it cost the debug line its purpose."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = ">=1.7.0,<2.0.0"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: you require bandit{constraint} but VAL-9281 was "
                    f"pinned elsewhere, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=("VAL-9281",),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "VAL-9281" not in shown, shown
        assert constraint in shown, shown

    def test_a_generator_of_values_redacts_every_attempt(
        self, runner, monkeypatch, caplog
    ):
        """``values`` is normalized to a tuple at entry: passed straight into
        the retry loop, a generator would be used up by the first attempt and
        leave every later attempt's debug line unredacted. Today's caller
        passes a tuple, so this pins the latent trap, as
        run_command_with_output_handling already does with value_tuple."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr="error: VAL-7733 is not an available version, retrying.",
            )

        config = UVToolRetryConfig(max_retries=1, base_delay=0.0, jitter=False)
        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint="==1.0",
                retry_config=config,
                values=(value for value in ["VAL-7733"]),
            )

        assert len(installs) == 2, "the cell shows nothing: no second attempt ran"
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG and "retrying" in record.getMessage()
        ]
        assert len(debug_lines) == 2, debug_lines
        for shown in debug_lines:
            assert "VAL-7733" not in shown, shown

    def test_the_debug_log_redacts_a_callers_value_whatever_its_spelling(
        self, runner, monkeypatch, caplog
    ):
        """An env-read constraint can come back from uv in a form no assembled
        token matches; the caller holds the real values, so the runner takes
        them and redacts the stderr with text_without_values before any token
        replacement -- the mixin's own pattern for text it logs."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        value = "9.9.9rc777"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                # The value alone, in a sentence no assembled token matches.
                stderr=f"error: {value} is not one of the available versions.",
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=f"=={value}",
                package_extras=["sarif"],
                values=(value,),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "available versions" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert value not in shown, shown

    @pytest.mark.parametrize(
        ("constraint", "printed", "forbidden"),
        [
            pytest.param(
                ">=9.9.9rc777,<10",
                "bandit>=9.9.9rc777, <10",
                ["9.9.9rc777"],
                id="respaced",
            ),
            pytest.param(
                ">=9.9.9rc777,<10",
                "bandit<10, >=9.9.9rc777",
                ["9.9.9rc777"],
                id="reordered",
            ),
            pytest.param(
                ">= 55.1, < 77.2",
                "bandit>=55.1, <77.2",
                ["55.1", "77.2"],
                id="value-with-spaces",
            ),
        ],
    )
    def test_an_env_read_constraints_pieces_hide_however_uv_respells_it(
        self, runner, monkeypatch, caplog, constraint, printed, forbidden
    ):
        """A whole-constraint env value is never a substring of its own
        space-stripped pieces, so a token filter asking ``value in token``
        kept nothing and the env-read constraint printed respaced. The filter
        reads the token's ORIGIN instead: an input that holds one of the
        caller's values is hidden with every specifier piece parsed from it,
        whatever spacing or order uv prints them in."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: there is no version of {printed}, so your "
                    f"requirements are unsatisfiable."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=(constraint,),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "unsatisfiable" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        for text in forbidden:
            assert text not in shown, (text, shown)

    @pytest.mark.parametrize("with_value", [True, False])
    def test_a_respaced_with_specifier_is_hidden(
        self, runner, monkeypatch, caplog, with_value
    ):
        """A --with entry's pieces come from the Requirement fallback (a name
        plus specifiers is no SpecifierSet), and they hide whether the entry
        rides in ``values`` (an env-read dependency) or no values were passed
        at all (unknown provenance, everything plugin-built is hidden)."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        entry = "pyyaml>= 55.1, < 77.2"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    "error: only pyyaml<=6.0.2 is available and you require "
                    "pyyaml>=55.1, <77.2, so your requirements are unsatisfiable."
                ),
            )

        kwargs = {"values": (entry,)} if with_value else {}
        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", with_dependencies=[entry], **kwargs
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "unsatisfiable" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "55.1" not in shown, shown
        assert "77.2" not in shown, shown

    @pytest.mark.parametrize(
        ("kwargs", "values", "printed", "forbidden"),
        [
            pytest.param(
                {"version_constraint": "==9.9.9-RC777"},
                ("9.9.9-RC777",),
                "bandit==9.9.9rc777",
                ["9.9.9rc777"],
                id="pep440-pre-respelled",
            ),
            pytest.param(
                {"version_constraint": "==9.9.9-post777"},
                ("9.9.9-post777",),
                "bandit==9.9.9.post777",
                ["9.9.9.post777", "post777"],
                id="pep440-post-respelled",
            ),
            pytest.param(
                {"version_constraint": "==9.9.9-RC777"},
                ("==9.9.9-RC777",),
                "bandit==9.9.9rc777",
                ["9.9.9rc777"],
                id="pep440-whole-constraint-respelled",
            ),
            pytest.param(
                {"with_dependencies": ["Ruamel.YAML==0.17.777"]},
                ("Ruamel.YAML==0.17.777",),
                "ruamel-yaml==0.17.777",
                ["0.17.777", "ruamel-yaml"],
                id="name-normalized-whole-entry",
            ),
        ],
    )
    def test_a_value_uv_normalizes_is_hidden_in_its_normalized_spelling(
        self, runner, monkeypatch, caplog, kwargs, values, printed, forbidden
    ):
        """uv prints a requirement in PEP 440/503 canonical form ("9.9.9-RC777"
        as "9.9.9rc777", "Ruamel.YAML" as "ruamel-yaml"), which neither the
        value's own spellings nor an as-written token matches: the canonical
        forms -- operator plus the parsed Version per piece, canonicalize_name
        for a name -- are spellings of the value and of each hidden input too.
        uv's exact canonical output here is inferred, not measured against a
        real uv; the final wave confirms the shapes."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: there is no version of {printed} and you require "
                    f"{printed}, so your requirements are unsatisfiable."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", values=values, **kwargs)

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "unsatisfiable" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        for text in forbidden:
            assert text not in shown, (text, shown)

    def test_an_explicit_empty_values_tuple_shows_builtin_arguments(
        self, runner, monkeypatch, caplog
    ):
        """An explicit empty ``values`` means the caller checked and its config
        read nothing from the environment, so every plugin-built input is
        builtin and stays diagnosable. Only the default -- no ``values``
        argument at all, unknown provenance -- hides them all; without the
        distinction the constraint's visibility flipped on unrelated config."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = "==1.7.5"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: there is no version of bandit{constraint}, so "
                    f"resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", version_constraint=constraint, values=()
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        assert constraint in debug_lines[0], debug_lines[0]

    def test_a_hidden_name_leaves_other_words_that_contain_it_alone(
        self, runner, monkeypatch, caplog
    ):
        """A requirement NAME is made of word characters, so replacing it as a
        raw substring mangles every word that contains it: a hidden "toml"
        turned "pyproject.toml" into noise. On the CHECKED branch -- the
        caller vouched for ``values``, here the env-read version that makes
        the entry hidden -- a name-shaped token is replaced only at
        requirement-name boundaries (PEP 503's name alphabet, letters, digits
        and ".-_"), so the whole entry and its pieces still hide while uv's
        surrounding diagnostics stay readable. The unknown-provenance branch
        keeps raw replacement; its own cell pins that."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        entry = "toml==2.0.77"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    "error: pyproject.toml could not be parsed, and you "
                    f"require {entry}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", with_dependencies=[entry], values=("2.0.77",)
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "pyproject.toml" in shown, shown
        assert "toml==2.0.77" not in shown, shown
        assert "2.0.77" not in shown, shown

    def test_hide_all_replaces_a_name_wherever_it_appears(
        self, runner, monkeypatch, caplog
    ):
        """The ``values is None`` branch means NOBODY checked where the inputs
        came from, so hide-all means hide-all: raw replacement, no boundary
        rules. A name-boundary rule here leaks the input through uv's own
        respellings -- "-" in a dist file name ("secret-pkg-1.0-py3-none-
        any.whl") and "." at a sentence's end are both name characters, so a
        boundary match replaces neither. The readability rule belongs to the
        checked branch only."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        entry = "secret" + "-pkg"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"Saved {entry}-1.0-py3-none-any.whl, but you require "
                    f"{entry}. So resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", with_dependencies=[entry])

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert entry not in shown, shown
        assert "not shown" in shown, shown

    def test_a_short_unrelated_value_does_not_hide_a_builtin_constraint(
        self, runner, monkeypatch, caplog
    ):
        """The origin filter decides whether an input is hidden with the SAME
        matcher the value layer redacts with, boundary rules included: a raw
        substring test hid the builtin ">=1.7.4,<2" because an unrelated
        option read "4" from the environment -- the exact visibility-flips-on-
        unrelated-config problem the None-vs-() distinction removed. A short
        value hides an input only where the value layer would hide it there
        (under four characters, only quoted)."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = ">=1.7.4,<2"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: you require bandit{constraint}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=("4",),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        assert constraint in debug_lines[0], debug_lines[0]

    def test_a_value_glued_into_an_input_still_hides_it(
        self, runner, monkeypatch, caplog
    ):
        """The substring arm: a token is hidden where the value layer would
        hide a value in it, OR where a value of MIN_REDACTED_LENGTH or more
        characters is a plain substring of it. The boundary-rules-only
        matcher left "qz4b" glued into "pkgqz4b==1.0" in clear, because a
        letter neighbors the value on one side; the token is hidden whole, so
        the substring arm costs only debug readability, never a false reveal
        of surrounding text."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        entry = "pkg" + "qz4b" + "==1.0"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: there is no version of {entry}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", with_dependencies=[entry], values=("qz4b",)
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "qz4b" not in shown, shown
        assert "not shown" in shown, shown

    def test_a_short_env_read_pin_hides_the_constraint_it_built(
        self, runner, monkeypatch, caplog
    ):
        """The structure arm: a value of ANY length that equals, or
        canonicalizes to, a version part of one of the input's specifiers
        hides the input. A short pin sits below the substring floor and
        inside a boundary ("=" is no word edge the short-value rule accepts),
        so without this arm the env-read "1.8" printed as "bandit==1.8" at
        all three matcher sites."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = "==1.8"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: you require bandit{constraint}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=("1.8",),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert constraint not in shown, shown
        assert "not shown" in shown, shown

    def test_a_value_glued_into_a_hidden_names_file_name_is_hidden(
        self, runner, monkeypatch, caplog
    ):
        """A hidden input's NAME printed inside a larger word -- "pkgqz4b" in
        "pkgqz4b-1.0.tar.gz", where "-" and "." are name characters the
        boundary rule respects -- is right for a name with no value in it and
        wrong when the glued env-read value sits inside the name itself. The
        substring arm's clause applies to name tokens too: a name holding a
        value of MIN_REDACTED_LENGTH or more characters is replaced wherever
        it appears, boundaries or not."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        value = "qz4b"
        entry = "pkg" + value + "==1.0"

        def resolver_error(_attempt):
            # Every neighbor shape uv's dist text puts beside a name: the
            # sdist and wheel file names ("-" neighbor), the metadata
            # directory ("." neighbor), and a sentence-final period.
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"Saved pkg{value}-1.0.tar.gz and "
                    f"pkg{value}-1.0-py3-none-any.whl beside "
                    f"pkg{value}.egg-info, and you require {entry}, "
                    f"so resolution failed for pkg{value}."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", with_dependencies=[entry], values=(value,)
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert value not in shown, shown
        assert "not shown" in shown, shown

    def test_a_bare_dependency_gluing_a_value_is_hidden_whole(
        self, runner, monkeypatch, caplog
    ):
        """A bare --with dependency is all name: its whole token is a name
        token, so under the boundary rule alone the full input escaped in
        every dist-text form. A bare name holding a glued env-read value is
        replaced wherever it appears."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        value = "qz4b"
        entry = "pkg" + value

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"Because you require {entry} and saved "
                    f"{entry}-1.0.tar.gz, resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit", with_dependencies=[entry], values=(value,)
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert value not in shown, shown
        assert entry not in shown, shown

    @pytest.mark.parametrize(
        ("constraint", "value", "hidden"),
        [
            # A range constraint is diagnosable context, not a pin: an
            # env-read "2" that happens to equal the "<2" bound must not
            # hide the builtin -- the must-stay-visible example.
            (">=1.7.4,<2", "2", False),
            # Pinning operators carry the env-read value itself.
            ("==2", "2", True),
            ("===1.8", "1.8", True),
            ("~=1.8", "1.8", True),
            # A wildcard pin carries the value as its base.
            ("==1.8.*", "1.8", True),
        ],
    )
    def test_the_structure_arm_reads_only_pinning_operators(
        self, runner, monkeypatch, caplog, constraint, value, hidden
    ):
        """The structure arm applies only to pinning operators (==, ===, ~=):
        a value equal to a pin's version part IS the env-read value printed
        back, while a value equal to a range bound (">=1.7.4,<2" against an
        env-read "2") is a coincidence that would hide the very constraint a
        resolver conflict is about."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: you require bandit{constraint}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=(value,),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        if hidden:
            assert constraint not in shown, shown
            assert "not shown" in shown, shown
        else:
            assert constraint in shown, shown

    def test_a_short_fragment_matching_no_version_part_stays_shown(
        self, runner, monkeypatch, caplog
    ):
        """The substring floor still governs UNSTRUCTURED fragments: a value
        shorter than MIN_REDACTED_LENGTH that equals no version part of the
        constraint decides nothing, so the builtin ">=1.8.2,<2" stays
        diagnosable while an unrelated option read "1.8" from the
        environment. Short numeric fragments sit inside almost every
        constraint; hiding whole inputs over them is the visibility-flips-on-
        unrelated-config problem again."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        constraint = ">=1.8.2,<2"

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: you require bandit{constraint}, so resolution failed."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint=constraint,
                values=("1.8",),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "resolution failed" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        assert constraint in debug_lines[0], debug_lines[0]

    @pytest.mark.parametrize(
        ("variable", "value"),
        [("FORCE_COLOR", "1"), ("CLICOLOR_FORCE", "1"), ("COLUMNS", "20")],
    )
    def test_uv_installs_under_no_display_variable(
        self, runner, monkeypatch, caplog, variable, value
    ):
        """The install's stderr is parsed by both redaction layers, which read
        contiguous text, so the install runs under environ_for_parsed_output
        like the module's other parsed uv calls: uv wraps at COLUMNS and
        colors under FORCE_COLOR into a pipe, and either breaks a token."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        monkeypatch.setenv(variable, value)
        environments: list = []

        def _run(cmd, *args, **kwargs):
            environments.append(kwargs.get("env"))
            raise subprocess.CalledProcessError(1, ["uv"], stderr="error: x")

        runner._uv_available_cache = True
        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            patch.object(runner, "is_tool_installed", return_value=False),
            patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ),
            patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain",
                side_effect=_run,
            ),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", version_constraint="==1.7.5")

        assert environments, "the cell shows nothing: the install never spawned"
        env = environments[0] or {}
        assert variable not in env, (variable, env.get(variable))
        assert env.get("NO_COLOR") == "1", env.get("NO_COLOR")

    @pytest.mark.parametrize(
        "colored",
        [
            pytest.param("\x1b[1mbandit==9.9.9rc777\x1b[0m", id="one-span"),
            pytest.param(
                "\x1b[1mbandit\x1b[0m\x1b[36m==9.9.9rc777\x1b[39m",
                id="name-and-range",
            ),
            pytest.param(
                "\x1b[1mbandit\x1b[0m\x1b[36m==\x1b[39m\x1b[36m9.9.9rc777\x1b[39m",
                id="operator-and-version",
            ),
        ],
    )
    def test_a_colored_requirement_is_still_hidden(
        self, runner, monkeypatch, caplog, colored
    ):
        """A color code INSIDE a token breaks the contiguous text both layers
        match, so SGR codes are removed from the stderr before the layers
        read it; the one-record-one-line step stays the log call site's.
        environ_for_parsed_output makes colored output unexpected
        (NO_COLOR=1); this holds the line if uv colors anyway. Where uv puts
        its codes is inferred, not measured."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1,
                ["uv"],
                stderr=(
                    f"error: there is no version of {colored}, so your "
                    f"requirements are unsatisfiable."
                ),
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version(
                "bandit",
                version_constraint="==9.9.9rc777",
                values=("==9.9.9rc777",),
            )

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "unsatisfiable" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert "9.9.9rc777" not in shown, shown

    def test_the_debug_record_is_bounded_with_a_dropped_count(
        self, runner, monkeypatch, caplog
    ):
        """A failed sdist build writes a multi-megabyte stderr, and the record
        went to the handler whole, per attempt. The record keeps the TAIL --
        uv's conclusion and hints come last -- at the module's tool-output
        bound, and the marker counts what was dropped so a reader knows the
        record is an excerpt."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        stderr = "Downloading build log line\n" * 80000 + "error: final line."

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(1, ["uv"], stderr=stderr)

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", version_constraint="==1.7.5")

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "uv tool install for bandit exited" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        shown = debug_lines[0]
        assert len(shown) <= 4096, len(shown)
        assert "characters not shown" in shown, shown
        assert "error: final line." in shown, shown[-200:]

    def test_numbering_is_lexicographic_among_equal_lengths(
        self, runner, monkeypatch, caplog
    ):
        """The tiebreak: longest first, then lexicographic, so the
        <argument N> numbering is the same in every process. Twenty --with
        entries of one length, printed in reverse: under a set-order tiebreak
        the chance all twenty land in order is 1/20!."""
        import logging

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        entries = [f"pk{n:02d}==1" for n in range(1, 21)]
        printed = list(reversed(entries))

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1, ["uv"], stderr="error: " + " ".join(printed)
            )

        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", with_dependencies=entries)

        assert len(installs) == 1
        debug_lines = [
            record.getMessage()
            for record in caplog.records
            if record.levelno == logging.DEBUG
            and "uv tool install for bandit exited" in record.getMessage()
        ]
        assert debug_lines, "the cell shows nothing: no debug line carried the stderr"
        expected = " ".join(
            f"<argument {sorted(entries).index(entry) + 1} not shown>"
            for entry in printed
        )
        assert expected in debug_lines[0], debug_lines[0]

    def test_a_timeout_after_a_failed_attempt_chains_no_argv(
        self, runner, monkeypatch, caplog
    ):
        """The raised text is fixed-shape, but ``raise ... from e`` kept the
        TimeoutExpired, whose own text quotes the assembled argv -- the spec
        and --with dependencies that can hold env-read values -- so every
        traceback printer rendered it. The env-blind raises disavow their
        chain (``from None``), and this one does too."""
        import logging
        import traceback

        monkeypatch.delenv("UV_OFFLINE", raising=False)
        # Held in variables: a traceback renders each frame's source line, so
        # a literal on the test's own call line would read as a leak.
        marker = "9.9.9" + "rc777"
        constraint = "==" + marker

        def outcome(attempt):
            if attempt == 1:
                return subprocess.CalledProcessError(
                    1, ["uv"], stderr=f"error: no version of bandit{constraint}"
                )
            return subprocess.TimeoutExpired(
                ["uv", "tool", "install", f"bandit{constraint}"], 300
            )

        config = UVToolRetryConfig(max_retries=1, base_delay=0.0, jitter=False)
        with (
            caplog.at_level(logging.DEBUG, logger="ash"),
            _install_harness(runner, outcome) as (installs, _),
            pytest.raises(UVToolRunnerError) as caught,
        ):
            runner.install_tool_with_version(
                "bandit", version_constraint=constraint, retry_config=config
            )

        assert len(installs) == 2, "the cell shows nothing: the timeout never ran"
        assert "timed out" in str(caught.value), str(caught.value)
        chain = "".join(
            traceback.format_exception(
                type(caught.value), caught.value, caught.value.__traceback__
            )
        )
        assert marker not in chain, chain

    @pytest.mark.parametrize(
        ("offline", "kwargs", "present", "absent"),
        [
            pytest.param(
                True,
                {
                    "version_constraint": ">=1.7,<2",
                    "with_dependencies": ["bandit-sarif-formatter"],
                },
                ["--offline", "1 --with dependency", "a version constraint"],
                [">=1.7", "bandit-sarif-formatter", "an extras list"],
                id="offline-constraint-one-dep",
            ),
            pytest.param(
                False,
                {
                    "package_extras": ["sarif"],
                    "with_dependencies": ["dep-one==1.0", "dep-two==2.0"],
                },
                ["2 --with dependencies", "an extras list"],
                ["--offline", "sarif", "dep-one", "dep-two", "a version constraint"],
                id="extras-two-deps",
            ),
        ],
    )
    def test_the_installs_error_names_value_free_parts_only(
        self, runner, monkeypatch, offline, kwargs, present, absent
    ):
        """The label carries each part that cannot hold a value separately --
        the offline flag, the --with count with its singular and plural forms,
        an extras list, a version constraint -- so the message stays
        diagnosable without quoting the spec or any dependency, and a reader
        can tell whether a version pin was involved in a resolver failure."""
        if offline:
            monkeypatch.setenv("UV_OFFLINE", "1")
        else:
            monkeypatch.delenv("UV_OFFLINE", raising=False)

        def resolver_error(_attempt):
            return subprocess.CalledProcessError(
                1, ["uv"], stderr="no version of bandit==9.9.9rc777"
            )

        with (
            _install_harness(runner, resolver_error) as (installs, _),
            pytest.raises(UVToolRunnerError) as caught,
        ):
            runner.install_tool_with_version("bandit", **kwargs)

        assert len(installs) == 1
        text = str(caught.value)
        assert "9.9.9rc777" not in text, text
        for piece in present:
            assert piece in text, (piece, text)
        for piece in absent:
            assert piece not in text, (piece, text)

    def test_a_retry_config_buys_one_attempt_per_configured_retry(self, runner):
        config = UVToolRetryConfig(max_retries=3, base_delay=0.0, jitter=False)
        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert len(installs) == 4, (
            "expected 1 initial attempt plus 3 retries; a 1 here means "
            "retry_config is being accepted and dropped again"
        )

    def test_no_retry_config_still_means_exactly_one_attempt(self, runner):
        """Callers that never asked for retries must be left alone."""
        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit")
        assert len(installs) == 1
        assert sleeps == []

    def test_a_none_config_never_reaches_the_delay_computation(self, runner):
        """The delay helper takes a non-optional config, so it must not be called
        with ``None`` -- and that call site runs only on the retry path.

        This is the invariant behind ``retry_config is not None`` in the sleep
        guard. It holds today because ``attempts`` is 1 whenever ``retry_config``
        is falsy, so ``attempt + 1 < attempts`` is already False. The reason to
        pin it rather than trust it: a break would surface as an AttributeError
        thrown from *inside* the retry path, which only executes after an install
        has already failed. Every test that installs successfully, and every test
        that fails without a retry config, would stay green.

        Asserting it by making the delay helper explode is deliberate -- it fails
        if the guard is ever loosened, rather than merely checking a count that
        happens to match.
        """
        sentinel = AssertionError("_install_retry_delay called with no retry_config")

        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner._install_retry_delay",
                side_effect=sentinel,
            ),
            _install_harness(runner, _always_fails_with_reset) as (installs, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=None)

        assert len(installs) == 1
        assert sleeps == []

    def test_the_interval_grows_and_is_exactly_the_configured_schedule(self, runner):
        config = UVToolRetryConfig(
            max_retries=3,
            base_delay=1.0,
            exponential_base=2.0,
            max_delay=60.0,
            jitter=False,
        )
        with (
            _install_harness(runner, _always_fails_with_reset) as (_, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert sleeps == [1.0, 2.0, 4.0], (
            "the interval must grow between attempts. A flat list is a "
            "fixed-interval retry wearing the name backoff; an empty list is no "
            "backoff at all, which fires every retry back-to-back at whatever "
            "the retry was supposed to be gentle with"
        )

    def test_the_interval_stops_growing_at_max_delay(self, runner):
        config = UVToolRetryConfig(
            max_retries=4,
            base_delay=10.0,
            exponential_base=2.0,
            max_delay=25.0,
            jitter=False,
        )
        with (
            _install_harness(runner, _always_fails_with_reset) as (_, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert sleeps == [10.0, 20.0, 25.0, 25.0]

    def test_nothing_is_slept_after_the_final_attempt(self, runner):
        """A wait after the last try buys nothing and only delays the error."""
        config = UVToolRetryConfig(max_retries=2, base_delay=1.0, jitter=False)
        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert len(installs) == 3
        assert len(sleeps) == len(installs) - 1

    def test_a_transient_failure_is_recovered_by_the_retry(self, runner):
        """Fails once on the network then succeeds: the case the config exists for."""

        def _fails_once(attempt_number):
            if attempt_number == 1:
                return subprocess.CalledProcessError(
                    1, ["uv", "tool", "install"], "", "Recv failure"
                )
            return MagicMock(returncode=0)

        config = UVToolRetryConfig(max_retries=3, base_delay=1.0, jitter=False)
        with _install_harness(runner, _fails_once) as (installs, sleeps):
            assert (
                runner.install_tool_with_version("bandit", retry_config=config) is True
            )
        assert len(installs) == 2, "the second attempt is what made this succeed"
        assert sleeps == [1.0], "exactly one wait, taken between the two attempts"

    def test_a_timeout_is_not_retried(self, runner):
        """Deliberate: the attempt already spent the whole timeout budget.

        Retrying would multiply wall clock by the attempt count, so three 300s
        timeouts would be fifteen minutes of a scan phase spent waiting on a tool
        that is not coming.
        """

        def _times_out(attempt_number):
            return subprocess.TimeoutExpired("uv", 300)

        config = UVToolRetryConfig(max_retries=3, base_delay=1.0, jitter=False)
        with (
            _install_harness(runner, _times_out) as (installs, sleeps),
            pytest.raises(UVToolRunnerError, match="timed out"),
        ):
            runner.install_tool_with_version("bandit", timeout=300, retry_config=config)
        assert len(installs) == 1
        assert sleeps == []

    def test_jitter_stays_inside_the_growing_envelope(self, runner):
        """With jitter on the exact values vary, but the growth must survive it."""
        config = UVToolRetryConfig(
            max_retries=3,
            base_delay=10.0,
            exponential_base=2.0,
            max_delay=600.0,
            jitter=True,
        )
        with (
            _install_harness(runner, _always_fails_with_reset) as (_, sleeps),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        # Jitter adds at most 1.0s, and each step doubles a >=10s base, so the
        # envelopes cannot overlap and the sequence must still be increasing.
        assert sleeps == sorted(sleeps), sleeps
        assert 10.0 <= sleeps[0] < 11.0, sleeps
        assert 20.0 <= sleeps[1] < 21.0, sleeps
        assert 40.0 <= sleeps[2] < 41.0, sleeps


class TestRetryDelayIsAlwaysSleepable:
    """``time.sleep`` raises ValueError on a negative argument.

    ``UVToolRetryConfig`` is assembled in ``UVToolMixin._install_uv_tool`` from a
    plain dict via ``.get(key, default)`` with no validation, so a nonsensical
    value reaches the arithmetic instead of being rejected at the boundary. A
    negative interval would surface as a ValueError thrown from inside the
    install path, which a caller cannot tell apart from the install itself having
    failed.
    """

    def test_a_negative_max_delay_cannot_produce_a_negative_interval(self):
        config = UVToolRetryConfig(base_delay=1.0, max_delay=-30.0, jitter=False)
        intervals = [_install_retry_delay(config, n) for n in range(4)]
        assert all(interval >= 0.0 for interval in intervals), intervals

    def test_a_negative_base_delay_cannot_produce_a_negative_interval(self):
        config = UVToolRetryConfig(base_delay=-5.0, jitter=False)
        intervals = [_install_retry_delay(config, n) for n in range(4)]
        assert all(interval >= 0.0 for interval in intervals), intervals

    def test_the_cap_is_never_normalized_below_the_floor(self):
        """A max_delay under base_delay would cap every interval below its start."""
        config = UVToolRetryConfig(base_delay=10.0, max_delay=1.0)
        assert config.max_delay >= config.base_delay

    def test_a_sub_unit_exponential_base_cannot_shrink_the_backoff(self):
        config = UVToolRetryConfig(base_delay=1.0, exponential_base=0.5, jitter=False)
        intervals = [_install_retry_delay(config, n) for n in range(4)]
        assert intervals == sorted(intervals), intervals

    def test_negative_max_retries_becomes_a_single_attempt(self):
        """``1 + max_retries`` must not be able to produce an empty range."""
        assert UVToolRetryConfig(max_retries=-4).max_retries == 0

    def test_a_field_mutated_after_construction_still_cannot_go_negative(self):
        """The one case ``__post_init__`` cannot reach, so the only case that
        distinguishes the two overlapping guards.

        Every other test in this class is satisfied by the normalization in
        ``__post_init__`` alone -- deleting the ``max(0.0, ...)`` clamp inside
        ``_install_retry_delay`` leaves them all green, which would make the
        clamp an untested guard whose removal nothing notices.
        ``UVToolRetryConfig`` is a plain mutable dataclass, so assigning to a
        field after construction bypasses normalization entirely. That is what
        this pins, and it fails if the clamp is removed.
        """
        config = UVToolRetryConfig(base_delay=1.0, jitter=False)
        config.max_delay = -30.0

        intervals = [_install_retry_delay(config, n) for n in range(3)]
        assert intervals == [0.0, 0.0, 0.0], intervals

    def test_a_zero_base_delay_stays_zero_when_the_power_overflows(self):
        """``0.0 * inf`` is NaN, and NaN read as the cap: a config asking for
        no wait between attempts slept ``max_delay`` from the attempt the
        power overflowed. The base is assigned after construction, past the
        bound ``__post_init__`` puts on it, as the clamp test above does."""
        config = UVToolRetryConfig(base_delay=0.0, max_delay=60.0, jitter=False)
        config.exponential_base = 1e6
        late = [_install_retry_delay(config, n) for n in (0, 51, 52, 60)]
        assert late == [0.0, 0.0, 0.0, 0.0], late

    def test_a_positive_base_whose_power_overflows_reads_as_the_cap(self):
        """The control: with a base to grow from, the overflow is the cap."""
        config = UVToolRetryConfig(base_delay=1.0, max_delay=60.0, jitter=False)
        config.exponential_base = 1e6
        assert _install_retry_delay(config, 60) == 60.0


class TestTheAttemptCountCannotFallBelowOne:
    """``1 + max_retries`` must never collapse ``range(attempts)`` to empty.

    With ``attempts <= 0`` the loop body never executes, so ``last_error`` is
    never assigned and the function ends at ``raise UVToolRunnerError(None)`` --
    an install that never happened, reported as a failure carrying no message.
    ``str()`` of that exception is the literal "None".

    This is latent rather than live: ``__post_init__`` clamps ``max_retries`` to
    ``>= 0`` and ``UVToolMixin._install_uv_tool`` is the only constructor. It is
    guarded anyway, for the reason ``_install_retry_delay``'s own docstring gives
    for its own doubled clamp -- ``UVToolRetryConfig`` is a plain *mutable*
    dataclass, so assigning to a field after construction re-opens the hole
    normalization closed. That argument is already applied to the sleep value;
    the attempt count is where the consequence is worse, because a bad sleep
    value raises something a reader can name and an empty attempt range produces
    an error that names nothing.

    ``with-retry.sh`` in this same branch guards the identical case with
    ``if [ "$max" -lt 1 ]``, and its comment gives the identical reason: "All 0
    attempts failed" is a failure indistinguishable from the command having been
    run and failed.
    """

    def test_a_negative_retry_count_still_runs_one_attempt(self, runner):
        config = UVToolRetryConfig(max_retries=0, base_delay=0.0, jitter=False)
        config.max_retries = -1

        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, sleeps),
            pytest.raises(UVToolRunnerError) as excinfo,
        ):
            runner.install_tool_with_version("bandit", retry_config=config)

        assert len(installs) == 1, (
            "a negative retry count made range(attempts) empty, so uv was never "
            "invoked at all and the error raised below described nothing"
        )
        assert sleeps == [], "one attempt has no gap after it to wait in"
        assert str(excinfo.value) != "None", (
            "UVToolRunnerError(None) stringifies to the literal 'None': a "
            "failure report with no failure in it"
        )
        # The failure is named by its exit code; the stderr text never rides
        # (a resolver error quotes the requirement it could not satisfy).
        assert "exit code 1" in str(excinfo.value)
        assert "Connection reset by peer" not in str(excinfo.value)

    @pytest.mark.parametrize("max_retries", [-1, -4, -100])
    def test_the_error_always_names_the_failure_that_happened(
        self, runner, max_retries
    ):
        config = UVToolRetryConfig(max_retries=0, base_delay=0.0, jitter=False)
        config.max_retries = max_retries

        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, _),
            pytest.raises(UVToolRunnerError, match="exit code 1"),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert len(installs) == 1

    def test_a_zero_retry_count_is_unchanged(self, runner):
        """Positive control: the already-correct boundary must not move.

        ``max_retries=0`` is the value ``__post_init__`` normalizes a negative to,
        and it already meant one attempt. A clamp that shifted this to two would
        double every install's work while passing the tests above.
        """
        config = UVToolRetryConfig(max_retries=0, base_delay=0.0, jitter=False)

        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, sleeps),
            pytest.raises(UVToolRunnerError, match="exit code 1"),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert len(installs) == 1
        assert sleeps == []

    def test_a_positive_retry_count_is_unchanged(self, runner):
        """Positive control: ``max(1, ...)`` must not cap a real retry policy."""
        config = UVToolRetryConfig(max_retries=3, base_delay=0.0, jitter=False)

        with (
            _install_harness(runner, _always_fails_with_reset) as (installs, _),
            pytest.raises(UVToolRunnerError),
        ):
            runner.install_tool_with_version("bandit", retry_config=config)
        assert len(installs) == 4


class _ScaledClock:
    """Stand-in for the module's ``time`` where one real second reads as ``scale``.

    The monitor measures elapsed with ``time.time()`` and compares it against
    ``timeout``, and the smallest ``timeout`` that starts a monitor at all is 61
    seconds. Observing what the monitor does *after* an attempt's timeout has
    passed therefore costs a real minute per attempt. Scaling the clock the
    monitor reads buys that observation in seconds without touching any threshold
    in the code under test: nothing here raises a timeout or lowers a bound to
    make an assertion pass, and ``time()`` stays monotonic. Every other attribute
    proxies to the real module, so the retry backoff's ``time.sleep`` is
    unaffected.
    """

    def __init__(self, scale: float):
        self._scale = scale
        self._origin = time.time()

    def time(self) -> float:
        return self._origin + (time.time() - self._origin) * self._scale

    def __getattr__(self, name):
        return getattr(time, name)


def _elapsed_from(message: str) -> float:
    """Pull the N out of "Installation in progress... (Ns elapsed)"."""
    match = re.search(r"\(?(?:attempt \d+/\d+, )?(\d+)s elapsed\)", message)
    assert match is not None, f"unparseable progress message: {message!r}"
    return float(match.group(1))


class TestTheProgressMonitorCoversTheWholeRetriedRun:
    """The monitor's contract assumed one attempt; the retry loop gave it several.

    It was started once, before the loop, and self-terminated at
    ``elapsed > timeout`` measured from before the first attempt. Once
    ``retry_config`` made the install run up to ``attempts * timeout`` plus
    backoff -- roughly fifteen minutes for BanditScanner's ``max_retries=3`` at
    the default 300s timeout -- callbacks stopped at 300 seconds and the caller
    heard nothing for the remaining ten-plus minutes while the work continued.

    Two things compounded it. The elapsed figure emitted before that point
    described the first attempt, not the attempt in flight, so a caller reading
    "410s elapsed" was being told about a budget nothing enforces; ``timeout`` is
    what ``subprocess.run`` applies to a single attempt. And the line
    ``if progress_thread: progress_thread = None``, under a comment reading "Stop
    progress monitoring", dropped a reference and stopped nothing -- the thread is
    a daemon polling a fixed sleep, so it kept calling back for up to ``timeout``
    after the install had already returned.

    Nothing in the suite could see any of this: no test anywhere passed a
    ``progress_callback``, and no production caller passes one either, so the
    monitor was reachable only through the parameter and exercised by nothing.

    The chosen shape is one monitor per attempt: elapsed is anchored to the
    attempt in flight, and the stop is an Event the loop sets in a ``finally``.
    The alternative -- one monitor given the whole budget -- would have to invent
    that budget, since ``attempts * timeout + sum(jittered backoffs)`` is not a
    limit anything applies and varies run to run.
    """

    @staticmethod
    def _blocking_outcomes(first_block: float, second_block: float, windows: list):
        """Two attempts that occupy real time: the first fails, the second succeeds.

        ``threading.Event().wait`` rather than ``time.sleep`` deliberately. The
        install harness once patched the module's ``time.sleep`` to record the
        intervals, which made a sleep here return instantly and occupy no time at
        all; it now patches ``_sleep_between_attempts``, the wait between attempts,
        and leaves ``time.sleep`` alone. The Event wait stays so this helper keeps
        occupying real time whatever the harness stubs next.
        """

        def outcome(attempt_number):
            entered = time.time()
            block = first_block if attempt_number == 1 else second_block
            threading.Event().wait(block)
            windows.append((attempt_number, entered, time.time()))
            if attempt_number == 1:
                return subprocess.CalledProcessError(
                    1, ["uv", "tool", "install"], "", "Connection reset by peer"
                )
            return MagicMock(returncode=0)

        return outcome

    def test_callbacks_continue_past_the_first_attempts_timeout(self, runner):
        """A 120s timeout, two attempts, and a clock running 100x.

        Attempt 1 occupies 2.0 real seconds, which the monitor reads as 200 --
        past its 120-second horizon. Attempt 2 then runs for another 0.6 real
        seconds. The caller must still be hearing from the install during it.
        """
        scale = 100.0
        timeout = 120
        windows: list = []
        records: list = []
        config = UVToolRetryConfig(
            max_retries=1, base_delay=0.0, max_delay=0.0, jitter=False
        )

        with (
            patch.object(uv_tool_runner, "time", _ScaledClock(scale)),
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.05),
            _install_harness(runner, self._blocking_outcomes(2.0, 0.6, windows)) as (
                installs,
                _,
            ),
        ):
            assert (
                runner.install_tool_with_version(
                    "bandit",
                    timeout=timeout,
                    retry_config=config,
                    progress_callback=lambda m: records.append((time.time(), m)),
                )
                is True
            )

        assert len(installs) == 2, "the test needs both attempts to have run"
        assert len(windows) == 2
        second_attempt_started = windows[1][1]
        during_second = [m for t, m in records if t >= second_attempt_started]

        assert during_second, (
            f"the install ran for {windows[1][2] - windows[0][1]:.1f} real seconds "
            f"across two attempts and the caller heard nothing during the second. "
            f"The monitor self-terminated at elapsed > {timeout} measured from "
            f"before attempt 1, so it went silent while the work continued -- "
            f"{len(records)} callbacks, all of them in attempt 1"
        )

    def test_the_elapsed_figure_describes_the_attempt_in_flight(self, runner):
        """Anchored to the running attempt, not to the first one.

        The strict form: every figure reported during attempt 2 must match the
        time since attempt 2 began. Anchored to attempt 1 instead, each figure
        would be inflated by the whole of attempt 1 -- 200 scaled seconds here,
        which also puts every one of them past the 120-second timeout the caller
        is implicitly measuring against.
        """
        scale = 100.0
        timeout = 120
        windows: list = []
        records: list = []
        config = UVToolRetryConfig(
            max_retries=1, base_delay=0.0, max_delay=0.0, jitter=False
        )

        with (
            patch.object(uv_tool_runner, "time", _ScaledClock(scale)),
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.05),
            _install_harness(runner, self._blocking_outcomes(2.0, 0.6, windows)) as (
                installs,
                _,
            ),
        ):
            runner.install_tool_with_version(
                "bandit",
                timeout=timeout,
                retry_config=config,
                progress_callback=lambda m: records.append((time.time(), m)),
            )

        assert len(installs) == 2
        second_started = windows[1][1]
        during_second = [
            (t, _elapsed_from(m)) for t, m in records if t >= second_started
        ]
        assert during_second, "no callbacks during attempt 2; see the test above"

        for at, reported in during_second:
            expected = (at - second_started) * scale
            assert reported <= expected + 3 * scale, (
                f"reported {reported}s elapsed {at - second_started:.2f} real "
                f"seconds into attempt 2, which is ~{expected:.0f} scaled "
                f"seconds. A figure this far ahead is anchored to attempt 1"
            )
            assert reported < timeout, (
                f"reported {reported}s elapsed against a {timeout}s per-attempt "
                f"timeout: the number describes a budget nothing enforces"
            )

    def test_the_monitor_stops_when_the_install_does(self, runner):
        """The comment reading "Stop progress monitoring" has to actually stop it.

        The old line set ``progress_thread = None``, which drops a reference. The
        thread is a daemon polling a fixed interval, so it kept calling back for
        up to ``timeout`` after the install had returned -- into a callback whose
        owner has every reason to have torn down whatever it writes to.
        """
        records: list = []
        config = UVToolRetryConfig(
            max_retries=1, base_delay=0.0, max_delay=0.0, jitter=False
        )

        with (
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.02),
            _install_harness(runner, lambda n: MagicMock(returncode=0)) as (
                installs,
                _,
            ),
        ):
            assert (
                runner.install_tool_with_version(
                    "bandit",
                    timeout=120,
                    retry_config=config,
                    progress_callback=records.append,
                )
                is True
            )
            after_return = len(records)
            threading.Event().wait(0.5)
            arrived_late = len(records) - after_return

        assert len(installs) == 1
        assert arrived_late == 0, (
            f"{arrived_late} callbacks arrived in the half second after the "
            f"install returned, so the monitor outlived the work it was "
            f"reporting on"
        )

    def test_a_failed_attempt_stops_its_own_monitor(self, runner):
        """The gap between attempts is not work, so nothing should report on it.

        This is the half the old code could not have got right: it dropped the
        thread reference only on the *success* path, so after a failed attempt the
        monitor kept reporting elapsed time against an attempt that had already
        ended, right through the backoff and into the next one.

        Counted by *arrival order* rather than by timestamp, and this matters. The
        first form of this test bracketed the backoff with two ``time.time()``
        reads and asked which callback timestamps fell between them. That compares
        clock readings taken on two different threads and needs the wall clock to
        order them, which no clock promises: ``time.time()`` is not monotonic, and
        where its resolution is coarse two reads microseconds apart return the
        same value, which the inclusive bounds then counted as inside the gap.

        It failed on exactly one CI cell, windows-latest/py3.11, reporting one
        callback in a 0.41s gap. One is the tell. The monitor's cadence here is
        0.02s, measured at 5 callbacks per 0.1s attempt, so a monitor genuinely
        still running through that gap would have delivered about twenty, not one
        -- and quantizing this test's own timestamps to 15.625ms, Windows' timer
        granularity, puts a callback in the gap on 30 runs out of 30 with the code
        unchanged and behaving correctly. So the count was measuring the clock.

        A monotonically increasing arrival index has no such problem: the gap's
        endpoints are the callback count before and after the backoff, taken under
        the same lock the callback appends under, so "did anything arrive during
        the gap" is answered by a happens-before relation instead of by two
        clocks. The second assertion then reads the *content*, which is what the
        property is actually about -- a message naming attempt 1 must not arrive
        once attempt 1 is over -- and holds at any runner speed.
        """
        records: list = []
        gap_marks: list = []
        lock = threading.Lock()
        config = UVToolRetryConfig(
            max_retries=1, base_delay=0.4, max_delay=0.4, jitter=False
        )

        def _record(message):
            with lock:
                records.append(message)

        def _outcomes(attempt_number):
            threading.Event().wait(0.1)
            if attempt_number == 1:
                return subprocess.CalledProcessError(
                    1, ["uv", "tool", "install"], "", "Connection reset by peer"
                )
            return MagicMock(returncode=0)

        def _sleep_really(seconds):
            """Take the backoff for real, and mark the arrival index around it.

            The window between the two attempts is bounded by this sleep, not by
            anything inside the fake install: the monitor is stopped and joined in
            the loop's ``finally``, which runs before the backoff starts, and the
            next attempt's monitor starts after it ends. So any callback that
            arrives between these two marks came from a monitor outliving its own
            attempt, and no grace period is needed to say so.

            Only the backoff reaches this seam: it is patched onto
            ``_sleep_between_attempts``, which the install loop calls once per
            gap, while the monitor polls with the module's ``time.sleep``, which
            stays real. So every call here is a backoff and marks the gap; no
            size check is needed to tell a backoff from a monitor tick.
            """
            with lock:
                gap_marks.append(len(records))
            threading.Event().wait(seconds)
            with lock:
                gap_marks.append(len(records))

        with (
            _install_harness(runner, _outcomes) as (installs, _),
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.02),
            # Entered after the harness so this wins: the harness records the
            # interval instead of taking it, and this test needs a real gap
            # between the two attempts to look for callbacks inside.
            patch(
                "automated_security_helper.utils.uv_tool_runner._sleep_between_attempts",
                side_effect=_sleep_really,
            ),
        ):
            runner.install_tool_with_version(
                "bandit",
                timeout=120,
                retry_config=config,
                progress_callback=_record,
            )

        assert len(installs) == 2
        assert len(gap_marks) == 2, (
            f"expected exactly one backoff between attempts: {gap_marks}"
        )
        assert any("attempt 1/2" in m for m in records), (
            "attempt 1 itself must still have been reported on, or the two "
            "assertions below are satisfied by a monitor that never ran"
        )

        arrived_during_backoff = gap_marks[1] - gap_marks[0]
        assert arrived_during_backoff == 0, (
            f"{arrived_during_backoff} callbacks arrived during the backoff "
            f"between the two attempts, so attempt 1's monitor was still running "
            f"through it and reporting elapsed time against an attempt that had "
            f"already failed. At the 0.02s cadence a monitor that ran the whole "
            f"0.4s gap delivers about twenty"
        )
        reported_after_attempt_one = [
            m for m in records[gap_marks[0] :] if "attempt 1/2" in m
        ]
        assert reported_after_attempt_one == [], (
            f"attempt 1 had already failed, and {len(reported_after_attempt_one)} "
            f"callbacks still named it: {reported_after_attempt_one}. This is the "
            f"property the count above approximates, asserted on the message "
            f"instead of on a wall-clock window"
        )

    def test_a_short_timeout_still_starts_no_monitor(self, runner):
        """Positive control on the gate: 60 seconds or less means no monitor.

        The threshold is unchanged; a restructure that started monitoring for
        every install would flood short callers that never saw a callback before.
        """
        records: list = []

        with (
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.02),
            _install_harness(runner, lambda n: MagicMock(returncode=0)) as (
                installs,
                _,
            ),
        ):
            runner.install_tool_with_version(
                "bandit", timeout=60, progress_callback=records.append
            )
            threading.Event().wait(0.2)

        assert len(installs) == 1
        assert records == []

    def test_the_message_is_unchanged_when_there_is_only_one_attempt(self, runner):
        """No retry policy means no attempt numbering, byte for byte as before.

        Callers that never asked for retries are the only ones that ever saw this
        string, so it must not grow a counter that always reads 1/1.
        """
        records: list = []

        def _slow_success(attempt_number):
            threading.Event().wait(0.1)
            return MagicMock(returncode=0)

        with (
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.02),
            _install_harness(runner, _slow_success) as (installs, _),
        ):
            runner.install_tool_with_version(
                "bandit", timeout=120, progress_callback=records.append
            )

        assert len(installs) == 1
        assert records, "a 120s timeout with a callback must be monitored"
        assert all(
            re.fullmatch(r"Installation in progress\.\.\. \(\d+s elapsed\)", m)
            for m in records
        ), records

    def test_a_retried_install_names_the_attempt_in_its_message(self, runner):
        """With a retry policy the figure needs an anchor the caller can read."""
        records: list = []
        config = UVToolRetryConfig(
            max_retries=1, base_delay=0.0, max_delay=0.0, jitter=False
        )

        def _fails_then_succeeds(attempt_number):
            threading.Event().wait(0.1)
            if attempt_number == 1:
                return subprocess.CalledProcessError(
                    1, ["uv", "tool", "install"], "", "Connection reset by peer"
                )
            return MagicMock(returncode=0)

        with (
            patch.object(uv_tool_runner, "_PROGRESS_UPDATE_INTERVAL_SECONDS", 0.02),
            _install_harness(runner, _fails_then_succeeds) as (installs, _),
        ):
            runner.install_tool_with_version(
                "bandit",
                timeout=120,
                retry_config=config,
                progress_callback=records.append,
            )

        assert len(installs) == 2
        assert any("attempt 1/2" in m for m in records), records
        assert any("attempt 2/2" in m for m in records), records


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
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="checkov 3.0\n")
            assert runner.get_installed_tool_version("bandit") is None

    def test_returns_version_when_installed(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
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


@pytest.fixture
def an_executable(tmp_path):
    """A real executable file, for tests of the memos: a remembered path is
    answered only while it is still an executable file."""

    def make(name):
        path = tmp_path / name
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
        return str(path)

    return make


class TestFindUvOrNone:
    """Tests for find_uv_or_none's PATH branch.

    The uv installed with ASH is looked up first (test_uv_installed_with_ash.py);
    these pin it absent so they keep testing the search that follows it.
    """

    @pytest.fixture(autouse=True)
    def _no_uv_installed_with_ash(self, monkeypatch):
        monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: None)

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
            return_value=UV_PATH,
        ):
            assert find_uv_or_none() == UV_PATH

    def test_memoizes_result(self, reset_module_caches, an_executable):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=an_executable("uv"),
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

    def test_memoizes_result(self, reset_module_caches, an_executable):
        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=an_executable("bandit"),
        ) as mock_find:
            find_executable("bandit")
            find_executable("bandit")
            assert mock_find.call_count == 1


class TestGetUvToolCommand:
    """Tests for get_uv_tool_command."""

    def test_returns_uv_form_when_probe_succeeds(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="bandit 1.7\n", stderr=""
            )
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["uv", "tool", "run", "bandit"]
            assert mock_run.call_count == 1

    @pytest.mark.parametrize("offline", [True, False])
    def test_probe_honors_offline_mode(self, reset_module_caches, monkeypatch, offline):
        """Under ASH_OFFLINE the probe must not resolve the tool from PyPI.

        Online, it downloaded bandit and checkov during `ash scan --mode nix` and
        could be killed mid-download by its 5s timeout, leaving uv's cache with
        an index entry and no wheel.
        """
        if offline:
            monkeypatch.setenv("ASH_OFFLINE", "YES")
        else:
            monkeypatch.delenv("ASH_OFFLINE", raising=False)
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="bandit 1.7\n", stderr=""
            )
            get_uv_tool_command("bandit")
        probe = mock_run.call_args
        if offline:
            assert probe.args[0] == [
                UV_PATH,
                "tool",
                "run",
                "--offline",
                "bandit",
                "--version",
            ]
            assert probe.kwargs["env"]["UV_OFFLINE"] == "1"
        else:
            assert probe.args[0] == [
                UV_PATH,
                "tool",
                "run",
                "bandit",
                "--version",
            ]
            # An explicit copy of the environment, never None: see
            # utils/process_env.py. Compared by names, so a failure prints no value.
            assert probe.kwargs["env"] is not None
            assert differing_names(probe.kwargs["env"], os.environ) == []

    def test_falls_back_to_direct_binary_when_uv_probe_fails(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value="/usr/local/bin/bandit",
            ),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="not found"
            )
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]
            mock_run.assert_called_once()

    def test_falls_back_to_direct_binary_when_uv_missing(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value="/usr/local/bin/bandit",
            ),
        ):
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]

    def test_returns_none_when_neither_works(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            assert get_uv_tool_command("bandit") is None

    def test_handles_uv_probe_subprocess_error(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain",
                side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=30),
            ) as mock_run,
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value="/usr/local/bin/bandit",
            ),
        ):
            cmd = get_uv_tool_command("bandit")
            assert cmd == ["/usr/local/bin/bandit"]
            mock_run.assert_called_once()

    def test_uses_fallback_binary_override(self, reset_module_caches):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
            ) as mock_find,
        ):
            mock_find.return_value = "/usr/local/bin/detect-secrets"
            cmd = get_uv_tool_command(
                "detect-secrets", fallback_binary="detect-secrets"
            )
            assert cmd == ["/usr/local/bin/detect-secrets"]
            mock_find.assert_called_once_with("detect-secrets")

    def test_memoizes_result_no_re_probe(self, reset_module_caches, an_executable):
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=an_executable("uv"),
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok\n", stderr=""
            )
            first = get_uv_tool_command("bandit")
            second = get_uv_tool_command("bandit")
            assert first == second == ["uv", "tool", "run", "bandit"]
            assert mock_run.call_count == 1

    def test_a_miss_with_no_uv_to_probe_is_looked_up_again(self, reset_module_caches):
        """Nothing was probed, so a None is not remembered: a tool installed
        after this lookup is found by the next."""
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ) as mock_find,
        ):
            assert get_uv_tool_command("bandit") is None
            assert get_uv_tool_command("bandit") is None
            assert mock_find.call_count == 2

    def test_memoizes_a_failed_probe(self, reset_module_caches):
        """A None after a probe is remembered: the probe is not run again."""
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_executable",
                return_value=None,
            ),
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="not found"
            )
            assert get_uv_tool_command("bandit") is None
            assert get_uv_tool_command("bandit") is None
            assert mock_run.call_count == 1


class TestGetUvToolCommandThreadSafety:
    """Concurrency tests for the module-level cache (an earlier review finding).

    Twenty threads race on the same cache key with a slow probe. The single
    shared lock around the cache guarantees:

    1. The probe subprocess is invoked exactly once.
    2. Every thread observes the same return value.
    3. No ``None`` value ever leaks to a caller during the racing window.
    """

    def test_probe_runs_exactly_once_under_thread_race(
        self, reset_module_caches, an_executable
    ):
        import threading
        import time

        uv = an_executable("uv")

        call_count = {"n": 0}
        call_lock = threading.Lock()

        def slow_probe(*_args, **_kwargs):
            # Simulate a real subprocess that takes long enough for other
            # threads to pile up at the cache. Without the cache lock, all
            # 20 would launch their own probe.
            with call_lock:
                call_count["n"] += 1
            time.sleep(0.05)
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="bandit 1.7\n", stderr=""
            )

        results: list = []
        none_observations: list = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(20)

        def worker():
            barrier.wait()  # Maximize the race window.
            cmd = get_uv_tool_command("bandit")
            with results_lock:
                results.append(cmd)
                if cmd is None:
                    none_observations.append(cmd)

        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=uv,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain",
                side_effect=slow_probe,
            ),
        ):
            threads = [threading.Thread(target=worker) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        # 1. Probe ran exactly once across the racing window.
        assert call_count["n"] == 1, (
            f"expected exactly one probe call, got {call_count['n']}"
        )
        # 2. All threads observed the same successful result.
        assert len(results) == 20
        expected = ["uv", "tool", "run", "bandit"]
        assert all(r == expected for r in results), results
        # 3. No transient ``None`` leak.
        assert none_observations == [], (
            f"unexpected None leak during racing window: {none_observations}"
        )

    def test_probe_uses_5s_timeout(self, reset_module_caches):
        """The version probe timeout is 5 s, not 30 s (an earlier review finding)."""
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="ok\n", stderr=""
            )
            get_uv_tool_command("bandit")
            assert mock_run.call_count == 1
            _, kwargs = mock_run.call_args
            assert kwargs.get("timeout") == 5, (
                f"expected 5 s probe timeout, got {kwargs.get('timeout')}"
            )


class TestGetToolVersionRunsOneProcessPerTool:
    """``get_tool_version`` must spawn ONE process per tool, however many ask.

    Why this is a correctness test and not a performance test: the probe *runs
    the tool*, and a stevedore-based tool builds a shared per-user entry-point
    cache at ``$XDG_CACHE_HOME/python-entrypoints/<digest>`` on first import.
    stevedore writes it with a truncating ``open(path, 'w')`` and no lock, and
    orders the JSON by iterating a set -- so two processes emit equal-length,
    different-content streams that interleave at the 8 KiB flush boundary. The
    spliced file can still parse while holding an entry whose arity is not 3,
    and then EVERY later reader dies in ``stevedore/_cache.py`` with
    ``TypeError: EntryPoint.__init__()``.

    ASH builds one scanner per project and each construction probed the
    version, so an N-project workspace scan fired N concurrent cold-start
    imports of the same tool -- N writers racing on one file. One probe per
    tool means one writer, so no splice is possible. Regression test for #542.
    """

    def test_concurrent_callers_spawn_exactly_one_subprocess(self, runner):
        import threading
        import time

        runner._uv_available_cache = True
        calls = {"n": 0}
        calls_lock = threading.Lock()

        def slow_probe(*_args, **_kwargs):
            with calls_lock:
                calls["n"] += 1
            time.sleep(0.05)  # Let the other threads pile up on the cache.
            return MagicMock(returncode=0, stdout="bandit 1.9.4\n")

        seen: list = []
        seen_lock = threading.Lock()
        barrier = threading.Barrier(12)

        def worker():
            barrier.wait()  # Maximize the race window.
            version = runner.get_tool_version("bandit")
            with seen_lock:
                seen.append(version)

        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=slow_probe,
        ):
            threads = [threading.Thread(target=worker) for _ in range(12)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        assert calls["n"] == 1, (
            "the tool must be imported once, not once per caller: "
            f"{calls['n']} concurrent cold-start processes would race "
            "stevedore's entry-point cache write"
        )
        assert seen == ["bandit 1.9.4"] * 12

    def test_distinct_tools_are_not_serialized_into_one_probe(self, runner):
        """Per-key, not global: two different tools still get their own probe."""
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.0\n")
            runner.get_tool_version("bandit")
            runner.get_tool_version("checkov")
            assert mock_run.call_count == 2

    def test_invalidation_matches_a_tool_whose_command_is_not_its_package(self, runner):
        """The key-shape the previous invalidator missed entirely.

        A memo key is "<command>::<from-spec>", but the name reaching
        install_tool_with_version is ``uv_tool_package_name or command``. For
        JupyterConverter those differ -- command 'jupyter-nbconvert', package
        'nbconvert' -- so a prefix match on the package name cleared nothing:
        "jupyter-nbconvert::nbconvert".startswith("nbconvert::") is False. The
        pre-install None then survived the install meant to invalidate it, and
        tool_version stayed None forever after a *successful* install.

        The earlier test could not catch this: it invalidated by the same name it
        probed with and passed no package_name, which is the one shape where
        command and package coincide -- the shape that already worked.
        """
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("jupyter-nbconvert", "nbconvert") is None
            assert mock_run.call_count == 1

            # The installer knows this tool as 'nbconvert'.
            invalidate_tool_version_cache("nbconvert")

            mock_run.return_value = MagicMock(returncode=0, stdout="7.16.6\n")
            assert runner.get_tool_version("jupyter-nbconvert", "nbconvert") == "7.16.6"
            assert mock_run.call_count == 2

    def test_invalidation_matches_a_from_spec_carrying_extras(self, runner):
        """Keys hold the whole --from spec, so equality on the bare name is not enough."""
        runner._uv_available_cache = True
        spec = "bandit[sarif,toml]>=1.7.0,<2.0.0"
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("bandit", spec) is None

            invalidate_tool_version_cache("bandit")

            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            assert runner.get_tool_version("bandit", spec) == "bandit 1.9.4"
            assert mock_run.call_count == 2

    def test_a_real_install_invalidates_through_install_tool_with_version(self, runner):
        """End to end through the wiring, not just the invalidator in isolation.

        install_tool_with_version is the single function every install path
        funnels through, so the invalidation belongs there -- but being in the
        right place does not help if the installer and the memo derive their keys
        from different variables, which is exactly what went wrong.
        """
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("jupyter-nbconvert", "nbconvert") is None

        with (
            patch.object(runner, "is_tool_installed", return_value=False),
            patch(
                "automated_security_helper.core.constants.is_offline_mode",
                return_value=False,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils.find_executable",
                return_value=None,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            # The installer's own name for this tool is the package name.
            assert runner.install_tool_with_version("nbconvert") is True

        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="7.16.6\n")
            assert (
                runner.get_tool_version("jupyter-nbconvert", "nbconvert") == "7.16.6"
            ), "the install did not clear the pre-install None"

    def test_installing_a_tool_forgets_its_remembered_version(self, runner):
        """An install is what makes a memoized version wrong, so it invalidates.

        Without this, a caller that probes, installs, then re-reads the version
        (the converters do exactly that) would keep the pre-install answer.
        """
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.7.0\n")
            assert runner.get_tool_version("bandit") == "bandit 1.7.0"
            # Cached: no second process.
            assert runner.get_tool_version("bandit") == "bandit 1.7.0"
            assert mock_run.call_count == 1

            invalidate_tool_version_cache("bandit")

            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            assert runner.get_tool_version("bandit") == "bandit 1.9.4"
            assert mock_run.call_count == 2


class TestAMemoizedFailureIsRecoverable:
    """A failed probe is cached, so it must be forcibly refreshable.

    Caching failures is deliberate -- caching only successes would reopen the
    concurrent-probe window on exactly the path where a slow cold start makes it
    most likely. The cost is that one transient failure is then served
    process-wide: a cold probe that exceeds the subprocess ceiling caches None,
    and every consumer afterwards reports uv_version None and
    is_functional False for a tool that works.

    That compounds -- a non-functional result sends the mixin into
    "Proceeding with reinstallation", install_tool_with_version returns True
    early because the tool IS installed, so no install and therefore no
    invalidation runs and the poison is never cleared. For a security scanner a
    report that omits the version of the tool that produced the findings is a
    provenance defect. So validate_cached_tool forces a re-probe.
    """

    def test_a_timeout_is_memoized_and_served_to_later_callers(self, runner):
        """Documents the caching that makes the refresh below necessary."""
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ) as mock_run:
            assert runner.get_tool_version("bandit") is None
            assert runner.get_tool_version("bandit") is None
            assert mock_run.call_count == 1

    def test_validate_cached_tool_re_probes_past_a_memoized_failure(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ):
            assert runner.get_tool_version("bandit") is None

        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            result = runner.validate_cached_tool("bandit")

        assert result["is_functional"] is True, (
            "a tool that works must not be reported broken because an earlier "
            "probe timed out"
        )
        assert result["version"] == "bandit 1.9.4"

    def test_the_refresh_overwrites_the_memo_for_everyone(self, runner):
        """Recovery must be shared, not private to the refreshing caller."""
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ):
            assert runner.get_tool_version("bandit") is None

        with patch(
            "automated_security_helper.utils.subprocess_utils._run_plain"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            runner.validate_cached_tool("bandit")
            # No further subprocess: the good answer replaced the poisoned one.
            assert runner.get_tool_version("bandit") == "bandit 1.9.4"
            assert mock_run.call_count == 1


class TestProbeLocksAreNamespaced:
    """The two probes must not share a lock object.

    Before the keys were namespaced, get_tool_version keyed on
    "<tool>::<package>" and get_uv_tool_command on "<tool>::<fallback_binary>",
    so get_tool_version("bandit", "bandit") and get_uv_tool_command("bandit")
    both produced "bandit::bandit". These are non-reentrant threading.Lock, so
    sharing one is a deadlock waiting for a refactor that makes either call into
    the other. Today the version probe keys on "version::<tool>" (the tool alone,
    see the second test) and the command probe on
    "command::<tool>::<fallback_binary>::<environment>".
    """

    def test_the_two_probes_use_different_lock_keys(self, runner):
        """Observed at call time, not by inspecting the registry afterwards.

        ``_uv_tool_probe_locks`` is a WeakValueDictionary, so every lock is
        collected as soon as the call that held it returns -- reading the keys
        after the fact finds an empty mapping regardless of what happened.
        """
        import automated_security_helper.utils.uv_tool_runner as mod

        real = mod._get_or_create_probe_lock
        seen: list = []

        def recording(cache_key):
            seen.append(cache_key)
            return real(cache_key)

        runner._uv_available_cache = True
        with (
            patch.object(mod, "_get_or_create_probe_lock", recording),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.9.4\n", stderr=""
            )
            # Two specs of one tool, so that a key built from the package ("bandit"
            # and the spec below) would tell them apart and a key built from the
            # tool does not. Each spec has its own memo, so each takes the lock.
            runner.get_tool_version("bandit", "bandit")
            runner.get_tool_version("bandit", "bandit[sarif,toml]>=1.7.8,<2.0.0")
            with patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value=UV_PATH,
            ):
                get_uv_tool_command("bandit")

        # The version probe's lock is keyed by the TOOL alone, so two spec keys
        # of one tool take ONE lock (the next test pins it): they can resolve to
        # the same installed environment, and locking them apart reopened the
        # first-import race the lock exists to close. How many environments a
        # ``--from`` spec can name is ``_uv_from_spec``'s separate question.
        assert seen.count("version::bandit") == 2, seen
        assert not any(key.startswith("version::bandit[") for key in seen), seen
        # The command probe's key goes on to name the environment it was made in.
        assert any(key.startswith("command::bandit::bandit::") for key in seen), seen
        # The collision the namespacing exists to prevent.
        assert "bandit::bandit" not in seen
        assert len(set(seen)) == 2

    def test_two_spec_keys_of_one_tool_share_the_version_lock(self, runner):
        """The version lock is keyed by the TOOL, not by the tool::spec memo key.

        ``bandit`` and ``bandit==1.9.4`` are two memo keys that resolve to one
        installed environment, and probing them under two locks reopened the
        first-import race the lock exists to close. So both calls must take the
        same lock, ``version::bandit``, while their memos stay apart (the second
        call still probes, which is what the two subprocess runs show). A key
        that carried the spec, ``version::bandit::bandit==1.9.4``, fails the
        equality below.
        """
        import automated_security_helper.utils.uv_tool_runner as mod

        real = mod._get_or_create_probe_lock
        seen: list = []

        def recording(cache_key):
            seen.append(cache_key)
            return real(cache_key)

        runner._uv_available_cache = True
        with (
            patch.object(mod, "_get_or_create_probe_lock", recording),
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain"
            ) as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.9.4\n", stderr=""
            )
            runner.get_tool_version("bandit", "bandit")
            runner.get_tool_version("bandit", "bandit==1.9.4")

        assert seen == ["version::bandit", "version::bandit"], seen
        # Two memo keys, so the second call probed again rather than reading the
        # first call's answer: the lock is shared, the memo is not.
        assert mock_run.call_count == 2


class TestRunToolContract:
    """What run_tool's callers rely on, pinned against the real method.

    The jupyter converter runs nbconvert through ``run_tool`` with no
    ``results_dir``, so these pin that branch: a mock accepting any keyword
    could not show that ``quiet=`` is taken, and only the real method shows
    where the scan's cancel goes.
    """

    def test_quiet_rides_the_command_and_is_off_by_default(self, runner, monkeypatch):
        monkeypatch.setattr(runner, "is_uv_available", lambda: True)
        commands = []

        def spawn(command, **kwargs):
            commands.append([str(part) for part in command])
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(uv_tool_runner, "spawn_run", spawn)

        result = runner.run_tool(
            "nbconvert",
            package_name="nbconvert>=7.16.0,<8.0.0",
            args=["--help"],
            quiet=True,
        )
        assert result.returncode == 0
        # uv takes --quiet only between "run" and the tool: after the tool's
        # name it would ride into nbconvert's own arguments.
        assert commands[0][:4] == ["uv", "tool", "run", "--quiet"], commands[0]
        assert commands[0].index("--quiet") < commands[0].index("nbconvert")

        runner.run_tool(
            "nbconvert", package_name="nbconvert>=7.16.0,<8.0.0", args=["--help"]
        )
        assert "--quiet" not in commands[1], commands[1]

    def test_the_scans_cancel_passes_through_unread(self, runner, monkeypatch):
        """With no results_dir the run goes through spawn_run, which raises
        ScanCancelled inside a cancelled scan. run_tool reads nothing into it:
        it reaches the caller as the scan's own stop, never as a run result."""
        from automated_security_helper.core.cancellation import ScanCancelled

        monkeypatch.setattr(runner, "is_uv_available", lambda: True)

        def cancelled(command, **kwargs):
            raise ScanCancelled("the server is stopping")

        monkeypatch.setattr(uv_tool_runner, "spawn_run", cancelled)

        with pytest.raises(ScanCancelled):
            runner.run_tool(
                "nbconvert", package_name="nbconvert>=7.16.0,<8.0.0", args=["--help"]
            )


def test_a_timeouts_token_matches_subprocess_utils_for_any_value():
    """The timed-out message quotes the timeout as the caller gave it. Python's
    general float format turns 1000000 into '1e+06', which reads as a corrupted
    value in a message meant for a person, and a second copy of the token
    builder is free to drift from the one subprocess_utils' own messages use."""
    from automated_security_helper.utils import subprocess_utils

    assert uv_tool_runner._timeout_token(1000000) == "'1000000' s"
    for value in (60, 60.0, 0.5, 1800, None, 1000000, 1234567.5):
        assert uv_tool_runner._timeout_token(value) == subprocess_utils._timeout_token(
            value
        ), value


def _pin_posix_signal_gate(monkeypatch):
    """Make subprocess_utils read the platform as POSIX for one test.

    ``signal_death`` reads a negative returncode as a signal only off Windows
    (``os.name != "nt"``), and ``_exit_description`` takes that gate. A test
    that asserts the signal wording therefore reads the POSIX side of the gate;
    without the pin it fails on a Windows host, where -9 is the process's own
    exit status and the message says "exited -9". The ``os`` seen by
    subprocess_utils is replaced by a stand-in whose ``name`` is "posix" and
    whose every other attribute is the real module's (the same shape the
    Windows-side test uses with "nt").
    """
    from automated_security_helper.utils import subprocess_utils as spu

    class _PosixOs:
        name = "posix"

        def __getattr__(self, attribute):
            return getattr(os, attribute)

    monkeypatch.setattr(spu, "os", _PosixOs())
    assert spu.signal_death(-9, "x") is not None, (
        "the platform gate was not taken: signal_death read -9 as an exit"
    )


class TestARefusedRequirementIsLoggedWithoutItsText:
    """The runner's two requirement refusals name the tool, never the spec.

    The runner is shared by every plugin and holds no config, so it cannot
    tell which part of a spec a config read from the environment. A plugin
    that builds its constraint from such a value and hands it over would have
    the value logged verbatim if the refusal quoted the spec; the refusal's
    text therefore carries no part of it, and the tool's name comes from the
    caller's own argument, which is plugin code, not configuration."""

    CANARY = "~~9.9.9rc777"

    @pytest.fixture
    def runner(self, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        built = UVToolRunner(uv_executable="/nonexistent-ash-test/uv")
        with (
            patch.object(built, "is_uv_available", return_value=True),
            patch.object(built, "is_tool_installed", return_value=False),
        ):
            yield built

    @pytest.fixture
    def logged(self):
        import logging

        from automated_security_helper.utils.log import ASH_LOGGER

        class _Lines(logging.Handler):
            def __init__(self):
                super().__init__(level=logging.DEBUG)
                self.lines: list = []

            def emit(self, record):
                self.lines.append(record.getMessage())

        handler = _Lines()
        level = ASH_LOGGER.level
        ASH_LOGGER.addHandler(handler)
        ASH_LOGGER.setLevel(logging.DEBUG)
        try:
            yield handler.lines
        finally:
            ASH_LOGGER.removeHandler(handler)
            ASH_LOGGER.setLevel(level)

    def test_the_install_refusal_logs_the_tool_and_no_constraint_text(
        self, runner, logged
    ):
        assert (
            runner.install_tool_with_version("bandit", version_constraint=self.CANARY)
            is False
        )
        joined = "\n".join(logged)
        # The controls: the refusal ran and names the tool.
        assert "Refusing to pass" in joined, joined
        assert "bandit" in joined, joined
        assert "9.9.9rc777" not in joined, joined

    def test_the_version_refusal_logs_the_tool_and_no_constraint_text(
        self, runner, logged
    ):
        assert (
            runner.get_tool_version("bandit", package_name=f"bandit{self.CANARY}")
            is None
        )
        joined = "\n".join(logged)
        assert "Refusing to pass" in joined, joined
        assert "bandit" in joined, joined
        assert "9.9.9rc777" not in joined, joined

    def test_the_check_still_refuses_and_its_text_holds_no_spec(self):
        with pytest.raises(UVToolRunnerError) as refused:
            uv_tool_runner.checked_requirement(f"bandit{self.CANARY}")
        message = str(refused.value)
        assert "Refusing to pass" in message, message
        assert "9.9.9rc777" not in message, message
        assert "bandit" not in message, message

    def test_the_install_refusal_names_which_with_dependency(self, runner, logged):
        """A refused install can hold three requirements: the tool spec and
        each --with dependency. The log names the position of the one that
        was refused, in fixed value-free words, so the operator knows which
        entry to fix without the spec itself ever being quoted."""
        assert (
            runner.install_tool_with_version(
                "bandit",
                with_dependencies=[
                    "bandit-sarif-formatter",
                    f"extra{self.CANARY}",
                ],
            )
            is False
        )
        joined = "\n".join(logged)
        assert "Refusing to pass" in joined, joined
        assert "--with dependency 2" in joined, joined
        assert "9.9.9rc777" not in joined, joined

    def test_the_run_refusal_names_the_tool(self, runner):
        """run_tool's --from specs were checked with the bare refusal, which
        raised with no tool name at all: the only caller-facing text said a
        requirement was refused, naming nothing to act on. The raise carries
        the tool's name (the runner's own argument) and the --from position,
        and still none of the spec."""
        with pytest.raises(UVToolRunnerError) as refused:
            runner.run_tool("bandit", package_name=f"bandit{self.CANARY}")
        message = str(refused.value)
        assert "Refusing to pass" in message, message
        assert "bandit" in message, message
        assert "--from" in message, message
        assert "9.9.9rc777" not in message, message

    def test_the_run_exit_error_quotes_no_argv_or_stderr(self, runner, tmp_path):
        """run_tool's non-zero-exit raise stringified a CalledProcessError,
        whose str quotes the whole argv including the --from spec, which can
        hold a value a plugin's config read from the environment. The raise
        names the exit code and the command's fixed shape instead, and uv's
        stderr, which repeats the requirement it could not satisfy, never
        rides."""
        secret = "==9.9.9rc777"

        def refuses_to_resolve(*args, **kwargs):
            return {
                "returncode": 2,
                "stdout": "",
                "stderr": f"no version of bandit{secret}",
            }

        with patch(
            "automated_security_helper.utils.subprocess_utils."
            "run_command_with_output_handling",
            side_effect=refuses_to_resolve,
        ):
            with pytest.raises(UVToolRunnerError) as raised:
                runner.run_tool(
                    "bandit",
                    package_name=f"bandit{secret}",
                    check=True,
                    results_dir=tmp_path,
                )
        message = str(raised.value)
        assert secret not in message, message
        assert "the command exited 2" in message, message
        assert "(uv tool run bandit, arguments not shown)" in message, message

    @pytest.mark.parametrize(
        ("response", "expected", "never"),
        [
            pytest.param(
                {"returncode": -11},
                "was ended by signal 11",
                "exited",
                id="signal",
            ),
            pytest.param(
                {"returncode": 124, "timed_out": True, "error": "timed out"},
                "the command timed out",
                "exited",
                id="timeout",
            ),
            pytest.param(
                {"returncode": None, "error": "stop refused"},
                "the command did not exit",
                "None",
                id="no-exit",
            ),
            pytest.param(
                {"returncode": 3},
                "the command exited 3",
                "signal",
                id="plain-exit",
            ),
            pytest.param(
                {"returncode": 1, "cancelled": True, "error": "cancelled"},
                "the run was cancelled",
                "exited",
                id="cancelled",
            ),
            pytest.param(
                {"returncode": 1, "result_rejected": True, "error": "rejected"},
                "ASH rejected the tool's result",
                "exited",
                id="result-rejected",
            ),
            pytest.param(
                {"returncode": 127, "spawn_failed": True, "error": "never ran"},
                "the command never started",
                "exited",
                id="spawn-failed",
            ),
        ],
    )
    def test_the_run_exit_error_names_how_the_command_ended(
        self, runner, tmp_path, monkeypatch, response, expected, never
    ):
        """A signal death, a timeout and a child the stop did not end are not
        ordinary exits: "the command exited 124" misreads a timeout, "exited
        None" reads as nonsense, and the old str(CalledProcessError) at least
        said "died with <signal>". Each ending is named by its own value-free
        words.

        The signal case reads the POSIX side of the platform gate: on Windows a
        negative returncode is the process's own exit status, never a signal
        (the test below pins that side), so the gate is pinned to "posix" here
        and the case reads the same on every host."""
        _pin_posix_signal_gate(monkeypatch)

        def returns_response(*args, **kwargs):
            return dict(response)

        with patch(
            "automated_security_helper.utils.subprocess_utils."
            "run_command_with_output_handling",
            side_effect=returns_response,
        ):
            with pytest.raises(UVToolRunnerError) as raised:
                runner.run_tool("bandit", check=True, results_dir=tmp_path)
        message = str(raised.value)
        assert expected in message, message
        assert never not in message, message

    def test_the_fallback_runs_signal_death_is_not_an_exit(self, runner, monkeypatch):
        """The fallback branch sees signal deaths as negative returncodes on
        the raised CalledProcessError; the same value-free naming applies. The
        platform gate is pinned to "posix": on Windows -9 is an exit status."""
        _pin_posix_signal_gate(monkeypatch)

        def raises_signal_death(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(-9, cmd, stderr="killed")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=raises_signal_death,
        ):
            with pytest.raises(UVToolRunnerError) as raised:
                runner.run_tool("bandit", check=True)
        message = str(raised.value)
        assert "was ended by signal 9" in message, message
        assert "exited" not in message, message
        assert "(uv tool run bandit, arguments not shown)" in message, message

    def test_a_negative_code_on_windows_is_an_exit_not_a_signal(
        self, runner, monkeypatch, tmp_path
    ):
        """Windows has no signal deaths: a negative returncode there is the
        process's own exit status (an NTSTATUS), so naming it "ended by signal
        11" would invent a signal. _exit_description takes the platform gate
        from signal_death rather than re-implementing ``rc < 0`` without it."""
        from automated_security_helper.utils import subprocess_utils as spu

        class _NtOs:
            """subprocess_utils' ``os`` with name "nt", the rest the real one."""

            name = "nt"

            def __getattr__(self, attribute):
                return getattr(os, attribute)

        monkeypatch.setattr(spu, "os", _NtOs())
        assert spu.signal_death(-11, "x") is None, (
            "the cell shows nothing: the platform gate was not taken"
        )
        with (
            patch.object(runner, "is_uv_available", return_value=True),
            patch(
                "automated_security_helper.utils.subprocess_utils."
                "run_command_with_output_handling",
                side_effect=lambda *args, **kwargs: {"returncode": -11},
            ),
            pytest.raises(UVToolRunnerError) as raised,
        ):
            runner.run_tool("bandit", check=True, results_dir=tmp_path)
        message = str(raised.value)
        assert "the command exited -11" in message, message
        assert "signal" not in message, message

    def test_the_fallback_runs_exit_error_quotes_no_argv_or_stderr(self, runner):
        """The no-results-dir fallback raised uv's CalledProcessError text
        whole: the same argv, through the other branch. Same rule, same
        shape: exit code plus the fixed command name, never the exception's
        own str or stderr."""
        secret = "==9.9.9rc777"

        def raises_called_process_error(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(
                2, cmd, stderr=f"no version of bandit{secret}"
            )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=raises_called_process_error,
        ):
            with pytest.raises(UVToolRunnerError) as raised:
                runner.run_tool("bandit", package_name=f"bandit{secret}", check=True)
        message = str(raised.value)
        assert secret not in message, message
        assert "the command exited 2" in message, message
        assert "(uv tool run bandit, arguments not shown)" in message, message


class TestShownUvOutputOrdersRedactionBeforeTheBound:
    def test_a_value_straddling_the_kept_tails_edge_leaves_no_fragment(self):
        """shown_uv_output redacts BEFORE it bounds. Bounding first keeps the
        RAW text's last _UV_OUTPUT_LIMIT characters, and a value straddling
        that edge survives as a live fragment at the kept tail's start --
        a piece the redaction then cannot match, because it matches whole
        spellings, not pieces. The value here is placed so a bound-first
        order keeps its last seven characters."""
        from automated_security_helper.utils.uv_tool_runner import (
            _UV_OUTPUT_LIMIT,
            shown_uv_output,
        )

        value = "RUNSECRET" + "881777"
        tail = "t" * (_UV_OUTPUT_LIMIT - 7)
        text = f"head text {value}{tail}"
        shown = shown_uv_output(text, (value,))
        assert value not in shown, shown[:120]
        assert "881777" not in shown, shown[:120]
        assert "characters not shown" in shown, shown[:120]


class TestBuiltinPluginEnvironmentReadsAreAudited:
    """shown_uv_output's origin filter rests on a contract no production code
    path enforces: ``values`` is the run's COMPLETE env-read set, so a plugin
    that reads os.environ itself must contribute the value through
    _environment_values(), or keep the read's value out of the inputs it
    builds -- otherwise that input fails the holds-a-value filter and prints
    at DEBUG, value included. The hide-all ``values is None`` branch never
    runs in production (_install_uv_tool always passes _values_to_redact()),
    so until now the contract was held by review alone. This audit makes it
    measured: every direct environment read in the builtin plugin modules is
    pinned here with the reason it satisfies the contract, and a new or
    removed read fails until its entry is justified or dropped. A flag such
    as ``provenance_checked`` on the call would only rename the trust; the
    audit measures it. The tripwire reads syntax: ``from os import environ``
    and ``import os as X`` are flagged as shapes of their own rather than
    traced, a bare ``os.getenv`` or ``os.environ.get`` reference (rebinding
    without a call) reads as its own shape, and ``os.environb`` counts like
    ``os.environ``. What still slips past it is an indirection the syntax
    does not show -- ``getattr(os, "environ")``, or a helper module exporting
    a read -- which would have to survive review.
    """

    #: (path under plugin_modules/ash_builtin, read shape) -> (count, why the
    #: read satisfies the origin-filter contract).
    _JUSTIFIED = {
        ("scanners/_grep_scanner_base.py", "os.environ.get(<dynamic>)"): (
            2,
            (
                "the grep-family offline rules-cache directory"
                " (cache_dir_env_var()): a path for the tool's own cache,"
                " validated and handed to the scanner child, never a uv"
                " install input"
            ),
        ),
        ("scanners/cdk_nag_scanner.py", 'os.environ.get("JSII_NODE")'): (
            1,
            (
                "the operator's node path for jsii (_jsii_node_value):"
                " contributed through the scanner's _environment_values() so"
                " the run's redaction and shown_uv_output's origin filter both"
                " see it; the dependency check only asks whether it names a"
                " file, and cdk-nag's node is not installed through uv, so it"
                " is never a uv install input"
            ),
        ),
        ("scanners/cfn_nag_scanner.py", 'os.environ.get("RI_DEVKIT")'): (
            1,
            (
                "a presence check only; the value itself is never used, so"
                " nothing of it can print"
            ),
        ),
        ("scanners/cfn_nag_scanner.py", 'os.environ.get("DEVELOPER_DIR")'): (
            1,
            (
                "a filesystem probe for the macOS developer tools"
                " (_macos_developer_tools_present): the value is one candidate"
                " directory tested for usr/bin/clang while the scanner is"
                " constructed; it is never passed to a process or a uv install"
                " input, and nothing of it prints"
            ),
        ),
        ("scanners/_trivy_scanner_base.py", 'os.environ.get("TRIVY_CONFIG")'): (
            1,
            (
                "the operator's trivy config path, anchored and checked by"
                " honored_path and passed to the trivy binary; trivy is not"
                " installed through uv, so it is never a uv install input"
            ),
        ),
        ("scanners/_trivy_scanner_base.py", "os.environ.get(<dynamic>)"): (
            1,
            (
                "the operator's trivy ignore or input file path"
                " (_trivy_input_file), anchored and checked by honored_path"
                " and passed to the trivy binary; never a uv install input"
            ),
        ),
        ("scanners/_trivy_scanner_base.py", 'os.environ.get("TRIVY_IGNOREFILE")'): (
            1,
            (
                "read inside _environment_values itself, so the value joins the"
                " run's redaction set by that call; it is the operator's trivy"
                " ignore file path, passed to the trivy binary; never a uv"
                " install input"
            ),
        ),
        ("scanners/_trivy_scanner_base.py", 'os.environ.get("TRIVY_SECRET_CONFIG")'): (
            1,
            (
                "read inside _environment_values itself, so the value joins the"
                " run's redaction set by that call; it is the operator's trivy"
                " secret config path, passed to the trivy binary; never a uv"
                " install input"
            ),
        ),
        ("scanners/gitleaks_scanner.py", "os.environ.get(<dynamic>)"): (
            1,
            (
                "a presence check over CONFIG_ENV_VARS for the sandbox"
                " warning; only the variable names are logged, never a value"
            ),
        ),
        ("scanners/gitleaks_scanner.py", 'os.environ.get("GITLEAKS_CONFIG")'): (
            1,
            (
                "GITLEAKS_CONFIG as the operator set it (_config_env_value, the"
                " module's one read site): the first run anchors a non-absolute"
                " value and passes it as --config, and the re-scan makes it"
                " absolute for the gitleaks child's environment; gitleaks is"
                " not installed through uv, so it is never a uv install input"
            ),
        ),
        (
            "scanners/semgrep_scanner.py",
            '"SEMGREP_RULES_CACHE_DIR" in os.environ',
        ): (
            1,
            "an offline-mode presence check for the rules cache",
        ),
        (
            "scanners/semgrep_scanner.py",
            'os.environ["SEMGREP_RULES_CACHE_DIR"]',
        ): (
            1,
            (
                "the offline rules path, written into SEMGREP_RULES for the"
                " semgrep child's environment, never a uv install input"
            ),
        ),
    }

    @staticmethod
    def _reads_in(tree: ast.AST) -> list:
        """Every direct environment read in *tree*, as a shape string.

        Shapes: ``os.environ.get(key)``, ``os.environ[key]``,
        ``key in os.environ``, ``os.getenv(key)``, any other attribute of
        os.environ (``os.environ.copy`` would surface as its own shape, and a
        bare ``os.environ.get`` rebinding reads as ``os.environ.get``),
        ``os.environ passed as a value`` for a bare reference, a bare
        ``os.getenv`` reference, the same set over ``os.environb``, and the
        import shapes ``from os import environ/environb/getenv`` and
        ``import os as X``, flagged whole rather than traced. A key that is
        not a string literal reads as ``<dynamic>``.
        """
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def is_os_attr(node, attr: str) -> bool:
            return (
                isinstance(node, ast.Attribute)
                and node.attr == attr
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            )

        def key_of(node) -> str:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return f'"{node.value}"'
            return "<dynamic>"

        reads = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name in ("environ", "environb", "getenv"):
                        reads.append(f"from os import {alias.name}")
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "os" and alias.asname:
                        reads.append(f"import os as {alias.asname}")
                continue
            if is_os_attr(node, "getenv"):
                parent = parents.get(node)
                if isinstance(parent, ast.Call) and parent.func is node:
                    first = parent.args[0] if parent.args else None
                    reads.append(f"os.getenv({key_of(first)})")
                else:
                    reads.append("os.getenv")
                continue
            mapping = next(
                (attr for attr in ("environ", "environb") if is_os_attr(node, attr)),
                None,
            )
            if mapping is None:
                continue
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute):
                call = parents.get(parent)
                if (
                    parent.attr == "get"
                    and isinstance(call, ast.Call)
                    and call.func is parent
                ):
                    first = call.args[0] if call.args else None
                    reads.append(f"os.{mapping}.get({key_of(first)})")
                else:
                    reads.append(f"os.{mapping}.{parent.attr}")
            elif isinstance(parent, ast.Subscript) and parent.value is node:
                reads.append(f"os.{mapping}[{key_of(parent.slice)}]")
            elif isinstance(parent, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops
            ):
                reads.append(f"{key_of(parent.left)} in os.{mapping}")
            else:
                reads.append(f"os.{mapping} passed as a value")
        return reads

    def test_the_read_classifier_sees_every_shape(self):
        """Self-test: the classifier is the audit's instrument, so prove it
        reports each shape before trusting its zero on a real module."""
        tree = ast.parse(
            "import os\n"
            "import os as _os\n"
            "from os import environ, getenv\n"
            'a = os.environ.get("NAME")\n'
            "b = os.environ.get(dynamic)\n"
            'c = os.environ["NAME"]\n'
            'd = "NAME" in os.environ\n'
            'e = os.getenv("NAME")\n'
            "f = os.environ.copy()\n"
            "g = consume(os.environ)\n"
            "h = os.getenv\n"
            "i = os.environ.get\n"
            'j = "NAME" in os.environb\n'
        )
        assert sorted(self._reads_in(tree)) == sorted(
            [
                "import os as _os",
                "from os import environ",
                "from os import getenv",
                'os.environ.get("NAME")',
                "os.environ.get(<dynamic>)",
                'os.environ["NAME"]',
                '"NAME" in os.environ',
                'os.getenv("NAME")',
                "os.environ.copy",
                "os.environ passed as a value",
                "os.getenv",
                "os.environ.get",
                '"NAME" in os.environb',
            ]
        )

    def test_every_builtin_environment_read_is_on_the_justified_list(self):
        root = (
            Path(automated_security_helper.__file__).parent
            / "plugin_modules"
            / "ash_builtin"
        )
        files = sorted(root.rglob("*.py"))
        # Denominator control: an empty or relocated tree must fail, not
        # pass vacuously.
        assert any(file.name == "semgrep_scanner.py" for file in files), files
        found: Counter = Counter()
        for file in files:
            tree = ast.parse(file.read_text(encoding="utf-8"))
            for shape in self._reads_in(tree):
                found[(file.relative_to(root).as_posix(), shape)] += 1
        expected = Counter({key: count for key, (count, _) in self._JUSTIFIED.items()})
        new_reads = found - expected
        assert not new_reads, (
            "new direct environment reads in builtin plugins: "
            f"{dict(new_reads)}. Each read's value must either be"
            " contributed through _environment_values() (so the run's"
            " redaction and shown_uv_output's origin filter both see it) or"
            " provably never flow into a uv install input; add a justified"
            " entry to _JUSTIFIED once that holds."
        )
        stale = expected - found
        assert not stale, (
            f"stale _JUSTIFIED entries (the read is gone): {dict(stale)}."
            " Drop them so the list stays the measured whole."
        )


@pytest.mark.parametrize(
    ("text", "values", "inputs", "hidden", "kept"),
    [
        pytest.param(
            "you require pkg-tool==9.9.9rc777, so resolution failed",
            ["9.9.9rc777"],
            ["pkg-tool==9.9.9rc777"],
            ["9.9.9rc777", "pkg-tool==9.9.9rc777"],
            [],
            id="holds-a-value",
        ),
        pytest.param(
            "Saved pkgqz4b-1.0.tar.gz, and you require pkgqz4b==1.0",
            ["qz4b"],
            ["pkgqz4b==1.0"],
            ["qz4b", "pkgqz4b==1.0"],
            [],
            id="substring-glued",
        ),
        pytest.param(
            "you require bandit==1.8, so resolution failed",
            ["1.8"],
            ["bandit==1.8"],
            ["bandit==1.8"],
            [],
            id="structure-pin",
        ),
        pytest.param(
            "resolving sarif-tools beside bandit==1.8",
            ["1.8"],
            ["bandit==1.8", "sarif-tools"],
            ["bandit==1.8"],
            ["sarif-tools"],
            id="non-holding-input-stays",
        ),
        pytest.param(
            "you require bandit>=1.7.4,<2, so resolution failed",
            ["2"],
            ["bandit>=1.7.4,<2"],
            [],
            ["bandit>=1.7.4,<2"],
            id="range-bound-is-not-a-pin",
        ),
    ],
)
def test_each_hiding_arm_decides_one_table_row(text, values, inputs, hidden, kept):
    """One table over the three hiding arms and their boundaries: an input the
    value layer would hide a value inside, a value glued into an input's
    name, a pinned short value, an input holding no value, and a range bound
    that must stay visible."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        text, values, plugin_inputs=inputs, tool_name="bandit", limit=None
    )

    for piece in hidden:
        assert piece not in shown, (piece, shown)
    for piece in kept:
        assert piece in shown, (piece, shown)


def test_the_install_input_builder_names_every_plugin_built_part():
    """One builder for every record ABOUT an install: the full spec, the base
    spec (name with extras, no constraint), the bare constraint, and each
    --with entry -- the parts uv respells and quotes back separately in its
    stderr. A record site assembling its own subset drifts: the mixin's
    install record carried only the spec and the constraint, so the sets
    disagreed about the --with entries. Pointing both sites at the builder
    was STRUCTURAL (the debug line already named the --with entries, and the
    attempt record's lines print only the spec and the constraint); the
    behavior change this cell can catch is the builder's shape itself."""
    from automated_security_helper.utils.uv_tool_runner import uv_install_inputs

    built = uv_install_inputs("bandit", "==9.9", ["toml", "sarif"], ["tomli==9.9"])
    assert built.inputs == (
        "bandit[toml,sarif]==9.9",
        "bandit[toml,sarif]",
        "==9.9",
        "tomli==9.9",
    ), built.inputs
    # The spec uv installs is the builder's own, the record set's first
    # entry: the argv and every record about it are tied to one string.
    assert built.spec == "bandit[toml,sarif]==9.9", built.spec
    assert built.spec == built.inputs[0]
    # Without a constraint the spec IS the base spec, named once, and no
    # empty-string input rides along to confuse the origin arm.
    bare = uv_install_inputs("bandit")
    assert bare.spec == "bandit" and bare.inputs == ("bandit",), bare


def test_an_extra_quoted_without_its_constraint_is_hidden():
    """uv's resolver quotes an extra without its constraint ("Because
    stub-tool[sarifqz4b] depends on sarif-om"), and an extra can hold a glued
    env-read value a third-party plugin's config built in. The bare
    "name[extras]" was no form of the hidden input "stub-tool[sarifqz4b]==1.0",
    so the glued value printed on every text route. The public tool name
    stays visible, and uninvolved text stays whole."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "Because stub-tool[sarifqz4b] depends on sarif-om, resolution failed "
        "for stub-tool",
        ("qz4b",),
        plugin_inputs=("stub-tool[sarifqz4b]==1.0",),
        tool_name="stub-tool",
        limit=None,
    )

    assert "sarifqz4b" not in shown, shown
    assert "qz4b" not in shown, shown
    assert "sarif-om" in shown, shown
    assert "for stub-tool" in shown, shown


def test_a_wheel_file_name_respelling_of_a_hidden_name_is_hidden():
    """Wheel and sdist file names respell "." and "-" in a package name as
    "_" (PEP 427, PEP 625): "pkg.aqz4bb" downloads as
    "pkg_aqz4bb-1.0-py3-none-any.whl". Neither the as-written nor the PEP
    503 name token matches that spelling, and the glued value "qz4b" sits
    inside one word, below the value layer's reach. The "_" form is a name,
    so the boundary rules hold: "pyproject.toml" around a hidden "toml"
    stays whole."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "Downloading pkg_aqz4bb-1.0-py3-none-any.whl (1.2MiB)",
        ("qz4b",),
        plugin_inputs=("pkg.aqz4bb==1.0",),
        tool_name="stub-tool",
        limit=None,
    )
    assert "pkg_aqz4bb" not in shown, shown
    assert "qz4b" not in shown, shown
    assert "Downloading" in shown, shown

    # The boundary control: a hidden name's "_" form must not mangle a word
    # that merely contains the name.
    control = shown_uv_output(
        "wrote pyproject.toml for the build",
        ("qz4b",),
        plugin_inputs=("toml==1.0qz4b",),
        tool_name="stub-tool",
        limit=None,
    )
    assert "pyproject.toml" in control, control


def test_a_two_extra_spec_quoted_as_written_is_hidden():
    """``requirement.extras`` is a set, so only a SORTED gluing of
    "name[extras]" was a form of the hidden input: a spec written
    "stub-tool[toml,sarifqz4b]" and quoted back as written kept the value
    glued inside its extra. Both orders are forms now; which one a real uv
    prints stays unmeasured, so both are hidden."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    for quoted in ("stub-tool[toml,sarifqz4b]", "stub-tool[sarifqz4b,toml]"):
        shown = shown_uv_output(
            f"Because {quoted} depends on sarif-om, resolution failed",
            ("qz4b",),
            plugin_inputs=("stub-tool[toml,sarifqz4b]==1.0",),
            tool_name="stub-tool",
            limit=None,
        )
        assert "sarifqz4b" not in shown, (quoted, shown)
        assert "qz4b" not in shown, (quoted, shown)
        assert "sarif-om" in shown, (quoted, shown)


def test_a_hidden_inputs_underscore_name_never_replaces_the_tools_module_name():
    """The hidden input's name set carries the wheel-name "_" respelling, and
    the discard of the tool's own name removed only the as-written and
    canonical forms: the tool's module name in a traceback ("No module named
    'detect_secrets'") was then replaced by the input layer, against the rule
    that the tool's name is never replaced by it, and the replacement shifted
    the argument numbering. The pinned value stays hidden."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "ModuleNotFoundError: No module named 'detect_secrets' (pin 1.77rc9)",
        ("1.77rc9",),
        plugin_inputs=("detect-secrets==1.77rc9",),
        tool_name="detect-secrets",
        limit=None,
    )
    assert "detect_secrets" in shown, shown
    assert "1.77rc9" not in shown, shown


def test_the_install_debug_line_hides_a_with_dependency_pinning_a_value(
    monkeypatch, caplog
):
    """uv's resolver stderr quotes --with entries back, and a --with entry can
    pin an env-read value below the value layer's whole-word band ("9.9"):
    only the input-origin arm hides it, so an install debug line whose input
    set drops the --with entries prints the pin in clear. The set comes from
    the one install-input builder."""
    import logging as logging_module

    pin = "9.9"
    with_dep = f"tomli=={pin}"

    def _spawn_run(command, **kwargs):
        raise subprocess.CalledProcessError(
            1, command, output="", stderr=f"no solution: {with_dep} cannot be satisfied"
        )

    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    monkeypatch.setattr(runner, "is_tool_installed", lambda *a, **k: False)
    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    monkeypatch.setattr(
        "automated_security_helper.core.constants.is_offline_mode", lambda: False
    )

    with caplog.at_level(logging_module.DEBUG, logger="ash"):
        with pytest.raises(UVToolRunnerError):
            runner.install_tool_with_version(
                "stub-tool", with_dependencies=[with_dep], values=(pin,)
            )

    line = next((text for text in caplog.messages if "stderr (redacted" in text), None)
    assert line is not None, caplog.messages
    assert "no solution" in line, line
    assert with_dep not in line, line


def test_the_uv_layer_strips_a_non_color_escape_inside_a_value():
    """shown_uv_output stripped only color codes before its layers, so a
    non-color escape inside a value split the match the same way it did on
    the neutral layer. The strip takes every complete escape code."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    value = "EDGESECRET-9912"
    shown = shown_uv_output(
        "uv saw EDGE\x1b[KSECRET-9912 while resolving",
        (value,),
        plugin_inputs=(),
        tool_name="bandit",
        limit=None,
    )

    assert value not in shown, shown
    assert "EDGE" not in shown, shown
    assert "\x1b" not in shown, shown


def test_a_placeholder_is_never_read_as_a_token_by_a_later_replacement():
    """Every plugin-built token is replaced in turn, longest first, with a
    numbered placeholder. A later token made of digits -- the bare pin "1" of
    "pk01==1" -- is also a piece of an earlier placeholder's own text, so it
    was found inside "<argument 1 not shown>" and renumbered it. The
    placeholders are written so that no token can match them, and spelled out
    after the last replacement."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "error: pk01==1 is unsatisfiable",
        None,
        plugin_inputs=("pk01==1",),
        tool_name="stub-tool",
        limit=None,
    )

    assert shown == "error: <argument 1 not shown> is unsatisfiable", shown


def test_a_text_that_uses_up_the_private_marks_still_hides_every_input():
    """The placeholders borrow private-use characters that appear in neither
    the text nor a token. A text that holds every one of them leaves none to
    borrow, and the input is still hidden: the fallback writes the numbered
    placeholders as it goes."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    every_mark = "".join(chr(code) for code in range(0xE000, 0xF900))
    shown = shown_uv_output(
        f"{every_mark} error: pk01==1 is unsatisfiable",
        None,
        plugin_inputs=("pk01==1",),
        tool_name="stub-tool",
        limit=None,
    )

    assert "pk01" not in shown, shown
    assert "<argument" in shown, shown


def test_an_unchecked_installs_output_hides_the_pinned_version_in_a_file_name():
    """Control for the version answer below: by default an input's pinned
    version is hidden where uv prints it inside a wheel or sdist file name."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "Downloading pkg-9.9.9-py3-none-any.whl (1.2MiB)",
        None,
        plugin_inputs=("pkg==9.9.9",),
        tool_name="stub-tool",
        limit=None,
    )

    assert "9.9.9" not in shown, shown
    assert "Downloading" in shown, shown


def test_a_tools_own_version_answer_keeps_its_version_and_hides_the_spec():
    """A tool's ``--version`` line is the answer, not an argument uv printed:
    with ``pinned_versions`` off the pinned version stays in it, while the
    spec the tool echoes back is still hidden."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    shown = shown_uv_output(
        "vtool 1.0 vtool==1.0",
        None,
        plugin_inputs=("vtool==1.0",),
        tool_name="vtool",
        limit=None,
        pinned_versions=False,
    )

    assert shown.startswith("vtool 1.0 "), shown
    assert "==1.0" not in shown, shown


def test_a_value_holding_input_is_hidden_whole_not_only_its_value():
    """The value layer runs before the input arm, so by the time the arm
    looked for a hidden input's own spelling the value inside it already read
    as the value layer's placeholder, and a raw replace of the input found
    nothing: the input's REMAINDER -- here a repository path, elsewhere an
    index URL -- printed around a hidden value, against the contract that an
    input holding a value is hidden, not partly shown. The arm now matches
    the input in that respelled form too. The whole-input case (the input IS
    the value) keeps the value layer's own placeholder: respelling it would
    re-label every hidden value in the text as an argument. The tool's own
    name and uninvolved text stay."""
    from automated_security_helper.utils.uv_tool_runner import shown_uv_output

    host = "example.invalid"
    spec = f"tool @ git+https://{host}/it's-a-spec.git"
    shown = shown_uv_output(
        f"uv tool run --from {spec} tool failed to resolve",
        (host,),
        plugin_inputs=(spec,),
        tool_name="tool",
        limit=None,
    )

    assert host not in shown, shown
    assert "it's-a-spec" not in shown, shown
    assert "git+https" not in shown, shown
    expected = "uv tool run --from <argument 1 not shown> tool failed to resolve"
    assert shown == expected, shown

    whole = shown_uv_output(
        f"index {host} refused the request",
        (host,),
        plugin_inputs=(host,),
        tool_name="tool",
        limit=None,
    )
    assert whole == "index <value> refused the request", whole
