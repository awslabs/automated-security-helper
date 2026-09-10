"""Tests for utils/uv_tool_runner.py — covers UVToolRunner class methods."""

import subprocess  # nosec B404
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

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


def _always_fails_with_reset(attempt_number):
    """Every attempt dies the way a flaky index does: non-zero exit, no output."""
    return subprocess.CalledProcessError(
        1, ["uv", "tool", "install"], "", "Connection reset by peer"
    )


@contextmanager
def _install_harness(runner, outcome_for_attempt):
    """Reduce ``install_tool_with_version`` to just its own install subprocess.

    ``is_tool_installed`` is stubbed out rather than driven through
    ``subprocess.run`` deliberately: these tests read a *count*, and a count that
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=_run,
        ),
        patch(
            "automated_security_helper.utils.uv_tool_runner.time.sleep",
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
    and what ``time.sleep`` is handed between them. Jitter is off wherever an
    exact interval is asserted, so the schedule is arithmetic rather than a
    range. Nothing here measures wall clock, which would flake low on a fast
    machine and high on a loaded one.
    """

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


class TestGetUvToolCommandThreadSafety:
    """Concurrency tests for the module-level cache (DA r4 #3).

    Twenty threads race on the same cache key with a slow probe. The single
    shared lock around the cache guarantees:

    1. The probe subprocess is invoked exactly once.
    2. Every thread observes the same return value.
    3. No ``None`` value ever leaks to a caller during the racing window.
    """

    def test_probe_runs_exactly_once_under_thread_race(self, reset_module_caches):
        import threading
        import time

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

        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=slow_probe,
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
        """The version probe timeout is 5 s, not 30 s (DA r4 #5)."""
        with patch(
            "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
            return_value="/opt/uv/bin/uv",
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="1.0\n")
            runner.get_tool_version("bandit")
            runner.get_tool_version("checkov")
            assert mock_run.call_count == 2

    def test_invalidation_matches_a_tool_whose_command_is_not_its_package(
        self, runner
    ):
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert (
                runner.get_tool_version("jupyter-nbconvert", "nbconvert") is None
            )
            assert mock_run.call_count == 1

            # The installer knows this tool as 'nbconvert'.
            invalidate_tool_version_cache("nbconvert")

            mock_run.return_value = MagicMock(returncode=0, stdout="7.16.6\n")
            assert (
                runner.get_tool_version("jupyter-nbconvert", "nbconvert") == "7.16.6"
            )
            assert mock_run.call_count == 2

    def test_invalidation_matches_a_from_spec_carrying_extras(self, runner):
        """Keys hold the whole --from spec, so equality on the bare name is not enough."""
        runner._uv_available_cache = True
        spec = "bandit[sarif,toml]>=1.7.0,<2.0.0"
        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert runner.get_tool_version("bandit", spec) is None

            invalidate_tool_version_cache("bandit")

            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            assert runner.get_tool_version("bandit", spec) == "bandit 1.9.4"
            assert mock_run.call_count == 2

    def test_a_real_install_invalidates_through_install_tool_with_version(
        self, runner
    ):
        """End to end through the wiring, not just the invalidator in isolation.

        install_tool_with_version is the single function every install path
        funnels through, so the invalidation belongs there -- but being in the
        right place does not help if the installer and the memo derive their keys
        from different variables, which is exactly what went wrong.
        """
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert (
                runner.get_tool_version("jupyter-nbconvert", "nbconvert") is None
            )

        with patch.object(runner, "is_tool_installed", return_value=False), patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ), patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value=None,
        ), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            # The installer's own name for this tool is the package name.
            assert runner.install_tool_with_version("nbconvert") is True

        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ) as mock_run:
            assert runner.get_tool_version("bandit") is None
            assert runner.get_tool_version("bandit") is None
            assert mock_run.call_count == 1

    def test_validate_cached_tool_re_probes_past_a_memoized_failure(self, runner):
        runner._uv_available_cache = True
        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ):
            assert runner.get_tool_version("bandit") is None

        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
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
            "automated_security_helper.utils.uv_tool_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=15),
        ):
            assert runner.get_tool_version("bandit") is None

        with patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="bandit 1.9.4\n")
            runner.validate_cached_tool("bandit")
            # No further subprocess: the good answer replaced the poisoned one.
            assert runner.get_tool_version("bandit") == "bandit 1.9.4"
            assert mock_run.call_count == 1


class TestProbeLocksAreNamespaced:
    """The two probes must not share a lock object.

    get_tool_version keys on "<tool>::<package>" and get_uv_tool_command on
    "<tool>::<fallback_binary>", so get_tool_version("bandit", "bandit") and
    get_uv_tool_command("bandit") both produced "bandit::bandit". These are
    non-reentrant threading.Lock, so sharing one is a deadlock waiting for a
    refactor that makes either call into the other.
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
        with patch.object(mod, "_get_or_create_probe_lock", recording), patch(
            "automated_security_helper.utils.uv_tool_runner.subprocess.run"
        ) as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="bandit 1.9.4\n", stderr=""
            )
            runner.get_tool_version("bandit", "bandit")
            with patch(
                "automated_security_helper.utils.uv_tool_runner.find_uv_or_none",
                return_value="/opt/uv/bin/uv",
            ):
                get_uv_tool_command("bandit")

        assert "version::bandit::bandit" in seen
        assert "command::bandit::bandit" in seen
        # The collision the namespacing exists to prevent.
        assert "bandit::bandit" not in seen
        assert len(set(seen)) == 2
