"""Regression tests for base plugin bug fixes.

Bug #194: reporter_plugin.py configure() writes self._config (from medium)
Bug #51: suppression_matcher invalid expiration silently skips (from medium)
Bug #147/148: are_values_equivalent broken list/dict comparison (from medium)
Bug #167: models/core.py expiration validator rewraps semantic error (from medium)

finally:return fixes for reporters (from test_finally_return_fix):
- uv_tool_runner.py :: is_tool_installed
- get_shortest_name.py :: get_shortest_name
- s3_reporter.py :: validate_plugin_dependencies
- cloudwatch_logs_reporter.py :: validate_plugin_dependencies
"""

import inspect
import logging
from datetime import date, timedelta
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bug #194 -- base/reporter_plugin.py:45-51 -- configure() writes self._config
# ---------------------------------------------------------------------------
class TestReporterPluginConfigure:
    """configure() must write self.config, not self._config."""

    def test_configure_sets_public_config(self):
        """After configure(cfg), self.config should be cfg."""
        from automated_security_helper.base.reporter_plugin import ReporterPluginBase

        source = inspect.getsource(ReporterPluginBase.configure)
        # The fix should write self.config = config, not self._config = config
        assert "self.config = config" in source, (
            "configure() must assign to self.config, not self._config"
        )
        assert "self._config" not in source, (
            "configure() must not use self._config"
        )


# ---------------------------------------------------------------------------
# Bug #51 -- suppression_matcher.py:247-251 -- Invalid expiration silently skips
# ---------------------------------------------------------------------------
class TestInvalidExpirationWarnsInsteadOfSilentSkip:
    """A malformed expiration date must log a warning, not silently continue.

    NOTE: This was already fixed by a previous batch. This test verifies
    the fix remains in place.
    """

    def test_invalid_expiration_logs_warning(self, caplog):
        """When expiration is 'not-a-date', a warning must be logged."""
        from automated_security_helper.utils.suppression_matcher import (
            should_suppress_finding,
        )
        from automated_security_helper.models.flat_vulnerability import FlatVulnerability
        from automated_security_helper.utils.log import ASH_LOGGER

        # Build minimal finding
        finding = MagicMock(spec=FlatVulnerability)
        finding.rule_id = "TEST-RULE"
        finding.file_path = "test.py"
        finding.line_start = 1
        finding.line_end = 1

        suppression = MagicMock()
        suppression.rule_id = "TEST-RULE"
        suppression.expiration = "not-a-date"
        suppression.paths = []
        suppression.reason = "test"
        suppression.justification = "test"

        # ASH_LOGGER uses name "ash" and propagate=False, so caplog won't
        # capture it by default. Temporarily enable propagation.
        old_propagate = ASH_LOGGER.propagate
        ASH_LOGGER.propagate = True
        try:
            with caplog.at_level(logging.WARNING, logger="ash"):
                should_suppress_finding(finding, [suppression])
        finally:
            ASH_LOGGER.propagate = old_propagate

        warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Invalid expiration" in m for m in warning_msgs), (
            f"Expected a warning about invalid expiration, got: {warning_msgs}"
        )


# ---------------------------------------------------------------------------
# Bug #147/148 -- are_values_equivalent.py:37-46 -- Broken list/dict comparison
# ---------------------------------------------------------------------------
class TestAreValuesEquivalent:
    """List comparison is broken for duplicates; dict ignores values."""

    def test_list_multiset_different(self):
        """[1,1,2] != [1,2,2] -- different multiplicities."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 1, 2], [1, 2, 2]) is False

    def test_list_multiset_same(self):
        """[1,1,2] == [1,1,2] even if order differs."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 2, 1], [1, 1, 2]) is True

    def test_dict_values_matter(self):
        """{"a": 1} != {"a": 2} -- values must be compared."""
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1}, {"a": 2}) is False

    def test_dict_equal_values(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1, "b": 2}, {"b": 2, "a": 1}) is True

    def test_dict_nested_values(self):
        from automated_security_helper.utils.meta_analysis.are_values_equivalent import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": [1, 2]}, {"a": [1, 2]}) is True
        assert are_values_equivalent({"a": [1, 2]}, {"a": [2, 1]}) is True
        assert are_values_equivalent({"a": [1, 1]}, {"a": [1, 2]}) is False


# ---------------------------------------------------------------------------
# Bug #167 -- models/core.py:83-98 -- except ValueError rewraps semantic error
# ---------------------------------------------------------------------------
class TestExpirationValidatorPreservesMessage:
    """'expiration must be in the future' must not be rewrapped as format error."""

    def test_past_date_gives_future_error(self):
        """A past date should say 'must be in the future', not 'Invalid format'."""
        from automated_security_helper.models.core import AshSuppression

        yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        with pytest.raises(Exception) as exc_info:
            AshSuppression(
                rule_id="R1",
                reason="test",
                justification="test",
                expiration=yesterday,
            )
        # The error should mention "future", not "Invalid format"
        error_str = str(exc_info.value)
        assert "future" in error_str.lower(), (
            f"Expected 'future' in error message, got: {error_str}"
        )

    def test_bad_format_gives_format_error(self):
        """A truly malformed date should give the format error."""
        from automated_security_helper.models.core import AshSuppression

        with pytest.raises(Exception) as exc_info:
            AshSuppression(
                rule_id="R1",
                reason="test",
                justification="test",
                expiration="not-a-date",
            )
        error_str = str(exc_info.value)
        assert "format" in error_str.lower() or "YYYY-MM-DD" in error_str, (
            f"Expected format-related error, got: {error_str}"
        )


# ===========================================================================
# finally:return regression tests (from test_finally_return_fix.py)
# ===========================================================================

# ---------------------------------------------------------------------------
# Site 1: utils/uv_tool_runner.py :: UVToolRunner.is_tool_installed
# ---------------------------------------------------------------------------
def test_is_tool_installed_propagates_uncaught_exception():
    """``is_tool_installed`` catches only ``UVToolRunnerError``.

    Other exceptions raised by ``list_available_tools`` (e.g. ``OSError``
    from a subprocess failure, ``TimeoutExpired``, etc.) must propagate
    instead of being swallowed by ``finally: return``.
    """
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    runner = UVToolRunner()

    with patch.object(
        UVToolRunner, "list_available_tools", side_effect=OSError("disk error")
    ):
        with pytest.raises(OSError, match="disk error"):
            runner.is_tool_installed("some-tool")


def test_is_tool_installed_still_handles_uvtoolrunnererror():
    """The existing handled path must keep working: UVToolRunnerError -> False."""
    from automated_security_helper.utils.uv_tool_runner import (
        UVToolRunner,
        UVToolRunnerError,
    )

    runner = UVToolRunner()

    with patch.object(
        UVToolRunner,
        "list_available_tools",
        side_effect=UVToolRunnerError("uv missing"),
    ):
        assert runner.is_tool_installed("some-tool") is False


def test_is_tool_installed_returns_true_when_listed():
    """Happy path: returns True when the tool is in the installed list."""
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    runner = UVToolRunner()

    with patch.object(
        UVToolRunner, "list_available_tools", return_value=["foo", "bandit"]
    ):
        assert runner.is_tool_installed("bandit") is True
        assert runner.is_tool_installed("missing") is False


# ---------------------------------------------------------------------------
# Site 2: utils/get_shortest_name.py :: get_shortest_name
# ---------------------------------------------------------------------------
def test_get_shortest_name_propagates_oserror_from_cwd(tmp_path):
    """``get_shortest_name`` has no ``except`` clause.

    Before the fix, ``finally: return Path(input).as_posix()`` swallowed
    every exception including ``OSError`` from ``Path.cwd()``. After the
    fix, real errors must reach the caller.
    """
    from automated_security_helper.utils import get_shortest_name as mod

    # Use a real, existing path so the function reaches Path.cwd().
    with patch.object(mod.Path, "cwd", side_effect=OSError("cwd gone")):
        with pytest.raises(OSError, match="cwd gone"):
            mod.get_shortest_name(str(tmp_path))


def test_get_shortest_name_dot_shortcircuit_still_works():
    """Passing ``.`` bypasses the cwd call and must still return ``.``."""
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    assert get_shortest_name(".") == "."


def test_get_shortest_name_nonexistent_path_returns_input():
    """Nonexistent paths short-circuit before any cwd work."""
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    result = get_shortest_name("/definitely/does/not/exist/anywhere/xyzzy-123")
    assert result == "/definitely/does/not/exist/anywhere/xyzzy-123"


# ---------------------------------------------------------------------------
# Site 3: plugin_modules/ash_aws_plugins/s3_reporter.py
#          :: S3Reporter.validate_plugin_dependencies
# ---------------------------------------------------------------------------
def _build_s3_reporter():
    """Build an S3Reporter with minimum config needed to enter the try block."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
    )

    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(
            aws_region="us-east-1",
            bucket_name="test-bucket",
        )
    )
    # Construct without running the full plugin init machinery.
    reporter = S3Reporter.model_construct(config=config)
    reporter.dependencies_satisfied = False
    return reporter


def test_s3_reporter_validate_plugin_dependencies_propagates_baseexception():
    """``validate_plugin_dependencies`` catches ``Exception``, not ``BaseException``.

    ``KeyboardInterrupt`` (BaseException subclass) must propagate so users
    can Ctrl-C out of a hung boto3 call. The old ``finally: return``
    swallowed it and returned ``False`` instead.
    """
    import automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter as mod

    reporter = _build_s3_reporter()

    with patch.object(mod.boto3, "Session", side_effect=KeyboardInterrupt()):
        with pytest.raises(KeyboardInterrupt):
            reporter.validate_plugin_dependencies()


def test_s3_reporter_validate_plugin_dependencies_handles_regular_exception():
    """Regular ``Exception`` subclasses must still be handled -> False."""
    import automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter as mod

    reporter = _build_s3_reporter()

    with patch.object(mod.boto3, "Session", side_effect=RuntimeError("boom")):
        # Suppress plugin logging during the test.
        with patch.object(type(reporter), "_plugin_log", lambda *a, **k: None):
            assert reporter.validate_plugin_dependencies() is False


def test_s3_reporter_validate_plugin_dependencies_returns_false_on_missing_config():
    """Short-circuit path: missing region/bucket returns False without raising."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
        S3ReporterConfig,
        S3ReporterConfigOptions,
    )

    config = S3ReporterConfig(
        options=S3ReporterConfigOptions(aws_region=None, bucket_name=None)
    )
    reporter = S3Reporter.model_construct(config=config)
    reporter.dependencies_satisfied = True  # ensure reset logic zeroes it
    assert reporter.validate_plugin_dependencies() is False


# ---------------------------------------------------------------------------
# Site 4: plugin_modules/ash_aws_plugins/cloudwatch_logs_reporter.py
#          :: CloudWatchLogsReporter.validate_plugin_dependencies
# ---------------------------------------------------------------------------
def _build_cwlogs_reporter():
    from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
        CloudWatchLogsReporter,
        CloudWatchLogsReporterConfig,
        CloudWatchLogsReporterConfigOptions,
    )

    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region="us-east-1",
            log_group_name="ash-log-group",
        )
    )
    reporter = CloudWatchLogsReporter.model_construct(config=config)
    reporter.dependencies_satisfied = False
    return reporter


def test_cwlogs_reporter_validate_plugin_dependencies_propagates_baseexception():
    """Same pattern as the S3 reporter: BaseException must propagate."""
    import automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter as mod

    reporter = _build_cwlogs_reporter()

    with patch.object(mod.boto3, "client", side_effect=KeyboardInterrupt()):
        with pytest.raises(KeyboardInterrupt):
            reporter.validate_plugin_dependencies()


def test_cwlogs_reporter_validate_plugin_dependencies_handles_regular_exception():
    """Regular Exception subclasses are handled by except Exception -> False."""
    import automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter as mod

    reporter = _build_cwlogs_reporter()

    with patch.object(mod.boto3, "client", side_effect=RuntimeError("sts down")):
        with patch.object(type(reporter), "_plugin_log", lambda *a, **k: None):
            assert reporter.validate_plugin_dependencies() is False


def test_cwlogs_reporter_validate_plugin_dependencies_returns_false_on_missing_config():
    """Short-circuit path: missing region/log_group returns False without raising."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
        CloudWatchLogsReporter,
        CloudWatchLogsReporterConfig,
        CloudWatchLogsReporterConfigOptions,
    )

    config = CloudWatchLogsReporterConfig(
        options=CloudWatchLogsReporterConfigOptions(
            aws_region=None, log_group_name=None
        )
    )
    reporter = CloudWatchLogsReporter.model_construct(config=config)
    reporter.dependencies_satisfied = True
    assert reporter.validate_plugin_dependencies() is False
