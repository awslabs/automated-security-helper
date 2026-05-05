"""Regression tests for base plugin bug fixes.

PR#274 Bug #94: reporter_plugin.py configure() writes self._config (from medium)
PR#274 Bug #41: suppression_matcher invalid expiration silently skips (from medium)
PR#274 Bug #24/148: are_values_equivalent broken list/dict comparison (from medium)
PR#274 Bug #32: models/core.py expiration validator rewraps semantic error (from medium)

finally:return fixes for reporters (from test_finally_return_fix):
- uv_tool_runner.py :: is_tool_installed
- get_shortest_name.py :: get_shortest_name
- s3_reporter.py :: validate_plugin_dependencies
- cloudwatch_logs_reporter.py :: validate_plugin_dependencies
"""

import inspect
import logging
from datetime import date, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


# ---------------------------------------------------------------------------
# PR#274 Bug #94 -- base/reporter_plugin.py:45-51 -- configure() writes self._config
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
# PR#274 Bug #41 -- suppression_matcher.py:247-251 -- Invalid expiration silently skips
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
# PR#274 Bug #24/148 -- are_values_equivalent.py:37-46 -- Broken list/dict comparison
# ---------------------------------------------------------------------------
class TestAreValuesEquivalent:
    """List comparison is broken for duplicates; dict ignores values."""

    def test_list_multiset_different(self):
        """[1,1,2] != [1,2,2] -- different multiplicities."""
        from automated_security_helper.utils.meta_analysis.field_mapping import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 1, 2], [1, 2, 2]) is False

    def test_list_multiset_same(self):
        """[1,1,2] == [1,1,2] even if order differs."""
        from automated_security_helper.utils.meta_analysis.field_mapping import (
            are_values_equivalent,
        )

        assert are_values_equivalent([1, 2, 1], [1, 1, 2]) is True

    def test_dict_values_matter(self):
        """{"a": 1} != {"a": 2} -- values must be compared."""
        from automated_security_helper.utils.meta_analysis.field_mapping import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1}, {"a": 2}) is False

    def test_dict_equal_values(self):
        from automated_security_helper.utils.meta_analysis.field_mapping import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": 1, "b": 2}, {"b": 2, "a": 1}) is True

    def test_dict_nested_values(self):
        from automated_security_helper.utils.meta_analysis.field_mapping import (
            are_values_equivalent,
        )

        assert are_values_equivalent({"a": [1, 2]}, {"a": [1, 2]}) is True
        assert are_values_equivalent({"a": [1, 2]}, {"a": [2, 1]}) is True
        assert are_values_equivalent({"a": [1, 1]}, {"a": [1, 2]}) is False


# ---------------------------------------------------------------------------
# PR#274 Bug #32 -- models/core.py:83-98 -- except ValueError rewraps semantic error
# ---------------------------------------------------------------------------
class TestExpirationValidatorPreservesMessage:
    """'expiration must be in the future' must not be rewrapped as format error."""

    def test_past_date_warns_and_clears(self):
        """A past date should warn and set expiration to None, not raise."""
        import warnings
        from automated_security_helper.models.core import AshSuppression

        yesterday = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s = AshSuppression(
                path="test.py",
                rule_id="R1",
                reason="test",
                expiration=yesterday,
            )
        assert s.expiration is None
        assert len(w) >= 1
        assert "past" in str(w[0].message).lower()

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


# ---------------------------------------------------------------------------
# Batch 2: suppression_matcher.py regression tests
# ---------------------------------------------------------------------------


class TestBug23LineStartOnlyIgnoresEnd:
    """#23: When suppression has only line_start, a multi-line finding that
    starts before suppression.line_start but ends at or after it should be
    suppressed (overlap), but the old code only checked finding.line_start."""

    def test_multiline_finding_overlapping_start_only_suppression(self):
        """A finding spanning lines 5-15 should be suppressed by a
        suppression with line_start=10 (no line_end) because the finding
        overlaps."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=5,
            line_end=15,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert _line_range_matches(finding, suppression), (
            "Bug #23: multi-line finding (5-15) overlapping suppression "
            "line_start=10 should match"
        )

    def test_finding_entirely_before_start_only_suppression(self):
        """A finding on lines 1-5 should NOT be suppressed by
        suppression line_start=10."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=1,
            line_end=5,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert not _line_range_matches(finding, suppression), (
            "Finding entirely before suppression start should not match"
        )

    def test_finding_starts_at_suppression_start(self):
        """A finding starting exactly at suppression line_start should match."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=10,
            line_end=20,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert _line_range_matches(finding, suppression), (
            "Finding starting at suppression line_start should match"
        )


class TestBug52SameDayExpiry:
    """#52: should_suppress_finding uses `<` for expiry check while
    check_for_expiring_suppressions uses `<=`. After fix, both use `<=`,
    so a suppression expiring today is treated as expired (not active)."""

    def test_same_day_expiry_does_not_suppress(self):
        """A suppression expiring today should NOT suppress (consistent
        with check_for_expiring_suppressions treating day-0 as expiring)."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        today_str = datetime.now().strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        # Use model_construct to bypass the expiration-in-future validator
        suppression = AshSuppression.model_construct(
            reason="r", path="f.py", rule_id="R1",
            expiration=today_str,
            line_start=None, line_end=None,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert not suppressed, (
            "Bug #52: suppression expiring today should not suppress "
            "(consistent with <= semantics)"
        )

    def test_yesterday_expiry_does_not_suppress(self):
        """A suppression that expired yesterday should not suppress."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        # Use model_construct to bypass the expiration-in-future validator
        suppression = AshSuppression.model_construct(
            reason="r", path="f.py", rule_id="R1",
            expiration=yesterday_str,
            line_start=None, line_end=None,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert not suppressed, (
            "Suppression that expired yesterday should not suppress"
        )

    def test_tomorrow_expiry_still_suppresses(self):
        """A suppression expiring tomorrow should still suppress."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        tomorrow_str = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        suppression = AshSuppression(
            reason="r", path="f.py", rule_id="R1",
            expiration=tomorrow_str,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert suppressed, (
            "Suppression expiring tomorrow should still suppress"
        )


class TestBug54FnmatchCaseSensitivity:
    """#54: fnmatch case sensitivity is OS-dependent. On macOS/Windows,
    fnmatch.fnmatch is case-insensitive, but on Linux it's case-sensitive.
    Fix: normalize both sides to lowercase."""

    def test_rule_id_match_case_insensitive(self):
        """Rule ID matching should be case-insensitive regardless of OS."""
        from automated_security_helper.utils.suppression_matcher import _rule_id_matches

        # These should match regardless of platform
        assert _rule_id_matches("AWS-S3-001", "aws-s3-*"), (
            "Bug #54: rule ID match should be case-insensitive"
        )
        assert _rule_id_matches("aws-s3-001", "AWS-S3-*"), (
            "Bug #54: rule ID match should be case-insensitive (reverse)"
        )

    def test_rule_id_exact_match_case_insensitive(self):
        """Exact rule ID should match case-insensitively."""
        from automated_security_helper.utils.suppression_matcher import _rule_id_matches

        assert _rule_id_matches("MyRule", "myrule"), (
            "Bug #54: exact rule ID match should be case-insensitive"
        )

    def test_file_path_match_case_insensitive(self):
        """File path matching should be case-insensitive regardless of OS."""
        from automated_security_helper.utils.suppression_matcher import _file_path_matches

        assert _file_path_matches("SRC/File.py", "src/file.py"), (
            "Bug #54: file path match should be case-insensitive"
        )

    def test_file_path_glob_case_insensitive(self):
        """File path glob matching should be case-insensitive."""
        from automated_security_helper.utils.suppression_matcher import _file_path_matches

        assert _file_path_matches("SRC/MyFile.py", "src/*.py"), (
            "Bug #54: file path glob should be case-insensitive"
        )
