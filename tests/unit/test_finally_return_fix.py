"""Regression tests for ``return`` inside ``finally:`` blocks.

A ``return`` in a ``finally:`` clause silently swallows any exception that
was propagating at that point. Each of the sites below previously returned
a fallback value from ``finally:``, masking real failures (OSError,
KeyboardInterrupt, SystemExit, etc.) from callers.

These tests pin the fix: exceptions that are not explicitly handled by the
function's own ``except`` clauses must propagate to the caller.
"""

from unittest.mock import patch

import pytest


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
