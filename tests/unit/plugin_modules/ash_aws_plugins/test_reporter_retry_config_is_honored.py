"""The AWS reporters' retry options must reach the decorator that implements them.

``retry_with_backoff`` gives every parameter a default, so ``@retry_with_backoff()``
is a legal application -- it is not a syntax or type error, and a reviewer reading
the decorator alone sees nothing wrong. What makes it a defect at these two call
sites is *when* it runs: a decorator on a method is applied while the class body
executes, where no instance exists, so it cannot read ``self.config``. The
reporters' ``max_retries``, ``base_delay`` and ``max_delay`` options were
therefore accepted from user configuration, logged, documented in their field
descriptions -- and discarded.

Repo-wide, the only reads of ``options.max_retries`` / ``options.base_delay`` /
``options.max_delay`` before this change were the three lines inside
``CloudWatchLogsReporter._create_log_stream_with_retry``, which applies the
decorator to a closure and so does see ``self``. Log-stream creation obeyed the
configuration while put-log-events, thirty lines below it, did not; S3 read none
of the three anywhere.

These tests parameterize over retry counts that differ from the module default of
3, which is what makes them able to fail: asserting the default value would pass
against the defect. Each case pins the attempt count, and one pins the interval,
because a config that is read but ignored looks identical to one that is honored
if only the call count is checked at the default.

Not covered here, deliberately: BedrockSummaryReporter declares the same three
options and imports ``retry_with_backoff``, but never applies it anywhere -- there
is no decorated call site to correct. Wiring it up would mean introducing retry to
Bedrock calls that have none today, which is new behavior rather than repairing an
inert guard, so it is left alone and the import stays flagged as unused.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)

# The module defaults the bare decorator fell back to. Every parameterized case
# below avoids 3 so that "config ignored" and "config honored" give different
# answers.
MODULE_DEFAULT_MAX_RETRIES = 3


def _throttling_error():
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        "operation",
    )


def _reporter(cls, *, max_retries, base_delay=0.0, max_delay=60.0):
    """A reporter with only the config the retry path reads.

    model_construct skips validation on purpose: these tests are about the retry
    wiring, and building the full plugin context would drag in AshConfig,
    PluginContext and a temp output tree without making the assertions any
    sharper.
    """
    reporter = cls.model_construct()
    reporter.config = MagicMock()
    reporter.config.options.max_retries = max_retries
    reporter.config.options.base_delay = base_delay
    reporter.config.options.max_delay = max_delay
    reporter.config.options.log_group_name = "group"
    reporter.config.options.log_stream_name = "stream"
    reporter._plugin_log = lambda *a, **k: None
    return reporter


def _count_attempts(call):
    """Run ``call`` with sleep stubbed; return (attempt count, sleep intervals)."""
    sleeps: list[float] = []
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time.sleep",
        side_effect=sleeps.append,
    ):
        with pytest.raises(botocore.exceptions.ClientError):
            call()
    return sleeps


class TestS3ReporterHonorsItsRetryConfig:
    @pytest.mark.parametrize("max_retries", [0, 1, 5, 7])
    def test_attempt_count_follows_configured_max_retries(self, max_retries):
        reporter = _reporter(S3Reporter, max_retries=max_retries)
        client = MagicMock()
        client.put_object.side_effect = _throttling_error()

        _count_attempts(lambda: reporter._put_object_with_retry(client, Bucket="b"))

        assert client.put_object.call_count == max_retries + 1, (
            f"configured max_retries={max_retries} must give {max_retries + 1} "
            f"attempts; {MODULE_DEFAULT_MAX_RETRIES + 1} means the decorator is "
            f"still using its own defaults and the option is inert"
        )

    def test_base_delay_reaches_the_backoff(self):
        reporter = _reporter(S3Reporter, max_retries=2, base_delay=100.0, max_delay=1e6)
        client = MagicMock()
        client.put_object.side_effect = _throttling_error()

        sleeps = _count_attempts(
            lambda: reporter._put_object_with_retry(client, Bucket="b")
        )

        # Jitter adds under 1s, so a 100s base cannot be confused with the 1.0s
        # module default.
        assert len(sleeps) == 2, sleeps
        assert 100.0 <= sleeps[0] < 101.0, sleeps
        assert 200.0 <= sleeps[1] < 201.0, sleeps


class TestCloudWatchReporterHonorsItsRetryConfig:
    @pytest.mark.parametrize("max_retries", [0, 1, 5, 7])
    def test_attempt_count_follows_configured_max_retries(self, max_retries):
        reporter = _reporter(CloudWatchLogsReporter, max_retries=max_retries)
        client = MagicMock()
        client.put_log_events.side_effect = _throttling_error()

        _count_attempts(lambda: reporter._put_log_events_with_retry(client))

        assert client.put_log_events.call_count == max_retries + 1, (
            f"configured max_retries={max_retries} must give {max_retries + 1} "
            f"attempts; {MODULE_DEFAULT_MAX_RETRIES + 1} means the option is inert"
        )

    def test_both_retry_paths_in_the_file_now_agree(self):
        """create_log_stream already honored the config; put_log_events did not.

        The bug was one file disagreeing with itself, so assert the two paths
        take the same number of attempts under one configuration rather than
        checking either in isolation.
        """
        reporter = _reporter(CloudWatchLogsReporter, max_retries=4)

        stream_client = MagicMock()
        stream_client.create_log_stream.side_effect = _throttling_error()
        with patch(
            "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time.sleep"
        ):
            # This path swallows the final error by design; the count is the point.
            reporter._create_log_stream_with_retry(stream_client)

        events_client = MagicMock()
        events_client.put_log_events.side_effect = _throttling_error()
        _count_attempts(lambda: reporter._put_log_events_with_retry(events_client))

        assert (
            events_client.put_log_events.call_count
            == stream_client.create_log_stream.call_count
            == 5
        ), (
            f"create_log_stream took {stream_client.create_log_stream.call_count} "
            f"attempts and put_log_events took "
            f"{events_client.put_log_events.call_count}; both read the same option "
            f"and must agree"
        )
