# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone
import json
import logging
import os
from pydantic import BaseModel, Field, field_validator, model_validator
import boto3
import botocore.exceptions

from typing import Annotated, Any, Literal, TYPE_CHECKING

from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    AWS_REGION_PATTERN,
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    check_retry_delays,
    report_missing_setting,
    reporter_client_config,
    retry_with_backoff,
)


if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

# PutLogEvents caps a request at 1,048,576 bytes, counted as the UTF-8 size of
# every event message plus 26 bytes for each event (the API reference page the
# class docstring links). This reporter sends one event per request, so the
# event's message plus its overhead has to fit; one that does not is refused
# here, with the reason, instead of being sent to fail as a parameter error.
MAX_PUT_LOG_EVENTS_BYTES = 1_048_576
LOG_EVENT_OVERHEAD_BYTES = 26


class CloudWatchLogsReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            # An empty value is unset: AWS_REGION="" does not hide
            # AWS_DEFAULT_REGION, and an empty region is named as the missing
            # setting rather than refused by the pattern or sent to AWS.
            default_factory=lambda: (
                os.environ.get("AWS_REGION")
                or os.environ.get("AWS_DEFAULT_REGION")
                or None
            ),
            # The three AWS reporters share one pattern (aws_utils), so a
            # region one of them accepts is never a configuration error for
            # another; its wording of the list is kept there.
            pattern=AWS_REGION_PATTERN,
            description="AWS region for CloudWatch Logs",
        ),
    ]
    log_group_name: Annotated[
        str | None,
        Field(
            # An empty value is unset, so it is named as missing instead of
            # reaching CreateLogStream as an empty group name.
            default_factory=lambda: (
                os.environ.get("ASH_CLOUDWATCH_LOG_GROUP_NAME") or None
            ),
            description="CloudWatch Logs group name to publish results to",
        ),
    ]
    log_stream_name: Annotated[
        str,
        Field(
            default="ASHScanResults",
            description="CloudWatch Logs stream name to publish results to",
        ),
    ] = "ASHScanResults"
    # Retry configuration
    max_retries: Annotated[
        int,
        Field(
            le=MAX_RETRIES,
            default=3,
            description="Maximum number of retry attempts for CloudWatch API calls",
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            default=1.0,
            description="Base delay in seconds between retry attempts",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            default=60.0,
            description="Maximum delay in seconds between retry attempts",
        ),
    ] = 60.0

    @field_validator("aws_region", "log_group_name", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        """An empty or blank value is no value, whichever way it arrives.

        The default factories read the environment that way; a config file
        (``aws_region: "${AWS_REGION}"`` with the variable empty) or
        ``--config-overrides`` reaches the field here instead. Mapped to None, a
        blank region or group name is named as the missing setting rather than
        refused by the region pattern or sent to AWS as an empty name.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _retry_delays_are_bounded(self):
        return check_retry_delays(self)


class CloudWatchLogsReporterConfig(ReporterPluginConfigBase):
    name: Annotated[
        Literal["cloudwatch-logs"],
        Field(
            default="cloudwatch-logs",
            description="Name identifier for the CloudWatch Logs reporter plugin",
        ),
    ] = "cloudwatch-logs"
    extension: Annotated[
        str,
        Field(
            default="cwlog.json",
            description="File extension for CloudWatch Logs output files",
        ),
    ] = "cwlog.json"
    # Off by default: this reporter sends findings to an AWS service with the
    # operator's credentials, so only the operator's config turns it on.
    enabled: Annotated[
        bool,
        Field(
            default=False,
            description="Whether the CloudWatch Logs reporter is enabled",
        ),
    ] = False
    # A factory, so the environment defaults are read when the config is built.
    options: Annotated[
        CloudWatchLogsReporterConfigOptions,
        Field(
            default_factory=CloudWatchLogsReporterConfigOptions,
            description="Configuration options for CloudWatch Logs reporter",
        ),
    ]


@ash_reporter_plugin
class CloudWatchLogsReporter(ReporterPluginBase[CloudWatchLogsReporterConfig]):
    """Formats results and publishes to CloudWatch Logs.

    Workspace mode: per project. The RFC's reporter table did not rule on this
    one, so the reasoning is recorded here.

    This is a delivery mechanism rather than a format, and it has a side effect --
    ``PutLogEvents``. Each project's own scan already publishes its own event, so
    a workspace-level invocation would add an N+1st event to the same log stream
    describing the same findings, and a CloudWatch Logs Insights query would then
    double-count every one of them.

    What the extra event would contain is the stronger argument. It publishes
    ``model.to_simple_dict()``, whose two substantive keys at workspace level are
    the *lossy* ``scanner_results`` rollup -- per-scanner counts summed across
    projects, status taken as the worst across projects -- and an ``ash_config``
    that is no project's config, because workspace-level config does not exist
    until Phase 3. The event would describe a scan that never ran, in a stream
    where it sits indistinguishably beside N events that did.

    A size limit also applies, though it is not the binding argument here because
    ``to_simple_dict()`` omits findings and SARIF: PutLogEvents caps a single
    event at 1 MB and a batch at 1,048,576 bytes
    (https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html).
    It is worth naming because it forecloses the obvious alternative -- publishing
    the merged findings instead of the summary -- which would exceed it for any
    workspace of consequence.

    A publish that fails after the retries returns None, which ``ReportPhase``
    reports as a reporter that produced nothing. It used to return the exception
    text, which the phase wrote to ``ash.cwlog.json`` as a successful report and
    ``ash report --format cloudwatch-logs`` printed with exit 0 (or failed to
    pretty-print, with a JSON parse error in place of the reason).
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    # Sends findings to AWS with the host's credentials.
    sends_off_host = True
    destination_options = (
        "aws_region",
        "log_group_name",
        "log_stream_name",
        # How long it keeps calling CloudWatch Logs with the operator's credentials.
        "max_retries",
        "base_delay",
        "max_delay",
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = CloudWatchLogsReporterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if self._settings_missing():
            return self.dependencies_satisfied
        try:
            sts_client = boto3.client("sts", region_name=self.config.options.aws_region)
            caller_id = sts_client.get_caller_identity()
            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            # error_text with the config's environment values: botocore's
            # exceptions name the region, group or stream they were given.
            # At ERROR, like report_missing_setting: the report phase leaves
            # the reporter out on False, so under --quiet a WARNING was the
            # only word of why an enabled publish did not happen, and --quiet
            # hid it.
            self._plugin_log(
                f"Error when calling STS: {error_text(e, self._environment_values())}",
                level=logging.ERROR,
                target_type="source",
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def _settings_missing(self) -> bool:
        """Name each required setting that is unset or empty; True when one is.

        The options model maps a blank value to None (``_blank_is_unset``), from
        the environment or a config file alike; ``not`` rather than ``is None``
        keeps an empty name out of CreateLogStream should one ever get through.
        """
        missing = False
        if not self.config.options.aws_region:
            report_missing_setting(
                self.config.name, "aws_region", ("AWS_REGION", "AWS_DEFAULT_REGION")
            )
            missing = True
        if not self.config.options.log_group_name:
            report_missing_setting(
                self.config.name, "log_group_name", ("ASH_CLOUDWATCH_LOG_GROUP_NAME",)
            )
            missing = True
        return missing

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Publishes AshAggregatedResults as a CloudWatchLogs event.

        Returns the JSON receipt, or None when a required setting is unset or
        the publish failed. ``ash report`` never calls
        ``validate_plugin_dependencies``, so the settings are checked here too:
        an unset log group used to reach PutLogEvents and come back as a
        botocore parameter error.
        """
        if isinstance(self.config, dict):
            self.config = CloudWatchLogsReporterConfig.model_validate(self.config)
        if self._settings_missing():
            return None
        if isinstance(getattr(model, "workspace", None), BaseModel):
            # A workspace's unified results: each project's own scan already
            # published its event (the class docstring says why the rollup is
            # not published), and `ash report` on the workspace output
            # directory is the one path that reaches here with them.
            self._plugin_log(
                "cloudwatch-logs publishes one project's results at a time, and "
                "these are a workspace's unified results, which each project's "
                "own scan already published. Run ash report with --output-dir "
                "set to a project's directory under the workspace output.",
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return None
        timestamp = int(
            (
                datetime.now(timezone.utc)
                - datetime(1970, 1, 1, 0, 0, 0, 0, timezone.utc)
            ).total_seconds()
            * 1000
        )
        output_dict = model.to_simple_dict()
        output = json.dumps(output_dict, default=str)
        event_bytes = len(output.encode("utf-8")) + LOG_EVENT_OVERHEAD_BYTES
        if event_bytes > MAX_PUT_LOG_EVENTS_BYTES:
            # metadata.inputs_not_scanned and the scanner records have no bound,
            # so a large scan can outgrow the one event this reporter sends.
            self._plugin_log(
                "The results are too large for one CloudWatch Logs event: "
                f"{event_bytes} bytes with the event overhead, where PutLogEvents "
                f"takes at most {MAX_PUT_LOG_EVENTS_BYTES}; nothing was published",
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return None

        # Create CloudWatch Logs client. The calls below repeat a failure
        # themselves (retry_with_backoff), so the client makes one attempt per
        # call: botocore does not resend inside the reporter's retries. The
        # reporter's own retries still repeat a read timeout, a closed
        # connection and a 5xx answer, which can come after PutLogEvents was
        # accepted, so an event can be written up to max_retries + 1 times.
        cwlogs_client = boto3.client(
            "logs",
            region_name=self.config.options.aws_region,
            config=reporter_client_config(),
        )

        # Create log stream with retry logic
        self._create_log_stream_with_retry(cwlogs_client)

        # Create log event
        log_event = {
            "timestamp": timestamp,
            "message": output,
        }

        # The destination is named by its options, not their values, which a
        # config file can read from the environment.
        ASH_LOGGER.verbose(
            "Publishing event to CloudWatch Logs, to the log group and region in "
            "the reporter's log_group_name and aws_region options",
        )
        ASH_LOGGER.verbose(output)

        # Put log events with retry logic
        try:
            resp = self._put_log_events_with_retry(
                cwlogs_client,
                logGroupName=self.config.options.log_group_name,
                logStreamName=self.config.options.log_stream_name,
                logEvents=[log_event],
            )
            # PutLogEvents answers 200 and lists an event it would not keep
            # (too old, too new, or past the group's retention) in
            # rejectedLogEventsInfo; such an answer is not a publish.
            rejected = (
                resp.get("rejectedLogEventsInfo") if isinstance(resp, dict) else None
            )
            if rejected:
                self._plugin_log(
                    "CloudWatch Logs accepted the request but rejected the event "
                    f"({', '.join(sorted(rejected))}), so the results were not "
                    "published",
                    level=logging.ERROR,
                    append_to_stream="stderr",
                )
                return None
            return json.dumps({"message": output_dict, "response": resp}, default=str)
        except Exception as e:
            # Redacted: the line names the group, stream or region it was given.
            described = error_text(e, self._environment_values())
            self._plugin_log(
                "Error when publishing results to CloudWatch Logs after retries: "
                f"{described}",
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            # None, not the message: ReportPhase reports a None result as a
            # reporter that produced nothing and writes no ash.cwlog.json.
            # Returning the message wrote it into that file as if it were a
            # report, and `ash report` printed it with exit 0.
            return None

    def _create_log_stream_with_retry(self, cwlogs_client):
        """Create log stream with retry logic."""
        try:
            # Define the retry decorator for creating log stream
            @retry_with_backoff(
                max_retries=self.config.options.max_retries,
                base_delay=self.config.options.base_delay,
                max_delay=self.config.options.max_delay,
            )
            def create_log_stream():
                return cwlogs_client.create_log_stream(
                    logGroupName=self.config.options.log_group_name,
                    logStreamName=self.config.options.log_stream_name,
                )

            # Call the decorated function
            create_log_stream()
        except botocore.exceptions.ClientError as e:
            # ResourceAlreadyExistsException is expected if the stream already exists
            if (
                e.response.get("Error", {}).get("Code")
                == "ResourceAlreadyExistsException"
            ):
                # Redacted: the stream name is configured, and ash.log keeps
                # DEBUG lines under --debug.
                ASH_LOGGER.debug(
                    "The log stream the log_stream_name option names already exists"
                )
            else:
                self._plugin_log(
                    "Error when creating log stream: "
                    f"{error_text(e, self._environment_values())}",
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
        except Exception as e:
            self._plugin_log(
                "Error when creating log stream: "
                f"{error_text(e, self._environment_values())}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )

    def _put_log_events_with_retry(self, cwlogs_client, **kwargs):
        """Put log events, retrying on the schedule this reporter was configured with.

        The decorator used to be applied to this method directly, with no
        arguments -- valid, since every parameter has a default, but evaluated
        when the class body runs, where there is no ``self`` to read config from.
        So this call used max_retries=3 while ``_create_log_stream_with_retry``
        thirty lines above honored ``self.config.options.max_retries``. One file
        disagreeing with itself about whether a documented option means anything.

        Deferring the decorator to call time via a closure, exactly as
        ``_create_log_stream_with_retry`` does, makes both paths obey the same
        configuration. The method name and signature are unchanged.
        """

        @retry_with_backoff(
            max_retries=self.config.options.max_retries,
            base_delay=self.config.options.base_delay,
            max_delay=self.config.options.max_delay,
        )
        def put_log_events():
            return cwlogs_client.put_log_events(**kwargs)

        return put_log_events()
