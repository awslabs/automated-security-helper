# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone
import json
import logging
import os
from pydantic import Field
import boto3
import botocore.exceptions

from typing import Annotated, Literal, TYPE_CHECKING

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
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


class CloudWatchLogsReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get(
                "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None)
            ),
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}",
            description="AWS region for CloudWatch Logs",
        ),
    ]
    log_group_name: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get(
                "ASH_CLOUDWATCH_LOG_GROUP_NAME", None
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
            default=3,
            description="Maximum number of retry attempts for CloudWatch API calls",
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            default=1.0,
            description="Base delay in seconds between retry attempts",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            default=60.0,
            description="Maximum delay in seconds between retry attempts",
        ),
    ] = 60.0


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
    enabled: Annotated[
        bool,
        Field(
            default=True,
            description="Whether the CloudWatch Logs reporter is enabled",
        ),
    ] = True
    options: Annotated[
        CloudWatchLogsReporterConfigOptions,
        Field(
            description="Configuration options for CloudWatch Logs reporter",
        ),
    ] = CloudWatchLogsReporterConfigOptions()


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
    workspace of consequence, and this reporter's error path returns the exception
    text as its report rather than failing the run.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = CloudWatchLogsReporterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if (
            self.config.options.aws_region is None
            or self.config.options.log_group_name is None
        ):
            return self.dependencies_satisfied
        try:
            sts_client = boto3.client("sts", region_name=self.config.options.aws_region)
            caller_id = sts_client.get_caller_identity()
            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            self._plugin_log(
                f"Error when calling STS: {e}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Publishes AshAggregatedResults as a CloudWatchLogs event"""
        timestamp = int(
            (
                datetime.now(timezone.utc)
                - datetime(1970, 1, 1, 0, 0, 0, 0, timezone.utc)
            ).total_seconds()
            * 1000
        )
        output_dict = model.to_simple_dict()
        output = json.dumps(output_dict, default=str)
        if isinstance(self.config, dict):
            self.config = CloudWatchLogsReporterConfig.model_validate(self.config)

        # Create CloudWatch Logs client
        cwlogs_client = boto3.client("logs", region_name=self.config.options.aws_region)

        # Create log stream with retry logic
        self._create_log_stream_with_retry(cwlogs_client)

        # Create log event
        log_event = {
            "timestamp": timestamp,
            "message": output,
        }

        ASH_LOGGER.verbose(
            f"Publishing event to CloudWatch Logs log group {self.config.options.log_group_name}@{self.config.options.aws_region}",
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
            return json.dumps({"message": output_dict, "response": resp}, default=str)
        except Exception as e:
            self._plugin_log(
                f"Error when publishing results to CloudWatch Logs after retries: {e}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            return str(e)

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
                ASH_LOGGER.debug(
                    f"Log stream already exists: {self.config.options.log_stream_name}"
                )
            else:
                self._plugin_log(
                    f"Error when creating log stream: {e}",
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
        except Exception as e:
            self._plugin_log(
                f"Error when creating log stream: {e}",
                level=logging.WARNING,
                append_to_stream="stderr",
            )

    @retry_with_backoff()
    def _put_log_events_with_retry(self, cwlogs_client, **kwargs):
        """Put log events with retry logic."""
        return cwlogs_client.put_log_events(**kwargs)
