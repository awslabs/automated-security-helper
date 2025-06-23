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
        ),
    ]
    log_group_name: str | None = Field(
        default_factory=lambda: os.environ.get("ASH_CLOUDWATCH_LOG_GROUP_NAME", None)
    )
    log_stream_name: str = "ASHScanResults"
    # Retry configuration
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0


class CloudWatchLogsReporterConfig(ReporterPluginConfigBase):
    name: Literal["cloudwatch-logs"] = "cloudwatch-logs"
    extension: str = "cwlog.json"
    enabled: bool = True
    options: CloudWatchLogsReporterConfigOptions = CloudWatchLogsReporterConfigOptions()


@ash_reporter_plugin
class CloudWatchLogsReporter(ReporterPluginBase[CloudWatchLogsReporterConfig]):
    """Formats results and publishes to CloudWatch Logs."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CloudWatchLogsReporterConfig()
        return super().model_post_init(context)

    def validate(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if (
            self.config.options.aws_region is None
            or self.config.options.log_group_name is None
        ):
            return self.dependencies_satisfied
        try:
            sts_client = boto3.client("sts", region=self.config.options.aws_region)
            caller_id = sts_client.get_caller_identity()
            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            self._plugin_log(
                f"Error when calling STS: {e}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        finally:
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
