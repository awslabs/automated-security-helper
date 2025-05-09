# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone
import json
import logging
from pydantic import Field
import boto3

from typing import Annotated, Literal, TYPE_CHECKING


if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CloudWatchLogsReporterConfigOptions(ReporterOptionsBase):
    aws_account_id: Annotated[str | None, Field(pattern=r"^\d{12}$")] = None
    aws_region: Annotated[
        str | None,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}"
        ),
    ] = None
    log_group_name: str | None = None
    log_stream_name: str = "ASHScanResults"


class CloudWatchLogsReporterConfig(ReporterPluginConfigBase):
    name: Literal["cloudwatch-logs"] = "cloudwatch-logs"
    extension: str = "cwlog.json"
    enabled: bool = False
    options: CloudWatchLogsReporterConfigOptions = CloudWatchLogsReporterConfigOptions()


@ash_reporter_plugin
class CloudWatchLogsReporter(ReporterPluginBase[CloudWatchLogsReporterConfig]):
    """Formats results as Amazon Security Finding Format (ASFF)."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CloudWatchLogsReporterConfig()
        return super().model_post_init(context)

    def validate(self) -> bool:
        """Validate reporter configuration and requirements.

        Defaults to returning True as most reporter plugins are entirely Python based."""
        self.dependencies_satisfied = False
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
        timestamp = int(datetime.now(timezone.utc).timestamp())
        simple_dict = model.to_simple_dict()
        if isinstance(self.config, dict):
            self.config = CloudWatchLogsReporterConfig.model_validate(self.config)
        cwlogs_client = boto3.client("logs", region_name=self.config.options.aws_region)
        try:
            cwlogs_client.create_log_stream(
                logGroupName=self.config.options.log_group_name,
                logStreamName=self.config.options.log_stream_name,
            )
        except Exception as e:
            self._plugin_log(
                f"Error when creating log stream: {e}",
                level=logging.DEBUG,
                append_to_stream="stderr",
            )

        output = json.dumps(simple_dict, default=str)
        self._plugin_log(
            f"Publishing results to CloudWatch Logs log group {self.config.options.log_group_name}@{self.config.options.aws_region}: {output}",
            level=15,
            append_to_stream="stdout",
        )
        resp = cwlogs_client.put_log_events(
            logGroupName=self.config.options.log_group_name,
            logStreamName=self.config.options.log_stream_name,
            logEvents=[
                {
                    "timestamp": timestamp,
                    "message": output,
                }
            ],
        )
        return json.dumps(resp, default=str)
