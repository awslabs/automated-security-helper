# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from pathlib import Path
from typing import Annotated, Literal, Optional, TYPE_CHECKING

import boto3
from pydantic import Field
import yaml

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    retry_with_backoff,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class S3ReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get(
                "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None)
            ),
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}",
            description="AWS region to use for S3 operations",
        ),
    ]
    aws_profile: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get("AWS_PROFILE", None),
            description="AWS profile to use for authentication",
        ),
    ]
    bucket_name: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get("ASH_S3_BUCKET_NAME", None),
            description="Name of the S3 bucket to store reports",
        ),
    ]
    key_prefix: Annotated[
        str,
        Field(
            description="Prefix for S3 object keys",
        ),
    ] = "ash-reports/"
    file_format: Annotated[
        Literal["json", "yaml"],
        Field(
            description="Format to use for the report file",
        ),
    ] = "json"
    # Retry configuration
    max_retries: Annotated[
        int,
        Field(
            description="Maximum number of retry attempts for S3 operations",
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            description="Base delay in seconds between retry attempts",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            description="Maximum delay in seconds between retry attempts",
        ),
    ] = 60.0


class S3ReporterConfig(ReporterPluginConfigBase):
    name: Literal["s3"] = "s3"
    extension: str = "s3.json"
    enabled: bool = True
    options: S3ReporterConfigOptions = S3ReporterConfigOptions()


@ash_reporter_plugin
class S3Reporter(ReporterPluginBase[S3ReporterConfig]):
    """Formats results and uploads to an S3 bucket."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = S3ReporterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if (
            self.config.options.aws_region is None
            or self.config.options.bucket_name is None
        ):
            return self.dependencies_satisfied
        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()

            # Check if S3 bucket exists and is accessible
            s3_client = session.client("s3")
            s3_client.head_bucket(Bucket=self.config.options.bucket_name)

            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            self._plugin_log(
                f"Error when validating S3 access: {e}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        finally:
            return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model and upload to S3 bucket."""
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)

        # Create a unique key for the S3 object
        timestamp = model.metadata.summary_stats.start
        file_extension = "json" if self.config.options.file_format == "json" else "yaml"
        s3_key = (
            f"{self.config.options.key_prefix}ash-report-{timestamp}.{file_extension}"
        )

        # Format the results based on the specified format
        if self.config.options.file_format == "json":
            output_dict = model.to_simple_dict()
            output_content = json.dumps(output_dict, default=str, indent=2)
        else:
            output_dict = model.to_simple_dict()
            output_content = yaml.dump(output_dict, default_flow_style=False)

        # Create a session with the specified profile and region
        session = boto3.Session(
            profile_name=self.config.options.aws_profile,
            region_name=self.config.options.aws_region,
        )
        s3_client = session.client("s3")

        try:
            # Upload the content to S3 with retry logic
            self._put_object_with_retry(
                s3_client,
                Bucket=self.config.options.bucket_name,
                Key=s3_key,
                Body=output_content,
                ContentType=(
                    "application/json"
                    if file_extension == "json"
                    else "application/yaml"
                ),
            )

            s3_url = f"s3://{self.config.options.bucket_name}/{s3_key}"
            ASH_LOGGER.info(f"Successfully uploaded report to {s3_url}")

            # Also write to local file if needed
            output_path = (
                Path(self.context.output_dir)
                / "reports"
                / f"s3-report.{file_extension}"
            )
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output_content)

            return s3_url
        except Exception as e:
            error_msg = f"Error uploading to S3 after retries: {str(e)}"
            self._plugin_log(
                error_msg,
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return error_msg

    @retry_with_backoff()
    def _put_object_with_retry(self, s3_client, **kwargs):
        """Put object to S3 with retry logic."""
        return s3_client.put_object(**kwargs)
