# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from typing import Annotated, Literal, TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class SecurityHubReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            description="AWS Region for Security Hub integration",
        ),
    ] = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None))
    aws_profile: Annotated[
        str | None,
        Field(
            default=None,
            description="AWS Profile to use for authentication",
        ),
    ] = os.environ.get("AWS_PROFILE", None)
    account_id: Annotated[
        str | None,
        Field(
            default=None,
            description="AWS Account ID (will be auto-detected if not provided)",
        ),
    ] = None


class SecurityHubReporterConfig(ReporterPluginConfigBase):
    name: Literal["aws-security-hub"] = "aws-security-hub"
    extension: Annotated[
        str,
        Field(
            default="aws-security-hub.asff.json",
            description="File extension for Security Hub ASFF output",
        ),
    ] = "aws-security-hub.asff.json"
    enabled: Annotated[
        bool,
        Field(
            default=True,
            description="Whether the Security Hub reporter is enabled",
        ),
    ] = True
    options: Annotated[
        SecurityHubReporterConfigOptions,
        Field(
            description="Configuration options for Security Hub reporter",
        ),
    ] = SecurityHubReporterConfigOptions()


@ash_reporter_plugin
class SecurityHubReporter(ReporterPluginBase[SecurityHubReporterConfig]):
    """Sends security findings to AWS Security Hub in ASFF format."""

    def model_post_init__(self, context):
        if self.config is None:
            self.config = SecurityHubReporterConfig()
        return super().model_post_init__(context)

    def validate(self) -> bool:
        """Validate reporter configuration and AWS connectivity."""
        self.dependencies_satisfied = False

        if not self.config.options.aws_region:
            ASH_LOGGER.error("AWS region is required for Security Hub reporter")
            return self.dependencies_satisfied

        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )

            # Test Security Hub connectivity
            securityhub_client = session.client("securityhub")
            securityhub_client.describe_hub()

            # Get account ID if not provided
            if not self.config.options.account_id:
                sts_client = session.client("sts")
                identity = sts_client.get_caller_identity()
                self.config.options.account_id = identity["Account"]

            self.dependencies_satisfied = True
            ASH_LOGGER.info(
                f"Security Hub reporter validated for region {self.config.options.aws_region}"
            )

        except NoCredentialsError:
            ASH_LOGGER.error("AWS credentials not found for Security Hub reporter")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidAccessException":
                ASH_LOGGER.error(
                    "Security Hub is not enabled in this region or insufficient permissions"
                )
            else:
                ASH_LOGGER.error(f"AWS Security Hub validation failed: {e}")
        except Exception as e:
            ASH_LOGGER.error(f"Security Hub reporter validation failed: {e}")

        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Send findings to AWS Security Hub and return ASFF JSON."""
        # TODO: Implement full ASFF conversion and Security Hub integration
        findings_count = 0
        if model.sarif and model.sarif.runs:
            for run in model.sarif.runs:
                if run.results:
                    findings_count += len(run.results)

        return json.dumps(
            {
                "message": "Security Hub integration in development",
                "findings_count": findings_count,
            },
            indent=2,
        )
