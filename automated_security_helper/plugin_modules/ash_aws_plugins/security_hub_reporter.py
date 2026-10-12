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
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class SecurityHubReporterConfigOptions(ReporterOptionsBase):
    # Read from the environment when the options are built, not when this module
    # is imported, so a config built later sees the run's environment.
    aws_region: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get(
                "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None)
            ),
            description="AWS Region for Security Hub integration",
        ),
    ]
    aws_profile: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get("AWS_PROFILE", None),
            description="AWS Profile to use for authentication",
        ),
    ]
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
    # Off by default: this reporter sends findings to an AWS service with the
    # operator's credentials, so only the operator's config turns it on.
    enabled: Annotated[
        bool,
        Field(
            default=False,
            description="Whether the Security Hub reporter is enabled",
        ),
    ] = False
    options: Annotated[
        SecurityHubReporterConfigOptions,
        Field(
            default_factory=SecurityHubReporterConfigOptions,
            description="Configuration options for Security Hub reporter",
        ),
    ]


@ash_reporter_plugin
class SecurityHubReporter(ReporterPluginBase[SecurityHubReporterConfig]):
    """Sends security findings to AWS Security Hub in ASFF format.

    Workspace mode: per project.

    This reporter has a side effect -- it calls ``BatchImportFindings`` -- so the
    behaviour is not only about document shape. Each project's own scan already
    publishes that project's findings. Invoking it again at workspace level would
    import every finding a second time, and ASFF findings are keyed on ``Id``, so
    the duplicates would either overwrite the per-project imports or land beside
    them depending on how the ids collide. Neither outcome is one an operator
    asked for, and both are silent.

    Per project is also the correct scope for the data: an ASFF finding is
    attributed to one resource in one account, and a workspace's projects are
    independently owned.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    # Sends findings to AWS with the host's credentials.
    sends_off_host = True
    destination_options = ("aws_region", "aws_profile", "account_id")

    def model_post_init(self, context):
        if self.config is None:
            self.config = SecurityHubReporterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
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
            # The region is named by its option, not its value, which a config
            # file can read from the environment.
            ASH_LOGGER.info(
                "Security Hub reporter validated for the region in its aws_region "
                "option"
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
        ASH_LOGGER.warning(
            "SecurityHubReporter.report() is a stub -- full ASFF conversion and "
            "Security Hub import are not yet implemented. The returned JSON is a "
            "placeholder and findings have NOT been sent to Security Hub."
        )
        findings_count = len(model.sarif.get_all_results()) if model.sarif else 0

        return json.dumps(
            {
                "message": "Security Hub integration in development",
                "findings_count": findings_count,
            },
            indent=2,
        )
