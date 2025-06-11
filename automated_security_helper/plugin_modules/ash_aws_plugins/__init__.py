# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)


# Make plugins discoverable
# ASH_CONVERTERS = []
# ASH_SCANNERS = []
ASH_REPORTERS = [
    SecurityHubReporter,
    CloudWatchLogsReporter,
    BedrockSummaryReporter,
    S3Reporter,
]

# __all__ = [
#     "ASH_CONVERTERS",
#     "ASH_SCANNERS",
#     "ASH_REPORTERS",
#     "SecurityHubReporter",
#     "CloudWatchLogsReporter",
# ]
