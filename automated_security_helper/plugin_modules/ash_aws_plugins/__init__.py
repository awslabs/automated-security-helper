# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_aws_plugins.asff_reporter import (
    AsffReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)


# Make plugins discoverable
ASH_CONVERTERS = []
ASH_SCANNERS = []
ASH_REPORTERS = [
    AsffReporter,
    CloudWatchLogsReporter,
]

# __all__ = [
#     "ASH_CONVERTERS",
#     "ASH_SCANNERS",
#     "ASH_REPORTERS",
#     "AsffReporter",
#     "CloudWatchLogsReporter",
# ]
