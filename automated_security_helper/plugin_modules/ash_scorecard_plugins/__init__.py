# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_scanner import (
    ScorecardScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ScorecardScanner,
]
ASH_REPORTERS: list[type] = []
