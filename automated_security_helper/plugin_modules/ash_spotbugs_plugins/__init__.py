# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_spotbugs_plugins.spotbugs_scanner import (
    SpotBugsScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SpotBugsScanner,
]
ASH_REPORTERS: list[type] = []
