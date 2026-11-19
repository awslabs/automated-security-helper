# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_betterleaks_plugins.betterleaks_scanner import (
    BetterleaksScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BetterleaksScanner,
]
ASH_REPORTERS: list[type] = []
