# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_brakeman_plugins.brakeman_scanner import (
    BrakemanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BrakemanScanner,
]
ASH_REPORTERS: list[type] = []
