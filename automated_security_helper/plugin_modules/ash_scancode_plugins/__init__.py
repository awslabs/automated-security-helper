# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_scancode_plugins.scancode_scanner import (
    ScanCodeScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ScanCodeScanner,
]
ASH_REPORTERS: list[type] = []
