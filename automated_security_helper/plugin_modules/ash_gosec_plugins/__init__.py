# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_gosec_plugins.gosec_scanner import (
    GosecScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    GosecScanner,
]
ASH_REPORTERS: list[type] = []
