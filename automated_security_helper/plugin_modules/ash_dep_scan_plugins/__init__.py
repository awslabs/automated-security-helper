# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_dep_scan_plugins.dep_scan_scanner import (
    DepScanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    DepScanScanner,
]
ASH_REPORTERS: list[type] = []
