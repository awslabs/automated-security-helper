# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_scanner import (
    OsvScannerScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    OsvScannerScanner,
]
ASH_REPORTERS: list[type] = []
