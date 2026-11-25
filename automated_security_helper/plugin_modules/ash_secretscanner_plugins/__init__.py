# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_secretscanner_plugins.secretscanner_scanner import (
    SecretScannerScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SecretScannerScanner,
]
ASH_REPORTERS: list[type] = []
