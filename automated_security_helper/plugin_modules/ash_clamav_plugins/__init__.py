# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_clamav_plugins.clamav_scanner import (
    ClamAVScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ClamAVScanner,
]
ASH_REPORTERS: list[type] = []
