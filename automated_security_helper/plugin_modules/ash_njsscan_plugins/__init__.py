# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_njsscan_plugins.njsscan_scanner import (
    NjsscanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    NjsscanScanner,
]
ASH_REPORTERS: list[type] = []
