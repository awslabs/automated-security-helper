# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_psalm_plugins.psalm_scanner import (
    PsalmScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    PsalmScanner,
]
ASH_REPORTERS: list[type] = []
