# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_slither_plugins.slither_scanner import (
    SlitherScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SlitherScanner,
]
ASH_REPORTERS: list[type] = []
