# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_binskim_plugins.binskim_scanner import (
    BinskimScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    BinskimScanner,
]
ASH_REPORTERS: list[type] = []
