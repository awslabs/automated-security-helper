# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_pmd_plugins.pmd_scanner import (
    PmdScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    PmdScanner,
]
ASH_REPORTERS: list[type] = []
