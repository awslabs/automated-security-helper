# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_kics_plugins.kics_scanner import (
    KicsScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    KicsScanner,
]
ASH_REPORTERS: list[type] = []
