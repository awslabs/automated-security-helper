# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    GuardDogScanner,
]
ASH_REPORTERS: list[type] = []
