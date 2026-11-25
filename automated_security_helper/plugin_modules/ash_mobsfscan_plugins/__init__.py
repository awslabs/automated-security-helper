# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_mobsfscan_plugins.mobsfscan_scanner import (
    MobsfscanScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    MobsfscanScanner,
]
ASH_REPORTERS: list[type] = []
