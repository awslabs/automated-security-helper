# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_dockle_plugins.dockle_scanner import (
    DockleScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    DockleScanner,
]
ASH_REPORTERS: list[type] = []
