# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_zizmor_plugins.zizmor_scanner import (
    ZizmorScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ZizmorScanner,
]
ASH_REPORTERS: list[type] = []
