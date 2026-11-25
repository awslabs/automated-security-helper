# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_scanner import (
    YaraXScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    YaraXScanner,
]
ASH_REPORTERS: list[type] = []
