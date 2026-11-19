# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_scanner import (
    PolarisScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    PolarisScanner,
]
ASH_REPORTERS: list[type] = []
