# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_conftest_plugins.conftest_scanner import (
    ConftestScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ConftestScanner,
]
ASH_REPORTERS: list[type] = []
