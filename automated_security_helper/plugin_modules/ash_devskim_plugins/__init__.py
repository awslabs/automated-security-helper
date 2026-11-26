# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_devskim_plugins.devskim_scanner import (
    DevSkimScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    DevSkimScanner,
]
ASH_REPORTERS: list[type] = []
