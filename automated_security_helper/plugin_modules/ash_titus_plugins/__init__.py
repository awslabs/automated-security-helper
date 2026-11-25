# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_titus_plugins.titus_scanner import (
    TitusScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    TitusScanner,
]
ASH_REPORTERS: list[type] = []
