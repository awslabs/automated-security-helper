# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    CapslockScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CapslockScanner,
]
ASH_REPORTERS: list[type] = []
