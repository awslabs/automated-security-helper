# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_ggshield_plugins.ggshield_scanner import (
    GgshieldScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    GgshieldScanner,
]
ASH_REPORTERS: list[type] = []
