# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_capa_plugins.capa_scanner import (
    CapaScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CapaScanner,
]
ASH_REPORTERS: list[type] = []
