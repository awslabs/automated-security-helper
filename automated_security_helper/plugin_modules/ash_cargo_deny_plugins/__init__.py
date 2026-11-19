# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_scanner import (
    CargoDenyScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CargoDenyScanner,
]
ASH_REPORTERS: list[type] = []
