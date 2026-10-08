# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_gitleaks_plugins.gitleaks_scanner import (
    GitleaksScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    GitleaksScanner,
]
ASH_REPORTERS: list[type] = []
