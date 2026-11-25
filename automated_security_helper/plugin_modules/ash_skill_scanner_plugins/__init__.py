# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_skill_scanner_plugins.skill_scanner_scanner import (
    SkillScannerScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SkillScannerScanner,
]
ASH_REPORTERS: list[type] = []
