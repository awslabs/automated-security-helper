# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_skillspector_plugins.skillspector_scanner import (
    SkillSpectorScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SkillSpectorScanner,
]
ASH_REPORTERS: list[type] = []
