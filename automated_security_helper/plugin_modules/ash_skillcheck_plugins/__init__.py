# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_skillcheck_plugins.skillcheck_scanner import (
    SkillcheckScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SkillcheckScanner,
]
ASH_REPORTERS: list[type] = []
