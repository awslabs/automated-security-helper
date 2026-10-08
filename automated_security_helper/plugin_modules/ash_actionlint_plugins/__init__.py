# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_actionlint_plugins.actionlint_scanner import (
    ActionlintScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ActionlintScanner,
]
ASH_REPORTERS: list[type] = []
