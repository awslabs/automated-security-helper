# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_credsweeper_plugins.credsweeper_scanner import (
    CredSweeperScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    CredSweeperScanner,
]
ASH_REPORTERS: list[type] = []
