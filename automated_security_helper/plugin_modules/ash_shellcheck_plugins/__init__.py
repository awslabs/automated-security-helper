# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_shellcheck_plugins.shellcheck_scanner import (
    ShellCheckScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    ShellCheckScanner,
]
ASH_REPORTERS: list[type] = []
