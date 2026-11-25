# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_secretlint_plugins.secretlint_scanner import (
    SecretlintScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    SecretlintScanner,
]
ASH_REPORTERS: list[type] = []
