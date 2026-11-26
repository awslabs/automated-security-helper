# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from automated_security_helper.plugin_modules.ash_trufflehog_plugins.trufflehog_scanner import (
    TruffleHogScanner,
)

# Make plugins discoverable
ASH_SCANNERS = [
    TruffleHogScanner,
]
ASH_REPORTERS: list[type] = []
